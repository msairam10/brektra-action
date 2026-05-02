import * as core from "@actions/core";
import * as github from "@actions/github";

type Severity = "info" | "low" | "medium" | "high" | "critical";

const SEVERITY_RANK: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

const ALLOWED_SURFACES = new Set(["ai", "web", "api", "cloud", "hosts"]);
const ALLOWED_MODES = new Set(["safe", "aggressive"]);

// Outbound requests carry the user's API key, so the destination must be a
// trusted https origin. http would expose the key on the wire; arbitrary
// schemes would let a misconfigured env var exfiltrate it.
const DEFAULT_API_BASE = "https://brektra.com";
const ALLOWED_API_HOST_SUFFIXES = [".brektra.com", "brektra.com"];

// Bound polling and per-request work so a hung or hostile server can't tie up
// the runner indefinitely.
const MAX_TIMEOUT_MIN = 120;
const REQUEST_TIMEOUT_MS = 30_000;
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;

interface FindingSummary {
  id: string;
  title: string;
  severity: Severity;
  category: string;
  owasp_web_category: string | null;
  owasp_llm_category: string | null;
  business_impact_line: string;
  proof_excerpt: string;
  root_node_id: string | null;
}

interface ScanStatus {
  id: string;
  status: "queued" | "running" | "complete" | "failed" | "cancelled";
  findings_count: number;
  highest_severity: Severity | null;
  replay_url: string;
  share_shortcode: string | null;
  duration_ms: number | null;
  surfaces: string[];
  mode: string;
  findings?: FindingSummary[];
}

// Resolved at the start of main() so any validation failure surfaces as a
// clean action failure rather than an unhandled module-load exception.
let API_BASE = DEFAULT_API_BASE;

async function main() {
  API_BASE = resolveApiBase(process.env.BREKTRA_API_BASE);

  const apiKey = core.getInput("api_key", { required: true });
  // Treat the API key as a secret so it is masked in any subsequent log
  // output, including accidental echoes from libraries or stack traces.
  core.setSecret(apiKey);

  const targetUrl = validateTargetUrl(core.getInput("target_url", { required: true }));

  const surfaces = (core.getInput("surfaces") || "ai,web,api")
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
  for (const s of surfaces) {
    if (!ALLOWED_SURFACES.has(s)) {
      core.setFailed(`surfaces contains unknown value: ${s}. allowed: ${[...ALLOWED_SURFACES].join(", ")}`);
      return;
    }
  }

  const mode = (core.getInput("mode") || "safe").toLowerCase();
  if (!ALLOWED_MODES.has(mode)) {
    core.setFailed(`mode must be one of: ${[...ALLOWED_MODES].join(", ")}`);
    return;
  }

  const failOn = (core.getInput("fail_on_severity") || "high").toLowerCase() as Severity;
  if (!(failOn in SEVERITY_RANK)) {
    core.setFailed(`fail_on_severity must be one of: ${Object.keys(SEVERITY_RANK).join(", ")}`);
    return;
  }

  const rawTimeout = core.getInput("timeout_minutes") || "10";
  const timeoutMin = Number.parseInt(rawTimeout, 10);
  if (!Number.isFinite(timeoutMin) || timeoutMin <= 0 || timeoutMin > MAX_TIMEOUT_MIN) {
    core.setFailed(`timeout_minutes must be an integer between 1 and ${MAX_TIMEOUT_MIN}`);
    return;
  }

  const ctx = github.context;
  const prNumber = ctx.payload.pull_request?.number;
  const repo = ctx.repo;

  core.info(`brektra: scanning ${redactUrl(targetUrl)} (${surfaces.join(",")}, ${mode})`);

  const start = await postJson(`${API_BASE}/api/v1/scans/ci`, apiKey, {
    target_url: targetUrl,
    surfaces,
    mode,
    pr_url: ctx.payload.pull_request?.html_url ?? null,
    repo: `${repo.owner}/${repo.repo}`,
    commit_sha: ctx.sha,
  });

  const scanId = typeof start.scan_id === "string" ? start.scan_id : "";
  if (!scanId) {
    core.setFailed("brektra: server response missing scan_id");
    return;
  }

  core.info(`brektra: scan ${scanId} queued. polling…`);
  core.setOutput("scan_id", scanId);

  const deadline = Date.now() + timeoutMin * 60_000;
  let final: ScanStatus | null = null;

  while (Date.now() < deadline) {
    await sleep(10_000);
    const s = await getJson<ScanStatus>(`${API_BASE}/api/v1/scans/ci/${encodeURIComponent(scanId)}`, apiKey);
    if (s.status === "complete" || s.status === "failed" || s.status === "cancelled") {
      final = s;
      break;
    }
    core.info(`brektra: ${s.status}, ${s.findings_count} findings so far`);
  }

  if (!final) {
    core.setFailed(`brektra: scan did not complete within ${timeoutMin}m`);
    return;
  }

  // The replay URL is propagated to downstream workflow steps and rendered in
  // PR comments, so it must not be an attacker-chosen scheme/host. Fall back
  // to a server-built URL on our own origin if validation fails.
  const safeReplayUrl = sanitizeReplayUrl(final.replay_url, scanId);

  core.setOutput("findings_count", String(final.findings_count));
  core.setOutput("highest_severity", final.highest_severity ?? "");
  core.setOutput("replay_url", safeReplayUrl);

  if (prNumber != null) {
    try {
      const body = composeComment({ ...final, replay_url: safeReplayUrl }, targetUrl, failOn);
      const token = process.env.GITHUB_TOKEN;
      if (!token) {
        core.warning("brektra: GITHUB_TOKEN not set, skipping PR comment");
      } else {
        core.setSecret(token);
        const oct = github.getOctokit(token);
        await oct.rest.issues.createComment({
          owner: repo.owner,
          repo: repo.repo,
          issue_number: prNumber,
          body,
        });
      }
    } catch (err) {
      // GitHub sometimes rejects the comment if perms are off; don't fail the
      // build over it. Use only the message — never the stack — to avoid
      // pulling header values from rich error objects into logs.
      core.warning(`brektra: could not post PR comment: ${errorMessage(err)}`);
    }
  }

  if (final.status === "failed") {
    core.setFailed(`brektra: scan failed (${scanId}). see ${safeReplayUrl}`);
    return;
  }

  const top = final.highest_severity;
  if (top && SEVERITY_RANK[top] >= SEVERITY_RANK[failOn]) {
    core.setFailed(
      `brektra: ${final.findings_count} findings, highest=${top} (>= ${failOn}). see ${safeReplayUrl}`,
    );
    return;
  }

  core.info(`brektra: clean. ${final.findings_count} findings, highest=${top ?? "none"}.`);
}

function resolveApiBase(raw: string | undefined): string {
  if (!raw) return DEFAULT_API_BASE;
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    throw new Error(`BREKTRA_API_BASE is not a valid URL`);
  }
  if (parsed.protocol !== "https:") {
    throw new Error(`BREKTRA_API_BASE must use https`);
  }
  const host = parsed.hostname.toLowerCase();
  const ok = ALLOWED_API_HOST_SUFFIXES.some((suffix) =>
    suffix.startsWith(".") ? host.endsWith(suffix) : host === suffix,
  );
  if (!ok) {
    throw new Error(`BREKTRA_API_BASE host ${host} is not an allowed brektra host`);
  }
  if (parsed.username || parsed.password) {
    throw new Error(`BREKTRA_API_BASE must not contain credentials`);
  }
  // Strip path/query/fragment and trailing slash to normalise the origin.
  return `${parsed.protocol}//${parsed.host}`;
}

function validateTargetUrl(raw: string): string {
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    throw new Error(`target_url is not a valid URL`);
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error(`target_url must use http or https`);
  }
  return parsed.toString();
}

function sanitizeReplayUrl(raw: unknown, scanId: string): string {
  // Server-built fallback when the response value is missing or unsafe.
  const fallback = `${API_BASE}/scans/${encodeURIComponent(scanId)}/replay`;
  if (typeof raw !== "string" || raw.length === 0 || raw.length > 2048) return fallback;
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    return fallback;
  }
  if (u.protocol !== "https:") return fallback;
  const host = u.hostname.toLowerCase();
  const ok = ALLOWED_API_HOST_SUFFIXES.some((suffix) =>
    suffix.startsWith(".") ? host.endsWith(suffix) : host === suffix,
  );
  return ok ? u.toString() : fallback;
}

function redactUrl(raw: string): string {
  try {
    const u = new URL(raw);
    if (u.username || u.password) {
      u.username = "";
      u.password = "";
    }
    return u.toString();
  } catch {
    return raw;
  }
}

function composeComment(s: ScanStatus, target: string, failOn: Severity): string {
  const counts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of s.findings ?? []) counts[f.severity] += 1;
  const summary = `Findings: ${counts.critical} critical, ${counts.high} high, ${counts.medium} medium, ${counts.low} low`;

  const ms = s.duration_ms ?? 0;
  const mins = Math.floor(ms / 60_000);
  const secs = Math.floor((ms % 60_000) / 1000);
  const dur = `${mins}m ${secs}s`;

  const sections: string[] = [];
  for (const sev of ["critical", "high", "medium", "low", "info"] as Severity[]) {
    const findings = (s.findings ?? []).filter((f) => f.severity === sev);
    if (findings.length === 0) continue;
    const lines: string[] = [`### ${capitalize(sev)} severity`];
    for (const f of findings) {
      const tag = f.owasp_web_category ?? f.owasp_llm_category ?? f.category ?? "";
      const replayPath = buildFindingReplayUrl(s, f);
      lines.push(`- ${escapeMarkdown(f.title ?? "")} ${codeSpan(tag)}`);
      if (f.proof_excerpt) {
        lines.push(`  - Proof: ${codeSpan(truncate(String(f.proof_excerpt), 240))}`);
      }
      lines.push(`  - [View exploit replay](${escapeLinkTarget(replayPath)})`);
    }
    sections.push(lines.join("\n"));
  }

  const head = [
    "## Brektra security scan",
    "",
    `Target: ${codeSpan(target)}`,
    `Mode: ${codeSpan(s.mode ?? "")}`,
    `Surfaces: ${codeSpan(Array.isArray(s.surfaces) ? s.surfaces.join(",") : "")}`,
    `Duration: ${dur}`,
    "",
    summary,
    "",
  ].join("\n");

  const body = sections.length > 0 ? sections.join("\n\n") + "\n\n" : "No findings.\n\n";

  const fullReportUrl = sanitizeReplayUrl(`${API_BASE}/scans/${s.id}`, s.id);
  const tail = [
    `[Full report](${escapeLinkTarget(fullReportUrl)})`,
    "",
    `Brektra blocks merge on ${codeSpan(failOn)} severity findings. To override, remove the Brektra Security required status check in repo settings.`,
  ].join("\n");

  return head + body + tail;
}

function buildFindingReplayUrl(s: ScanStatus, f: FindingSummary): string {
  const node = typeof f.root_node_id === "string" ? f.root_node_id : null;
  const code = typeof s.share_shortcode === "string" ? s.share_shortcode : null;
  // Build via URL so node ids and shortcodes are properly encoded and any
  // injection chars in the API response can't escape into the link target.
  const base = code
    ? `${API_BASE}/r/${encodeURIComponent(code)}`
    : `${API_BASE}/scans/${encodeURIComponent(s.id)}/replay`;
  if (!node) return base;
  const u = new URL(base);
  u.searchParams.set("node", node);
  return u.toString();
}

// Strip characters that change the meaning of an inline code span, then wrap.
// API-supplied strings can otherwise close the span and inject markdown.
function codeSpan(s: string): string {
  const cleaned = String(s).replace(/`/g, "'").replace(/[\r\n]+/g, " ");
  return `\`${cleaned}\``;
}

function escapeMarkdown(s: string): string {
  return String(s)
    .replace(/[\r\n]+/g, " ")
    .replace(/[\\`*_{}\[\]()#+!|<>~]/g, (c) => `\\${c}`);
}

// A markdown link target must not contain whitespace or unbalanced parens, and
// must not switch to a dangerous scheme. We've already sanitized the URL via
// sanitizeReplayUrl/buildFindingReplayUrl, but defence-in-depth: only allow
// http(s) and percent-encode the few chars that could close the link.
function escapeLinkTarget(s: string): string {
  const trimmed = String(s).trim();
  if (!/^https?:\/\//i.test(trimmed)) {
    return `${API_BASE}/`;
  }
  return trimmed.replace(/[\s()<>]/g, (c) => encodeURIComponent(c));
}

async function postJson(url: string, apiKey: string, body: unknown): Promise<Record<string, unknown>> {
  return fetchJson(url, apiKey, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
}

async function getJson<T>(url: string, apiKey: string): Promise<T> {
  return fetchJson<T>(url, apiKey, { method: "GET" });
}

async function fetchJson<T = Record<string, unknown>>(
  url: string,
  apiKey: string,
  init: RequestInit,
): Promise<T> {
  // Defence-in-depth: even though the API_BASE is validated up front, refuse
  // any per-request URL that doesn't share that origin. Stops a future bug or
  // a swapped string from sending the bearer token elsewhere.
  if (!url.startsWith(`${API_BASE}/`)) {
    throw new Error(`refusing to send api key to non-api origin`);
  }

  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), REQUEST_TIMEOUT_MS);
  try {
    const r = await fetch(url, {
      ...init,
      headers: {
        authorization: `Bearer ${apiKey}`,
        "user-agent": "brektra-action/1.0",
        ...(init.headers ?? {}),
      },
      signal: ctrl.signal,
      redirect: "error",
    });
    const text = await readBoundedText(r);
    if (!r.ok) {
      throw new Error(`${init.method ?? "GET"} ${redactUrl(url)} -> ${r.status}`);
    }
    if (!text) return {} as T;
    return JSON.parse(text) as T;
  } finally {
    clearTimeout(timer);
  }
}

async function readBoundedText(r: Response): Promise<string> {
  const declared = Number(r.headers.get("content-length") ?? "");
  if (Number.isFinite(declared) && declared > MAX_RESPONSE_BYTES) {
    throw new Error(`response exceeds ${MAX_RESPONSE_BYTES} bytes`);
  }
  if (!r.body) return "";
  const reader = r.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_RESPONSE_BYTES) {
        throw new Error(`response exceeds ${MAX_RESPONSE_BYTES} bytes`);
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  return new TextDecoder("utf-8").decode(Buffer.concat(chunks.map((c) => Buffer.from(c))));
}

function sleep(ms: number) {
  return new Promise((r) => setTimeout(r, ms));
}

function truncate(s: string, n: number): string {
  if (s.length <= n) return s;
  return s.slice(0, n - 1) + "…";
}

function capitalize(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

main().catch((err) => {
  // Use only the message — stack traces can include header values or other
  // captured request state that we'd rather not put in CI logs.
  core.setFailed(errorMessage(err));
});
