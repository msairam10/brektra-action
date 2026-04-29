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

const API_BASE =
  process.env.BREKTRA_API_BASE?.replace(/\/$/, "") ?? "https://brektra.com";

async function main() {
  const apiKey = core.getInput("api_key", { required: true });
  const targetUrl = core.getInput("target_url", { required: true });
  const surfaces = (core.getInput("surfaces") || "ai,web,api")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  const mode = core.getInput("mode") || "safe";
  const failOn = (core.getInput("fail_on_severity") || "high") as Severity;
  const timeoutMin = parseInt(core.getInput("timeout_minutes") || "10", 10);

  if (!(failOn in SEVERITY_RANK)) {
    core.setFailed(`fail_on_severity must be one of: ${Object.keys(SEVERITY_RANK).join(", ")}`);
    return;
  }

  const ctx = github.context;
  const prNumber = ctx.payload.pull_request?.number;
  const repo = ctx.repo;

  core.info(`brektra: scanning ${targetUrl} (${surfaces.join(",")}, ${mode})`);

  const start = await postJson(`${API_BASE}/api/v1/scans/ci`, apiKey, {
    target_url: targetUrl,
    surfaces,
    mode,
    pr_url: ctx.payload.pull_request?.html_url ?? null,
    repo: `${repo.owner}/${repo.repo}`,
    commit_sha: ctx.sha,
  });

  const scanId = start.scan_id as string;
  const replayUrl = (start.replay_url as string) ?? `${API_BASE.replace(/\/api$/, "")}/scans/${scanId}/replay`;

  core.info(`brektra: scan ${scanId} queued. polling…`);
  core.setOutput("scan_id", scanId);

  const deadline = Date.now() + timeoutMin * 60_000;
  let final: ScanStatus | null = null;

  // poll until done or we hit the timeout
  while (Date.now() < deadline) {
    await sleep(10_000);
    const s = await getJson<ScanStatus>(`${API_BASE}/api/v1/scans/ci/${scanId}`, apiKey);
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

  core.setOutput("findings_count", String(final.findings_count));
  core.setOutput("highest_severity", final.highest_severity ?? "");
  core.setOutput("replay_url", final.replay_url);

  if (prNumber != null) {
    try {
      const body = composeComment(final, targetUrl, failOn);
      const token = process.env.GITHUB_TOKEN;
      if (!token) {
        core.warning("brektra: GITHUB_TOKEN not set, skipping PR comment");
      } else {
        const oct = github.getOctokit(token);
        await oct.rest.issues.createComment({
          owner: repo.owner,
          repo: repo.repo,
          issue_number: prNumber,
          body,
        });
      }
    } catch (err) {
      // github sometimes rejects the comment if perms are off, don't kill the build over it
      core.warning(`brektra: could not post PR comment: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  if (final.status === "failed") {
    core.setFailed(`brektra: scan failed (${scanId}). see ${final.replay_url}`);
    return;
  }

  const top = final.highest_severity;
  if (top && SEVERITY_RANK[top] >= SEVERITY_RANK[failOn]) {
    core.setFailed(
      `brektra: ${final.findings_count} findings, highest=${top} (>= ${failOn}). see ${final.replay_url}`,
    );
    return;
  }

  core.info(`brektra: clean. ${final.findings_count} findings, highest=${top ?? "none"}.`);
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
      const tag = f.owasp_web_category ?? f.owasp_llm_category ?? f.category;
      const replayPath = s.share_shortcode
        ? `${API_BASE}/r/${s.share_shortcode}${f.root_node_id ? `?node=${f.root_node_id}` : ""}`
        : `${API_BASE}/scans/${s.id}/replay${f.root_node_id ? `?node=${f.root_node_id}` : ""}`;
      lines.push(`- ${f.title} \`${tag}\``);
      if (f.proof_excerpt) lines.push(`  - Proof: ${truncate(f.proof_excerpt, 240)}`);
      lines.push(`  - [View exploit replay](${replayPath})`);
    }
    sections.push(lines.join("\n"));
  }

  const head = [
    "## Brektra security scan",
    "",
    `Target: \`${target}\``,
    `Mode: \`${s.mode}\``,
    `Surfaces: \`${s.surfaces.join(",")}\``,
    `Duration: ${dur}`,
    "",
    summary,
    "",
  ].join("\n");

  const body = sections.length > 0 ? sections.join("\n\n") + "\n\n" : "No findings.\n\n";

  const tail = [
    `[Full report](${API_BASE}/scans/${s.id})`,
    "",
    `Brektra blocks merge on \`${failOn}\` severity findings. To override, remove the Brektra Security required status check in repo settings.`,
  ].join("\n");

  return head + body + tail;
}

async function postJson(url: string, apiKey: string, body: unknown): Promise<Record<string, unknown>> {
  const r = await fetch(url, {
    method: "POST",
    headers: {
      authorization: `Bearer ${apiKey}`,
      "content-type": "application/json",
      "user-agent": "brektra-action/1.0",
    },
    body: JSON.stringify(body),
  });
  const text = await r.text();
  if (!r.ok) throw new Error(`POST ${url} -> ${r.status}: ${text.slice(0, 400)}`);
  return text ? JSON.parse(text) : {};
}

async function getJson<T>(url: string, apiKey: string): Promise<T> {
  const r = await fetch(url, {
    headers: { authorization: `Bearer ${apiKey}`, "user-agent": "brektra-action/1.0" },
  });
  const text = await r.text();
  if (!r.ok) throw new Error(`GET ${url} -> ${r.status}: ${text.slice(0, 400)}`);
  return JSON.parse(text) as T;
}

function sleep(ms: number) {
  return new Promise((r) => setTimeout(r, ms));
}

function truncate(s: string, n: number): string {
  if (s.length <= n) return s;
  return s.slice(0, n - 1) + "…";
}

// TODO: handle the github rate limit case better. octokit retries internally
// but if the PR has tons of comments we still might hit secondary limits.
function capitalize(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

main().catch((err) => {
  core.setFailed(err instanceof Error ? err.stack ?? err.message : String(err));
});
