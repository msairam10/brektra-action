# Brektra Security Scan (GitHub Action)

Runs an autonomous Brektra scan against your PR preview and fails the build if an exploit is confirmed.

## Quick start

1. Create a Brektra API key at <https://brektra.com/settings/api-keys>. Pick the `scans:ci` scope. Copy the key. It's shown once.
2. Add it to your repo as a secret named `BREKTRA_API_KEY`.
3. Drop the workflow below into `.github/workflows/brektra.yml`.

```yaml
name: Brektra Security
on:
  pull_request:
    types: [opened, synchronize, reopened]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - name: Deploy preview
        id: preview
        uses: your-preview-action@v1
        # outputs.url should be the PR preview URL

      - name: Brektra scan
        uses: MSaiRam10/brektra-action@v1
        with:
          api_key: ${{ secrets.BREKTRA_API_KEY }}
          target_url: ${{ steps.preview.outputs.url }}
          surfaces: "ai,web,api"
          mode: "safe"
          fail_on_severity: "high"
```

4. (Recommended) Mark `Brektra Security` as a required status check in **Settings → Branches → branch protection rule**. Now Brektra blocks merge on confirmed exploits.

## Inputs

| Input              | Required | Default       | Description |
| ------------------ | -------- | ------------- | ----------- |
| `api_key`          | yes      |               | Brektra API key with the `scans:ci` scope. |
| `target_url`       | yes      |               | URL of the PR preview to scan. |
| `surfaces`         | no       | `ai,web,api`  | Comma-separated surfaces. Valid values: `ai`, `web`, `api`, `cloud`, `hosts`. |
| `mode`             | no       | `safe`        | `safe` or `aggressive`. Aggressive needs per-domain enablement. |
| `fail_on_severity` | no       | `high`        | Build fails if any finding is at or above this. `info`, `low`, `medium`, `high`, `critical`. |
| `timeout_minutes`  | no       | `10`          | Hard timeout. The action fails if the scan does not finish in this window. |

## Outputs

| Output             | Notes |
| ------------------ | ----- |
| `findings_count`   | Total findings. |
| `highest_severity` | Highest severity, or empty string if none. |
| `replay_url`       | Link to the full replay UI. |
| `scan_id`          | Brektra scan id. |

## What you get

- A scan runs against your preview every PR.
- A PR comment lists each finding with severity, OWASP tag, a proof excerpt, and a deep link straight to the exploit step in the replay.
- The action fails the check if any finding meets or exceeds `fail_on_severity`. Combined with branch protection, this blocks merge.
- After a fix is merged, Brektra automatically re-tests against the patched preview and updates the PR comment.

## Pinning

- `@v1` (recommended): moves with patch and minor releases of the v1 line.
- `@v1.0.0`: pinned, never moves. Use this if you need bit-for-bit reproducibility.

## Plan requirement

CI scanning is on Pro and above. Free and Starter accounts get a `402 ci_not_available` from the API and the action fails fast with an upgrade link.

## Troubleshooting

- **"target host not in a verified domain"**: add the preview hostname under <https://brektra.com/targets> and verify the TXT record. Vercel preview URLs change per PR; verify the wildcard parent (e.g. `vercel.app` is not allowed; use a CNAME-stable subdomain like `pr-*.preview.example.com`).
- **"scan_limit_reached"**: your billing cycle is exhausted. Upgrade or wait for the cycle reset shown in the response.
- **"GITHUB_TOKEN not set, skipping PR comment"**: your job needs `permissions: pull-requests: write`. Add it to the job that runs the action.

## Reporting issues

<https://github.com/MSaiRam10/brektra-action/issues>. Include the scan id from the failed run.

## License

MIT.
