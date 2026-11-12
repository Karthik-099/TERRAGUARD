# Security Policy

Report vulnerabilities in TerraGuard privately via **Security → Report a vulnerability**
on GitHub. You'll get a response within 7 days.

## Data handling

* The web app runs the engine in your browser (WebAssembly). Terraform you paste is never uploaded.
* Share links carry your files inside the URL fragment (`#s=…`), which browsers never send to servers.
* AI keys are kept in your browser's `localStorage` and sent only to the provider you choose.
* The GitHub Action runs inside your own workflow; nothing is sent to third parties unless you enable `ai`.
* `terraguard serve` keeps keys in its `.env`; `/api/config` returns provider/model names only, and provider errors are redacted before logging or display.
* `TERRAGUARD_AI_LOCAL_ONLY=true` (or **Private mode** in the web app) guarantees no hosted AI is called.
* Usage counters contain numbers and rule IDs only — never code, file names, IPs or keys — and are skipped under Do-Not-Track / Global Privacy Control, private mode, or when disabled. CLI/Action counters are opt-in.
* CI runs `scripts/check-secrets.sh`, which fails if any credential or `.env` is tracked.

## Verifying releases

From v2.1 onward, every release ships SPDX and CycloneDX SBOMs
(`terraguard.spdx.json`, `terraguard.cdx.json`), `checksums.txt` signed keyless
with Sigstore (`checksums.txt.sigstore.json`), build provenance for every file,
and a keyless signature on the Docker image. Everything uses free GitHub and
Sigstore services; no key is stored anywhere.

```bash
# 1. The checksum file was signed by this repository's release workflow.
cosign verify-blob checksums.txt --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github.com/Karthik-099/TERRAGUARD/.github/workflows/release.yml@' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
# 2. The binary matches the signed checksum.
sha256sum --ignore-missing -c checksums.txt
# Or, with the GitHub CLI, check provenance directly.
gh attestation verify terraguard_linux_amd64 --repo Karthik-099/TERRAGUARD
# The container image.
cosign verify ghcr.io/karthik-099/terraguard:latest \
  --certificate-identity-regexp '^https://github.com/Karthik-099/TERRAGUARD/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## Where data goes

| Mode | Terraform code | AI keys | Network calls |
|---|---|---|---|
| Web app | Stays in the browser (WebAssembly) | Browser storage, sent only to the chosen provider | Static assets; AI only if configured |
| CLI, CI, editor | Stays on the machine or runner | Environment or `.env` | None, unless AI or telemetry is configured |
| Self-hosted server | Scanned in the browser; server API scans in memory, nothing is stored | Server `.env` only | None, unless AI is configured |
| Air-gapped image | Never leaves the network | Internal endpoint only | None |

Server hardening: security headers on every response, per-client rate
limiting, request size limits and timeouts, an optional bearer token, an audit
log with metadata only, and a non-root, read-only distroless container.

## Threat model

| Threat | Mitigation |
|---|---|
| Malicious Terraform or policy input crashes or hangs the engine | The engine does no file or network I/O; the parser and policy loader are fuzzed in CI; the server caps request size (5 MB) and sets timeouts |
| A crafted share link exhausts browser memory | Expansion is capped at 5 MB and the payload's shape is validated before anything is loaded |
| Script injection through file names, findings or AI output | All dynamic text is escaped; AI Markdown is sanitized with DOMPurify; a Content-Security-Policy restricts scripts to this origin and pinned CDN files with integrity hashes |
| API keys leak through logs, errors or responses | Keys are redacted from every error and never returned by `/api/config`; the audit log stores metadata only |
| AI proposes a change that weakens security | `engine.Verify` rejects any AI change that adds findings at medium or above, adds an apply-blocking issue, or does not lower risk |
| A dependency has a known vulnerability | `govulncheck` runs in CI on every change to Go code |
| Abuse of a self-hosted server | Optional bearer token (the server warns when it listens beyond localhost without one), per-client rate limits, non-root read-only container, internal-only deployment templates |
| A web page the user visits drives a local server (CSRF, DNS rebinding) | Cross-site browser POSTs are refused (`Sec-Fetch-Site`/`Origin`); without a token, a server on loopback and `terraguard ui` answer only loopback `Host` names, and the `ui` file API also needs a one-time token |
| A scanned repository injects command-line flags | Paths that start with `-` are passed to helm, kustomize and bicep as `./-name`; git receives file names after `--` |
| A crafted container image exhausts memory in `vuln image` | Nothing is extracted to disk; per-file, per-layer and total size caps, a file-count cap and a layer-count cap |
| A redirect leaks AI keys or downgrades a download | AI calls never follow redirects (custom gateway headers would be forwarded); `vuln update` follows HTTPS redirects only |
| A remote AI agent abuses the MCP endpoint | `/mcp` needs the server token, is rate limited, accepts inline files only and refuses `path` and `write`, so it cannot read or change the server's disk |
| A forged run-task request makes the server fetch internal URLs | Run tasks are HMAC-verified; plan downloads and callbacks go only to the configured Terraform host over HTTPS, redirects included |
| A compromised GitHub Action or dependency | Every action is pinned to a commit SHA; CodeQL, dependency review, govulncheck and staticcheck run on every change |
| Committed state files expose secrets | Detected without being read; the web app never loads their contents |
| A policy file pulls in secrets or internal URLs through `extends` | Local `extends` are read through a root confined to the working folder (no absolute paths, `..` or symlinks out); remote ones are HTTPS only, at most 5 HTTPS redirects, 10 s and 1 MB, must parse as a policy, and are refused with `TERRAGUARD_OFFLINE=true`; errors never echo file content |
| Secrets in scanned code leak through reports | `TG-SECRET-*` findings show only the first four characters of a value, in every output format, and never carry a fix; secret-bearing files such as `.env`, `*.pem` and `id_rsa` are flagged by name and never read |
| A plugin misbehaves | Plugins are executables the user installed on PATH; one inside the scanned folder is refused. Their output is capped (8 MB, 10,000 findings, a timeout), rule IDs are prefixed with the plugin name, and they cannot waive, disable, block or fix |

Known limits, by design:

- `drift --live`, `scan --helm`, `--kustomize` and `--bicep`, and `preflight --live` run external tools (terraform or tofu, helm, kustomize, bicep, cloud CLIs) on the repository with the user's own credentials. A `terraform plan` can run the repository's external data sources. Use them only on code you trust.
- The local `ui` and the language server follow symbolic links inside the opened folder.
- `terraguard serve` on a non-loopback address without a token only warns; set `TERRAGUARD_SERVER_TOKEN` for any shared deployment.
- There is no per-request CPU limit on scans in `serve` beyond the size cap, timeouts and rate limit.
- `vuln update` trusts the OSV download on TLS alone; OSV does not sign its exports.
- Docker base images are pinned by tag, not digest.

Not covered yet: an independent security audit. If you can help with one,
please open a discussion.
