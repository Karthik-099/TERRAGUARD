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

From v2.1 onward, every release ships an SPDX SBOM, build provenance for each
binary, and a keyless Sigstore signature on the Docker image.

```bash
gh attestation verify terraguard_linux_amd64 --repo Karthik-099/TERRAGUARD
cosign verify ghcr.io/karthik-099/terraguard:latest \
  --certificate-identity-regexp 'https://github.com/Karthik-099/TERRAGUARD/' \
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
