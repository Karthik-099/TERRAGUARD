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
