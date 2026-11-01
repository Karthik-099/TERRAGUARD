# AGENTS.md

Guidance for AI coding agents (and new contributors) working in this repository.

## What TerraGuard is

An open-source Terraform checker. One deterministic Go engine finds
misconfigurations, apply-time failures and destructive plan changes, and
fixes many of them. The same engine runs in the browser (WebAssembly), the
CLI, the GitHub Action, VS Code, an MCP server and a self-hosted server.
AI is optional: it explains and proposes; the engine decides.

## What makes it different

- **Will-it-apply verdict.** Blocking findings predict `terraform validate`/`apply` failures (invalid bucket names, non-canonical CIDRs, retired runtimes) without `init` or credentials.
- **Verified AI fixes.** `engine.Verify` accepts an AI-proposed file only if risk goes down, nothing new at medium or above appears, and nothing new blocks apply.
- **Diff-aware review.** `terraguard review --base <ref>` gates only on findings a change introduces, with risk tiers.
- **Policy-as-code.** `.terraguard.yml` with `extends`, custom rules (`where`/`assert`), expiring waivers with approver, budgets (`max_findings`), baselines, `policy test`.
- **Plain-English standards.** `engine.DraftRule` turns a model's draft into one validated custom rule (no waivers, disables or built-in IDs) and dry-runs it; `terraguard policy suggest` and the Policy tab use it.
- **Remote MCP.** `terraguard serve` exposes the MCP tools at `/mcp` (token-protected, inline files only).
- **Quota preflight.** `terraguard preflight --live` counts what a plan needs per cloud quota and checks S3 name availability with read-only CLI calls; it is separate from the deterministic gate.
- **Pulse.** Control adoption, waiver inventory and trend across many modules.
- **Attack paths.** Cross-resource graph checks (for example a public instance reaching an unencrypted database).
- **Privacy.** Code never leaves the device in the browser; air-gapped mode makes zero outside requests; paid AI is opt-in only.

## Layout

| Path | Purpose |
|---|---|
| `engine/` | Pure Go, no I/O. `parse.go` (HCL), `plan.go` (plan JSON), `rules.go` + `rules_clouds.go` (resource rules), `checks.go` (module, state, graph), `policy.go`, `scan.go` (report, verdict, gate), `fix.go` (hclwrite), `verify.go`, `review.go`, `format.go` (SARIF, JUnit, Code Quality, Markdown) |
| `cmd/terraguard/` | CLI: scan, fix, review, agent, pulse, policy, docs, agents-md, ask, ai, serve, mcp, rules |
| `cmd/wasm/` | Browser build of the engine |
| `internal/ai` | Free-first model router with fallback and key redaction |
| `web/` | Static site and workspace (`index.html`, `app.js`, `style.css`), embedded into `terraguard serve` |
| `evals/cases/` | Labelled `.tf` cases: `# expect:` and `# forbid:` rule IDs |
| `deploy/`, `templates/` | Private deployments (AWS, Azure, GCP, Helm) and CI templates |

## Commands

```bash
make build        # bin/terraguard
make test         # vet + unit tests
make evals        # every labelled case must pass
make policy-test  # example policy fixtures
make web          # WASM + example files for the site
make serve        # http://127.0.0.1:8080
make secrets      # no credential is tracked
```

## Adding a rule

1. Add a function to `engine/rules.go` or `engine/rules_clouds.go` returning hits with a line and, if safe, a fix.
2. Add two cases to `evals/cases/`: one that must fire (`# expect:`) and one that must not (`# forbid:`).
3. Run `make test evals`.

## Boundaries

- Go only for product code. JavaScript only where the platform requires it (browser, VS Code, optional worker).
- The engine stays deterministic and free of network or file I/O.
- Never add a paid service, scheduled workflow, telemetry or tracker by default.
- Never commit `.env`, keys, state files or `docs/brand/`. Keys must never appear in logs or errors.
- No emojis in code, UI or docs.
