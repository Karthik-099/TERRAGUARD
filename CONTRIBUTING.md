# Contributing to TerraGuard

Thanks for helping make Terraform safer. Every rule exists because someone hit
that problem in production. If you have a story like that, it belongs here.

## Local setup (2 minutes)

You need Go 1.25+ and Python 3.10+ (stdlib only, no `pip install`). Node 22 only if you touch `stats-worker/`. Everything is free; no paid services or keys are needed.

```bash
git clone https://github.com/Karthik-099/TERRAGUARD && cd TERRAGUARD
make test      # vet + unit tests
make evals     # rule recall/precision gate
make serve     # full app on http://127.0.0.1:8080 (reads .env if present)
make secrets   # make sure no credential is tracked
ln -s ../../scripts/check-secrets.sh .git/hooks/pre-commit   # recommended
```

Try the CLI on the demo project:

```bash
make build
bin/terraguard scan examples/insecure --plan examples/plan.json
```

## Project layout

| Path | What lives there |
|---|---|
| `engine/` | Pure-Go analysis core: parser, rules (`rules.go`, `rules_clouds.go`), graph checks, plan, policy, compliance, docs, autofix, report formats |
| `internal/ai/` | Free-model router with fallback, `.env` loader, key redaction |
| `internal/stats/` | Anonymous counters for the self-hosted dashboard |
| `cmd/terraguard/` | CLI (`scan`, `fix`, `docs`, `ask`, `rules`), MCP server (`mcp`), self-hosted server (`serve`) |
| `cmd/wasm/` | WebAssembly bridge used by the web app |
| `web/` | Static site (GitHub Pages), also embedded in `terraguard serve` |
| `stats-worker/` | Optional Cloudflare Worker (free plan) for public counters |
| `action.yml` | Composite GitHub Action |
| `evals/` | Labelled cases, the rule regression gate, and the LLM benchmark |
| `examples/` | Demo projects and a sample plan |
| `docs/` | Architecture (HLD/LLD) |

## Adding a rule

1. **Write two cases** in `evals/cases/`: one that must fire and a safe twin that must not.

   ```hcl
   # expect: TG-AWS-SQS-001
   resource "aws_sqs_queue" "q" {
     sqs_managed_sse_enabled = false
   }
   ```

2. **Add the rule** to `Rules` in `engine/rules.go`. Rules receive a normalized
   `Resource`, so the same code works on `.tf` source *and* on plan JSON:

   ```go
   {ID: "TG-AWS-SQS-001", Title: "SQS queue is not encrypted", Severity: Medium, Category: CatSecurity, CWE: "CWE-311",
       Types: []string{"aws_sqs_queue"}, Remediation: "Set sqs_managed_sse_enabled = true or kms_master_key_id.",
       Check: func(r *Resource) []Hit {
           if is(r.get("sqs_managed_sse_enabled"), false) && r.get("kms_master_key_id") == nil {
               return []Hit{{Path: "sqs_managed_sse_enabled", Msg: "Messages are stored unencrypted.",
                   Fix: fix(true, "Enable SSE", "sqs_managed_sse_enabled")}}
           }
           return nil
       }},
   ```

   * `r.get("a.b")` walks nested blocks. Non-literal values come back as `Unknown`. Treat them as "can't tell" and don't flag them.
   * `Hit.Path` picks the line to report; `Hit.Fix` (optional) makes it one-click fixable.
   * Cross-resource or whole-module checks go in `engine/checks.go`, with metadata in `ModuleRules`.

3. Run `make test evals`, then open a PR. The rule appears automatically in the
   CLI, the Action, the MCP server and the web app's Rules tab.

## Guidelines

* **Precision over recall.** A noisy rule gets disabled by users, so only flag what you can prove from the code.
* Keep `engine/` free of I/O so it keeps compiling to WebAssembly.
* The LLM never gates anything. AI features must stay optional, and only free or local models may be defaults.
* Never log, return or commit keys. Use `ai.Redact` for any provider error you surface.
* Commit messages: `feat(rules): ...`, `fix(engine): ...`, `docs: ...`.

## Reporting security issues

Please don't open public issues for vulnerabilities in TerraGuard itself. Use
GitHub's **Report a vulnerability** (Security tab) instead.
