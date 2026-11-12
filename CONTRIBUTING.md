# Contributing to TerraGuard

Thank you for being here. A short, honest note first.

This is not a company or a product for sale. It is a learning project. I
have worked in a tech firm, so I know some things about infrastructure, but
certainly not everything, and I am building TerraGuard to learn how these tools
can be made better. It is free, I am not asking for money, and it does not even
have its own domain yet; it lives on GitHub Pages, and maybe one day it will
have a proper home.

If you know a better way to do something here, I would genuinely like to learn
from you. Contributions of any size are welcome and never expected: a star, an
issue, a review of the architecture, a correction, or a new rule.

If you are new to open source too, this is a friendly place to start; issues
labelled `good first issue` are a good entry point.

Thanks for helping make Terraform safer. Every rule exists because someone hit
that problem in production. If you have a story like that, it belongs here.

## Proposing a rule without writing Go

Write the rule as a custom rule, in the workspace's Policy tab (form or plain
English) or in `.terraguard.yml`, then press **Propose as built-in rule**. It
opens a pre-filled GitHub issue with your YAML and an example. A maintainer
reviews it and adds it in Go with two test cases. Nothing is merged
automatically: built-in rules run in other people's CI, so every one is
reviewed.

## Local setup (2 minutes)

You need Go 1.26.11+, nothing else. Node 22 only if you touch `stats-worker/`. Everything is free; no paid services or keys are needed.

```bash
git clone https://github.com/Karthik-099/TERRAGUARD && cd TERRAGUARD
make test      # vet + unit tests
make evals     # every labelled rule case must pass
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
| `internal/pulse/` | Adoption, waiver and trend aggregation for `terraguard pulse` |
| `editors/vscode/` | VS Code extension (diagnostics and quick fixes via the CLI) |
| `templates/` | CI templates: GitLab, Jenkins, AWS CodeBuild, Azure Pipelines, Google Cloud Build |
| `deploy/` | Private deployments for AWS, Azure, Google Cloud and Kubernetes (Helm) |
| `evals/` | Labelled rule cases and `evals/llmeval` (Go LLM benchmark) |
| `schema/` | JSON Schema for `.terraguard.yml` |
| `examples/policies/` | Example policy pack (org baseline, team policy, fixtures) |
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

## Contributing a policy pack

Policy packs are plain `.terraguard.yml` files that others `extends`. To
share one, add it under `examples/policies/` with fixtures in a `tests/`
folder, and make sure `terraguard policy test` passes:

```bash
bin/terraguard policy test examples/policies/tests --config examples/policies/team-payments.yml
```

## Guidelines

* **Precision over recall.** A noisy rule gets disabled by users, so only flag what you can prove from the code.
* Keep `engine/` free of I/O so it keeps compiling to WebAssembly.
* The LLM never gates anything. AI features must stay optional, and only free or local models may be defaults.
* Never log, return or commit keys. Use `ai.Redact` for any provider error you surface.
* Commit messages: `feat(rules): ...`, `fix(engine): ...`, `docs: ...`.
* No emojis in code, UI text, reports or docs.

## Reporting security issues

Please don't open public issues for vulnerabilities in TerraGuard itself. Use
GitHub's **Report a vulnerability** (Security tab) instead.
