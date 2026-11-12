# AGENTS.md

Guidance for AI coding agents (and new contributors) working in this repository.

## What TerraGuard is

An open-source infrastructure-as-code checker: Terraform and OpenTofu,
Kubernetes (Helm, Kustomize), CloudFormation and SAM, Serverless, ARM and
Bicep, Dockerfile, docker-compose, CI pipelines, Ansible, OpenAPI, Pulumi,
Crossplane and OpenShift, on public clouds and on Nutanix, VMware vSphere and
Red Hat (ROSA, ARO). One deterministic Go engine finds misconfigurations,
leaked secrets, apply-time failures, destructive plan changes and cost, and
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
- **Rule pinning.** `rules_version` in the policy; `engine.RuleSince` says when each rule arrived (add a release's new rules to `rule_versions.go` when it ships).
- **Pulse.** Control adoption, waiver inventory and trend across many modules.
- **Attack paths.** Cross-resource graph checks (for example a public instance reaching an unencrypted database).
- **Teams.** CODEOWNERS on every finding (`--group-by owner`), whole-folder and zip scans in the browser, plugins and add-on rules.
- **Privacy.** Code never leaves the device in the browser; air-gapped mode (`TERRAGUARD_OFFLINE=true`) makes zero outside requests; paid AI is opt-in only.

## Layout

| Path | Purpose |
|---|---|
| `engine/` | Pure Go, no I/O. `parse.go` (HCL), `json_config.go` (.tf.json), `plan.go` (plan JSON), `rules*.go` (resource rules: hand-written, `rules_port_*.go`, table checks in `rules_table.go`, generated `rules_parity.go`), `graphpolicy.go` + `rules_graph_gen.go` (graph policies), `checks.go` (module, state, graph), `schema*.go` (provider schemas, bundled in `schemas/`), `cost.go`, `policy.go`, `scan.go` (report, verdict, gate), `fix.go` (hclwrite), `verify.go`, `review.go`, `format.go` (SARIF, JUnit, Code Quality, Markdown) |
| `engine/format_*.go` | Parsers for non-Terraform formats, registered in `formats.go`; each turns a file into `Resource`s. Rules for them are in `rules_k8s_manifest.go`, `rules_cfn.go`, `rules_azure_rm.go`, `rules_docker.go`, `rules_ci.go`, `rules_ansible.go`, `rules_openapi.go`, `rules_redhat.go` (OpenShift, ROSA, ARO); private clouds in `rules_nutanix.go` and `rules_vsphere.go`; secret scanning in `secrets.go`; CODEOWNERS in `codeowners.go`; SBOM in `sbom.go`; AWS API value checks in `rules_values.go` (generated table `values_aws_gen.go`) |
| `tools/` | Generators: `awsvalgen` (AWS API value table), `ckvgen` (rule table and graph policies, with reviewed `wording*.txt`, `overrides.txt`, `duplicates.txt`), `schemagen` (bundled provider schemas) |
| `cmd/terraguard/` | CLI: init, scan (`--watch`, `--coverage`), fix, review, agent, pulse, policy, cost, preflight, explain, doctor, docs, agents-md, ask, ai, ui, lsp, serve (with the admission webhook), mcp, rules, drift, vuln, sbom, plugins (`terraguard-<name>` executables) |
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

1. A single setting on one resource type: add a `check` to `tableChecks` in `engine/rules_table.go`. Anything else: a function in `engine/rules.go` or a `rules_*.go` file, returning hits with a line and, if safe, a fix. Do not edit the generated `rules_parity.go` or `rules_graph_gen.go`; change `tools/ckvgen/*.txt` and regenerate.
2. Add two cases to `evals/cases/`: one that must fire (`# expect:`) and one that must not (`# forbid:`).
3. For another format, put the rule in that format's `rules_*.go` file and the case in `evals/cases/` with a `# path:` header when the file name decides the format (JSON cases use a `.expect` sidecar).
4. Run `make test evals`. A rule that fires on an absent setting must check the provider default first; `CKV_SRC=<checkout> go test ./engine -run Parity` and a scan of real modules catch most mistakes.

## Boundaries

- Go only for product code. JavaScript only where the platform requires it (browser, VS Code, optional worker).
- The engine stays deterministic and free of network or file I/O.
- Never add a paid service, scheduled workflow, telemetry or tracker by default.
- Never commit `.env`, keys, state files or `docs/brand/`. Keys must never appear in logs or errors.
- No emojis in code, UI or docs.
