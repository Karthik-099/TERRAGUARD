# Reference

Complete reference for the CLI, the policy file, the HTTP API, the MCP server
and configuration. For a walkthrough, start with [Getting started](GUIDE.md).

## Files read

`.tf` and `.tofu` code (OpenTofu uses `x.tofu` instead of `x.tf` when both
exist), Terraform JSON (`.tf.json`; findings point at the JSON lines and are
not auto-fixed), `.tfvars`, `.terraform.lock.hcl` (only to read pinned provider
versions), and `terragrunt.hcl`: its `inputs` are used as variable values and
its `remote_state` is checked for encryption and locking. Modules that
`terraform init` downloaded are read with `--include-modules`.

Other formats are recognised by name and content, so unrelated YAML and JSON
files are skipped:

| Format | Recognised by | Resource types the rules see |
|---|---|---|
| Kubernetes | YAML or JSON with `apiVersion` and `kind` | The Terraform kubernetes provider's types (`kubernetes_deployment_v1`, ...), so one rule set covers both |
| CloudFormation, SAM | `AWSTemplateFormatVersion`, `AWS::Serverless`, or `Resources` with `Type: AWS::` | `AWS::S3::Bucket` and so on; address `Type.LogicalId` |
| Serverless Framework | `serverless.yml` | `serverless_provider`, `serverless_function`, plus `resources` as CloudFormation |
| ARM | `deploymentTemplate` schema | `Microsoft.Storage/storageAccounts` and so on (case-insensitive) |
| Dockerfile | `Dockerfile`, `Dockerfile.*`, `*.dockerfile`, `Containerfile` | `dockerfile`, `dockerfile_stage` |
| docker-compose | `docker-compose*.yml`, `compose.yml` | `compose`, `compose_service` |
| GitHub Actions | `.github/workflows/*.yml` | `github_workflow`, `github_job` |
| GitLab CI, Azure Pipelines, CircleCI, Bitbucket | `.gitlab-ci.yml`, `azure-pipelines.yml`, `.circleci/config.yml`, `bitbucket-pipelines.yml` | `gitlab_job`, `azure_pipeline_job`, `circleci_job`, `bitbucket_step` and their file-level types |
| Ansible | YAML with `hosts:` and `tasks:` or `roles:` | `ansible_<module>` per task |
| OpenAPI | `openapi:` or `swagger:` | `openapi_document`, `openapi_operation` |

YAML containing `{{ }}` templates is skipped; render it first (`--helm`).
Auto-fix edits Terraform only; findings in other formats have no fix.

## CLI

| Command | Purpose |
|---|---|
| `terraguard scan [paths] [flags]` | Scan `.tf` and `.tfvars` files (default `.`) |
| `terraguard review --base REV [paths]` | Report only what a change introduces or resolves, with a risk tier |
| `terraguard report [paths] --framework soc2\|iso27001\|cis\|pci\|hipaa` | Audit evidence report grouped by framework control (HTML or JSON) |
| `terraguard fix [paths]` | Apply safe, deterministic fixes in place |
| `terraguard agent [paths] [--write]` | Deterministic fixes, then AI proposals that the engine verifies |
| `terraguard pulse [roots]` | Control adoption, waivers and trend across many modules |
| `terraguard preflight --plan FILE --live` | Check the plan against live cloud quotas, S3 name availability and IAM permissions (read-only) |
| `terraguard cost [paths] [--plan FILE] [--usage FILE] [--prices FILE] [--fail-above USD]` | Offline monthly cost estimate of a plan or of the code; exit 1 when it adds more than the budget |
| `terraguard policy validate` | Validate `.terraguard.yml`, including `extends` |
| `terraguard policy test DIR` | Run policy fixtures (`# expect:` and `# forbid:` headers) |
| `terraguard policy suggest "standard" [paths]` | Draft one custom rule from plain English: AI drafts, the engine validates and dry-runs it |
| `terraguard docs [path]` | Module README: inputs, outputs, providers, resources |
| `terraguard graph [paths] [--format mermaid\|dot\|json] [--plan FILE]` | Resource graph; attack paths in red, high-risk resources in amber. Mermaid renders on GitHub; DOT for Graphviz |
| `terraguard agents-md [path]` | AGENTS.md for coding agents: commands, guardrails, boundaries |
| `terraguard ask "question" [paths]` | Ask the optional AI assistant about your Terraform |
| `terraguard ai` | Print the AI fallback route built from the environment |
| `terraguard rules [--format text\|json\|markdown]` | The rule catalog |
| `terraguard init [path] [--pack P] [--ci github\|gitlab\|none] [--force]` | Write `.terraguard.yml` on a built-in pack, a CI workflow and a pre-commit config; existing files are kept unless `--force` |
| `terraguard explain RULE-ID` | Severity, category, CWE, the resource types, compliance themes, the other tools' IDs it answers to, and the fix |
| `terraguard doctor [path]` | Version, rule count, policy validity, and which optional tools (terraform, helm, kustomize, bicep, cloud CLIs) are on PATH |
| `terraguard lsp` | Language server over stdio: diagnostics on open, change and save, quick fixes for Terraform, Kubernetes and Dockerfiles. Packages: editors/nvim, editors/jetbrains |
| `terraguard drift [dir] --state FILE \| --live [--fail] [--format json]` | Inventory of code against state (not applied, not in code); `--live` runs a read-only `terraform plan -refresh-only` to list resources changed outside Terraform |
| `terraguard fix [paths] --pr [--base BRANCH]` | Apply safe fixes, commit only the fixed files on a new branch, push it and open a pull request with gh (or print the command) |
| `terraguard ui [path] [--no-browser]` | Open the workspace locally with the folder loaded from disk (loopback only, one-time token, read-only) |
| `terraguard serve [--addr host:port] [--tls-cert F --tls-key F] [--admission-policy F]` | Self-host the web app, the HTTP API and the Kubernetes admission webhook (`/api/k8s/validate`); flags below |
| `terraguard mcp` | Run the MCP server over stdio |
| `terraguard connect claude-code\|cursor\|vscode\|claude-ai\|print [--url https://host]` | Add TerraGuard to an MCP client; see below and [CONNECT.md](CONNECT.md) |
| `terraguard sbom [paths] [--format cyclonedx\|json] [--out FILE]` | Offline CycloneDX 1.5 inventory: Terraform providers (locked versions), modules, container images and lockfile packages, with purls |
| `terraguard migrate hpegl [paths] [--format text\|json\|markdown]` | Every `hpegl_*` resource and data source with file, line and its `hpe_*` replacement (or none), import IDs, the provider block change and HPE's tfmigrator commands, from HPE's migration guides; a report that always exits 0. See [HPE.md](HPE.md#migrate-from-greenlake) |
| `terraguard vuln --sbom FILE` | Offline OSV scan of the packages in a CycloneDX JSON SBOM (from `terraguard sbom` or another tool) instead of lockfiles |
| `terraguard version` | Print the version |

Every command accepts `-h` for its flags. Flags may appear before or after paths.

### scan flags

| Flag | Meaning |
|---|---|
| `--format` | stdout format: `text` (default), `json`, `sarif`, `junit`, `codequality`, `checkstyle`, `github` (workflow annotations), `azure` (Azure DevOps logging commands), `markdown` |
| `--plan FILE` | Also analyze `terraform show -json` output |
| `--schema FILE` | Check every argument and block against `terraform providers schema -json` output (otherwise the bundled AWS, Azure and Google schemas are used) |
| `--no-builtin-schema` | Do not use the bundled schemas |
| `--policy-dir DIR` | Also run graph policies in Checkov's YAML format from DIR (repeatable; `--external-checks-dir` is the same) |
| `--rego DIR` | Also run Rego policies, Conftest style: `deny`, `violation` (HIGH) and `warn` (LOW) rules in any package; input is the plan JSON with `--plan`, otherwise `{"resource": {type: {name: [body]}}}` |
| `--include-modules` | Also scan modules in `.terraform/modules` |
| `--coverage` | List every resource with the number of rules that checked it and which failed; the summary line is always printed |
| `--watch` | Rescan whenever a file the scan reads changes (polling; any OS) |
| `--framework LIST` | Scan only these formats: `terraform`, `kubernetes`, `cloudformation`, `serverless`, `arm`, `dockerfile`, `docker-compose`, `github-actions`, `gitlab-ci`, `azure-pipelines`, `circleci`, `bitbucket-pipelines`, `ansible`, `openapi` |
| `--helm` | Render each chart (`Chart.yaml`) with `helm template` and scan the manifests (needs `helm`) |
| `--kustomize` | Render each `kustomization.yaml` with `kustomize build` or `kubectl kustomize` |
| `--bicep` | Compile each `.bicep` file with `bicep build` or `az bicep build` and scan the ARM template |
| `--config FILE` | Policy file (default: `.terraguard.yml`, found automatically) |
| `--fail-on LEVEL` | Override the threshold: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `NONE` |
| `--sarif`, `--junit`, `--codequality`, `--markdown`, `--json FILE` | Write additional reports |
| `--var-file FILE` | Use this tfvars file, like `terraform -var-file` (repeatable; later files win; overrides `terraform.tfvars`) |
| `--check ID` / `--skip-check ID` | Run only, or skip, these rule IDs or globs (repeatable) |
| `--skip-path GLOB` | Do not scan matching paths, e.g. `test/**` (repeatable) |
| `--write-baseline FILE` | Save current findings as accepted debt |
| `--baseline FILE` | Report baselined findings as waived; gate only on new ones |
| `--ai` | Add an advisory AI remediation plan to the Markdown report |
| `--group-by owner` | Group `text` and `markdown` output into one section per CODEOWNERS owner, with counts; unowned findings last |
| `--snippets MODE` | Provider documentation examples: `auto` (default) detects them by path, `on` treats every `.tf` file as a standalone snippet, `off` scans them as modules; see below |

### Provider documentation examples

Terraform providers keep registry examples in the tfplugindocs layout: `examples/provider/*.tf`, and `examples/<kind>/<name>/*.tf` for `resources`, `data-sources`, `functions`, `ephemeral-resources` and `actions`. Each file is a standalone snippet: a folder can hold alternatives that declare the same address, and snippets use variables they never declare. With `--snippets auto` (or `snippets:` in the policy) TerraGuard scans each such file as its own scope: no duplicate check across files, no undeclared-reference, unused-object, description or type checks, no module-level checks (backend, `required_version`, provider pinning), and no missing-argument finding in a block that says it leaves arguments out with a `# ...` comment or in a context block of another type than the one the folder documents (the `aws_eks_cluster` a `tls_certificate` example reads from). Resource security rules, secret rules, value checks and schema checks still run, and a duplicate inside one file is still reported. Other folders under `examples/`, such as `examples/e2e/` or `examples/complete/`, are real modules and keep every check.

### review, agent and pulse flags

| Command | Flag | Meaning |
|---|---|---|
| review | `--base REV` | Git revision to compare with (default `origin/main`) |
| review | `--format markdown\|json\|github-review\|gitlab-review`, `--out FILE`, `--markdown FILE`, `--json FILE` | Outputs; `--out` writes the `--format` output to a file instead of stdout |
| review | `--fail-on`, `--config`, `--ai`, `--schema` | As for scan |
| agent | `--write` | Write accepted changes (default: dry run) |
| agent | `--rounds N` | Maximum AI rounds (default 2) |
| agent | `--min-severity LEVEL` | Only ask the AI about findings at or above this level (default `MEDIUM`) |
| pulse | `--baseline FILE` | Previous pulse JSON, to show the trend |
| pulse | `--json FILE`, `--markdown FILE`, `--format` | Outputs |
| pulse | `--min-adoption N` | Exit 1 if any control's adoption is below N percent |
| pulse | (CODEOWNERS) | With a CODEOWNERS file in a root, the report adds findings per owner (`owners` in JSON) |

### review --format github-review

Writes the body of GitHub's
[create a review](https://docs.github.com/en/rest/pulls/reviews#create-a-review-for-a-pull-request)
request: `body`, `event` (always `COMMENT`) and `comments`, each with `path`
(relative to the repository root), `line`, `side` (`RIGHT`), `start_line` and
`start_side` for a range, and `body`.

- A new finding on a line the change added becomes an inline comment. Others are listed in `body`.
- When the finding has a safe fix, TerraGuard applies that fix alone, keeps only the lines that differ, and adds them as a ` ```suggestion ` block if they sit inside the same run of changed lines. A fix that only inserts lines also replaces the line before it, since a suggestion must replace at least one line. A fix that reaches outside the change becomes a plain comment that says to run `terraguard fix`.
- Secret findings never get a suggestion, and their values stay redacted.
- Finding text is escaped, so a resource name cannot open a code fence, link or HTML comment, or @mention anyone. The fence around a suggestion is longer than any run of backticks inside it.
- `body` and each comment start with the hidden marker `<!-- terraguard-review -->`.
- The exit code is the same as for any review.

### review --format gitlab-review

The same findings, suggestions, escaping and secret handling as
`github-review`, in the shape of GitLab's
[merge request discussions](https://docs.gitlab.com/api/discussions/):

```json
{
  "body": "<!-- terraguard-review -->\n## TerraGuard review: passed (lite risk tier)\n...",
  "discussions": [
    {
      "body": "<!-- terraguard-review -->\n**MEDIUM** ` TG-AWS-EBS-001 ` ...\n\n```suggestion:-1+0\n...\n```",
      "position": {"base_sha": "...", "start_sha": "...", "head_sha": "...", "position_type": "text",
                   "old_path": "infra/main.tf", "new_path": "infra/main.tf", "new_line": 6}
    }
  ]
}
```

- `body` is the summary, with findings that are not on a changed line; post it as a thread without a position. Each entry of `discussions` is the body of one `POST /projects/:id/merge_requests/:iid/discussions`.
- `new_line` is the last line the fix replaces, and the suggestion is ` ```suggestion:-A+0 `: it replaces the `A` lines above the commented line and the line itself.
- `base_sha` and `start_sha` are `--base` resolved to a commit and `head_sha` is `HEAD`. The GitLab CI template replaces all three with the merge request's `diff_refs`.
- `body` and each discussion start with the hidden marker `<!-- terraguard-review -->`.

### report flags

| Flag | Meaning |
|---|---|
| `--framework soc2\|iso27001\|cis\|pci\|hipaa` | Framework to report on (required) |
| `--format html\|json` | Output (default `html`) |
| `--out FILE` | Write to a file instead of stdout |
| `--config FILE` | Policy file, for waivers (default: found automatically) |

The report groups checks by framework control, using the same theme mapping as
the `compliance` section of the scan JSON. That mapping is coarse: each rule
maps to one or more of eight themes (encryption at rest and in transit, network,
access, secrets, logging, backup, change), and each theme maps to one control.
The report says so, and lists the themes a framework has no control for.

Each control has a status:

| Status | Meaning |
|---|---|
| `fail` | At least one active finding of a mapped rule |
| `pass` | No active finding, and at least one mapped rule applied (it judged a scanned resource type, or reported a finding that was waived) |
| `not_assessed` | No mapped rule applied to the scanned code |

Rules with no resource type (module, plan and secret checks) count as applied
only when they report something, so a plan-only rule never makes a control look
assessed when no plan was given. Each control lists its failing resources with
file and line, and the waivers that matched its findings, with reason, approver
and expiry. Expired waivers are flagged, and their findings are failures again.

The header has the scan date (UTC), the TerraGuard version, the rules version,
the number of files, and `files_sha256`: sha256 over the scanned files sorted by
path, each written as `<len(path)>:<path><len(content)>:<content>`. It also
states that the report is automated evidence, not a certification.

The HTML is one self-contained, print-friendly file: inline CSS, no scripts and
no external requests (a Content-Security-Policy blocks them), and every value
is escaped. The JSON schema is `terraguard.compliance/v1`; fields are only added
within a schema version.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Passed |
| 1 | The policy gate failed |
| 2 | Error (bad input, unreadable file, invalid policy) |

## What the gate fails on, and what it leaves out

The gate decides the exit code of `scan` and `review`, the Action's status and
the admission webhook's answer.

| Always fails the gate | Reported but not gating by default |
|---|---|
| Any blocking finding (the change will not apply: syntax, undeclared references, unknown or missing provider arguments, values the cloud API rejects) | Findings below `fail_on` (default `HIGH`): MEDIUM, LOW and INFO |
| Any active finding at or above `fail_on` (default `HIGH`) | Findings from rules newer than `rules_version`, until you raise it |
| Exceeding a `max_findings` budget | Findings in a baseline (`--baseline`): accepted debt |
| | Waived findings (reason, approver, expiry) and inline ignores, until they expire |
| | In `review`: findings that already existed on the base branch |

Recommended setup:

- Keep `fail_on: HIGH` in CI and `review` on pull requests, so existing debt does not block work while new risk does.
- Leave hygiene, cost and workload choices (LOW and INFO, such as unpinned action tags, lifecycle rules or detailed monitoring) out of the gate; they appear in reports and the pull request comment.
- Use `unwaivable` for the few rules that must never be silenced (public data, wildcard admin, hard-coded secrets), and `max_waiver_days` so exceptions expire.
- Use `disable` only for rules that do not apply to your platform (for example `TG-GHA-011` if you pin actions by tag on purpose), with a comment saying why.
- Pin `rules_version` in shared policies so a TerraGuard upgrade adds new findings as reports first, not as surprise failures.

## Policy file: `.terraguard.yml`

A JSON Schema for editors is at [`schema/terraguard.schema.json`](https://github.com/Karthik-099/TERRAGUARD/blob/main/schema/terraguard.schema.json).

| Key | Type | Meaning |
|---|---|---|
| `extends` | list | Policy packs to inherit, base first: relative paths, https URLs or built-in packs `terraguard:minimal`, `terraguard:recommended`, `terraguard:strict` and `terraguard:hpe` (fail on HIGH; TG-HPE-STATE-001, TG-HPE-PRV-002 and TG-HPE-SEC-001 cannot be waived or disabled) |
| `fail_on` | severity | Lowest severity that fails the gate (default `HIGH`) |
| `max_findings` | map | Risk budget per severity, e.g. `{ MEDIUM: 20 }` |
| `disable` | list | Rule IDs or globs to turn off, e.g. `TG-COST-*` |
| `severity_overrides` | map | Rule ID or glob to a new severity |
| `waivers` | list | `rule`, `resource`, `reason`, `approved_by`, `expires` (YYYY-MM-DD) |
| `custom_rules` | list | Your own rules; see below |
| `inline_ignores` | bool | `false` makes `terraguard:ignore` comments have no effect, so every exception is a reviewed waiver |
| `unwaivable` | list | Rule IDs or globs that inline ignores and waivers cannot silence |
| `data` | map of lists | Named lists, e.g. `regions: [eu-west-1]`, used by custom rules with `in_data` / `not_in_data` |
| `rules_version` | string | Pin the gating rule set, e.g. `"2.0"`: findings from rules added later are reported but do not fail the gate |
| `snippets` | string | `auto` (default), `on` or `off`: how provider documentation examples are scanned; `--snippets` overrides it |
| `max_waiver_days` | number | Waivers with no expiry, or one further out than this, are not applied (reported as TG-POL-002) |

### Custom rules

| Key | Meaning |
|---|---|
| `id`, `title`, `severity`, `remediation` | Identity and guidance |
| `owner`, `docs_url` | Shown on every finding the rule raises |
| `resource_types` | Globs, e.g. `aws_*`, `google_storage_bucket` |
| `where` | Conditions that select resources; all must match |
| `assert` | Conditions that must all hold, or a finding is raised |
| `attribute` + one operator | Shorthand for a single assert condition |

Operators: `exists`, `equals`, `not_equals`, `in`, `not_in`, `matches`,
`not_matches`, `contains`, `min`, `max`. Attributes use dot paths through
nested blocks, e.g. `tags.owner` or `settings.ip_configuration.ssl_mode`.
Values only known at plan time are skipped, so static checks never guess.

```yaml
custom_rules:
  - id: ORG-DB-001
    title: Production databases keep 14 days of backups
    severity: HIGH
    resource_types: ["aws_db_instance"]
    where:
      - { attribute: tags.env, equals: prod }
    assert:
      - { attribute: backup_retention_period, min: 14 }
      - { attribute: deletion_protection, equals: true }
```

### Drafting rules from plain English

`terraguard policy suggest "every production database keeps 14 days of backups"`
(or the Policy tab in the workspace) asks the configured AI model for one rule,
then the engine:

1. accepts exactly one custom rule with known fields, so a draft can never add
   waivers, disable rules or change thresholds;
2. rejects built-in IDs (`TG-*`), rules without `resource_types`, and rules
   without a condition;
3. re-encodes the rule, dropping anything unexpected;
4. dry-runs it and lists the resources it would flag.

A rejected draft gets one repair round with the exact validation error. Only
resource type names are sent to the model, never code. The result runs without
AI from then on.

### Reviews use the base branch's policy

`terraguard review` judges a change by the `.terraguard.yml` on the base
branch, so a pull request cannot loosen its own gate. The review lists any way
the change loosens the policy (fail_on, disables, waivers, budgets, removed
rules) and any finding newly hidden by an inline ignore; those take effect
after merge. An explicit `--config` path is used as is.

### Inline ignores

```hcl
# terraguard:ignore TG-AWS-S3-003 exp:2026-12-31
resource "aws_s3_bucket" "scratch" { ... }
```

- `exp:YYYY-MM-DD` is optional; after that date the ignore stops applying.
- `# terraguard:ignore-file TG-TF-006` at the top of a file (before any code) ignores a rule for the whole file.
- Existing `checkov:skip=CKV_...` and `trivy:ignore:AVD-...` comments are honoured for the rules TerraGuard maps to those IDs, so migrating keeps your exceptions.
- `inline_ignores: false` and `unwaivable` in the policy restrict all of these.

Prefer waivers for anything long-lived: they carry a reason, an approver and an expiry.

## Secret scanning

Every scanned file, of any format, is also read as plain text for
credentials. The `TG-SECRET-*` rules report a known token shape (AWS key pairs,
GitHub, GitLab, Slack, Stripe live, Google API and service-account keys, Azure
account keys and SAS, PEM private keys, JWTs) or, for `password = "..."` style
assignments, a value of at least 12 characters with high entropy that is not a
placeholder (`changeme`, `example`, `${...}`, `var.x`, `<...>`, `xxx`, `test`
and similar). Documented sample values (AWS `...EXAMPLE` keys, the Azurite key,
the jwt.io token) are skipped. Messages show at most the first 4 characters of
a value. Inline ignores and waivers work as for any rule, and the
`recommended` and `strict` packs make `TG-SECRET-*` unwaivable. On the same
line a specific token rule replaces the older `TG-SEC-002`, and `TG-SECRET-014`
yields to `TG-SEC-001`.

`TG-SECRET-015` reports files whose name says they hold credentials: `.env`,
`.env.*` (not `.example`, `.sample`, `.template`), `*.pem` (not certificates),
`*.key`, `id_rsa`, `id_ed25519`, `*.pfx`, `*.p12`, `credentials.json` and
`kubeconfig`. The CLI passes them by name only and never reads them; files git
ignores are left out.

## Code owners

`scan`, `review` and the other commands that read a folder look for
`.github/CODEOWNERS`, `CODEOWNERS` or `docs/CODEOWNERS` in the first scanned
folder. Every finding with a file gets `code_owners` (JSON, SARIF result
`properties`, a Markdown column), matched with GitHub's rules: the last
matching line wins, patterns are gitignore-style, and a line without owners
clears them. `Finding.owner` is unchanged: the team that owns the standard.
API and WASM callers pass the file text as `code_owners` in the input, and
`code_owners_root` when file keys carry a prefix the CODEOWNERS paths do not.

### serve flags

| Flag | Effect |
|---|---|
| `--addr host:port` | Listen address (default `127.0.0.1:8080`) |
| `--tls-cert F --tls-key F` | Serve HTTPS with your own certificate |
| `--domain HOST` | Automatic HTTPS: a Let's Encrypt certificate for `HOST` only, HTTPS on :443, the HTTP-01 challenge and a redirect to HTTPS on :80, HSTS. Turns on the MCP secret link. Refused with `TERRAGUARD_OFFLINE=true` |
| `--cert-dir DIR` | Certificate cache and the stored MCP key (default `<user cache dir>/terraguard/autocert`) |
| `--https-only` | Refuse plain-HTTP requests that do not come straight from loopback (behind a proxy: `X-Forwarded-Proto` must be `https`) |
| `--rotate-mcp-key` | Replace the stored MCP key in `--cert-dir` and exit; restart the server to use it |
| `--scan-timeout D` | Longest a scan may run in the API and remote MCP (default `30s`); longer gets 504 |
| `--max-scans N` | Scans that may run at once (default GOMAXPROCS); more get 503 with `Retry-After` |
| `--audit-log F`, `--admission-policy F` | Audit log and admission webhook policy |

### connect

`terraguard connect <client>` adds the local stdio server (`terraguard mcp`)
to a client. With `--url https://host` it adds the remote server instead;
plain `http` is refused unless the host is loopback.

| Client | What it does |
|---|---|
| `claude-code` | Runs `claude mcp add` (`--scope user` by default, or `project`, `local`) when `claude` is on PATH, otherwise prints the command |
| `cursor` | Merges an entry into `.cursor/mcp.json` in `--dir` (default `.`), or `~/.cursor/mcp.json` with `--global` |
| `vscode` | Merges an entry into `.vscode/mcp.json` in `--dir`, or the user `mcp.json` (`<user config dir>/Code/User/mcp.json`) with `--global` |
| `claude-ai` | Prints the secret link and the claude.ai settings steps; claude.ai connectors are added by hand |
| `print` | Prints the Claude Code command and the Cursor and VS Code entries |

Other entries, their order and the file's indentation are kept; the old file
is saved as `.bak` and the new one is written atomically. Files with comments
are refused, with the entry to paste by hand. No token is written to Cursor or
VS Code files: Cursor reads `${env:TERRAGUARD_SERVER_TOKEN}` and VS Code
prompts for it. Tokens and the secret link are masked unless `--show-secret`
is given.

## HTTP API (`terraguard serve`)

| Method and path | Auth | Body or response |
|---|---|---|
| `GET /` | public | The web app |
| `GET /healthz` | public | `ok` |
| `GET /api/config` | public | Version and AI route (provider:model names, never keys) |
| `POST /api/scan` | token | `{"files": {"main.tf": "..."}, "plan": "...", "config": "...", "fail_on": "HIGH"}` returns the report |
| `POST /api/fix` | token | Same input; returns `{"files": {...}, "errors": [...]}` |
| `POST /api/ai/chat` | token | `{"messages": [{"role": "user", "content": "..."}]}` |
| `GET /api/stats` | public | Anonymous counters |
| `POST /api/stats/hit` | public | Anonymous counters from the web app; bounded |
| `GET /metrics` | token | Prometheus metrics |
| `POST /mcp` | token | Remote MCP server (streamable HTTP, stateless); see below |
| `POST /mcp/<key>` | key in path | The same MCP server for clients that cannot send headers (claude.ai); see below |
| `POST /api/run-task` | HMAC | HCP Terraform / Terraform Enterprise run task; enabled by `TERRAGUARD_RUN_TASK_HMAC_KEY` |

"token" means `Authorization: Bearer $TERRAGUARD_SERVER_TOKEN` is required when
the variable is set. Limits: request bodies 5 MB, 120 API requests and 20 AI
requests per minute per client, timeouts on every connection, at most
`--max-scans` scans at once (503 with `Retry-After` beyond that) and
`--scan-timeout` per scan (504).

```bash
curl -s -X POST localhost:8080/api/scan \
  -H "Authorization: Bearer $TERRAGUARD_SERVER_TOKEN" \
  -d '{"files": {"main.tf": "resource \"aws_s3_bucket\" \"b\" { acl = \"public-read\" }"}}'
```

## MCP server

`terraguard mcp` speaks the Model Context Protocol over stdio.

| Tool | Input | Output |
|---|---|---|
| `scan_terraform` | `path` or `files`, optional `plan`, `config` | Report with findings, lines and fixes |
| `fix_terraform` | As scan, plus `write` (with `path`) | Fixed file contents |
| `generate_docs` | `path` or `files` | Module README in Markdown |
| `generate_agents_md` | `path` or `files` | AGENTS.md |
| `validate_rule` | `rule` (YAML) plus `files` or `path` | Validated rule and the resources it would flag |
| `list_rules` | none | The rule catalog |
| `explain_rule` | `id` | Title, severity, remediation, CWE, compliance themes and resource types |
| `review_diff` | `base_files`, `head_files`, optional `config` | Findings the change introduces and resolves, risk tier, pass/fail |
| `suggest_policy` | `standard`, `files` or `path`, optional `rule` | The rule-writing guide and resource types (no AI call on the server); with `rule`, the validated rule and its dry run |
| `generate_sbom` | `files` or `path`, optional `format` (`json`) | CycloneDX JSON, or the component list |
| `check_plan` | `plan` (`terraform show -json`), optional `config` | Plan summary, risk findings, verdict and cost change |
| `estimate_cost` | `plan`, or `files` or `path`, optional `usage`, `prices` | Monthly cost before and after |
| `plan_hpe_migration` | `files` or `path` | The `terraguard migrate hpegl` report as JSON |

Prompts, each a few numbered steps that name the tools above:

| Prompt | Steps |
|---|---|
| `review_hpe_terraform` | Scan, explain the HPE findings, fix, re-scan to verify |
| `plan_greenlake_migration` | `plan_hpe_migration`, call out items with no replacement, the provider change and the tfmigrator commands as written, re-scan after |
| `harden_before_apply` | Scan, fix, re-scan until nothing blocking remains |

Resources: `terraguard://rules` (the rule catalog as JSON) and the template
`terraguard://rules/{id}` (one rule, for example `terraguard://rules/TG-HPE-STATE-001`).

```bash
claude mcp add terraguard -- terraguard mcp
```

### Remote MCP

`terraguard serve` also exposes the same tools at `/mcp` over streamable HTTP,
so agents can use a team's TerraGuard by URL with nothing installed locally.
It requires the server token when one is set, accepts inline `files` only, and
never reads or writes the server's disk (`path` and `write` are refused).

```bash
claude mcp add --transport http terraguard https://terraguard.internal.example.com/mcp \
  --header "Authorization: Bearer $TERRAGUARD_SERVER_TOKEN"
```

When the server is reachable beyond loopback (a non-loopback `--addr`, or
`TERRAGUARD_TRUST_PROXY=true`), `/mcp` needs the token; without a token or a
key, MCP is refused.

**Secret link.** `/mcp/<key>` serves the same tools for clients that cannot
send a header. The key is `TERRAGUARD_MCP_KEY` (at least 32 characters from
`A-Z a-z 0-9 - _`), or with `--domain` a random 256-bit key generated once and
stored with mode 0600 in `--cert-dir`. A wrong key gets 404, like any unknown
path; the key is compared in constant time and is never logged (the audit log
records the route as `/mcp/<key>`). Print the link with
`terraguard connect claude-ai --url https://host --show-secret`; replace it
with `terraguard serve --rotate-mcp-key`.

## Environment variables

All are optional. The CLI and server also read `./.env`.

| Variable | Purpose |
|---|---|
| `GROQ_API_KEY`, `OPENROUTER_API_KEY`, `GEMINI_API_KEY` | Free-tier AI providers |
| `TERRAGUARD_OLLAMA_URL`, `TERRAGUARD_OLLAMA_MODEL` | Local model (Ollama) |
| `TERRAGUARD_AI_BASE_URL`, `TERRAGUARD_AI_MODEL`, `TERRAGUARD_AI_KEY` | Any OpenAI-compatible endpoint |
| `TERRAGUARD_AI_HEADERS` | Extra auth headers for gateways, `Name: value; Other: value` |
| `TERRAGUARD_AI_ROUTE` | Explicit fallback chain, e.g. `groq:openai/gpt-oss-120b,openrouter` |
| `TERRAGUARD_AI_PROVIDER` | Provider to try first; also the explicit opt-in for paid providers |
| `OPENAI_API_KEY`, `ANTHROPIC_API_KEY` | Paid providers, used only when named in the route or provider |
| `TERRAGUARD_AI_LOCAL_ONLY` | `true` never calls a hosted provider |
| `TERRAGUARD_SERVER_TOKEN` | Bearer token for the server API, `/mcp` and metrics |
| `TERRAGUARD_MCP_KEY` | Key for the MCP secret link `/mcp/<key>` (at least 32 random URL-safe characters); overrides the key `--domain` stores |
| `TERRAGUARD_TRUST_PROXY` | `true` when behind a reverse proxy: client IP and SSO user from its headers |
| `TERRAGUARD_AUDIT_LOG` | File for one JSON line per API call (metadata only) |
| `TERRAGUARD_TELEMETRY_URL` | Opt-in anonymous usage counts from the CLI |
| `TERRAGUARD_OFFLINE` | `true` makes the CLI start no outside request: remote policy `extends` and `vuln update` are refused, telemetry is off, and AI uses local endpoints only. Scans never need the network |
| `TERRAGUARD_ENV_FILE` | Read a different env file instead of `./.env` |
| `TERRAGUARD_RUN_TASK_HMAC_KEY` | Enables `/api/run-task`; the HMAC key configured on the run task |
| `TERRAGUARD_TFC_HOST` | The only host run tasks may call (default `app.terraform.io`) |
| `TERRAGUARD_RUN_TASK_CONFIG` | Path to a `.terraguard.yml` applied to every run task |

## Quota preflight

```bash
terraform plan -out tfplan && terraform show -json tfplan > plan.json
terraguard preflight --plan plan.json --live
```

| Flag | Meaning |
|---|---|
| `--plan FILE` | `terraform show -json` output (required) |
| `--live` | Read limits and usage with the `aws`, `az` and `gcloud` CLIs; read-only calls only |
| `--quotas FILE` | JSON of known limits and usage, keyed like the output (`aws/ec2/L-1216C47A@eu-west-1`), instead of `--live` |
| `--region` | AWS region when the provider's region is not a literal (defaults to `AWS_REGION`); aliased providers use their own region |
| `--headroom N` | Percent of each limit to keep spare; a plan that only fits by using it fails as `TIGHT` |
| `--strict-permissions` | Also fail on `implicitDeny`; by default only `explicitDeny` fails |
| `--format`, `--markdown`, `--json` | Outputs |

With `--live`, preflight also checks AWS permissions: the IAM actions the
plan's creates, deletes and replacements need are evaluated with the IAM policy simulator for the
identity CI runs as (it needs `iam:SimulatePrincipalPolicy`,
`iam:GetRole` and `sts:GetCallerIdentity`).

Checked: AWS standard on-demand vCPUs, VPCs, Elastic IPs, internet gateways,
Application Load Balancers, RDS instances and S3 buckets per account; Azure
regional vCPUs and public IPs; Google Cloud regional CPUs per machine family,
static and in-use external addresses; and whether new S3 bucket names are free.
vCPUs are estimated from instance type names. Exit code 1 means a quota would
be exceeded or a bucket name is taken. In GitHub Actions use `command:
preflight` with the `plan` input after configuring cloud credentials.

## Cost estimate

```bash
terraguard cost --plan plan.json                  # before and after; --format json or markdown
terraguard cost .                                 # from the code when there is no plan
terraguard cost --plan plan.json --usage usage.yml --prices prices.yml --fail-above 500
```

Fixed charges are priced from bundled list prices (AWS us-east-1, Azure East
US, Google Cloud us-central1, on-demand, Linux, 730 hours a month; the snapshot
date is in the output). Priced without usage: EC2, RDS (Multi-AZ doubles the
instance), Aurora instances, ElastiCache, OpenSearch, MSK, Redshift, EBS, NAT
gateways, load balancers, EKS, public IPv4, interface endpoints, KMS keys,
secrets, hosted zones, alarms; Azure VMs and scale sets, AKS node pools and
paid control plane, managed disks, public IPs, load balancers, NAT gateways,
App Service plans, SQL databases (DTU and vCore); Google Compute instances,
disks, GKE clusters and node pools, Cloud SQL, forwarding rules, addresses and
Cloud NAT.

Usage-based charges need a usage file (YAML):

```yaml
resource_usage:                # by address
  aws_lambda_function.api: { monthly_requests: 10000000, request_duration_ms: 120 }
  aws_s3_bucket.logs: { storage_gb: 500, monthly_put_requests: 1000000 }
resource_type_default_usage:   # for every resource of a type
  aws_nat_gateway: { monthly_data_processed_gb: 200 }
```

Keys: S3 `storage_gb`, `monthly_put_requests`, `monthly_get_requests`; Lambda
`monthly_requests`, `request_duration_ms`; DynamoDB on-demand
`monthly_write_request_units`, `monthly_read_request_units`, `storage_gb`;
CloudWatch logs `monthly_data_ingested_gb`, `storage_gb`; SQS, SNS, API Gateway
`monthly_requests`; CloudFront `monthly_data_transfer_gb`; NAT
`monthly_data_processed_gb`; load balancer `lcu`; Route 53 `monthly_queries`;
EFS and ECR `storage_gb`; Azure storage `storage_gb`, Functions
`monthly_executions`, `execution_duration_ms`, `memory_mb`; Google Storage
`storage_gb`, Cloud Functions `monthly_invocations`, `execution_duration_ms`.

`--prices` replaces any bundled price by key, for negotiated rates; the keys
are listed in `engine.Prices` (for example `aws.nat_gateway.hour`,
`azure.vm.d.vcpu_hour`, `gcp.e2.vcpu_hour`). Free configuration resources are
not listed as unpriced. Nothing is sent anywhere.

## Kubernetes admission webhook

`terraguard serve --tls-cert crt --tls-key key --admission-policy .terraguard.yml`
serves `POST /api/k8s/validate` for a `ValidatingWebhookConfiguration`. Each
object is checked with the Kubernetes rules and the policy; findings at or
above `TERRAGUARD_ADMISSION_FAIL_ON` (default `HIGH`) deny the request with the
reasons, lower ones are returned as warnings. Waivers and ignores in the policy
apply. The API server only calls webhooks over HTTPS, so TLS flags are needed
unless a proxy terminates TLS.

## Provider schema checks

Schemas for `hashicorp/aws` 6.71, `hashicorp/azurerm` 5.12 and
`hashicorp/google` 8.9 are bundled, so these checks run with no `terraform
init`. The bundled schema for a provider is used only when every
`required_providers` constraint allows the bundled version and the lock file
(if any) pins the same major version; resources that use another provider
(`provider = google-beta`, or a module that requires `google-beta`) are
skipped. A read-only argument set from an expression is not reported, because
the value may be null. For other providers or versions, pass your own:

```bash
terraform init
terraform providers schema -json > schema.json
terraguard scan . --schema schema.json
```

With a schema, every resource and data block is checked against what the
provider accepts: unknown arguments and blocks (with a "did you mean"
suggestion), read-only arguments, arguments written as blocks and the reverse,
missing required arguments and blocks, too many blocks, and deprecated
arguments. This is the ground truth `terraform validate` uses, so these findings
block apply. Types from providers not in the schema are skipped. The schema is
large (AWS alone is about 13 MB), so this runs in the CLI, the GitHub Action
(`schema:` input) and the local MCP server, not through the HTTP API.

## HCP Terraform and Terraform Enterprise run tasks

`terraguard serve` can act as a run task, so every plan in a workspace is
checked before apply and the result appears in the run.

1. Set `TERRAGUARD_RUN_TASK_HMAC_KEY` (and `TERRAGUARD_TFC_HOST` for Terraform Enterprise).
2. In HCP Terraform: Settings, Run tasks, create one with URL `https://<your-server>/api/run-task` and the same HMAC key.
3. Attach it to workspaces at the post-plan stage, advisory or mandatory.

Requests are verified with the HMAC signature. TerraGuard only calls the
configured host over HTTPS (plan download and result callback), handles four
runs at a time, and applies `TERRAGUARD_RUN_TASK_CONFIG` if set.

## Output formats

| Format | Use |
|---|---|
| text | Terminal |
| json | Automation; the full report |
| sarif | GitHub code scanning and other SARIF viewers. Results with a safe fix carry SARIF `fixes` (`artifactChanges` with one whole-line `replacements` entry); secret findings never do. GitHub accepts these, but its code scanning UI does not show them today; other SARIF viewers may |
| junit | Test reports in GitLab, Jenkins, Azure DevOps, Bitbucket, CircleCI |
| codequality | GitLab merge request widget |
| markdown | Pull request comments |

## GitHub Action inputs for pull-request reviews

| Input | Default | Meaning |
|---|---|---|
| `pr-comments` | `false` | On `pull_request` events, run `terraguard review --format github-review` and post the result as one pull-request review with suggested fixes |

With `pr-comments: true`:

- The workflow needs `permissions: pull-requests: write` (and `contents: read`), and `actions/checkout` with `fetch-depth: 0` so the base commit is there. It works with `command: scan` or `review`.
- It posts with `gh api` and the workflow's `GITHUB_TOKEN`, against the pull request's head commit. All inputs reach the script through environment variables.
- It posts nothing when no new finding is on a changed line.
- After posting, it deletes the inline comments of earlier TerraGuard reviews (found by the hidden marker, authored by `github-actions[bot]`) and replaces their summaries with "Superseded". GitHub does not allow deleting a submitted review.
- If anything fails, such as a missing permission, a fork's read-only token, or a line GitHub will not accept, it prints a warning and the job goes on.

## Rules

See the generated [rule reference](RULES.md), or run `terraguard rules`.
