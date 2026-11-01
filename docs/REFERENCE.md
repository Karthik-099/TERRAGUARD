# Reference

Complete reference for the CLI, the policy file, the HTTP API, the MCP server
and configuration. For a walkthrough, start with [Getting started](GUIDE.md).

## CLI

| Command | Purpose |
|---|---|
| `terraguard scan [paths] [flags]` | Scan `.tf` and `.tfvars` files (default `.`) |
| `terraguard review --base REV [paths]` | Report only what a change introduces or resolves, with a risk tier |
| `terraguard fix [paths]` | Apply safe, deterministic fixes in place |
| `terraguard agent [paths] [--write]` | Deterministic fixes, then AI proposals that the engine verifies |
| `terraguard pulse [roots]` | Control adoption, waivers and trend across many modules |
| `terraguard preflight --plan FILE --live` | Check the plan against live cloud quotas and S3 name availability (read-only) |
| `terraguard policy validate` | Validate `.terraguard.yml`, including `extends` |
| `terraguard policy test DIR` | Run policy fixtures (`# expect:` and `# forbid:` headers) |
| `terraguard policy suggest "standard" [paths]` | Draft one custom rule from plain English: AI drafts, the engine validates and dry-runs it |
| `terraguard docs [path]` | Module README: inputs, outputs, providers, resources |
| `terraguard agents-md [path]` | AGENTS.md for coding agents: commands, guardrails, boundaries |
| `terraguard ask "question" [paths]` | Ask the optional AI assistant about your Terraform |
| `terraguard ai` | Print the AI fallback route built from the environment |
| `terraguard rules [--format text\|json\|markdown]` | The rule catalog |
| `terraguard serve [--addr host:port]` | Self-host the web app and HTTP API |
| `terraguard mcp` | Run the MCP server over stdio |
| `terraguard version` | Print the version |

Every command accepts `-h` for its flags. Flags may appear before or after paths.

### scan flags

| Flag | Meaning |
|---|---|
| `--format` | stdout format: `text` (default), `json`, `sarif`, `junit`, `codequality`, `markdown` |
| `--plan FILE` | Also analyze `terraform show -json` output |
| `--schema FILE` | Check every argument and block against `terraform providers schema -json` output |
| `--config FILE` | Policy file (default: `.terraguard.yml`, found automatically) |
| `--fail-on LEVEL` | Override the threshold: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `NONE` |
| `--sarif`, `--junit`, `--codequality`, `--markdown`, `--json FILE` | Write additional reports |
| `--write-baseline FILE` | Save current findings as accepted debt |
| `--baseline FILE` | Report baselined findings as waived; gate only on new ones |
| `--ai` | Add an advisory AI remediation plan to the Markdown report |

### review, agent and pulse flags

| Command | Flag | Meaning |
|---|---|---|
| review | `--base REV` | Git revision to compare with (default `origin/main`) |
| review | `--format markdown\|json`, `--markdown FILE`, `--json FILE` | Outputs |
| review | `--fail-on`, `--config`, `--ai`, `--schema` | As for scan |
| agent | `--write` | Write accepted changes (default: dry run) |
| agent | `--rounds N` | Maximum AI rounds (default 2) |
| agent | `--min-severity LEVEL` | Only ask the AI about findings at or above this level (default `MEDIUM`) |
| pulse | `--baseline FILE` | Previous pulse JSON, to show the trend |
| pulse | `--json FILE`, `--markdown FILE`, `--format` | Outputs |
| pulse | `--min-adoption N` | Exit 1 if any control's adoption is below N percent |

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Passed |
| 1 | The policy gate failed |
| 2 | Error (bad input, unreadable file, invalid policy) |

## Policy file: `.terraguard.yml`

A JSON Schema for editors is at [`schema/terraguard.schema.json`](https://github.com/Karthik-099/TERRAGUARD/blob/main/schema/terraguard.schema.json).

| Key | Type | Meaning |
|---|---|---|
| `extends` | list | Policy packs to inherit, base first: relative paths or https URLs |
| `fail_on` | severity | Lowest severity that fails the gate (default `HIGH`) |
| `max_findings` | map | Risk budget per severity, e.g. `{ MEDIUM: 20 }` |
| `disable` | list | Rule IDs or globs to turn off, e.g. `TG-COST-*` |
| `severity_overrides` | map | Rule ID or glob to a new severity |
| `waivers` | list | `rule`, `resource`, `reason`, `approved_by`, `expires` (YYYY-MM-DD) |
| `custom_rules` | list | Your own rules; see below |

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

### Inline ignores

```hcl
# terraguard:ignore TG-AWS-S3-003
resource "aws_s3_bucket" "scratch" { ... }
```

Prefer waivers for anything long-lived: they carry a reason, an approver and an expiry.

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
| `POST /api/run-task` | HMAC | HCP Terraform / Terraform Enterprise run task; enabled by `TERRAGUARD_RUN_TASK_HMAC_KEY` |

"token" means `Authorization: Bearer $TERRAGUARD_SERVER_TOKEN` is required when
the variable is set. Limits: request bodies 5 MB, 120 API requests and 20 AI
requests per minute per client, timeouts on every connection.

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
| `TERRAGUARD_SERVER_TOKEN` | Bearer token for the server API and metrics |
| `TERRAGUARD_TRUST_PROXY` | `true` when behind a reverse proxy: client IP and SSO user from its headers |
| `TERRAGUARD_AUDIT_LOG` | File for one JSON line per API call (metadata only) |
| `TERRAGUARD_TELEMETRY_URL` | Opt-in anonymous usage counts from the CLI |
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
| `--region` | AWS region when the provider's region is not a literal (defaults to `AWS_REGION`) |
| `--format`, `--markdown`, `--json` | Outputs |

Checked: AWS standard on-demand vCPUs, VPCs, Elastic IPs, internet gateways,
Application Load Balancers, RDS instances and S3 buckets per account; Azure
regional vCPUs and public IPs; Google Cloud regional CPUs per machine family,
static and in-use external addresses; and whether new S3 bucket names are free.
vCPUs are estimated from instance type names. Exit code 1 means a quota would
be exceeded or a bucket name is taken. In GitHub Actions use `command:
preflight` with the `plan` input after configuring cloud credentials.

## Provider schema checks

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
| sarif | GitHub code scanning and other SARIF viewers |
| junit | Test reports in GitLab, Jenkins, Azure DevOps, Bitbucket, CircleCI |
| codequality | GitLab merge request widget |
| markdown | Pull request comments |

## Rules

See the generated [rule reference](RULES.md), or run `terraguard rules`.
