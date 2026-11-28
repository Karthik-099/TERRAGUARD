# TerraGuard for HPE

TerraGuard checks configurations for the HPE Terraform provider (`HPE/hpe`:
Morpheus, HPE VM Essentials and OpsRamp) and the earlier HPE GreenLake provider
(`HPE/hpegl`), before `terraform init` or `apply`, with nothing sent off the
machine. TerraGuard is an independent open-source project; it is not made or
endorsed by HPE.

```bash
terraguard scan .                 # every check below
terraguard fix .                  # apply the safe fixes
```

## What it checks

| Area | Rules | What is reported |
|---|---|---|
| Secrets in state | TG-HPE-STATE-001 | A plain password field is set where a write-only `_wo` field exists, so the value is stored in Terraform state in plain text. The fix renames it to `_wo`. |
| Credentials | TG-HPE-PRV-001, TG-HPE-PRV-002, TG-HPE-SEC-001 | `insecure = true` or `allow_insecure = true`, literal passwords, tokens and client secrets in provider blocks, Cypher secrets, credentials and OpsRamp credential sets |
| TLS | TG-HPE-TLS-001, TG-HPE-TLS-002, TG-HPE-LB-001, TG-HPE-LB-002 | Certificate checks turned off, credentials sent to `http://` endpoints, plain HTTP virtual servers, legacy SSL and TLS versions |
| Identity | TG-HPE-IAM-001, TG-HPE-IAM-002 | Active Directory without SSL, SAML without assertion signature validation |
| Network | TG-HPE-NET-001 | Security group and router firewall rules open to the internet on admin or all ports |
| Bare metal | TG-HPE-METAL-001 | Plain-text passwords in `hpegl_metal_host` user data |
| Will it apply | TG-VAL-026, TG-SCHEMA-001 to 003 | Values the provider rejects at plan time, unknown or missing arguments and deprecated ones, from the bundled HPE/hpe 2.3.0 and HPE/hpegl 0.4.20 schemas |
| Migration | TG-HPE-MIG-001 | Each `hpegl_vmaas_*` resource or data source with a direct `hpe_morpheus_*` replacement, with a pointer to HPE's tfmigrator tool and migration guide (informational, never fails a build) |

Templates inside `hpe_morpheus_app_blueprint_*` and `hpe_morpheus_spec_template_*`
resources (Terraform, CloudFormation, ARM, Kubernetes) are scanned with the
same rules as stand-alone files, and their findings point at the line inside the
heredoc.

## Write-only secrets

Terraform 1.11 and later support write-only arguments, which are sent to the
provider but never stored in state. In provider 2.3.0 three resources still
accept both forms:

| Resource | Plain field | Write-only field |
|---|---|---|
| `hpe_morpheus_network_domain` | `domain_password` | `domain_password_wo` |
| `hpe_morpheus_task_shell_script` | `remote_target_password` | `remote_target_password_wo` |
| `hpe_morpheus_task_powershell_script` | `remote_target_password` | `remote_target_password_wo` |

The provider marks the `*_wo_version` companions as deprecated and detects
changes to write-only fields itself, so the fix does not add them.

## Provider documentation examples

Files under `examples/resources/<type>/`, `examples/data-sources/<type>/`,
`examples/provider/` and similar tfplugindocs folders are checked one file at a
time, so alternative examples of the same resource and references to context
outside the snippet are not reported. `--snippets off` turns this off.

## Migrate from GreenLake

`terraguard migrate hpegl` lists every `hpegl_*` resource and data source with
its file, line and `hpe_*` replacement, marks those with none, shows the import
ID format where HPE documents a composite one, maps the `hpegl` provider block
to the `hpe` provider's `morpheus` block (connected, disconnected or direct),
and ends with HPE's tfmigrator commands. Everything comes from HPE's
`hpegl_to_hpe_migration.md` and `tfmigrator_migration.md` guides. It changes
nothing and always exits 0.

```bash
terraguard migrate hpegl . --format markdown > MIGRATION.md
```

## Gate Morpheus deployments

[`examples/hpe/morpheus-gate`](../examples/hpe/morpheus-gate) creates a shell
script task that installs a pinned TerraGuard release, checks its sha256 and runs
`terraguard scan . --fail-on HIGH`, and a provisioning workflow that runs it in
the `preProvision` phase. Its README lists what HPE's docs leave open, such as
where the task finds the app's code.

```bash
cd examples/hpe/morpheus-gate && terraform init && terraform apply -var app_dir=/path/to/app
```

## Policy pack

`terraguard:hpe` fails on HIGH, so the TG-HPE-*, TG-VAL-026 and TG-SCHEMA-*
findings gate (every rule runs by default; the pack turns none off), and makes
the secret rules TG-HPE-STATE-001, TG-HPE-PRV-002 and TG-HPE-SEC-001 impossible
to waive, ignore or disable.

```bash
printf 'extends: [terraguard:hpe]\n' > .terraguard.yml && terraguard scan .
```

## AI agents (MCP)

`terraguard mcp` adds the `plan_hpe_migration` tool (the migrate report as
JSON), the prompts `review_hpe_terraform`, `plan_greenlake_migration` and
`harden_before_apply`, and the resources `terraguard://rules` and
`terraguard://rules/{id}`. The remote `/mcp` endpoint offers the same, with
inline files only.

```bash
claude mcp add terraguard -- terraguard mcp
```

## In CI

```yaml
- uses: Karthik-099/TERRAGUARD@v3.2.0
  with:
    command: review
    fail-on: HIGH
    pr-comments: true   # fix suggestions on changed lines; needs pull-requests: write
```
