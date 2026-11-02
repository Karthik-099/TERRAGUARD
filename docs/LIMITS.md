# Guarantees and limits

What TerraGuard guarantees, what it cannot know before apply, and what covers
each gap.

## Two kinds of checks

| | `scan`, `review`, the GitHub Action gate | `preflight` |
|---|---|---|
| Input | Code, `.tfvars`, plan JSON, policy, optional provider schema | Plan JSON plus read-only cloud access |
| Deterministic | Yes: the same input always gives the same result | No: it reads live limits and usage |
| Needs credentials | No | Yes, read-only |
| Use it to | Gate merges | Catch failures the cloud only reports at apply time |

The merge gate stays deterministic on purpose. Live checks are opt-in and
reported separately, so a flaky API never blocks a pull request.

## Coverage by area

### Capacity and quotas

Quotas are enforced by the cloud when resources are created; they appear in
neither the code nor the plan. `preflight --live` counts what a plan creates
against each common quota and compares it with the account's limit and current
usage:

| Cloud | Quotas checked |
|---|---|
| AWS | Standard on-demand vCPUs, VPCs, Elastic IPs, internet gateways, Application Load Balancers, RDS instances, S3 buckets |
| Azure | Regional vCPUs, public IP addresses |
| Google Cloud | Regional CPUs per machine family, static and in-use external addresses |

vCPUs are estimated from instance type names. Each provider alias is checked
in its own region.

Preflight reads a snapshot. Another pipeline can use quota between preflight
and apply, and the cloud only reserves capacity at create time, so no check
can close that gap completely. Three things narrow it: run preflight in the
same job right before `terraform apply`; serialise applies that share an
account and region (a CI concurrency group); and keep spare capacity with
`--headroom 20`, which fails a plan that only fits by using the last 20% of a
limit. Whatever still slips through is recovered from state on the retry. In GitHub Actions the same check
runs with `command: preflight`.

### Live state and drift

A scan of code alone does not see live state. A plan does: `terraform plan`
refreshes state from the cloud, so findings on plan JSON reflect what exists.
Applying the saved plan that was checked (`terraform apply tfplan`) keeps review
and apply in step; Terraform refuses a saved plan whose state has changed
("Saved plan is stale"). Drift detection in the generated workflow is opt-in.

### Interrupted applies

When an apply stops partway, Terraform records what it created in state. The
next plan contains only the remaining changes and passes through the same
checks before it is applied.

### Global names

S3 bucket names are unique across all AWS accounts. `preflight --live` reports
each new name as free, owned by another account, or already in yours. Names
that only need to be unique within your configuration are covered by the
duplicate and reference checks in `scan`.

### Permissions

Whether a role may create a resource depends on IAM, permission boundaries and
organisation policies outside the code, so it is only known at apply. Planning
with the same role that applies surfaces read permissions early; `scan` keeps
the policies defined in Terraform tight.

### Computed values

Values that are only known at plan or apply time are skipped by static checks
rather than guessed. Plan JSON contains the resolved values, and every rule
runs on it.

### Modules

Local modules are analysed, including the inputs passed to them. Registry and
git modules are not downloaded; their resources are checked through plan JSON.

### Provider versions

Built-in rules follow current provider documentation. `scan --schema` checks
arguments against the exact provider versions in use
(`terraform providers schema -json`).

### Accuracy

Each rule has a configuration it must flag and one it must leave alone.
Intended exceptions are recorded as waivers with a reason, an approver and an
expiry, or as inline `terraguard:ignore` comments. Wrong findings can be
reported from the workspace. The [rule catalog](RULES.md) lists all 271 rules;
TerraGuard does not replace runtime monitoring of deployed infrastructure and
does not see resources created outside Terraform.

### AI

AI never gates anything. Proposed fixes are kept only when the engine confirms
risk goes down, nothing new at medium or above appears, and apply still works.
Drafted rules are validated and dry-run before they are added.

### Data

The browser engine runs locally. The CLI, Action and server run on your own
machines. `preflight --live` calls only your cloud's read-only APIs, and AI
requests go only to the provider you configure. See [Security](../SECURITY.md).

## Summary

| Failure | Caught by | When |
|---|---|---|
| Misconfiguration, insecure defaults | `scan` | Editor, pull request |
| Invalid names, CIDRs, module inputs, unknown arguments | `scan` (`--schema` for arguments) | Editor, pull request |
| Destroy or replace of stateful resources | `scan --plan` | Pull request |
| Quotas, global name collisions | `preflight --live` | Before apply |
| Drift between review and apply | Saved plan, drift detection | Apply |
| Permissions, API outages, eventual consistency | Not predictable; Terraform state and retries | Apply |
