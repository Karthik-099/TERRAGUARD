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

### Drift

A plan also lists resources changed outside Terraform. TerraGuard reports each
one (TG-PLAN-003) with the attributes that changed, and raises deleted or
stateful resources to medium, so manual changes are reviewed before the apply
reverts them.

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

`preflight --live` works out which IAM actions the plan's creates need (for
example `ec2:RunInstances`, or `iam:PassRole` for Lambda and EKS) and asks the
IAM policy simulator whether the role CI runs as is allowed each one. The
simulator evaluates identity policies and permission boundaries; resource
policies and organisation SCPs can still deny at apply. Updates and deletes are
not simulated yet.

The simulator checks each action against any resource (`*`), so a role allowed
only on specific ARNs shows `implicitDeny` even when the apply would work.
Those are reported as unsure and do not fail the run; only `explicitDeny`
fails, unless you pass `--strict-permissions`.

### Computed values

Values that are only known at plan or apply time are skipped by static checks
rather than guessed. Plan JSON contains the resolved values, and every rule
runs on it.

### Modules

Local modules are analysed, including the inputs passed to them. Registry and
git modules are not downloaded; scan them after `terraform init` with
`--include-modules`, or check their resources through plan JSON.

### Provider versions

Built-in rules follow current provider documentation. Argument checks use the
bundled AWS 6.71, AzureRM 5.12 and Google 8.9 schemas only when the module's
constraints and lock file allow those versions; otherwise they are skipped
unless you pass the exact schemas in use with `scan --schema`. Arguments that
exist only in `google-beta` are not checked against the bundled schema.

### Formats

Non-Terraform formats are read statically. Helm charts, Kustomize overlays and
Bicep files are only checked when rendered (`--helm`, `--kustomize`,
`--bicep`), which needs those tools installed; unrendered templates are
skipped. CloudFormation and ARM expressions are resolved when they reduce to a
literal (parameter defaults, variables, simple functions); everything else is
treated as unknown and never fires. GitLab `extends` and CI templates pulled
from other repositories are not resolved. Auto-fix edits Terraform only.

### Cost

`terraguard cost` estimates monthly charges from bundled list prices for one
region per cloud (AWS us-east-1, Azure East US, Google Cloud us-central1,
on-demand). Usage-based charges are included only from a usage file, and
negotiated prices only from `--prices`. Savings plans, reservations and other
regions are not modelled, so treat it as the size of a change, not a bill.

### Accuracy

Each rule has a configuration it must flag and one it must leave alone.
Intended exceptions are recorded as waivers with a reason, an approver and an
expiry, or as inline `terraguard:ignore` comments. Wrong findings can be
reported from the workspace. Rules are also measured against reference
fixtures and a corpus of public modules (see the README). The
[rule catalog](RULES.md) lists all 1,750 rules;
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
| Quotas, global name collisions, missing IAM permissions | `preflight --live` | Before apply |
| Drift between review and apply | Saved plan, drift detection | Apply |
| Resource policies, SCPs, API outages, eventual consistency | Not predictable; Terraform state and retries | Apply |
