# Guarantees and limits

What TerraGuard promises, what it cannot know, and what covers each gap. If a
question is not answered here, please open a discussion; it probably belongs
on this page.

## Two kinds of checks

| | `scan`, `review`, the GitHub Action gate | `preflight` |
|---|---|---|
| Input | Code, `.tfvars`, plan JSON, policy, optional provider schema | Plan JSON plus read-only cloud access |
| Deterministic | Yes: the same input always gives the same result | No: it reads live limits and usage |
| Needs credentials | No | Yes, read-only |
| Use it to | Gate merges | Catch failures the cloud only reports at apply time |

The merge gate stays deterministic on purpose. Live checks are opt-in and
reported separately, so a flaky API never blocks a pull request.

## Questions people ask

### The plan was clean, but apply failed halfway on a quota. What does TerraGuard do?

Quotas are not in the code or the plan, and `terraform plan` does not check
them even with credentials. `terraguard preflight --plan plan.json --live`
does: it counts what the plan creates per quota (vCPUs, VPCs, Elastic IPs,
internet gateways, load balancers, databases and buckets on AWS; regional vCPUs
and public IPs on Azure; CPU families and addresses on Google Cloud) and
compares that with the account's limit and current usage before apply starts.
In GitHub Actions use `command: preflight`.

If an apply still fails partway, for a reason no tool can predict, Terraform
records what it created in state. The next plan contains only what is left, and
it goes through the same checks before the retry.

### The plan is checked without credentials. Can it drift from live state?

`scan` without a plan checks code only, so it cannot see live state. A plan JSON
is different: `terraform plan` refreshes state from the real cloud, so findings
on a plan reflect what exists. Two practices close the remaining gap:

- Apply the saved plan you checked (`terraform plan -out tfplan`, then
  `terraform apply tfplan`). If state changed in between, Terraform refuses
  with "Saved plan is stale" instead of applying something unreviewed.
- Turn on drift detection in the generated workflow (opt-in) to find manual
  changes between deployments.

### What about names that are already taken?

S3 bucket names are global across every AWS account. `preflight --live` asks S3
whether each new bucket name is free, owned by another account, or already in
yours. Names that must be unique only inside your own account are caught by the
duplicate and reference checks in `scan`.

### Will it catch permission errors?

Not before apply. Whether a role may create a resource depends on IAM policies,
permission boundaries and organisation policies that live outside the code.
Run `terraform plan` with the same role that applies, so read permissions fail
early, and use `scan` to keep the policies you write in Terraform tight.

### What if a value is only known after apply?

Static checks skip values that are computed at plan time instead of guessing.
Scan the plan JSON as well: it contains the resolved values, and every rule
runs on it.

### Does it follow modules from the registry?

Local modules (`./modules/...`) are checked, including their inputs. Registry
and git modules are not downloaded, but their resources appear in the plan JSON,
which is checked like any other plan.

### Are the checks right for my provider version?

Built-in rules follow current provider documentation. For exact argument
checks, pass the schema of the providers you actually use: `terraform providers
schema -json > schema.json`, then `scan --schema schema.json`.

### What about false positives?

Every rule has two tests: one configuration it must flag and one it must leave
alone. When a finding is intended, add a waiver with a reason, an approver and
an expiry, or an inline `terraguard:ignore` comment. Report a wrong finding with
the "Report false positive" button; it opens an issue with the details.

### And false negatives?

TerraGuard checks 271 rules, listed in the [rule catalog](RULES.md). It does
not replace runtime security monitoring of what is already deployed, and it does
not see infrastructure created outside Terraform.

### Can AI change my infrastructure?

No. AI never gates anything. AI-proposed fixes are kept only if the engine
confirms that risk goes down, nothing new at medium or above appears, and apply
still works. AI-drafted rules are validated and dry-run before you add them.

### Where does my code go?

In the browser, nowhere: the engine runs locally. The CLI, Action and server
run on your machines. `preflight --live` calls only your own cloud's read-only
APIs. AI is optional and goes only to the provider you configure. See
[Security](../SECURITY.md).

## Summary

| Failure | Caught by | When |
|---|---|---|
| Misconfiguration, insecure defaults | `scan` | Editor, pull request |
| Invalid names, CIDRs, module inputs, unknown arguments | `scan` (`--schema` for arguments) | Editor, pull request |
| Destroy or replace of stateful resources | `scan --plan` | Pull request |
| Quotas, global name collisions | `preflight --live` | Before apply |
| Drift between review and apply | Saved plan, drift detection | Apply |
| Permissions, API outages, eventual consistency | Not predictable; Terraform state and retries | Apply |
