# Gate Morpheus provisioning with TerraGuard

`main.tf` creates a shell script task that downloads a pinned TerraGuard release,
checks its sha256 against the release's `checksums.txt`, and runs
`terraguard scan . --fail-on HIGH` in `app_dir`; and a provisioning workflow that
runs the task in the `preProvision` phase. A failing scan exits non-zero.

```bash
terraform init
terraform apply -var morpheus_url=https://morpheus.example.com -var app_dir=/path/to/app
```

Attach the workflow to a layout (`workflow_id` on `hpe_morpheus_instance_type_layout`).
The task needs `curl`, `sha256sum` and access to github.com.

What the HPE provider docs do not say, so check it on your appliance:
- where Morpheus puts a Terraform app's code, and whether a provisioning
  workflow task can read it; `app_dir` must point there;
- whether `execute_target = "local"` (the appliance) is the right place to run
  it, or `resource` / `remote`; and whether a failed task stops provisioning.
