# TerraGuard for VS Code

Inline Terraform security and apply-time validation, powered by the TerraGuard CLI.

- Findings appear as diagnostics when you save a `.tf` or `.tfvars` file. Errors are critical/high, warnings are medium.
- Quick fixes apply TerraGuard's auto-fixes to the file, or insert a `# terraguard:ignore` comment.
- Your `.terraguard.yml` policy (thresholds, waivers, custom rules) is respected.
- Everything runs locally. No account or network is needed.

## Install

```bash
go install github.com/Karthik-099/TERRAGUARD/cmd/terraguard@latest   # the CLI the extension calls
cd editors/vscode && npx @vscode/vsce package                        # builds terraguard-0.1.0.vsix
code --install-extension terraguard-0.1.0.vsix
```

## Settings

| Setting | Default | Purpose |
|---|---|---|
| `terraguard.path` | `terraguard` | Path to the CLI |
| `terraguard.scanOnSave` | `true` | Re-scan on save |
| `terraguard.minSeverity` | `LOW` | Hide findings below this severity |

Commands: **TerraGuard: Scan workspace**, **TerraGuard: Apply auto-fixes to this file**.
