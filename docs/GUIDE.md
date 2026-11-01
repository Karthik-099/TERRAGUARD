# Getting started

TerraGuard checks Terraform before you apply it. This guide takes you from a
first scan to a pull-request gate in about ten minutes. Every step is free and
works without an account or an AI key.

## 1. Try it without installing anything

Open the [workspace](https://karthik-099.github.io/TERRAGUARD/#/app), then paste
a `.tf` file, use **Folder** to load a whole project, or pick an example. The
engine runs in your browser as WebAssembly; nothing is uploaded.

What you see:

| Area | What it tells you |
|---|---|
| Score and grade | Overall posture, 0 to 100 |
| Will it apply? | Whether `terraform validate` or `apply` is expected to fail, and why |
| Findings | Each issue with its line, why it matters, and a fix |
| Plan | Destroys and replacements when you load a plan JSON |
| Graph | Resources, their connections and attack paths |
| Compliance | Findings mapped to SOC 2, ISO 27001, PCI DSS, HIPAA and CIS controls |
| Policy | Your own rules, waivers and thresholds |
| Pipeline | A ready-to-commit GitHub Actions workflow |

## 2. Install the CLI

```bash
# Linux and macOS: download the binary from the latest release
curl -fsSL -o terraguard https://github.com/Karthik-099/TERRAGUARD/releases/latest/download/terraguard_linux_amd64
chmod +x terraguard && sudo mv terraguard /usr/local/bin/

# or with Go
go install github.com/Karthik-099/TERRAGUARD/cmd/terraguard@latest

# or with Docker
docker run --rm -v "$PWD:/src" -w /src ghcr.io/karthik-099/terraguard scan .
```

## 3. Scan a project

```bash
terraguard scan .                          # every .tf and .tfvars below this folder
terraguard scan infra/ --fail-on HIGH      # exit 1 if anything HIGH or worse is active
```

Exit codes: `0` passed, `1` the policy gate failed, `2` an error occurred.

After `terraform init`, check every argument against the provider itself:

```bash
terraform providers schema -json > schema.json
terraguard scan . --schema schema.json   # typos, read-only and missing arguments
```

To include plan-time values and destructive changes:

```bash
terraform plan -out tfplan
terraform show -json tfplan > plan.json
terraguard scan . --plan plan.json
```

## 4. Fix issues

```bash
terraguard fix .        # applies safe, deterministic fixes in place; review with git diff
```

Optional AI help, verified by the engine before anything is kept:

```bash
export GROQ_API_KEY=...          # free tier; or OPENROUTER_API_KEY, GEMINI_API_KEY, or a local Ollama
terraguard agent .               # dry run: shows what would change
terraguard agent . --write       # writes only changes the engine accepted
```

## 5. Add your own standards

Create `.terraguard.yml` at the root of the repository:

```yaml
fail_on: HIGH

custom_rules:
  - id: ORG-TAG-001
    title: Every resource has an owner tag
    severity: MEDIUM
    resource_types: ["aws_*"]
    attribute: tags.owner
    exists: true
    owner: platform-team

waivers:
  - rule: TG-AWS-S3-001
    resource: aws_s3_bucket.public_site
    reason: Static website, reviewed by security
    approved_by: security@example.com
    expires: 2027-03-31
```

Check it, and test it against fixtures:

```bash
terraguard policy validate
terraguard policy test policy-tests/      # each fixture declares # expect: and # forbid: rule IDs
```

The workspace's Policy tab has a form that writes custom rules for you. You can
also describe a standard in plain English and let AI draft the rule; the engine
validates it and shows what it would flag before you add it:

```bash
terraguard policy suggest "every production database keeps 14 days of backups"
```

## 6. Adopt it on an existing codebase

Old findings should not block new work:

```bash
terraguard scan . --write-baseline .terraguard-baseline.json   # commit this file
terraguard scan . --baseline .terraguard-baseline.json         # in CI: only new findings fail
```

Or review only what a change introduces:

```bash
terraguard review --base origin/main .
```

## 7. Gate every pull request

GitHub Actions:

```yaml
- uses: Karthik-099/TERRAGUARD@v2.0.0
  with:
    command: review          # scan | review | pulse
    path: infra
    fail-on: HIGH
```

GitLab, Jenkins, Bitbucket, CircleCI, Atlantis, AWS CodeBuild, Azure Pipelines
and Google Cloud Build templates are in [`templates/`](https://github.com/Karthik-099/TERRAGUARD/tree/main/templates).
Every CI can also use the exit code plus `--junit`, `--sarif` or `--codequality`.

## 8. Use it in your editor and with AI agents

- **VS Code:** install the `.vsix` from the latest release. Findings appear as you save.
- **pre-commit:** add `id: terraguard` from this repository.
- **MCP:** `claude mcp add terraguard -- terraguard mcp`, or add it to any MCP client. Agents can scan, fix, document and write AGENTS.md.

## 9. Run it for a team

```bash
cp .env.example .env            # optional: AI keys, server token
docker compose up -d            # http://127.0.0.1:8080
```

See [Self-hosting](SELF_HOSTING.md) for private deployments on AWS, Azure,
Google Cloud and Kubernetes, and air-gapped installs.

## Keyboard shortcuts in the workspace

Press `?` in the workspace for the list: `/` searches findings or rules,
`Alt+1` to `Alt+9` switch tabs, `Alt+F` applies every safe fix and `Alt+S`
copies a share link.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `Reference to var.x, which is not declared` | The file that declares it was not scanned. Scan the module folder, not a single file. |
| A finding is intended | Add a waiver with a reason and an expiry, or an inline `# terraguard:ignore TG-RULE-ID` comment above the line. |
| Too many findings on day one | Write a baseline (step 6) and fix gradually. |
| AI says "no provider" | Set a key in `.env` or the environment, or run Ollama. AI is optional; everything else works without it. |
| `terraguard serve` warns about a token | You are listening on a non-local address. Set `TERRAGUARD_SERVER_TOKEN`. |
