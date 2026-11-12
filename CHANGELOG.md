# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed
- The site opens in the light theme by default; dark and system are one click away and remembered.
- The comparison with Checkov, Trivy, TFLint and terraform validate is on the home page as a pure yes, partly or no table (`#/compare` scrolls to it).
- "How it works": a clickable diagram of how information flows (files, one model, the engine, your policy, results, with the optional AI lane), on the home page and the Architecture page, which drops its history and module map.
- The home page drops the duplicate integrations grid; Integrations has it.
- More space between the logo and the menu, and gentle scroll motion (switched off for reduced motion).

## [3.0.1] - 2026-11-13

### Changed
- New TerraGuard logo across the site (light and dark versions), the favicon (follows the system theme), the README and social banner, the VS Code extension icon and the Helm chart icon.
- The VS Code extension description lists every supported format, not only Terraform.

## [3.0.0] - 2026-11-13

A major release: private clouds and Red Hat, secret scanning, team features,
plugins and a redesigned web app. Rule set 3.0 adds 62 rules (1,750 in all,
26 providers). Policies that pin `rules_version: "2.1"` keep their gate
unchanged: the new rules report but do not fail CI until the pin moves.

### Added
- **Nutanix:** provider TLS verification and inline Prism credentials, VM boot and guest tools, Flow policies that allow all traffic, images fetched over HTTP, NKE, storage containers, SNMP v1/v2c, Cluster API (CAPX) manifests, and Nutanix API value checks (TG-VAL-023).
- **VMware vSphere:** `allow_unverified_ssl`, port group promiscuous mode and forged transmits, VM secure boot and hardware settings, host lockdown and SSH, HA and DRS, datastores, and value checks (TG-VAL-024).
- **Red Hat OpenShift:** Routes (plain HTTP, HTTP allowed next to HTTPS, wildcard), SecurityContextConstraints (privileged, host namespaces, any user, hostPath, all capabilities), BuildConfigs with inline credentials or stale base images, insecure ImageStreams, cluster roles bound to every user, OAuth over plain HTTP, and deprecated DeploymentConfigs (which also get every Kubernetes pod rule).
- **ROSA and ARO:** public API and routes, etcd encryption, FIPS, single-zone production clusters, inline passwords, user workload monitoring (`rhcs` provider); ARO API and ingress exposure, FIPS and encryption at host.
- **Secret scanning:** 15 `TG-SECRET-*` rules across every file of any format (AWS, GitHub, GitLab, Slack, Stripe, Google, Azure, private keys, JWTs, Nutanix Prism, high-entropy passwords) and secret-bearing files by name. Values are redacted to four characters in every output; the rules are unwaivable in the `recommended` and `strict` packs.
- **Code owners:** CODEOWNERS (`.github/`, root or `docs/`) is applied to every finding (`code_owners` in JSON and SARIF); `scan --group-by owner`; per-owner tables in Pulse and Markdown.
- **Plugins:** `terraguard-<name>` executables on PATH add findings in JSON or SARIF (`scan --plugins`, `plugins:` in the policy, `terraguard plugins list|test`). Waivers, baselines and the gate apply to their findings. See docs/PLUGINS.md and examples/plugins.
- **SBOM:** `terraguard sbom` writes an offline CycloneDX 1.5 inventory of providers, modules, images and packages; `terraguard vuln --sbom` scans one.
- **Red Hat images in `vuln`:** RHEL (UBI), Rocky Linux, AlmaLinux, Mageia and Azure Linux packages are read from the rpm database (SQLite, Berkeley DB, ndb) and matched against OSV with rpm version ordering.
- **Offline mode:** `TERRAGUARD_OFFLINE=true` makes the CLI start no outside request: remote policies and `vuln update` are refused, telemetry is off, and AI is local only.
- **Web app:** a redesigned, calmer interface with light and dark themes; drop a whole folder or zip (10, 15 or hundreds of files) and scan it at once, with a file tree and grouping by file or owner; an Add-ons panel to write, test, import and export custom rules; HTML report export; integration setup snippets with copy buttons; a command palette (Ctrl/Cmd+K).
- Brand logos for Nutanix, VMware vSphere, Red Hat and OpenShift.

### Changed
- `RulesVersion` is now 3.0. A secret previously reported as TG-SEC-001 or TG-SEC-002 may now be reported under a more specific TG-SECRET ID, so it shows as new against an old baseline.
- A `.env` file that git ignores is no longer reported.

### Security
- Go 1.26.11 (fixes GO-2026-6859 in net/http).
- Local policy `extends` are confined to the working folder; remote ones are HTTPS only with redirect, size and time limits, and must parse as a policy. Errors never echo file content.
- `terraguard serve` and `terraguard ui` refuse cross-site requests and, without a token on loopback, unknown `Host` names (DNS rebinding).
- `review --base` refuses values that start with `-`; paths starting with `-` are passed to external tools as `./-name`.
- `vuln image` streams layers with per-file, per-layer, total and layer-count caps; `vuln update` follows HTTPS redirects only; AI calls never follow redirects.
- Git commands run with `core.fsmonitor` off, so a scanned repository's `.git/config` cannot run a command.
- `terraguard sbom` removes `user:password@` from module sources; plugin names cannot start with `tg` or `org`, so plugins cannot report under built-in rule IDs.
- The rpm database readers cap the bytes they copy, so a small crafted database cannot exhaust memory; a large rpm database (up to 256 MB) no longer stops an image scan.
- `drift` with an absolute folder path no longer reports every resource as missing from the code.
- Release workflow: no default token permissions, per-job permissions, checkout without persisted credentials; workflow inputs pass through environment variables.

## [2.1.0] - 2026-11-03

### Added (late in 2.1.0)
- Auto-fix for Kubernetes manifests (YAML node edits that keep comments and key order) and Dockerfiles (MAINTAINER to LABEL, ADD to COPY for local files).
- Values passed to local modules flow into the module's variables, so rules see them.
- Azure and Google Cloud argument value checks (TG-VAL-021, TG-VAL-022), generated by tools/cloudvalgen.
- Pulumi YAML and stack exports, Crossplane managed resources, and Google Deployment Manager configs.
- `terraguard vuln`: offline OSV vulnerability scan of lockfiles and container image tarballs.
- `terraguard drift`: inventory of code against state, and read-only drift with `--live`.
- `terraguard fix --pr`: fixes on a new branch, pushed, with a pull request through gh.
- Neovim plugin (editors/nvim) and JetBrains setup through LSP4IJ (editors/jetbrains).
- Releases ship a CycloneDX SBOM and a keyless Sigstore signature on checksums.txt.
- Brand logos for supported clouds, formats and integrations on the site.

### Fixed
- An independent review of the new rules removed ten false positives (data bind mounts, wait-for-port loops, images whose names merely contain "tiller", ElastiCache group members, ICMP rules, Application Gateway defaults and variables, CA certificates, case of MQ engine names, variables inside heredoc OIDC policies) and eleven duplicate rules; each case has a regression test.
- Generated checks no longer fire when a parent object is an unresolved expression.
- Container rules also check init containers; ReplicationControllers count as workloads.
- Repositories with several modules that declare locals of the same name no longer get false "reference to an undeclared local" findings.
- `moved`, `removed` and `import` blocks no longer report their old addresses as undeclared references.
- A variable such as `secret_rotation_interval` or `password_length` is no longer treated as a secret.
- TG-AWS-EC2-001 no longer fires when the metadata service is disabled.
- Fourteen overlapping rules removed and nine narrowed, so one weakness gives one finding; two hand-written rules (Kubernetes `env_from`, Azure blob public access default) gained the cases the removed ones covered.
- Policies using `extends` lost `inline_ignores`, `max_waiver_days`, `unwaivable` and `rules_version`, even from the repository's own file.
- Values set through variables, tfvars and locals are now resolved before rules run, so moving an insecure value into a variable no longer hides it. Findings name the variable, and no auto-fix overwrites the reference.
- AI verification rejects a "fix" that deletes a resource.
- `review` judges a change by the base branch's policy, so a pull request cannot loosen its own gate; it lists policy loosening and newly silenced findings.
- Preflight checks aliased providers in their own region and counts create-before-destroy replacements.
- Require Go 1.26.10: Go 1.25.0's standard library has known net/http and crypto/tls vulnerabilities. Docker builds use golang:1.26.10-alpine.
- Server: `/metrics` requires the token when one is set; no directory listings or Go source from the embedded site; the rate limiter uses the proxy-appended client address; usage stats stay bounded under floods and keep counting known rules.
- CLI: every flag has a description, and `-h` exits cleanly on every command.
- Repositories with local modules no longer get false "duplicate declaration" findings: declarations, references, tfvars and unused-variable checks are scoped to each directory.
- Upgraded `golang.org/x/text` (and related `x/` modules) to fix known vulnerabilities reported by govulncheck.
- Share links are capped at 5 MB when expanded and their contents are validated before loading.

### Added
- New formats on the same engine, policy and gate: Kubernetes manifests (YAML and JSON; Helm with `--helm`, Kustomize with `--kustomize`), CloudFormation and SAM, Serverless Framework, Azure ARM (and Bicep with `--bicep`), Dockerfile, docker-compose, GitHub Actions, GitLab CI, Azure Pipelines, CircleCI, Bitbucket Pipelines, Ansible and OpenAPI. Every existing Kubernetes rule runs on manifests; each new format has its own rules, mapped to the reference IDs so skip comments keep working. `--framework` limits a scan to some formats.
- Coverage report: every resource with the number of checks that ran on it, which passed and which failed, and the resource types no rule is written for (`scan --coverage`, the JSON report, the Markdown comment and a workspace tile).
- `terraguard lsp`: a Language Server Protocol server, so Neovim, JetBrains, Zed, Helix, Emacs and Sublime show findings and offer Terraform quick fixes.
- `terraguard init` (policy, CI workflow, pre-commit), `terraguard explain RULE-ID`, `terraguard doctor`, and `scan --watch`.
- Built-in policy packs: `extends: [terraguard:minimal | recommended | strict]`.
- Cloudflare: eight more rules (Access policies open to everyone, long sessions, public r2.dev buckets, API tokens without expiry or IP limits, security features off, missing HSTS, skip-everything firewall rules, tunnels without origin TLS verification) for both provider generations, and a guide to hosting the site on Cloudflare Pages.
- `terraguard ui [path]`: the workspace on your machine with a folder loaded from disk (loopback only, one-time token, read-only), the desktop experience without a desktop framework.
- MCP: `scan_terraform` reads every format and takes `frameworks`; new `estimate_cost` tool.
- GitHub Action inputs `frameworks` and `args` (any extra scan flags, such as `--helm` or `--rego`); pre-commit and VS Code run on every supported format.
- Site: a 3D view of how formats flow through the engine to every surface (three.js, bundled, so no outside request), formats and use-case sections, an architecture flow, desktop and admission install guides, and a Support section; `SUPPORT.md` and a bug report template.
- Documentation of what the gate fails on and what it leaves out by default.
- TG-VAL-020: values the AWS API rejects (enums, patterns, lengths) for 1,322 arguments of 531 resource types, generated from the published AWS API models. Blocking, because the apply would fail.
- Kubernetes admission webhook: `terraguard serve` validates objects at `/api/k8s/validate` with the same rules (`--admission-policy`, `--tls-cert`, `--tls-key`).
- Cost for Azure and Google Cloud, usage-based charges from a usage file (`--usage`), negotiated prices (`--prices`), and estimates from code without a plan (`terraguard cost .`).
- Literal secrets are detected in every format, not only Terraform.
- Eval cases can be any format (`# path:` header; `.expect` sidecar for JSON).
- Rule catalogue grows from 277 to 1,688 rules across 23 providers, covering the controls of the major open-source scanners. Every Checkov Terraform check ID maps to the TerraGuard rule that covers it, so existing skip comments keep working. Accuracy against the reference fixtures: 563 of 643 resource checks and 172 of 175 graph policies agree; the rest differ on purpose (safe provider defaults, invalid fixtures, stale lists).
- Graph policies: cross-resource checks in the common YAML format (connections, attribute conditions, filters, and/or/not, JSONPath filters). 177 are built in; `scan --policy-dir` (or `--external-checks-dir`) runs your own.
- Rego policies: `scan --rego DIR` runs Conftest-style `deny`, `violation` and `warn` rules against the code or a plan, through the same waivers and gate.
- Bundled provider schemas for AWS 6.71, AzureRM 5.12 and Google 8.9: argument, block and required-argument checks run with no `terraform init`, only when the module's constraints and lock file allow those versions (`--no-builtin-schema` turns it off).
- Terraform JSON (`.tf.json`, including CDKTF output), with findings on the JSON lines.
- `scan --include-modules` reads modules downloaded into `.terraform/modules`.
- `terraguard cost --plan`: offline monthly cost estimate of a plan's AWS fixed charges, with a `--fail-above` budget gate; scans with `--plan` add it to the report and the pull request comment.
- Permission preflight covers deletes and replacements as well as creates.
- Measured on 14 widely used public module repositories (2,016 files): no false "will not apply" predictions.
- `scan --var-file`, `--check`, `--skip-check` and `--skip-path`.
- Inline ignores can expire (`exp:YYYY-MM-DD`); `terraguard:ignore-file`; policy `unwaivable` rules; `checkov:skip=` and `trivy:ignore:` comments honoured through an ID mapping.
- Policy `data` lists with `in_data` / `not_in_data` in custom rules.
- SARIF results carry line-independent fingerprints.
- Atlantis template runs the scan on plan and preflight before apply.
- Plan analysis reports imports, moved resources and output changes, and explains drift: each resource changed outside Terraform is named with the attributes that changed (TG-PLAN-003).
- Hygiene rules: deprecated `"${...}"` interpolation, untyped variables, unused locals, unused data sources.
- Output formats `github` (PR annotations, on by default in the Action), `azure` (Azure DevOps) and `checkstyle`.
- `terraguard graph`: export the resource graph as Mermaid (renders on GitHub), Graphviz DOT or JSON, with attack paths and high-risk resources highlighted.
- OpenTofu `.tofu` files (with OpenTofu's precedence over `.tf`) and Terragrunt `terragrunt.hcl` (inputs as variable values, remote_state checks).
- `rules_version` in the policy pins the gating rule set; newer rules are reported but do not gate. The rule catalog shows the version each rule arrived in.
- Permission preflight: `preflight --live` checks the IAM actions a plan's creates need with the IAM policy simulator. Only `explicitDeny` fails by default; `--strict-permissions` also fails on `implicitDeny`.
- Policy options `inline_ignores: false` and `max_waiver_days`.
- `preflight --headroom N` (and the Action's `headroom` input): fail a plan that only fits by using the last N% of a quota.
- `terraguard preflight` (and the Action's `command: preflight`): checks a plan against live cloud quotas (AWS, Azure, Google Cloud) and S3 bucket name availability before apply, with read-only calls. Separate from the deterministic gate.
- Guarantees and limits page: drift, quotas, partial applies, permissions, unknown values, modules, false positives, AI.
- Redesigned site and workspace: animated node-network background, 3D hero, cursor light, scroll progress, a teal-to-violet palette in both themes, self-hosted Manrope and Space Grotesk fonts (no Google Fonts request). Workspace tabs show icons and live counts; the status bar shows a severity distribution; the graph draws clearly visible, hover-highlighted connections.
- Install picker: choosing a platform shows its command; downloads only start from the Download button.
- Provider schema checks: `scan --schema` (and the Action's `schema` input) checks every argument and block against `terraform providers schema -json`: unknown and read-only arguments with "did you mean" hints, missing required arguments and blocks, block limits, deprecations.
- HCP Terraform and Terraform Enterprise run task at `/api/run-task`: HMAC-verified, outbound calls limited to the configured host.
- Rule catalog filters (provider, severity, category, blocks apply) and a "Propose as built-in rule" flow that opens a pre-filled GitHub issue for review.
- Workspace keyboard shortcuts (`?` lists them).
- CI: CodeQL code scanning, dependency review on pull requests, every GitHub Action pinned to a commit SHA; generated workflows pin TerraGuard to a release.
- Server sends HSTS when served over HTTPS.
- 182 new rules (271 in total, up from 89), most as one-line table entries with a generated must-fire and must-stay-quiet test each, covering AWS (DocumentDB, Neptune, MQ, DMS, SageMaker, Kinesis, MSK, OpenSearch, EFS, Redshift, API Gateway, ECS, EKS, CodeBuild, SSM, GuardDuty, NACLs, AMI sharing, privilege escalation, GitHub OIDC trust), Azure (storage, Key Vault, SQL, flexible servers, Cosmos DB, Redis, ACR, AKS, App Service, custom roles, messaging), Google Cloud (GKE, Cloud SQL, GCS, VM access, IAM impersonation, public resource IAM, workload identity, SSL policies, Memorystore, BigQuery, KMS), Kubernetes (host paths, root, capabilities, RBAC) and GitHub (branch protection, Actions secrets). Each has labelled must-fire and must-stay-quiet cases.
- Plain-English standards: `terraguard policy suggest` and the Policy tab turn a sentence into one validated custom rule. The engine rejects anything that could weaken the policy and dry-runs the rule before you add it.
- Remote MCP: `terraguard serve` exposes the MCP tools at `/mcp` (streamable HTTP, token-protected, inline files only), plus a `validate_rule` tool.
- Website Docs page rendering the repository's guide, reference, rules, self-hosting, security, academy and architecture docs; copy buttons on every code block; per-finding copy; OS-aware download button; sitemap and structured data.
- Module-aware validation: `TG-VAL-011` (a local module call passes an undeclared input) and `TG-VAL-012` (a required input is missing).
- Resource graph: original icons for each kind of resource (buckets, NAT gateways, subnets, routes, load balancers, DNS, CDN, keys, secrets, queues, clusters and more), a provider tag on every node, and two-line labels.
- Workspace: a "Start here" guide, a custom rule builder in the Policy tab, and live policy error messages.
- Examples: an AWS network stack (VPC, subnets, internet and NAT gateways, load balancer, ECS, RDS, S3, CloudFront).
- CI templates for Bitbucket Pipelines, CircleCI and Atlantis.
- CI: race detector, fuzz tests for the scanner and policy loader, govulncheck, and a check that `docs/RULES.md` is up to date.
- Docs: generated rule reference (`docs/RULES.md`), threat model in SECURITY.md, AGENTS.md, `llms.txt`, trademark note.
- Site: a plain-language "The problem" section; deployment options and AI choices merged into Integrations and AI (the Enterprise page is gone).
- Policy-as-code: `extends` policy packs (files or https), `where` and `assert` conditions, operators `not_matches`, `contains`, `min`, `max`, glob overrides and disables, risk budgets (`max_findings`), baselines (`scan --baseline`, `--write-baseline`), `owner` and `docs_url`, `policy validate`, `policy test`, JSON Schema.
- Commands: `review` (diff-aware), `agent` (verified AI fixes), `pulse` (adoption reports), `agents-md`.
- Outputs: JUnit and GitLab Code Quality; gate failure reasons in every report; per-stage engine trace.
- Integrations: VS Code extension, pre-commit hooks, GitLab CI and Jenkins templates, Action modes `review` and `pulse`, MCP tool `generate_agents_md`.
- Enterprise: opt-in OpenAI and Anthropic, custom auth headers for gateways, air-gapped Docker image, audit log, Prometheus `/metrics`, rate limiting and security headers.
- Supply chain: SBOM, keyless image signing and build provenance in releases.
- Website: multi-page product site, live scan, three-step AI demo, new logo, dark theme by default.

### Fixed
- A waived or baselined blocking finding no longer reports that `terraform apply` will succeed.

## [2.0.0] - 2026-11-01

### Added
- Go engine replacing the Python/GPT-4o MVP; WebAssembly web app; CLI; GitHub Action; MCP server; self-hosted server; multi-cloud rules; plan analysis; auto-fix; compliance mapping; free-model AI fallback.
