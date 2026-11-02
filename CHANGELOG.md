# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed
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
