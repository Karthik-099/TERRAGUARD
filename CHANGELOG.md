# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
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
