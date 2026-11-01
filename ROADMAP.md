# Roadmap

The roadmap is a direction, not a promise. Proposals and help are welcome in
[Discussions](https://github.com/Karthik-099/TERRAGUARD/discussions).

## Now (v2.x)

- [x] Deterministic engine compiled to WebAssembly, CLI, GitHub Action, MCP server, self-hosted server
- [x] 89 rules across 14 providers, plan risk, attack paths, auto-fix
- [x] Policy-as-code: `extends`, conditional rules, budgets, baselines, expiring waivers, policy tests, JSON Schema
- [x] Diff-aware review, verified AI agent, Pulse adoption reports, AGENTS.md generation
- [x] VS Code extension, pre-commit, GitLab CI and Jenkins templates, JUnit and GitLab Code Quality output
- [x] Enterprise: any OpenAI-compatible model, air-gapped image, audit log, Prometheus metrics, rate limiting
- [x] Supply chain: SBOM, signed images and build provenance from v2.1

## Next

- [ ] Provider-schema validation from `terraform providers schema -json` (argument names and types)
- [ ] Module-aware analysis that follows local modules and their inputs
- [ ] Language server (LSP) so every editor gets diagnostics; Open VSX and Marketplace listings
- [ ] SARIF fix suggestions shown inline on GitHub
- [ ] Community rule packs and OPA/Rego import
- [ ] Cost deltas for plan changes

## Later

- [ ] OpenTofu-specific checks (state encryption, early variable evaluation)
- [ ] Drift insights from scheduled plans across many workspaces
- [ ] Hosted policy-pack registry
