# Roadmap

The roadmap is a direction, not a promise. Proposals and help are welcome in
[Discussions](https://github.com/Karthik-099/TERRAGUARD/discussions).

## Shipped

- [x] One deterministic engine in the browser (WebAssembly), CLI, GitHub Action, VS Code, language server, MCP, self-hosted server and Kubernetes admission webhook
- [x] 1,750 rules across 26 providers and every supported format, plan risk, attack paths, auto-fix
- [x] Policy-as-code: `extends`, conditional rules, budgets, baselines, expiring waivers, policy tests, rule pinning, plain-English drafts, Rego
- [x] Diff-aware review, verified AI fixes, Pulse adoption reports, quota preflight, plan cost
- [x] Provider schema checks; AWS, Azure, Google, Nutanix and vSphere value checks; local module inputs
- [x] Pulumi, Crossplane, Deployment Manager; drift and inventory; offline vulnerability scan; `fix --pr`
- [x] 3.0: Nutanix, VMware vSphere, Red Hat OpenShift, ROSA and ARO
- [x] 3.0: secret scanning, CODEOWNERS on findings, plugins, SBOM, RHEL-family images, offline mode, folder and zip scans and add-on rules in the web app

## Next (3.x)

- [ ] Red Hat Ansible Automation Platform: job templates, credentials and execution environments
- [ ] Nutanix: NDB (database service), Nutanix Files and Objects, and Calm blueprints
- [ ] OpenShift: GitOps (Argo CD) and Pipelines (Tekton) resources, and MachineConfig hardening
- [ ] Auto-fix for OpenShift Routes and SCCs, and for Nutanix and vSphere provider TLS
- [ ] SARIF fix suggestions shown inline on GitHub
- [ ] Open VSX and Marketplace listings for the VS Code extension
- [ ] Shared add-on rule packs: a signed pack format that teams can host in their own Git repository

## Later

- [ ] OpenTofu-specific checks (state encryption, early variable evaluation)
- [ ] Drift insights across many workspaces, run by the user's own CI (never a scheduled job by default)
- [ ] Red Hat Satellite and OpenStack Platform (RHOSP) resources
- [ ] An independent security audit
