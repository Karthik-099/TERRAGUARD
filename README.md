# TerraGuard

An AI-powered security analysis engine for Infrastructure-as-Code.

TerraGuard statically analyzes Terraform (and, in future phases, OpenTofu, Pulumi, CloudFormation, and Kubernetes manifests) for security misconfigurations, policy violations, and architectural risk. It combines deterministic rule-based checks with LLM-driven semantic reasoning to surface issues that static linters alone cannot detect — such as implicit trust chains across resources, over-permissive cross-service relationships, and context-dependent risk that only becomes visible when resources are analyzed together.

This project is in early development. The current release is a working MVP: a web interface that accepts a Terraform file and returns a severity-ranked findings report with remediation guidance. The architecture described below is the full design target.

---

## The problem

IaC security tools today fall into two categories. Pure static analyzers (tfsec, Checkov, Terrascan) are fast and deterministic but limited to pattern matching against known rule sets. They miss novel misconfigurations, cannot reason about cross-resource risk, and produce high false-positive rates that teams learn to ignore. LLM-based tools on the other hand lack structured severity scoring, policy enforcement, audit trails, and the integrations that production security workflows require.

TerraGuard is an attempt to build something in the middle: deterministic rules for known control failures, AI semantic reasoning for context-dependent risk, and a policy engine that lets teams encode and enforce their own security standards.

---

## Current state (Phase 1 - MVP)

- Web UI: upload or paste a Terraform file, receive a structured findings report
- AI analysis via GPT-4o with severity classification (CRITICAL / HIGH / MEDIUM / LOW / INFO)
- Detects: overprivileged IAM, public storage, exposed ports, hardcoded secrets, disabled encryption, missing logging
- Each finding includes: resource reference, description, remediation guidance, CWE reference, and tags
- Backend: Python + Flask
- Frontend: single-file HTML/CSS/JS, no dependencies

---

## Target architecture

The full design is organized into six layers.

**Input sources**

The platform is designed to receive IaC from multiple entry points without requiring changes to existing workflows: GitHub Actions or GitLab CI as a pipeline step, direct Git repository integration, REST API for programmatic use, pre-commit hook for local enforcement, and the web UI for ad-hoc analysis.

**Parser and normalizer**

A unified HCL/YAML parser normalizes inputs across Terraform, OpenTofu, Pulumi, CloudFormation, and Kubernetes manifests into a common internal representation. This decouples the analysis engine from IaC dialect specifics and makes it possible to write rules once that apply across providers.

**Analysis engine**

Three analysis strategies run in parallel against the normalized representation.

The static rules engine applies deterministic checks against a versioned rule registry mapped to CIS Benchmarks, NIST 800-53, SOC2, and provider-specific best practices. These checks are fast, explainable, and produce zero false negatives on known control failures.

The AI semantic analysis engine sends resource context to an LLM and reasons about implicit risk: a Lambda function with an execution role scoped to S3:* that also happens to be triggered by a public API Gateway endpoint is a critical finding that no individual resource-level rule would surface. This layer catches the class of issues that only appear when resources are read together.

The dependency graph engine builds a directed graph of all resource relationships within a configuration and identifies cross-resource risk patterns: privilege escalation paths, data exfiltration paths, and lateral movement vectors.

A finding aggregator merges results from all three engines, deduplicates overlapping findings, and applies CVSS-based severity scoring.

**Policy engine**

Teams can define custom security policies in OPA/Rego that are evaluated against every scan. This allows encoding organization-specific controls (tag requirements, naming conventions, approved AMI lists, required encryption standards) as code, versioned in Git alongside the infrastructure it governs.

**Report generator**

Findings are serialized into multiple output formats depending on the integration context: an HTML dashboard for human review, JSON and SARIF for machine consumption, JUnit XML for CI gate integration, and Markdown for pull request comments.

**Output channels**

Results route to wherever the team works: Slack or PagerDuty for alerting, GitHub or GitLab PR comments for developer feedback, Jira or ServiceNow for ticket creation, and an immutable audit log for compliance evidence.

**Data plane**

Scan history, findings, policies, and rule versions are persisted to allow trend analysis, regression detection, and benchmarking across environments and time.

**Platform integrations**

Planned integrations include live cloud account scanning via AWS, Azure, and GCP APIs (to compare declared vs actual state), OPA Gatekeeper for Kubernetes admission control, SIEM and CSPM connectors (Wiz, Prisma Cloud, Splunk), and enterprise identity via SSO, LDAP, SAML, and OIDC.

---

## Why this matters at scale

The gap TerraGuard targets is most visible in organizations running large IaC estates across multiple cloud providers with multiple teams contributing configurations. At that scale, manual review of Terraform PRs is not tractable, rule-based tools produce noise that gets ignored, and the misconfigurations most likely to cause incidents are the ones that look correct in isolation but are dangerous in combination.

The dependency graph and AI semantic layers are designed specifically for that class of risk.

---

## Roadmap

Phase 1 (current): MVP — web UI, single-file Terraform analysis, GPT-4o backend, basic rule set

Phase 2: CLI tool, pre-commit hook, GitHub Actions integration, SARIF output, expanded rule set

Phase 3: Multi-file and module-aware analysis, dependency graph engine, policy engine with OPA

Phase 4: API server, multi-tenant support, scan history, trend dashboards

Phase 5: Live cloud account drift detection, SIEM integrations, enterprise auth

---

## Local setup

Requires Python 3.10+ and an OpenAI API key.

```
git clone https://github.com/Karthik-099/TERRAGUARD
cd terraguard
pip install -r requirements.txt
export OPENAI_API_KEY=your_key_here
python app.py
```

Open http://localhost:5000 in a browser. Use the "Load Sample" button to analyze a pre-built vulnerable configuration.

---

## What it detects (current rule set)

| Category | Examples |
|---|---|
| IAM | Wildcard actions, wildcard principals, overprivileged Lambda roles |
| Network | SSH, RDP, database ports exposed to 0.0.0.0/0 |
| Storage | Public S3 buckets, ACL misconfiguration, missing MFA delete |
| Secrets | Hardcoded passwords, API keys, tokens in .tf files |
| Encryption | Unencrypted EBS volumes, unencrypted RDS, disabled storage encryption |
| Logging | CloudTrail disabled, VPC flow logs disabled, S3 access logging disabled |
| Database | Publicly accessible RDS instances, deletion protection disabled |

---

## Tech stack

Current:
- Python 3.10+, Flask
- OpenAI GPT-4o
- HTML / CSS / JavaScript (zero frontend dependencies)

Planned additions:
- PostgreSQL (findings persistence)
- OPA (policy engine)
- Redis (job queue for async scanning)
- Prometheus + Grafana (observability)
- Docker + Kubernetes deployment manifests

---

## Contributing

The project is at an early stage. Contributions to the rule set, parser, or integrations are welcome. Open an issue before submitting large changes.

---

## License

MIT

---

## Author

Karthik
DevOps and Platform Engineering
GitHub: github.com/Karthik-099
Portfolio: karthik-portfolioo.netlify.app
