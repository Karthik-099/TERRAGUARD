# Governance

TerraGuard is an open-source project under the MIT license. This document
describes how decisions are made today and how that changes as the
community grows.

## Roles

| Role | Who | Responsibilities |
|---|---|---|
| **Users** | Anyone who runs TerraGuard | Report issues, request rules, share feedback |
| **Contributors** | Anyone with a merged pull request | Rules, fixes, docs, integrations |
| **Reviewers** | Contributors invited after sustained, high-quality reviews | Review and approve pull requests in their area |
| **Maintainers** | Listed in [MAINTAINERS.md](MAINTAINERS.md) | Releases, roadmap, security response, final decisions |

## Decision making

- Day-to-day changes are decided in pull requests. One maintainer approval is required, and CI (tests, evals, secret scan) must pass.
- Changes to the engine's public behaviour (rule semantics, policy format, output formats, CLI flags) are proposed as a GitHub Discussion or issue labelled `proposal`, and stay open for at least 7 days.
- Maintainers seek consensus. If consensus is not reached, the lead maintainer decides and records the reasoning on the proposal.

## Compatibility promise

- `.terraguard.yml` and the JSON report format are versioned. Breaking changes only happen in a major release, with a migration note in [CHANGELOG.md](CHANGELOG.md).
- Rule IDs are never reused. A removed rule keeps its ID reserved.

## Becoming a maintainer

Contributors who consistently review and ship high-quality changes over
several months may be nominated by a maintainer. Nominations are approved by
a majority of maintainers.

## Code of conduct

Everyone follows the [Code of Conduct](CODE_OF_CONDUCT.md).
