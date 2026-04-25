# TerraGuard High-Level Design (HLD)

This document describes the TerraGuard architecture as a production-oriented design while clearly separating the current MVP from planned expansion.

## 1) System Boundary

`Current MVP (implemented now)`:
- Web UI (`static/index.html`)
- Flask API (`app.py`)
- OpenAI-powered Terraform analysis
- Structured finding output and severity summary

`Target expansion (planned)`:
- Multi-source ingestion (CI, REST, pre-commit)
- Multi-engine analysis pipeline
- Policy engine and report adapters
- Data plane, queueing, observability, and enterprise integrations

## 2) Symbol Legend

| Symbol type | Meaning |
| --- | --- |
| `/parallelogram/` | External input/output channel |
| `([stadium])` | API/service entrypoint |
| `{{hexagon}}` | Parser/normalization logic |
| `[[subroutine]]` | Deterministic processing component |
| `((circle))` | AI semantic reasoning component |
| `{diamond}` | Graph/decision logic |
| `[rectangle]` | Internal orchestration component |
| `[(cylinder)]` | Persistent data store |

## 3) Data Flow Legend

| Line type | Meaning |
| --- | --- |
| `-->` | Synchronous request-response flow |
| `-.->` | Asynchronous/event or telemetry flow |
| `==>` | Governance or policy-enforced flow |

## 4) End-to-End HLD

```mermaid
flowchart TB
  %% ---------- Classes ----------
  classDef input fill:#e8f0fb,stroke:#2d6ac7,color:#0e3a70,stroke-width:1px;
  classDef service fill:#e7f8f3,stroke:#1c8d6b,color:#0a4d3b,stroke-width:1.2px;
  classDef engine fill:#eeedfe,stroke:#6a5fd3,color:#2b2467,stroke-width:1px;
  classDef control fill:#faece7,stroke:#d35a2d,color:#542010,stroke-width:1.2px;
  classDef data fill:#faeeda,stroke:#b9781e,color:#4a2c05,stroke-width:1px;
  classDef obs fill:#edf2ff,stroke:#5a78d1,color:#1f3f8a,stroke-width:1px;

  %% ---------- Inputs ----------
  CI[/CI\/CD Pipeline/]:::input
  REPO[/IaC Repository/]:::input
  WEB[/Web UI/]:::input
  APIIN[/REST API Clients/]:::input
  PRE[/Pre-commit Hook/]:::input

  %% ---------- Core ----------
  API([TerraGuard API Gateway]):::service
  NORM{{HCL/YAML Parser + Normalizer}}:::service

  SR[[Static Rules Engine]]:::engine
  AI((AI Semantic Engine)):::engine
  DG{Dependency Graph Engine}:::engine
  AGG[Finding Aggregator]:::control
  POL[Policy Engine<br/>OPA/Rego]:::control
  REP[[Report Generator]]:::service
  ROUTE[Output Router]:::control

  %% ---------- Outputs ----------
  ALERT[/Slack · PagerDuty · Email/]:::input
  PR[/GitHub/GitLab PR Comments/]:::input
  DASH[/Security Dashboard/]:::input
  TICKET[/Jira · ServiceNow/]:::input
  AUDIT[/Immutable Audit Trail/]:::input

  %% ---------- Data Plane ----------
  FDB[(Findings DB<br/>PostgreSQL)]:::data
  PST[(Policy Store)]:::data
  RREG[(Rule Registry)]:::data
  QUEUE[(Job Queue<br/>Redis)]:::data

  %% ---------- Integrations ----------
  CLOUD[/AWS · Azure · GCP APIs/]:::input
  K8S[/Kubernetes / Gatekeeper/]:::input
  SIEM[/SIEM / CSPM/]:::input
  IDP[/SSO / LDAP / SAML / OIDC/]:::input

  %% ---------- Observability ----------
  METRICS[(Prometheus/Grafana)]:::obs
  TRACING[(OpenTelemetry/Jaeger)]:::obs
  LOGS[(Structured Logs)]:::obs

  %% ---------- Sync Ingestion ----------
  CI --> API
  REPO --> API
  WEB --> API
  APIIN --> API
  PRE --> API

  %% ---------- Core Analysis ----------
  API --> NORM
  NORM --> SR
  NORM --> AI
  NORM --> DG
  SR --> AGG
  AI --> AGG
  DG --> AGG
  AGG ==>|Policy Gate| POL
  POL --> REP
  REP --> ROUTE

  %% ---------- Output Delivery ----------
  ROUTE --> ALERT
  ROUTE --> PR
  ROUTE --> DASH
  ROUTE --> TICKET
  ROUTE --> AUDIT

  %% ---------- Persistence ----------
  AGG --> FDB
  POL --> PST
  SR --> RREG

  %% ---------- Async/Integration ----------
  API -.-> QUEUE
  QUEUE -.-> API
  CLOUD -.-> API
  K8S -.-> API
  SIEM -.-> API
  IDP -.-> API

  %% ---------- Telemetry ----------
  API -.-> METRICS
  API -.-> TRACING
  API -.-> LOGS
  AGG -.-> METRICS
  REP -.-> LOGS
```

## 5) Scan Lifecycle (Sequence)

```mermaid
sequenceDiagram
  autonumber
  actor Dev as Developer
  participant UI as Web UI / CI Trigger
  participant API as TerraGuard API
  participant N as Parser+Normalizer
  participant E as Analysis Engines
  participant A as Finding Aggregator
  participant P as Policy Engine
  participant R as Report Generator
  participant O as Output Router

  Dev->>UI: Submit Terraform
  UI->>API: POST /analyze
  API->>N: Parse + normalize IaC
  N->>E: Dispatch IR to static/AI/graph analysis
  E->>A: Findings + metadata
  A->>P: Policy gate + org controls
  P->>R: Approved findings context
  R->>O: Render integration format (JSON/SARIF/Markdown/HTML)
  O-->>UI: Findings response
  O-->>Dev: PR comments / alerts / dashboard updates
```

## 6) Component Responsibilities

| Component | Responsibility | MVP status |
| --- | --- | --- |
| API Gateway | Accept scan input, validate payload, orchestrate analysis call | Implemented |
| Parser + Normalizer | Convert IaC into common representation | Partial (Terraform text context in MVP) |
| Static Rules Engine | Deterministic control checks | Planned |
| AI Semantic Engine | Context-aware risk reasoning | Implemented (LLM-backed) |
| Dependency Graph Engine | Cross-resource risk paths | Planned |
| Finding Aggregator | Deduplicate + prioritize findings | Partial (MVP severity summary) |
| Policy Engine | OPA/Rego org controls | Planned |
| Report Generator | Multi-format reporting | Partial (JSON API + UI rendering) |
| Data Plane | History, policies, registry, queue | Planned |
| Observability | Metrics, traces, logs | Planned |

## 7) Deployment Modes

- Local dev: single Flask process + static assets
- Team mode (planned): containerized API + worker + Redis + PostgreSQL
- Enterprise mode (planned): Kubernetes, SSO, policy bundles, audit export
