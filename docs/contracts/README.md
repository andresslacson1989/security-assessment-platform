# Security Assessment Platform: Master System Contracts & Specifications

This directory contains the authoritative, production-level architectural, safety, data schema, engine interface, compliance, technical implementation, and delivery contracts established for the Full-Stack Automated Security Assessment & Vulnerability Management Platform.

---

## Master Contract Index (Contracts 01 – 08)

| Contract File | Title | Description |
| :--- | :--- | :--- |
| [`01_PROJECT_SCOPE_AND_SAFETY_CONTRACT.md`](./01_PROJECT_SCOPE_AND_SAFETY_CONTRACT.md) | **Scope, Safety & Operational Boundaries** (v8.0.0) | Strict non-destructive constraints, target validation rules (`URL`, `DOMAIN`, `IP`, `LOCAL_PATH`, `DOCKERFILE`, `IAC_MANIFEST`), headless SPA sandbox rules, read-only cloud auditing, and zero-exfiltration privacy. |
| [`02_DATA_SCHEMA_AND_MODELS_CONTRACT.md`](./02_DATA_SCHEMA_AND_MODELS_CONTRACT.md) | **Data Schema & Models** (v8.0.0) | Formal Pydantic v2/JSON schemas for `Target`, `Finding`, `Evidence`, `ScanJobSummary`, `ScanJob`, `SBOMReport`, `CISBenchmarkResult`, `VerifiedSecretEvidence`, and the deterministic grading formula (`A+` to `F`). |
| [`03_ENGINE_PLUGIN_INTERFACE_CONTRACT.md`](./03_ENGINE_PLUGIN_INTERFACE_CONTRACT.md) | **Engine Plugin Interface** (v8.0.0) | Standardized `BaseAssessmentEngine` abstract interface, 5-tier binary resolution, safe loop-agnostic subprocess execution, and specifications for all 5 security engines and 22 hybrid tool adapters. |
| [`04_API_AND_STREAMING_EVENTS_CONTRACT.md`](./04_API_AND_STREAMING_EVENTS_CONTRACT.md) | **REST API & Streaming Events** (v8.0.0) | Complete REST endpoints (`/api/scans/*`, `/api/reports/*`, `/api/system/*`, `/api/tools/*`, `/api/scans/{id}/export/sbom/*`), HTTP Repeater API, and real-time SSE streaming event specifications. |
| [`05_DELIVERABLES_AND_ACCEPTANCE_CRITERIA_CONTRACT.md`](./05_DELIVERABLES_AND_ACCEPTANCE_CRITERIA_CONTRACT.md) | **Deliverables & Acceptance Criteria** (v8.0.0) | Deliverables checklist, 25 concrete acceptance test scenarios (including multi-page crawling, authenticated DAST, 22 hybrid tool adapters, SBOM exports, CIS benchmarks, and containerized distribution), and strict Definition of Done (DoD). |
| [`06_SECURITY_CHECK_CATALOG_AND_CWE_MAPPING_CONTRACT.md`](./06_SECURITY_CHECK_CATALOG_AND_CWE_MAPPING_CONTRACT.md) | **Master Security Check Catalog** (v8.0.0) | 70+ canonical security check IDs with default severities, CVSS 3.1 base scores, CWE IDs, OWASP Top 10 (2021), and NIST SP 800-53 controls across all 22 tools. |
| [`07_FRONTEND_UI_UX_SPECIFICATION_CONTRACT.md`](./07_FRONTEND_UI_UX_SPECIFICATION_CONTRACT.md) | **Frontend UI/UX & Design System** (v8.0.0) | Cyber SOC Dark Theme tokens, HUD component hierarchy, real-time log terminal streamer, 22-tool management matrix, SBOM export toolbar, verified secret badges, and SSE protocol manager. |
| [`08_TECHNICAL_IMPLEMENTATION_AND_TEST_VECTORS_CONTRACT.md`](./08_TECHNICAL_IMPLEMENTATION_AND_TEST_VECTORS_CONTRACT.md) | **Technical Implementation & Test Vectors** (v8.0.0) | Exact execution algorithms, 5-tier binary discovery with Windows Registry scan, Section 11 (22-Tool Enterprise Specifications), production multi-stage Dockerfile, docker-compose, and GitHub Actions CI/CD publishing pipeline. |

---

## Architectural Principles

1. **Non-Destructive by Design:** Strictly passive auditing, non-state-changing probes, safe TLS handshakes, header evaluation, and AST/regex secret detection.
2. **Deterministic & Objective:** Grade calculations and scores are computed through pure mathematical formulas based on CVSS ratings.
3. **Resilient & Isolated:** Individual check or network failures never cascade; all engines catch errors and isolate faults.
4. **Local & Private:** Zero external telemetry; all scan data, findings, and logs reside solely on the user's local machine.
5. **Open Interoperability:** Native export to Standalone HTML, OASIS SARIF v2.1.0 (GitHub Code Scanning), and standard JSON.
