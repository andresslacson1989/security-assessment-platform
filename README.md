# Automated Security Assessment & Vulnerability Management Platform

A production-grade, modular, and non-destructive automated security assessment and vulnerability management platform. Point the platform to a target (URL, Domain, IP, Code Repository, Dockerfile, or IaC manifest) to execute a comprehensive battery of calculated security audits across 5 engines with real-time SSE streaming, deterministic grading (`A+` to `F`), and multi-format exports (Standalone HTML, OASIS SARIF v2.1.0, JSON).

---

## Architecture & Security Engines

The platform is architected around 5 core assessment engines:
1. **Network Perimeter & TLS/SSL Auditor (`network`):** Certificate validity, deprecated protocols (SSLv3, TLS 1.0/1.1), weak ciphers, DNS hygiene (SPF, DMARC, MTA-STS, DNSSEC, AXFR), and sensitive port exposure.
2. **Web Application & API DAST (`web_dast`):** OWASP security headers, cookie attributes (`HttpOnly`, `Secure`, `SameSite`), CORS analysis, public `.env`/`.git` exposure, GraphQL introspection, and Subresource Integrity (SRI).
3. **Static Code Analysis & Secrets SAST (`code_sast`):** 40+ regex patterns with Shannon entropy thresholding, automatic secret masking in evidence, insecure cryptography/PRNG linting, and dependency lockfile CVE auditing.
4. **Infrastructure-as-Code & Container Auditor (`infra_iac`):** Dockerfile security (root user, unpinned tags, missing healthcheck), Docker Compose socket mounts, Kubernetes pod security contexts, and Terraform cloud configurations.
5. **CI/CD Pipeline Auditor (`cicd_audit`):** GitHub Actions workflow auditing (`pull_request_target`, unpinned action versions, script injection).

---

## Authoritative System Contracts

All formal architectural, data schema, interface, compliance, and execution contracts are established under [`contracts/`](./contracts/):

| Contract | Title | Description |
| :--- | :--- | :--- |
| **[Contract 01](./contracts/01_PROJECT_SCOPE_AND_SAFETY_CONTRACT.md)** | Scope, Safety & Operational Boundaries | Non-destructive mandate, target validation, rate limiting, and zero-exfiltration privacy. |
| **[Contract 02](./contracts/02_DATA_SCHEMA_AND_MODELS_CONTRACT.md)** | Data Schema & Models | Pydantic v2 schemas, CVSS 3.1 rating models, and mathematical grading formula ($S = 100 - \sum \text{penalties}$). |
| **[Contract 03](./contracts/03_ENGINE_PLUGIN_INTERFACE_CONTRACT.md)** | Engine Plugin Interface | Standard `BaseAssessmentEngine` abstract interface and 5-engine submodule contracts. |
| **[Contract 04](./contracts/04_API_AND_STREAMING_EVENTS_CONTRACT.md)** | REST API & Streaming Events | FastAPI REST endpoints, OpenAPI schemas, and real-time SSE streaming protocol. |
| **[Contract 05](./contracts/05_DELIVERABLES_AND_ACCEPTANCE_CRITERIA_CONTRACT.md)** | Deliverables & Acceptance Criteria | Deliverables checklist, 8 automated test scenarios, and strict Definition of Done (DoD). |
| **[Contract 06](./contracts/06_SECURITY_CHECK_CATALOG_AND_CWE_MAPPING_CONTRACT.md)** | Master Security Check Catalog | 50+ canonical security check IDs with CVSS 3.1, CWE, OWASP (2021), and NIST SP 800-53 mappings. |
| **[Contract 07](./contracts/07_FRONTEND_UI_UX_SPECIFICATION_CONTRACT.md)** | Frontend UI/UX & Design System | Cyber SOC Dark Theme tokens, HUD component layouts, log streamer, and telemetry lifecycle. |
| **[Contract 08](./contracts/08_TECHNICAL_IMPLEMENTATION_AND_TEST_VECTORS_CONTRACT.md)** | Technical Implementation & Test Vectors | Execution algorithms, socket/X.509 logic, entropy calculations, 40+ secret patterns, and remediation templates. |

---

## License

Proprietary / Internal Security Tooling.
