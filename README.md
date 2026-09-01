# CyberAssess - Full-Stack Automated Security Assessment & Vulnerability Management Platform

[![Platform Version](https://img.shields.io/badge/version-10.0.0-06b6d4.svg)](https://github.com/andresslacson1989/security-assessment-platform)
[![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688.svg)](https://fastapi.tiangolo.com/)
[![Tests](https://img.shields.io/badge/tests-199%20passed%20(100%25)-10b981.svg)](https://pytest.org/)
[![Standards](https://img.shields.io/badge/standards-ASVS%20v5.0.0%20%7C%20NIST%20SSDF%20v1.1%20%7C%20NIST%20800--53-purple.svg)](https://github.com/andresslacson1989/security-assessment-platform)
[![License](https://img.shields.io/badge/license-Proprietary%20Personal--Use-red.svg)](LICENSE)

CyberAssess is an enterprise-grade automated security assessment and vulnerability management platform conforming to **OWASP ASVS v5.0.0**, **NIST SP 800-218 SSDF v1.1**, and **NIST SP 800-53 Rev 5**. Point it at a URL, domain, IP address, container manifest, or local repository workspace, and the engine automatically conducts a comprehensive battery of vulnerability tests, scores posture deterministically, clusters findings with preserved SLA clocks, and streams live telemetry to an interactive SOC HUD.

## License

CyberAssess is proprietary software. The [CyberAssess Proprietary Personal-Use
License](LICENSE) grants only one individual acting privately and solely for
that person's own purposes a limited permission to run, study, and privately
modify the software. It does not grant ownership of CyberAssess, the repository,
its code, documentation, configuration, arrangement, or project identity.

Companies, organizations, institutions, schools, laboratories, nonprofits,
government bodies, teams, and other entities may not use CyberAssess. Use for
an employer, client, customer, sponsor, school, organization, or other third
party is also prohibited. Commercial use, organizational use, SaaS, hosting,
consulting, scanning services, internal business use, resale, and incorporation
into another product or service require a separate written license signed by
the copyright owner.

CyberAssess names, logos, branding, and product identity are not licensed as
trademarks. Third-party components remain subject to their own licenses.

The repository may remain publicly viewable and technically forkable on GitHub.
Public hosting does not transfer ownership or expand the limited permissions
granted by the license.

The repository may remain publicly viewable and forkable on GitHub. That public
hosting does not change the rights granted by the license or make CyberAssess
open source.

---

## ⚡ Quickstart (One Command)

### 1. Install Dependencies
```bash
pip install -r backend/requirements.txt
```

### 2. Launch the Platform
```bash
python run_platform.py
```
*Automatically starts the FastAPI backend on `http://127.0.0.1:8000` and opens the SOC Dark Theme Dashboard in your default web browser.*

---

## 🛡️ 5 Core Assessment Engines & 4 Hybrid Tool Adapters

| Engine | Name | Capabilities & Checks | Pluggable Tool Adapter |
|---|---|---|---|
| 🌐 **1** | `network` | **Network Perimeter, TLS/DNS & OSINT**: TLS 1.0–1.3 cipher suite checks, X.509 validity/SAN matching, DNS hygiene (SPF, DMARC, CAA, MTA-STS, DNSSEC, AXFR), crt.sh subdomain recon, CNAME takeover detection, daemon banner grabbing, and port scanner. | **Nmap** (Network & Version Scanner) |
| 🛡️ **2** | `web_dast` | **Web Application & REST/GraphQL API DAST**: OWASP response headers (CSP, HSTS, X-Frame-Options, nosniff, COOP/COEP), cookie security flags (`HttpOnly`, `Secure`, `SameSite`), CORS origin reflection, sensitive files (`.env`, `.git/HEAD`, actuator), active parameter fuzzing (Time SQLi, Canary XSS, LFI, SSTI, Open Redirect) with reproduction cURL generation, and GraphQL introspection. | **Nuclei** (Community CVE Template Scanner) |
| 💻 **3** | `code_sast` | **Static Code Analysis, Secrets & Dependency SCA**: Shannon entropy analysis ($H(X) \ge 4.5$), 40+ high-entropy credential patterns (100% masked in evidence), historical `git log -p` commit scanning, weak cryptographic algorithms (MD5/SHA-1/DES/ECB), interprocedural AST taint flow analysis (`SAST-TAINT-001`/`002`), and vulnerable dependency scanner. | **Semgrep** (AST Rule SAST) & **Trivy** (Deep SCA) |
| 📦 **4** | `infra_iac` | **Infrastructure-as-Code & Container Auditor**: Dockerfile root user & build secret audits, Docker Compose privileged containers & docker.sock mounts, Kubernetes Pod Security Standards (PSS), and Terraform AWS cloud posture. | **Trivy** (Container & IaC Scanner) |
| ⚡ **5** | `cicd_audit` | **CI/CD Pipeline & Build Security Auditor**: GitHub Actions workflow supply chain audit, insecure `pull_request_target` checkouts, unpinned third-party action versions, inline script injection via untrusted GitHub contexts, and default `GITHUB_TOKEN` permissions. | *Native Core Engine* |

*Note: All external tool adapters gracefully fall back to zero-dependency native Python implementations when binaries are absent on PATH.*

---

## 📊 Deterministic Grading Formula

Platform security grades are computed deterministically per **Contract 02**:

$$S = \max\left(0.0, 100.0 - \left[35 \cdot N_{\text{crit}} + 15 \cdot N_{\text{high}} + 5 \cdot N_{\text{med}} + 1 \cdot N_{\text{low}}\right]\right)$$

### Hard Threshold Gates:
- $N_{\text{crit}} \ge 1 \implies \text{Grade } \mathbf{F}$ (Hard capped regardless of score)
- $N_{\text{high}} \ge 1 \implies \text{Grade } \mathbf{D}$ (If $S \ge 50.0$; if $S < 50.0 \implies \mathbf{F}$)
- Score $96.0 \le S \le 100.0$ and $N_{\text{crit}} = N_{\text{high}} = N_{\text{med}} = N_{\text{low}} = 0 \implies \mathbf{A^+}$
- $90.0 \le S \le 100.0 \implies \mathbf{A}$
- $75.0 \le S < 90.0 \implies \mathbf{B}$
- $60.0 \le S < 75.0 \implies \mathbf{C}$
- $50.0 \le S < 60.0 \implies \mathbf{D}$
- $S < 50.0 \implies \mathbf{F}$

---

## 📡 REST API & Real-Time SSE Streaming

### System Endpoints
- `GET /api/system/health`: System health status, API version 4.1.0, uptime, and storage stats.
- `GET /api/system/capabilities`: External tool binary availability, detected version strings, and execution modes.
- `GET /api/system/engines`: Registered assessment engines metadata & supported target types.

### Pentester Tools & Workbench
- `POST /api/tools/repeater`: Interactive HTTP Repeater for raw request crafting, header modification, latency measurement, and TLS inspection.

### Scan Management
- `POST /api/scans/start`: Launch automated security scan on target.
- `GET /api/scans/{scan_id}`: Detailed snapshot with progress, findings, logs, and score.
- `POST /api/scans/{scan_id}/cancel`: Gracefully abort active scan execution.
- `GET /api/scans/history`: Paginated history of past scans.
- `DELETE /api/scans/{scan_id}`: Delete scan record from storage.
- `GET /api/scans/{scan_id}/events`: **Server-Sent Events (SSE)** real-time stream (`tool_status`, `progress`, `log`, `auth_status`, `crawl_discovered`, `subdomain_discovered`, `finding`, `completed`, `error`).

### Multi-Format Exporters
- `GET /api/scans/{scan_id}/export/html`: Standalone single-file interactive HTML report (zero external CDN dependencies).
- `GET /api/scans/{scan_id}/export/sarif`: 100% compliant **OASIS SARIF v2.1.0** for GitHub/GitLab Code Scanning.
- `GET /api/scans/{scan_id}/export/json`: Complete serialized raw scan model.

---

## 🧪 Automated Test Verification

Run all unit, integration, and contract acceptance test suites:
```bash
pytest tests/ -v
```

### Test Coverage Highlights:
- **102 Passed Tests (100% Pass Rate)**
- Full verification of all **15 Contract 05 Acceptance Scenarios**.
- Hybrid Tool Adapter execution & zero-cascade fallback tests (`Nmap`, `Nuclei`, `Semgrep`, `Trivy`).
- Active parameter fuzzing with copy-pasteable reproduction cURL PoC generation.
- Interprocedural AST taint flow analysis (`SAST-TAINT-001`/`002`) and historical Git secret scanning (`SAST-GIT-001`).
- Passive OSINT Certificate Transparency recon & dangling CNAME takeover detection (`NET-OSINT-001`).
- Token-bucket rate limiting (1–20 RPS) and circuit breaker tests.
- 100% secret evidence masking (`mask_secret()`) guarantee tests.
- SARIF v2.1.0 schema compliance and zero-CDN HTML export tests.

---

## 📂 Project Architecture

```
security-assessment-platform/
├── backend/
│   ├── app/
│   │   ├── adapters/             # Hybrid Tool Adapters (Nmap, Nuclei, Semgrep, Trivy)
│   │   ├── api/                  # REST & SSE route handlers
│   │   │   ├── system.py
│   │   │   ├── scans.py
│   │   │   ├── tools.py
│   │   │   └── export.py
│   │   ├── core/                 # Core engine models, grading & orchestrator
│   │   │   ├── models.py
│   │   │   ├── grading.py
│   │   │   ├── storage.py
│   │   │   ├── rate_limiter.py
│   │   │   └── orchestrator.py
│   │   ├── engines/              # 5 Modular Security Assessment Engines
│   │   │   ├── base.py
│   │   │   ├── network/
│   │   │   ├── web_dast/
│   │   │   ├── code_sast/
│   │   │   ├── infra_iac/
│   │   │   └── cicd_audit/
│   │   ├── exporters/            # HTML, SARIF v2.1.0, JSON exporters
│   │   └── main.py               # FastAPI application server entrypoint
│   └── requirements.txt
├── contracts/                    # Formal technical contract specifications (01-08)
├── docs/contracts/               # Mirrored authoritative contract documentation
├── data/scans/                   # Persistent JSON scan store
├── frontend/                     # Pure zero-build Cyber SOC HUD dashboard
│   ├── css/style.css
│   ├── js/app.js
│   └── index.html
├── tests/                        # 102 Unit, integration & acceptance test suites
├── run_platform.py               # One-command platform launcher
└── README.md
```
