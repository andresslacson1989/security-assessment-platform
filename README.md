# CyberAssess - Full-Stack Automated Security Assessment & Vulnerability Management Platform

[![Platform Version](https://img.shields.io/badge/version-3.0.0-06b6d4.svg)](https://github.com/andresslacson1989/security-assessment-platform)
[![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688.svg)](https://fastapi.tiangolo.com/)
[![Tests](https://img.shields.io/badge/tests-54%20passed%20(100%25)-10b981.svg)](https://pytest.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

CyberAssess is a production-grade, non-destructive automated security assessment and vulnerability management platform. Point it at a URL, domain, IP address, container manifest, or local repository, and the engine automatically conducts a comprehensive battery of calculated vulnerability tests, deterministically scores security posture, and streams live telemetry to a Cyber-Security SOC Dark Theme HUD.

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

## 🛡️ 5 Core Assessment Engines

| Engine | Name | Capabilities & Checks |
|---|---|---|
| 🌐 **1** | `network` | **Network Perimeter & TLS/DNS Auditor**: TLS 1.0–1.3 cipher suite checks, X.509 validity/SAN matching, DNS hygiene (SPF, DMARC, CAA, MTA-STS, DNSSEC), and safe non-destructive port scanner. |
| 🛡️ **2** | `web_dast` | **Web Application & REST/GraphQL API DAST**: OWASP response headers (CSP, HSTS, X-Frame-Options, nosniff, COOP/COEP), cookie security flags (`HttpOnly`, `Secure`, `SameSite`), CORS origin reflection, sensitive files (`.env`, `.git/HEAD`, actuator), SRI, and GraphQL introspection. |
| 💻 **3** | `code_sast` | **Static Code Analysis, Secrets & Dependency SCA**: Shannon entropy analysis ($H(X) \ge 4.5$), 40+ high-entropy credential patterns (100% masked in evidence), weak cryptographic algorithms (MD5/SHA-1/DES/ECB), insecure PRNG in auth context, SQLi/Command injection, and vulnerable dependency scanner. |
| 📦 **4** | `infra_iac` | **Infrastructure-as-Code & Container Auditor**: Dockerfile root user & build secret audits, Docker Compose privileged containers & docker.sock mounts, Kubernetes Pod Security Standards (PSS), and Terraform AWS cloud posture. |
| ⚡ **5** | `cicd_audit` | **CI/CD Pipeline & Build Security Auditor**: GitHub Actions workflow supply chain audit, insecure `pull_request_target` checkouts, unpinned third-party action versions, inline script injection via untrusted GitHub contexts, and default `GITHUB_TOKEN` permissions. |

---

## 📊 Deterministic Grading Formula

Platform security grades are computed deterministically per **Contract 02**:

$$S = \max\left(0.0, 100.0 - \left[35 \cdot N_{\text{crit}} + 15 \cdot N_{\text{high}} + 5 \cdot N_{\text{med}} + 1 \cdot N_{\text{low}}\right]\right)$$

### Hard Threshold Gates:
- $N_{\text{crit}} \ge 1 \implies \text{Grade } \mathbf{F}$ (Hard capped regardless of score)
- $N_{\text{high}} \ge 1 \implies \text{Grade capped at } \mathbf{C}$ (Score capped at 79.9)
- Score $\ge 95.0$ and $N_{\text{crit}} = N_{\text{high}} = N_{\text{med}} = N_{\text{low}} = 0 \implies \mathbf{A^+}$
- $90.0 \le S < 95.0 \implies \mathbf{A}$
- $80.0 \le S < 90.0 \implies \mathbf{B}$
- $70.0 \le S < 80.0 \implies \mathbf{C}$
- $60.0 \le S < 70.0 \implies \mathbf{D}$
- $S < 60.0 \implies \mathbf{F}$

---

## 📡 REST API & Real-Time SSE Streaming

### System Endpoints
- `GET /api/system/health`: System health status, API version 3.0.0, scan count.
- `GET /api/system/engines`: Registered assessment engines metadata & supported target types.

### Scan Management
- `POST /api/scans/start`: Launch automated security scan on target.
- `GET /api/scans/{scan_id}`: Detailed snapshot with progress, findings, logs, and score.
- `POST /api/scans/{scan_id}/cancel`: Gracefully abort active scan execution.
- `GET /api/scans/history`: Paginated history of past scans.
- `DELETE /api/scans/{scan_id}`: Delete scan record from storage.
- `GET /api/scans/{scan_id}/events`: **Server-Sent Events (SSE)** real-time stream (`progress`, `log`, `finding`, `completed`, `error`).

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
- **54 Passed Tests (100% Pass Rate)**
- Full verification of all 8 Contract 05 acceptance scenarios.
- Engine plugin isolation and error resilience tests.
- Token-bucket rate limiting (1–20 RPS) and circuit breaker tests.
- 100% secret evidence masking (`mask_secret()`) guarantee tests.
- SARIF v2.1.0 schema compliance and zero-CDN HTML export tests.

---

## 📂 Project Architecture

```
security-assessment-platform/
├── backend/
│   ├── app/
│   │   ├── api/                  # REST & SSE route handlers
│   │   │   ├── system.py
│   │   │   ├── scans.py
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
├── data/scans/                   # Persistent JSON scan store
├── frontend/                     # Pure zero-build Cyber SOC HUD dashboard
│   ├── css/style.css
│   ├── js/app.js
│   └── index.html
├── tests/                        # 54 Unit, integration & acceptance test suites
├── run_platform.py               # One-command platform launcher
└── README.md
```
