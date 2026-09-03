# CyberAssess - Enterprise Automated Security Assessment & Vulnerability Management Platform

[![Platform Version](https://img.shields.io/badge/version-14.3.0-06b6d4.svg)](https://github.com/andresslacson1989/security-assessment-platform)
[![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688.svg)](https://fastapi.tiangolo.com/)
[![Standards](https://img.shields.io/badge/standards-ASVS%20v5.0.0%20%7C%20NIST%20SSDF%20v1.1%20%7C%20NIST%20800--53-purple.svg)](https://github.com/andresslacson1989/security-assessment-platform)
[![License](https://img.shields.io/badge/license-Proprietary%20Personal--Use-red.svg)](LICENSE)

CyberAssess is an enterprise-grade automated security assessment and vulnerability management platform conforming to **OWASP ASVS v5.0.0**, **NIST SP 800-218 SSDF v1.1**, and **NIST SP 800-53 Rev 5**. It orchestrates a fleet of 26 curated security tools across 5 modular engines, provides deterministic vulnerability grading, maintains cryptographic audit logs, and streams live telemetry to an interactive SOC HUD dashboard.

---

## 🏛️ Operating Modes & Architecture

CyberAssess operates under two distinct deployment profiles:

### 1. Standalone Profile (Local / Single-Process)
- **Persistence**: ACID relational persistence using local SQLite.
- **Dispatch**: In-process asynchronous task execution.
- **Target Use**: Rapid local assessments, CI/CD runners, and developer workstations.
- **Launcher**: `python run_platform.py`

### 2. Enterprise Profile (Containerized / Segmented Multi-Service)
- **Persistence**: Enterprise PostgreSQL 16 on an internal-only data plane network.
- **Queue / Dispatch**: Redis 7 Streams with decoupled background workers (`cyberassess-worker`).
- **Network Segmentation**:
  - `control-plane`: API gateway and HUD server.
  - `data-plane`: Dedicated internal network (`internal: true`) for database and queue; no published host ports.
  - `execution-egress`: Outbound tool execution network isolated from internal persistence.
- **Launcher**: `docker compose --profile enterprise up -d`

---

## 🛡️ 5 Core Assessment Engines & 26-Tool Fleet

| Engine | Name | Capabilities & Scope | Integrated Tool Fleet |
|---|---|---|---|
| 🌐 **1** | `network` | **Perimeter, Port & TLS Assessment**: TCP port discovery, service banner extraction, TLS protocol & cipher analysis, passive certificate transparency recon, and DNS hygiene verification. | **Nmap** (Port scanner), **SSLyze** (TLS analyzer), **Subfinder** (Passive CT), **Amass** (EASM), **httpx** (HTTP probe) |
| 🛡️ **2** | `web_dast` | **Web Application & REST/GraphQL API DAST**: OWASP security headers, cookie attributes, CORS evaluation, sensitive file detection, parameter fuzzing, and contract fuzzing. | **Nuclei** (CVE templates), **FFuF** (Fuzzing), **Katana** (DOM crawler), **Schemathesis** (API contract DAST), **sqlmap** (Auxiliary) |
| 💻 **3** | `code_sast` | **Static Analysis, Secrets & Dependency SCA**: AST vulnerability patterns, high-entropy secret detection, Git history scanning, software bill of materials (SBOM), and CVE matching. | **Semgrep** (AST SAST), **Bandit** (Python AST), **Gitleaks** (Secret SAST), **TruffleHog** (Secret validator), **Syft** (SBOM), **Grype** (SCA), **OSV-Scanner** (OSV lookups), **Retire.js** (JS dependencies) |
| 📦 **4** | `infra_iac` | **Infrastructure-as-Code & Container Security**: Dockerfile and Compose posture, Kubernetes Pod Security Standards (PSS), CIS benchmarks, and Terraform scanning. | **Checkov** (IaC SAST), **Trivy** (Container & SCA), **Dockle** (Image linter), **Kube-Bench** (K8s CIS), **Prowler** (Cloud CIS) |
| ⚡ **5** | `cicd_audit` | **CI/CD Pipeline & Build Security Auditor**: GitHub Actions workflow analysis, insecure trigger checkouts (`pull_request_target`), unpinned actions, and token permission checks. | *Native Core Engine*, **Metasploit** (Auxiliary), **Hydra** (Auxiliary), **GTFOBins** (Native reference) |

*Note: Tool execution follows strict graceful degradation. When external binaries are absent or incompatible, the platform records truthful execution states (`NOT_EXECUTED_PREREQUISITE_MISSING`) without crashing or producing synthetic results.*

---

## 🔒 Security Invariants & Governance

CyberAssess enforces strict architectural security invariants:

1. **Deterministic Scope Authority**:
   - Authentication via RFC 8725 JWTs strictly bound to `HS256`.
   - Wildcard permissions (`*`) are restricted exclusively to system administrators (`PrincipalType.SYSTEM_PRINCIPAL`). Tenant administrators and users receive only explicit functional scopes.
   - API keys are cryptographically hashed (SHA-256) and cannot exceed the grantor's active permissions.

2. **8-State Network Classification & SSRF Protection**:
   - Network classification: `PUBLIC`, `PRIVATE`, `LOOPBACK`, `LINK_LOCAL`, `METADATA`, `MULTICAST`, `UNSPECIFIED`, `RESERVED`.
   - Loopback (`127.0.0.0/8`, `localhost`) and Cloud Metadata (`169.254.169.254`, `168.63.129.16`) are unconditionally blocked for all users.
   - Private subnets (RFC 1918 / RFC 4193) are blocked by default and permitted only when the caller possesses explicit `scan:internal` scope.
   - Target hostnames are pre-resolved and DNS rebinding protections verify all IP addresses before connection.

3. **Process Ownership & Cancellation Isolation**:
   - Subprocesses are tracked by unique `execution_id` and spawned in dedicated process groups.
   - Cancellation targets strictly the specific execution's process tree; the supervisor protects itself (`PID`), its parent (`PPID`), init (`PID 1`), and concurrent sibling scans from cross-cancellation.

4. **Evidence Truthfulness & No False Assurance**:
   - Missing, failed, or timed-out tool executions report authentic degraded states (`NOT_EXECUTED_PREREQUISITE_MISSING`, `FAILED_NON_ZERO_EXIT`, `FAILED_TIMEOUT`).
   - The platform never synthesizes `SAFE` results, dummy findings, or fake TLS evidence when checks did not run.

5. **Subprocess Environment Sanitization & Egress Governance**:
   - Subprocesses receive an explicitly curated environment containing only safe system keys (`PATH`, `SYSTEMROOT`, `LANG`, etc.).
   - Platform secrets (`JWT_SECRET`, `DATABASE_URL`, `REDIS_URL`, API keys) are strictly excluded from tool environments.
   - `SCANNER_EGRESS_PROXY` governs outbound tool proxy routing; ambient host proxies are purged.

---

## ⚡ Quickstart

### Prerequisites
- Python 3.11, 3.12, or 3.13
- Optional: Docker & Docker Compose for enterprise multi-service deployment

### 1. Standalone Local Setup
```bash
# Clone repository
git clone https://github.com/andresslacson1989/security-assessment-platform.git
cd security-assessment-platform

# Install dependencies
pip install -r backend/requirements.txt

# Run test suite
pytest tests/ -v

# Launch local platform
python run_platform.py
```
*Access the SOC Dark Theme Dashboard at `http://127.0.0.1:8000`.*

### 2. Enterprise Docker Deployment
```bash
# Set required secrets
export JWT_SECRET="your-32-char-min-production-secret-here"
export POSTGRES_PASSWORD="secure-postgres-password"
export DATABASE_URL="postgresql://cyberassess:${POSTGRES_PASSWORD}@postgres:5432/cyberassess"
export EXECUTION_QUEUE_URL="redis://redis:6379/0"
export CLOUD_CREDENTIALS_ENCRYPTION_KEY="$(openssl rand -base64 32)"

# Launch enterprise fleet
docker compose --profile enterprise up -d
```

---

## 📊 Deterministic Grading Formula

Platform security posture grades are computed deterministically per **Contract 02**:

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

## 🧪 Comprehensive Test Suites

Run the full adversarial security matrix, engine tests, and invariant validation:
```bash
pytest tests/ -v
```

Key Test Suites:
- `tests/security/test_adversarial_sec_matrix.py`: 30+ adversarial security invariants (SEC-001 through SEC-030).
- `tests/test_e13_auth_scope_closure.py`: JWT algorithm binding and least-privilege scope boundaries.
- `tests/test_e13_ssrf_closure.py`: 8-state network classification and pre-resolution SSRF protection.
- `tests/test_e13_process_isolation.py`: PID tracking and cancellation isolation.
- `tests/test_e13_evidence_truthfulness.py`: Honest execution states and absence of synthetic SAFE claims.
- `tests/test_e13_repeater_hardening.py`: Bounded streaming, binary handling, and authentic TLS evidence.
- `tests/test_e13_egress_env_sanitization.py`: Subprocess secret stripping and proxy propagation.
- `tests/test_e13_supply_chain_integrity.py`: Cryptographic hash verification and graceful tool degradation.
- `tests/test_e13_platform_hardening.py`: Security headers, rate limiting, and password hashing security.

---

## 📄 License

CyberAssess is proprietary software. The [CyberAssess Proprietary Personal-Use License](LICENSE) grants only one individual acting privately and solely for that person's own purposes a limited permission to run, study, and privately modify the software. Commercial use, organizational use, SaaS, and scanning services require a separate written license signed by the copyright owner.
