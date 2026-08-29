# Contract 05: Deliverables & Acceptance Criteria Contract

**Project Name:** Full-Stack Automated Security Assessment & Vulnerability Management Platform  
**Document Version:** 5.0.0 (Enterprise Adapters First-in-Line & Penetration Testing Architecture Specification)  
**Status:** APPROVED / AUTHORITATIVE SPECIFICATION  
**Scope Authority:** Quality Assurance, Test Automation & Acceptance Sign-Off  

---

## 1. Complete Deliverables Checklist

### 1.1 Backend Architecture (`/backend`)
- [ ] **FastAPI Application (`app/main.py`):** High-performance async server with CORS handling, structured error middleware, repeater router, system capabilities router, and static UI file serving.
- [ ] **Async Orchestrator (`app/core/orchestrator.py`):** Background scan manager with concurrent engine execution, token bucket rate limiter, task cancellation, and SSE event streaming.
- [ ] **Data & Storage Layer (`app/core/models.py`, `app/core/storage.py`):** Strict Pydantic v2 schemas and local JSON persistence in `data/scans/`.
- [ ] **Deterministic Grading Engine (`app/core/grading.py`):** Exact mathematical calculation of 0-100 scores and `A+` to `F` letter grades.
- [ ] **5 Modular Assessment Engines:**
  - [ ] `network` (`tls_auditor.py`, `dns_hygiene.py`, `port_checker.py`, `banner_grabber.py`, `subdomain_recon.py`)
  - [ ] `web_dast` (`headers_cookies.py`, `cors_analyzer.py`, `api_inspector.py`, `browser_posture.py`, `graphql_auditor.py`, `crawler.py`, `auth_session.py`, `parameter_fuzzer.py`)
  - [ ] `code_sast` (`secret_scanner.py`, `crypto_lint.py`, `injection_lint.py`, `dependency_auditor.py`, `ast_taint_analyzer.py`, `git_history_scanner.py`)
  - [ ] `infra_iac` (`dockerfile_auditor.py`, `compose_auditor.py`, `k8s_manifest_auditor.py`, `terraform_auditor.py`)
  - [ ] `cicd_audit` (`github_actions_auditor.py`)
- [ ] **10 Pluggable Hybrid Tool Adapters (`app/adapters/`):**
  - [ ] `BaseToolAdapter` (`app/adapters/base_adapter.py`)
  - [ ] `NmapAdapter` (`app/adapters/nmap_adapter.py`)
  - [ ] `SslyzeAdapter` (`app/adapters/sslyze_adapter.py`)
  - [ ] `NucleiAdapter` (`app/adapters/nuclei_adapter.py`)
  - [ ] `FfufAdapter` (`app/adapters/ffuf_adapter.py`)
  - [ ] `NiktoAdapter` (`app/adapters/nikto_adapter.py`)
  - [ ] `SemgrepAdapter` (`app/adapters/semgrep_adapter.py`)
  - [ ] `GitleaksAdapter` (`app/adapters/gitleaks_adapter.py`)
  - [ ] `BanditAdapter` (`app/adapters/bandit_adapter.py`)
  - [ ] `TrivyAdapter` (`app/adapters/trivy_adapter.py`)
  - [ ] `CheckovAdapter` (`app/adapters/checkov_adapter.py`)
- [ ] **3 Compliance & Security Exporters:**
  - [ ] Standalone interactive HTML report generator (`app/exporters/html_exporter.py`)
  - [ ] OASIS SARIF v2.1.0 JSON generator (`app/exporters/sarif_exporter.py`)
  - [ ] Full JSON data exporter (`app/exporters/json_exporter.py`)

### 1.2 Frontend Cyber-Security Dark-Theme UI (`/frontend`)
- [ ] **Cyber-Security SOC HUD (`index.html`, `css/style.css`, `js/app.js`):** Responsive dark interface (`#07090e` obsidian theme with neon emerald/cyan/amber/crimson accents).
- [ ] **Target Launcher Bar & Capabilities HUD:** Target input (URL, Domain, IP, File Path, IaC Manifest), profile preset selector, and live tool capability badges for all 10 adapters (`Nmap`, `SSLyze`, `Nuclei`, `FFuF`, `Nikto`, `Semgrep`, `Gitleaks`, `Bandit`, `Trivy`, `Checkov`).
- [ ] **Configuration Drawers:** Collapsible controls for Auth Mode, Crawl Limits, Active Parameter Fuzzing toggles, OSINT Recon options, and Tool Adapter switches.
- [ ] **Live Telemetry & Monospace Terminal:** Real-time animated progress bar, active stage indicator, tool status notifications, and auto-scrolling terminal log stream.
- [ ] **Security Scorecard Widget:** High-impact letter grade badge (`A+` to `F`), CVSS 0-100 score gauge, active tool badges, and severity counters.
- [ ] **Attack Surface Reconnaissance Tables:** Real-time tables displaying crawled endpoints and OSINT discovered subdomains with CNAME takeover risk indicators.
- [ ] **Interactive Vulnerability Explorer:** Filter tabs, live search, category chips, expandable cards with CVSS badges, `source_tool` tags, CWE tags, observed evidence diffs, copyable reproduction cURL PoC buttons, and remediation code blocks.
- [ ] **Interactive HTTP Repeater Tab:** Pentester workbench for crafting and testing raw HTTP requests with live response preview, header inspection, and latency metrics.
- [ ] **One-Click Export Toolbar:** Direct download buttons for Standalone HTML, SARIF v2.1.0, and JSON reports.
- [ ] **Historical Scan Archive Drawer:** Sidebar/table listing past scans with timestamps, targets, grades, and instant reload.

### 1.3 Developer & Ops Utilities
- [ ] **One-Command Platform Runner (`run_platform.py`):** Single Python script that verifies dependencies, discovers tools, boots uvicorn, and automatically opens the dashboard in the default browser.
- [ ] **Automated Test Suite (`/tests`):** Comprehensive `pytest` test suite with 100% engine check coverage across all 5 engines and 17 acceptance scenarios.
- [ ] **Documentation (`README.md`):** Complete setup, usage, architecture guide, and API documentation.

---

## 2. Rigorous Acceptance Test Scenarios

The platform must pass all 17 acceptance test scenarios deterministically:

1. **Scenario 1: Network & TLS Infrastructure Audit**
   - Given a mock or live HTTPS target, accurately detects certificate expiration dates, deprecated TLS 1.0/1.1 protocols, weak ciphers, and queries SPF, DMARC, MTA-STS, and DNSSEC records.
2. **Scenario 2: DAST Security Headers, Cookies & Modern Browser Isolation**
   - Flags missing CSP, HSTS, X-Frame-Options, missing `HttpOnly`/`Secure`/`SameSite` cookie attributes, and missing Subresource Integrity (SRI) on external scripts.
3. **Scenario 3: DAST CORS, GraphQL & Sensitive Exposure**
   - Detects origin reflection with credentials (`Origin: https://evil.com`), public GraphQL introspection (`__schema`), and public `.env` / `/.git/HEAD` files.
4. **Scenario 4: SAST Secret Detection & Token Masking**
   - Detects AWS keys, GitHub PATs, Stripe keys, and private RSA keys in sample repository files, **guaranteeing 100% masking of secret values in evidence output**.
5. **Scenario 5: SAST Insecure Cryptography & Injection Anti-Patterns**
   - Flags usage of MD5/SHA1, non-cryptographic PRNG in tokens, and raw SQL/shell formatting in source code.
6. **Scenario 6: Container, Kubernetes & Cloud IaC Posture**
   - Flags Dockerfile running as root, missing healthcheck, Docker Compose socket mount (`/var/run/docker.sock`), Kubernetes privileged pods, and Terraform open S3 buckets.
7. **Scenario 7: CI/CD Workflow Security**
   - Detects `pull_request_target` with untrusted checkouts and unpinned Actions in GitHub workflow files.
8. **Scenario 8: Multi-Format Exporters Validation**
   - Standalone HTML report renders offline with embedded styling and interactive drawers; SARIF export validates 100% against official OASIS SARIF v2.1.0 schema.
9. **Scenario 9: Scoped Web Crawler Link & Form Discovery**
   - Verifies BFS depth traversal ($D \le 3$), same-origin boundary enforcement, max page cap ($N \le 50$), sitemap/robots parsing, URL canonicalization, loop prevention, and form registration.
10. **Scenario 10: Authenticated DAST Session & Form Login Scanning**
    - Verifies automated form login, anti-CSRF token extraction (`csrf_token`, `_csrf`, etc.), session cookie preservation, logout path blacklisting, session heartbeat re-authentication, and unauthenticated vs authenticated access control differential checks (`DAST-AUTH-001` to `004`, `DAST-FORM-001` to `002`).
11. **Scenario 11: Active Parameter Fuzzing & Injection Verification**
    - Injects safe time-based SQLi probes (`SLEEP(2)`), canary reflected XSS tokens (`_CYBERASSESS_XSS_<hex>_`), path traversal (`../../../../etc/passwd`), and template injection (`{{7*7}}`), verifying findings `DAST-INJ-001`, `DAST-XSS-001`, `DAST-LFI-001`, `DAST-SSTI-001`, and `DAST-REDIR-001` with copy-pasteable `reproduction_curl` commands.
12. **Scenario 12: Passive OSINT Subdomain Reconnaissance & Dangling CNAME Takeover**
    - Queries crt.sh API, resolves subdomains, detects dangling CNAME records (`.s3.amazonaws.com`, `.github.io`), generates `NET-OSINT-001`, and inspects service banners for `NET-SVC-001`.
13. **Scenario 13: Interprocedural AST Taint Flow & Historical Git Secret Scanner**
    - Performs AST dataflow tracking from untrusted inputs to database/system execution sinks (`SAST-TAINT-001`, `SAST-TAINT-002`) and searches `git log` commit history for leaked secrets (`SAST-GIT-001`).
14. **Scenario 14: Interactive HTTP Repeater & One-Click cURL PoC Generation**
    - Executes custom requests via `POST /api/tools/repeater` returning latency and status, and confirms all web findings include valid `reproduction_curl` fields.
15. **Scenario 15: External Tool Adapter Discovery, Execution & Graceful Fallback**
    - Verifies discovery and invocation of `NmapAdapter`, `NucleiAdapter`, `SemgrepAdapter`, and `TrivyAdapter` with stdout/XML/JSON normalization into canonical `Finding` objects (`source_tool`).
    - Verifies 100% graceful fallback to native Python engines when binaries are absent, with zero unhandled exceptions or scan failures.
16. **Scenario 16: Adapters First-in-Line Priority Execution & Native Redundancy Pruning**
    - Asserts that when external adapters are active, they execute first as the primary assessment driver, establish the baseline findings, and suppress duplicate basic native port/linter runs while allowing native enrichments (AST Taint, CT OSINT, DNS) to proceed.
17. **Scenario 17: Enterprise Tool Adapter Integrations (Gitleaks, Bandit, Checkov, FFuF, Nikto, SSLyze)**
    - Verifies command construction, non-destructive execution flags, output parsing, and error isolation for `GitleaksAdapter`, `BanditAdapter`, `CheckovAdapter`, `FfufAdapter`, `NiktoAdapter`, and `SslyzeAdapter` with source tagging.

---

## 3. Strict Definition of Done (DoD)

A release is marked **DONE** only when:
1. All data structures strictly validate against Contract 02 Pydantic schemas.
2. All 5 engines and 10 adapters catch all exceptions with zero orchestrator crashes.
3. Scoring math conforms to Contract 02 formulas with zero deviations.
4. Frontend executes cleanly with zero JavaScript console errors.
5. `pytest tests/ -v` passes with 100% success rate across all 17 scenarios.

