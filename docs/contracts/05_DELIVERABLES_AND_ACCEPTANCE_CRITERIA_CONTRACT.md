# Contract 05: Deliverables & Acceptance Criteria Contract

**Project Name:** Full-Stack Automated Security Assessment & Vulnerability Management Platform  
**Document Version:** 6.0.0 (In-App Tool Installation & Capabilities Lifecycle Management Architecture Specification)  
**Status:** APPROVED / AUTHORITATIVE SPECIFICATION  
**Scope Authority:** Quality Assurance, Test Automation & Acceptance Sign-Off  

---

## 1. Complete Deliverables Checklist

### 1.1 Backend Architecture (`/backend`)
- [ ] **FastAPI Application (`app/main.py`):** High-performance async server with CORS handling, structured error middleware, repeater router, system capabilities router, tool management router, and static UI file serving.
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
  - [ ] `BaseToolAdapter` (`app/adapters/base_adapter.py`) with 3-tier resolution prioritizing `backend/bin/`
  - [ ] `NmapAdapter`, `SslyzeAdapter`, `NucleiAdapter`, `FfufAdapter`, `NiktoAdapter`, `SemgrepAdapter`, `GitleaksAdapter`, `BanditAdapter`, `TrivyAdapter`, `CheckovAdapter`
- [ ] **Pluggable In-App Tool Installers Engine (`app/installers/`):**
  - [ ] `BaseToolInstaller` (`app/installers/base_installer.py`)
  - [ ] `PipToolInstaller` (`app/installers/pip_installer.py`)
  - [ ] `GithubReleaseInstaller` (`app/installers/github_release_installer.py`)
  - [ ] `SystemToolHelper` (`app/installers/system_installer.py`)
  - [ ] `ToolInstallationManager` (`app/installers/manager.py`)
- [ ] **3 Compliance & Security Exporters:**
  - [ ] Standalone interactive HTML report generator (`app/exporters/html_exporter.py`)
  - [ ] OASIS SARIF v2.1.0 JSON generator (`app/exporters/sarif_exporter.py`)
  - [ ] Full JSON data exporter (`app/exporters/json_exporter.py`)

### 1.2 Frontend Cyber-Security Dark-Theme UI (`/frontend`)
- [ ] **Cyber-Security SOC HUD (`index.html`, `css/style.css`, `js/app.js`):** Responsive dark interface (`#07090e` obsidian theme with neon emerald/cyan/amber/crimson accents).
- [ ] **Target Launcher Bar & Capabilities HUD:** Target input (URL, Domain, IP, File Path, IaC Manifest), profile preset selector, and live tool capability badges for all 10 adapters.
- [ ] **Toolbox & Adapters Manager Modal:** Dedicated management dialog with 1-click "⚡ Install" buttons per tool, "⚡ Install All Missing Tools" master action, and live terminal console with real-time SSE installation logs.
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
- [ ] **Automated Test Suite (`/tests`):** Comprehensive `pytest` test suite with 100% engine check coverage across all 5 engines and 19 acceptance scenarios.
- [ ] **Documentation (`README.md`):** Complete setup, usage, architecture guide, and API documentation.

---

## 2. Rigorous Acceptance Test Scenarios

The platform must pass all 19 acceptance test scenarios deterministically:

1. **Scenario 1: Network & TLS Infrastructure Audit**
2. **Scenario 2: DAST Security Headers, Cookies & Modern Browser Isolation**
3. **Scenario 3: DAST CORS, GraphQL & Sensitive Exposure**
4. **Scenario 4: SAST Secret Detection & Token Masking**
5. **Scenario 5: SAST Insecure Cryptography & Injection Anti-Patterns**
6. **Scenario 6: Container, Kubernetes & Cloud IaC Posture**
7. **Scenario 7: CI/CD Workflow Security**
8. **Scenario 8: Multi-Format Exporters Validation**
9. **Scenario 9: Scoped Web Crawler Link & Form Discovery**
10. **Scenario 10: Authenticated DAST Session & Form Login Scanning**
11. **Scenario 11: Active Parameter Fuzzing & Injection Verification**
12. **Scenario 12: Passive OSINT Subdomain Reconnaissance & Dangling CNAME Takeover**
13. **Scenario 13: Interprocedural AST Taint Flow & Historical Git Secret Scanner**
14. **Scenario 14: Interactive HTTP Repeater & One-Click cURL PoC Generation**
15. **Scenario 15: External Tool Adapter Discovery, Execution & Graceful Fallback**
16. **Scenario 16: Adapters First-in-Line Priority Execution & Native Redundancy Pruning**
17. **Scenario 17: Enterprise Tool Adapter Integrations (Gitleaks, Bandit, Checkov, FFuF, Nikto, SSLyze)**
18. **Scenario 18: In-App Tool Installation Lifecycle for Pip & Standalone Binaries**
    - Verifies automated 1-click installation of Python packages (`PipToolInstaller` for `bandit`/`sslyze`) via `sys.executable -m pip`.
    - Verifies automated 1-click download, ZipSlip validation, unpacking, and binary placement (`GithubReleaseInstaller` for `nuclei`/`ffuf`) into `backend/bin/`, with automatic adapter resolution.
19. **Scenario 19: Batch Tool Installer & Live SSE Event Streaming**
    - Verifies batch installation execution across multiple missing user-space tools with real-time SSE telemetry emission (`install_progress`, `install_log`, `install_completed`) and capability refresh.

---

## 3. Strict Definition of Done (DoD)

A release is marked **DONE** only when:
1. All data structures strictly validate against Contract 02 Pydantic schemas.
2. All 5 engines and 10 adapters catch all exceptions with zero orchestrator crashes.
3. In-App Tool Installers successfully install, verify, and resolve binaries with zero elevation for user-space tools.
4. Scoring math conforms to Contract 02 formulas with zero deviations.
5. Frontend executes cleanly with zero JavaScript console errors.
6. `pytest tests/ -v` passes with 100% success rate across all 19 scenarios.

