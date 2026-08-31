# Contract 04: REST API, OpenAPI & Real-Time Streaming Events Contract

**Project Name:** Full-Stack Automated Security Assessment & Vulnerability Management Platform  
**Document Version:** 8.0.0 (Enterprise ASPM & EASM Suite, 22-Tool Parity, Software Supply Chain & CIS Benchmarks Architecture Specification)  
**Status:** APPROVED / AUTHORITATIVE SPECIFICATION  
**Scope Authority:** REST API Endpoints, OpenAPI 3.1 Schemas & SSE Streaming Protocol  

---

## 1. REST API Specification (FastAPI / OpenAPI 3.1)

Base URL: `http://localhost:8000/api`  
Content-Type: `application/json; charset=utf-8`

---

### 1.1 System & Discovery Endpoints

#### `GET /api/system/health`
- **Response (200 OK):**
```json
{
  "status": "HEALTHY",
  "version": "8.0.0",
  "timestamp": "2026-08-30T04:45:00Z",
  "uptime_seconds": 18450.2,
  "storage": {
    "status": "OK",
    "scans_stored": 58,
    "path": "data/scans"
  }
}
```

#### `GET /api/system/capabilities`
Returns host tool discovery status, binary paths, versions, and execution modes for all 22 enterprise adapters.
- **Response (200 OK):**
```json
{
  "tools": [
    {
      "name": "nmap",
      "available": true,
      "version": "Nmap 7.94",
      "path": "/usr/bin/nmap",
      "execution_mode": "ADAPTER_ACTIVE"
    },
    {
      "name": "sslyze",
      "available": true,
      "version": "5.2.0",
      "path": "/usr/local/bin/sslyze",
      "execution_mode": "ADAPTER_ACTIVE"
    },
    {
      "name": "nuclei",
      "available": true,
      "version": "nuclei v3.2.0",
      "path": "/usr/local/bin/nuclei",
      "execution_mode": "ADAPTER_ACTIVE"
    },
    {
      "name": "ffuf",
      "available": true,
      "version": "2.1.0",
      "path": "/usr/bin/ffuf",
      "execution_mode": "ADAPTER_ACTIVE"
    },
    {
      "name": "semgrep",
      "available": true,
      "version": "1.60.0",
      "path": "/usr/local/bin/semgrep",
      "execution_mode": "ADAPTER_ACTIVE"
    },
    {
      "name": "gitleaks",
      "available": true,
      "version": "8.18.2",
      "path": "/usr/local/bin/gitleaks",
      "execution_mode": "ADAPTER_ACTIVE"
    },
    {
      "name": "bandit",
      "available": true,
      "version": "1.7.8",
      "path": "/usr/local/bin/bandit",
      "execution_mode": "ADAPTER_ACTIVE"
    },
    {
      "name": "trivy",
      "available": true,
      "version": "0.50.1",
      "path": "/usr/local/bin/trivy",
      "execution_mode": "ADAPTER_ACTIVE"
    },
    {
      "name": "checkov",
      "available": false,
      "version": null,
      "path": null,
      "execution_mode": "NATIVE_FALLBACK"
    }
  ],
  "native_engines_ready": true,
  "os_platform": "Windows 11 / Linux x86_64"
}
```
  "os_platform": "Windows 11 / Linux x86_64"
}
```

#### `GET /api/system/engines`
- **Response (200 OK):**
```json
{
  "engines": [
    {
      "name": "network",
      "display_name": "Network, TLS & OSINT Auditor",
      "description": "Evaluates SSL/TLS certificates, deprecated protocols, cipher suites, DNS hygiene (SPF/DMARC/MTA-STS/DNSSEC), passive OSINT certificate transparency subdomains, exposed service ports, and integrates Nmap.",
      "supported_targets": ["URL", "DOMAIN", "IP"]
    },
    {
      "name": "web_dast",
      "display_name": "Web Application, Browser & API DAST",
      "description": "Audits OWASP security headers, cookie flags, CORS policies, modern browser isolation (COOP/COEP/SRI), active benign parameter fuzzing (SQLi, XSS, LFI, SSTI, Open Redirect), GraphQL introspection, and integrates Nuclei.",
      "supported_targets": ["URL", "DOMAIN"]
    },
    {
      "name": "code_sast",
      "display_name": "Static Code Analysis, Secrets & AST Taint",
      "description": "Scans local repositories for 40+ high-entropy secret patterns, git commit history secret leakage, AST interprocedural taint flow analysis (SQLi, Command Injection), weak cryptography/PRNG, and integrates Semgrep/Trivy.",
      "supported_targets": ["LOCAL_PATH"]
    },
    {
      "name": "infra_iac",
      "display_name": "Infrastructure-as-Code & Container Security",
      "description": "Audits Dockerfiles, Docker Compose, Kubernetes manifests, and Terraform templates for misconfigurations, root user execution, and open cloud storage.",
      "supported_targets": ["DOCKERFILE", "IAC_MANIFEST", "LOCAL_PATH"]
    },
    {
      "name": "cicd_audit",
      "display_name": "CI/CD Pipeline & Workflow Auditor",
      "description": "Scans GitHub Actions workflows for dangerous triggers (pull_request_target), unpinned actions, and script injection.",
      "supported_targets": ["LOCAL_PATH"]
    }
  ]
}
```

---

### 1.2 Scan Lifecycle Management Endpoints

#### `POST /api/scans/start`
- **Request Body (`application/json`):**
```json
{
  "target_type": "URL",
  "target_value": "https://example.com",
  "target_name": "Production Portal",
  "profile": "FULL_STACK",
  "enabled_engines": ["network", "web_dast", "infra_iac"],
  "config": {
    "rate_limit_rps": 5,
    "timeout_seconds": 10,
    "custom_headers": {
      "User-Agent": "CyberAssessBot/4.1"
    },
    "crawler": {
      "enabled": true,
      "max_depth": 3,
      "max_pages": 50,
      "exclude_patterns": ["*logout*", "*signout*", "*delete*"]
    },
    "auth": {
      "auth_type": "FORM_LOGIN",
      "login_url": "https://example.com/login",
      "username_field": "email",
      "username": "auditor@example.com",
      "password_field": "password",
      "password": "SecretPassword123!",
      "logged_in_indicator": "Sign Out"
    },
    "fuzzing": {
      "enabled": true,
      "fuzz_query_params": true,
      "fuzz_body_params": true,
      "fuzz_sqli": true,
      "fuzz_xss": true,
      "fuzz_lfi": true,
      "fuzz_ssti": true,
      "fuzz_redirect": true,
      "delay_seconds": 2.0
    },
    "osint": {
      "subdomain_enumeration": true,
      "subdomain_takeover_check": true,
      "crtsh_timeout_seconds": 10.0
    },
    "adapters": {
      "enable_nmap": true,
      "enable_nuclei": true,
      "enable_semgrep": true,
      "enable_trivy": true
    }
  }
}
```
- **Response (201 Created):**
```json
{
  "scan_id": "c4b3f8e2-9d3a-4a61-9c88-123456789abc",
  "status": "RUNNING",
  "message": "Scan job successfully queued and launched."
}
```

---

#### `GET /api/scans/{scan_id}`
Returns complete scan snapshot including `discovered_endpoints`, `discovered_subdomains`, `findings` (with `source_tool`, `reproduction_curl`, and `taint_trace`), and `logs`.

---

#### `POST /api/scans/{scan_id}/cancel`
Aborts an active scan.

---

#### `GET /api/scans/history`
Returns paginated list of historical scan summaries.

---

#### `DELETE /api/scans/{scan_id}`
Deletes scan record from disk.

---

### 1.3 Compliance & Export Endpoints

#### `GET /api/scans/{scan_id}/export/html`
- **Output:** Standalone single-file HTML report with interactive styling, severity filters, and cURL PoC copy buttons.

#### `GET /api/scans/{scan_id}/export/sarif`
- **Output:** Standard OASIS SARIF v2.1.0 JSON format for GitHub Code Scanning integration.

#### `GET /api/scans/{scan_id}/export/json`
- **Output:** Complete JSON dump conforming to the `ScanJob` schema.

#### `GET /api/scans/{scan_id}/export/sbom/cyclonedx`
- **Output:** Standard CycloneDX 1.5 JSON Software Bill of Materials containing all inventory packages, versions, licenses, and hashes (`application/vnd.cyclonedx+json`).

#### `GET /api/scans/{scan_id}/export/sbom/spdx`
- **Output:** Standard SPDX 2.3 JSON Software Bill of Materials (`application/spdx+json`).

---

### 1.4 Pentester Productivity Endpoints

#### `POST /api/tools/repeater`
Allows manual crafting, replay, and differential inspection of HTTP requests directly from the dashboard.
- **Request Body (`application/json`):**
```json
{
  "url": "https://example.com/api/v1/user?id=1",
  "method": "GET",
  "headers": {
    "Authorization": "Bearer sample_token",
    "User-Agent": "CyberAssess-Repeater/4.1"
  },
  "body": null,
  "follow_redirects": false,
  "timeout_seconds": 10.0
}
```
- **Response (200 OK):**
```json
{
  "status_code": 200,
  "headers": {
    "content-type": "application/json",
    "server": "nginx/1.18.0"
  },
  "body": "{\"id\": 1, \"name\": \"Admin\"}",
  "duration_ms": 142.5,
  "content_length": 27,
  "tls_version": "TLSv1.3",
  "cipher": "TLS_AES_256_GCM_SHA384"
}
```

---

### 1.5 In-App Tool Management & Installation Endpoints

#### `GET /api/system/tools`
Returns comprehensive installation status, versions, and installation metadata for all 10 tools.
- **Response (200 OK):**
```json
[
  {
    "name": "nuclei",
    "display_name": "Nuclei Vulnerability Scanner",
    "category": "Web DAST",
    "install_method": "STANDALONE_BINARY",
    "status": "NOT_INSTALLED",
    "version": null,
    "path": null,
    "is_elevated_required": false,
    "install_command_hint": "In-app automated 1-click install (or: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest)",
    "download_url": "https://github.com/projectdiscovery/nuclei/releases",
    "error_message": null,
    "progress_percent": 0
  },
  {
    "name": "sslyze",
    "display_name": "SSLyze TLS/SSL Auditor",
    "category": "Network / TLS",
    "install_method": "PIP",
    "status": "INSTALLED",
    "version": "5.2.0",
    "path": "/usr/local/bin/sslyze",
    "is_elevated_required": false,
    "install_command_hint": "pip install sslyze",
    "download_url": "https://pypi.org/project/sslyze/",
    "error_message": null,
    "progress_percent": 100
  }
]
```

#### `POST /api/system/tools/{tool_name}/install`
Asynchronously triggers in-app installation for a specific tool.
- **Request Body (`application/json`):**
```json
{
  "force": false
}
```
- **Response (202 Accepted):**
```json
{
  "task_id": "tool-inst-9a8b7c6d",
  "tool_name": "nuclei",
  "status": "INSTALLING",
  "message": "Initiated automated download and extraction of Nuclei to backend/bin/"
}
```

#### `POST /api/system/tools/install-all`
Asynchronously batch installs all missing user-space tools (`sslyze`, `bandit`, `semgrep`, `checkov`, `nuclei`, `ffuf`, `gitleaks`, `trivy`).
- **Response (202 Accepted):**
```json
[
  {
    "task_id": "tool-inst-1",
    "tool_name": "nuclei",
    "status": "INSTALLING",
    "message": "Queued for installation"
  }
]
```

#### `GET /api/system/tools/{tool_name}/status`
Returns real-time status and installation progress for a single tool.

---

## 2. Real-Time Streaming Event Contract (SSE)

### 2.1 Scan Execution Stream (`GET /api/scans/{scan_id}/events`)
Protocol: **Server-Sent Events (SSE)** (`text/event-stream; charset=utf-8`)

Event Types emitted:
1. `event: tool_status` — Data: `{"tool": "nmap", "available": true, "version": "7.94", "execution_mode": "ADAPTER_ACTIVE"}`
2. `event: progress` — Data: `{"percent": 45, "stage": "...", "status": "RUNNING"}`
3. `event: log` — Data: `{"timestamp": "...", "level": "INFO", "engine": "network", "message": "..."}`
4. `event: auth_status` — Data: `{"auth_type": "FORM_LOGIN", "authenticated": true, "session_active": true, "message": "Successfully authenticated."}`
5. `event: crawl_discovered` — Data: `{"url": "https://example.com/dashboard", "depth": 1, "status_code": 200, "is_authenticated": true, "total_discovered": 12}`
6. `event: subdomain_discovered` — Data: `{"domain": "api.example.com", "ip_addresses": ["93.184.216.34"], "cname_targets": ["api.example.com.cdn.cloudflare.net"], "is_takeover_vulnerable": false, "service_fingerprint": "Cloudflare", "total_subdomains": 5}`
7. `event: finding` — Data: `{ Finding Object }` (emitted immediately on identification with `source_tool` and `reproduction_curl` when available)
8. `event: completed` — Data: `{"scan_id": "...", "status": "COMPLETED", "overall_security_grade": "C", "weighted_score": 76.0, "total_findings": 10, "active_adapters": ["nmap", "semgrep"], "completed_at": "..."}`
9. `event: error` — Data: `{"message": "Scan failed: Target host unreachable."}`

---

## 3. Zero-Trust Authentication, Asset Management & Vulnerability Triage Endpoints

### 3.1 Authentication & API Key Endpoints (`/api/auth`)

#### `POST /api/auth/login`
Authenticates a user and issues a signed JWT Bearer token.
- **Request Body (`application/json`):**
```json
{
  "username": "admin",
  "password": "CorrectPassword123!"
}
```
- **Response (200 OK):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 86400,
  "user": {
    "id": "u-1234",
    "username": "admin",
    "email": "admin@example.com",
    "role": "ADMIN"
  }
}
```

#### `POST /api/auth/register`
Registers a new user (Restricted to `ADMIN` in production, open for initial setup).

#### `GET /api/auth/me`
Returns current authenticated user profile and permissions.

#### `POST /api/auth/api-keys`
Generates a new programmatic API Key with scoped role permissions.

---

### 3.2 Continuous Asset Inventory Endpoints (`/api/assets`)

#### `GET /api/assets`
Returns paginated list of monitored organization assets with posture statistics.

#### `POST /api/assets`
Registers a new asset (Web App, Domain, Repository, Cloud Account) into continuous inventory.
- **Request Body (`application/json`):**
```json
{
  "name": "Customer Portal",
  "type": "WEB_APPLICATION",
  "target_value": "https://portal.example.com",
  "criticality": "HIGH",
  "internet_exposed": true,
  "tags": ["production", "pci-dss"]
}
```

#### `GET /api/assets/{asset_id}`
Retrieves asset details, posture trend, active SLA breaches, and historical findings.

---

### 3.3 Vulnerability Lifecycle & Triage Endpoints (`/api/findings`)

#### `GET /api/findings`
Unified finding explorer with multi-scanner correlation filtering.
- Query Parameters: `asset_id`, `severity`, `status` (`OPEN`, `FIXED`, `RISK_ACCEPTED`), `cwe_id`, `search`.

#### `PATCH /api/findings/{finding_id}/status`
Updates finding lifecycle state and logs triage action in audit trail.
- **Request Body (`application/json`):**
```json
{
  "status": "IN_PROGRESS",
  "assigned_to": "alice@security.com",
  "comment": "Assigned to frontend team to implement strict CSP headers."
}
```

#### `POST /api/findings/{finding_id}/comments`
Appends a collaboration note or remediation evidence to a finding.

