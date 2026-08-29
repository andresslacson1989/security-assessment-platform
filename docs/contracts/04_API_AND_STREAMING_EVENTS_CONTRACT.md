# Contract 04: REST API, OpenAPI & Real-Time Streaming Events Contract

**Project Name:** Full-Stack Automated Security Assessment & Vulnerability Management Platform  
**Document Version:** 4.0.0 (Enterprise Penetration Testing & Advanced Threat Auditing Specification)  
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
  "version": "4.0.0",
  "timestamp": "2026-08-29T21:45:00Z",
  "uptime_seconds": 18450.2,
  "storage": {
    "status": "OK",
    "scans_stored": 58,
    "path": "data/scans"
  }
}
```

#### `GET /api/system/engines`
- **Response (200 OK):**
```json
{
  "engines": [
    {
      "name": "network",
      "display_name": "Network & TLS Auditor",
      "description": "Evaluates SSL/TLS certificates, deprecated protocols, cipher suites, DNS hygiene (SPF/DMARC/MTA-STS/DNSSEC), passive OSINT certificate transparency subdomains, and exposed service ports.",
      "supported_targets": ["URL", "DOMAIN", "IP"]
    },
    {
      "name": "web_dast",
      "display_name": "Web Application, Browser & API DAST",
      "description": "Audits OWASP security headers, cookie flags, CORS policies, modern browser isolation (COOP/COEP/SRI), active benign parameter fuzzing (SQLi, XSS, LFI, SSTI, Open Redirect), GraphQL introspection, and sensitive endpoint exposure.",
      "supported_targets": ["URL", "DOMAIN"]
    },
    {
      "name": "code_sast",
      "display_name": "Static Code Analysis, Secrets & Dependencies",
      "description": "Scans local repositories for 40+ high-entropy secret patterns, git commit history secret leakage, AST interprocedural taint flow analysis (SQLi, Command Injection), weak cryptography/PRNG, and lockfile CVEs.",
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
      "User-Agent": "CyberAssessBot/4.0"
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
Returns complete scan snapshot including `discovered_endpoints`, `discovered_subdomains`, `findings` (with `reproduction_curl` and `taint_trace`), and `logs`.

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
    "User-Agent": "CyberAssess-Repeater/4.0"
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

## 2. Real-Time Streaming Event Contract (SSE)

Endpoint: `GET /api/scans/{scan_id}/events`  
Protocol: **Server-Sent Events (SSE)** (`text/event-stream; charset=utf-8`)

Event Types emitted:
1. `event: progress` — Data: `{"percent": 45, "stage": "...", "status": "RUNNING"}`
2. `event: log` — Data: `{"timestamp": "...", "level": "INFO", "engine": "network", "message": "..."}`
3. `event: auth_status` — Data: `{"auth_type": "FORM_LOGIN", "authenticated": true, "session_active": true, "message": "Successfully authenticated."}`
4. `event: crawl_discovered` — Data: `{"url": "https://example.com/dashboard", "depth": 1, "status_code": 200, "is_authenticated": true, "total_discovered": 12}`
5. `event: subdomain_discovered` — Data: `{"domain": "api.example.com", "ip_addresses": ["93.184.216.34"], "cname_targets": ["api.example.com.cdn.cloudflare.net"], "is_takeover_vulnerable": false, "service_fingerprint": "Cloudflare", "total_subdomains": 5}`
6. `event: finding` — Data: `{ Finding Object }` (emitted immediately on identification with `reproduction_curl` when available)
7. `event: completed` — Data: `{"scan_id": "...", "status": "COMPLETED", "overall_security_grade": "C", "weighted_score": 76.0, "total_findings": 10, "completed_at": "..."}`
8. `event: error` — Data: `{"message": "Scan failed: Target host unreachable."}`
