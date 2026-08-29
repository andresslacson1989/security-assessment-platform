# Contract 04: REST API, OpenAPI & Real-Time Streaming Events Contract

**Project Name:** Full-Stack Automated Security Assessment & Vulnerability Management Platform  
**Document Version:** 3.0.0 (Comprehensive Production Specification)  
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
  "version": "3.0.0",
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
      "description": "Evaluates SSL/TLS certificates, deprecated protocols, cipher suites, DNS hygiene (SPF/DMARC/MTA-STS/DNSSEC), and exposed service ports.",
      "supported_targets": ["URL", "DOMAIN", "IP"]
    },
    {
      "name": "web_dast",
      "display_name": "Web Application, Browser & API DAST",
      "description": "Audits OWASP security headers, cookie flags, CORS policies, modern browser isolation (COOP/COEP/SRI), GraphQL introspection, and sensitive endpoint exposure.",
      "supported_targets": ["URL", "DOMAIN"]
    },
    {
      "name": "code_sast",
      "display_name": "Static Code Analysis, Secrets & Dependencies",
      "description": "Scans local repositories for 40+ high-entropy secret patterns, weak cryptography/PRNG, SQL/shell injection anti-patterns, and lockfile CVEs.",
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
      "User-Agent": "SecurityAssessmentBot/3.0"
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
Returns complete scan snapshot.
- **Response (200 OK):**
```json
{
  "id": "c4b3f8e2-9d3a-4a61-9c88-123456789abc",
  "target": {
    "id": "8f1a2b3c-4d5e-6f7a-8b9c-0d1e2f3a4b5c",
    "name": "Production Portal",
    "type": "URL",
    "value": "https://example.com",
    "resolved_ip": "93.184.216.34",
    "created_at": "2026-08-29T21:45:00Z"
  },
  "profile": "FULL_STACK",
  "enabled_engines": ["network", "web_dast"],
  "status": "COMPLETED",
  "progress_percent": 100,
  "current_stage": "Assessment complete.",
  "summary": {
    "critical_count": 0,
    "high_count": 1,
    "medium_count": 3,
    "low_count": 4,
    "info_count": 2,
    "total_findings": 10,
    "passed_checks": 34,
    "total_checks_evaluated": 44,
    "weighted_score": 76.0,
    "overall_security_grade": "C",
    "duration_seconds": 9.2,
    "engine_breakdown": {
      "network": 4,
      "web_dast": 6
    }
  },
  "findings": [...],
  "logs": [...],
  "started_at": "2026-08-29T21:45:00Z",
  "completed_at": "2026-08-29T21:45:09Z"
}
```

---

#### `POST /api/scans/{scan_id}/cancel`
Aborts an active scan.
- **Response (200 OK):**
```json
{
  "scan_id": "c4b3f8e2-9d3a-4a61-9c88-123456789abc",
  "status": "CANCELLED",
  "message": "Scan job successfully aborted."
}
```

---

#### `GET /api/scans/history`
Returns paginated list of historical scan summaries.
- **Query Parameters:** `limit` (default: 50), `offset` (default: 0)
- **Response (200 OK):**
```json
{
  "total": 24,
  "scans": [
    {
      "id": "c4b3f8e2-9d3a-4a61-9c88-123456789abc",
      "target_name": "Production Portal",
      "target_value": "https://example.com",
      "target_type": "URL",
      "profile": "FULL_STACK",
      "status": "COMPLETED",
      "overall_security_grade": "C",
      "weighted_score": 76.0,
      "total_findings": 10,
      "critical_count": 0,
      "high_count": 1,
      "started_at": "2026-08-29T21:45:00Z",
      "completed_at": "2026-08-29T21:45:09Z"
    }
  ]
}
```

---

#### `DELETE /api/scans/{scan_id}`
Deletes scan record from disk.
- **Response (200 OK):**
```json
{
  "scan_id": "c4b3f8e2-9d3a-4a61-9c88-123456789abc",
  "message": "Scan record deleted successfully."
}
```

---

### 1.3 Compliance & Export Endpoints

#### `GET /api/scans/{scan_id}/export/html`
- **Output:** Returns standalone, single-file HTML report (`text/html; charset=utf-8`).

#### `GET /api/scans/{scan_id}/export/sarif`
- **Output:** Returns standard OASIS SARIF v2.1.0 JSON format for GitHub Code Scanning integration.

#### `GET /api/scans/{scan_id}/export/json`
- **Output:** Returns full raw JSON dump conforming to the `ScanJob` schema.

---

## 2. Real-Time Streaming Event Contract (SSE)

Endpoint: `GET /api/scans/{scan_id}/events`  
Protocol: **Server-Sent Events (SSE)** (`text/event-stream; charset=utf-8`)

Event Types emitted:
1. `event: progress` — Data: `{"percent": 45, "stage": "...", "status": "RUNNING"}`
2. `event: log` — Data: `{"timestamp": "...", "level": "INFO", "engine": "network", "message": "..."}`
3. `event: finding` — Data: `{ Finding Object }` (emitted immediately on identification)
4. `event: completed` — Data: `{"scan_id": "...", "status": "COMPLETED", "overall_security_grade": "C", "weighted_score": 76.0, "total_findings": 10, "completed_at": "..."}`
5. `event: error` — Data: `{"message": "Scan failed: Target host unreachable."}`
