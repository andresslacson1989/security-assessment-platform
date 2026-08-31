# Contract 04: Control Plane REST API, SSE Streaming & Multi-Tenant Authorization Specification

**Project Name:** CyberAssess Automated Security Assessment & Vulnerability Management Platform  
**Document Version:** 10.0.0 (Control Plane REST/SSE APIs, One-Time Bootstrap, RFC 8725 JWT, IDOR Prevention & Multi-Layer Authorization)  
**Status:** APPROVED / AUTHORITATIVE SPECIFICATION  
**Scope Authority:** REST Endpoints, Streaming SSE Protocol, Multi-Tenant Authorization, Middleware & API Security Headers  

---

## 1. REST API Endpoint Specifications

### 1.1 Authentication & Identity Endpoints (`/api/auth`)
- `POST /api/auth/bootstrap`: One-time initial platform setup. Creates the initial administrator user when no users exist. Fails with 403 Forbidden once initialized.
- `POST /api/auth/login`: Authenticates username and password against the relational store. Returns signed JWT access token.
- `GET /api/auth/me`: Returns current authenticated `UserProfile` with organization and role context.
- `POST /api/auth/api-keys`: Creates a scoped API Key (Requires `ADMIN` or `SECURITY_ANALYST`). Plaintext key returned once only.
- `GET /api/auth/api-keys`: Lists active API keys for caller's organization.
- `DELETE /api/auth/api-keys/{key_id}`: Revokes an API Key.

### 1.2 Attack Surface & Asset Inventory Endpoints (`/api/assets`)
- `GET /api/assets`: Lists monitored assets belonging to the caller's organization.
- `POST /api/assets`: Registers a new asset (Requires `DEVELOPER` or higher in the tenant).
- `GET /api/assets/{asset_id}`: Retrieves asset details and posture status (Enforces tenant ownership; prevents IDOR).
- `PUT /api/assets/{asset_id}`: Updates asset metadata or criticality (Enforces tenant ownership).
- `DELETE /api/assets/{asset_id}`: Removes asset from inventory (Requires `ADMIN`).

### 1.3 Scan Execution & Lifecycle Endpoints (`/api/scans`)
- `POST /api/scans/start`: Initiates a security assessment against an authorized target. Enforces SSRF and workspace sandboxing.
- `GET /api/scans/{scan_id}`: Retrieves full scan job snapshot and findings (Enforces tenant ownership).
- `POST /api/scans/{scan_id}/cancel`: Cancels an active scan and terminates running worker subprocesses.
- `GET /api/scans` / `GET /api/scans/history`: Lists historical scan summaries for caller's organization.
- `DELETE /api/scans/{scan_id}`: Deletes a scan record (Requires `ADMIN`).

### 1.4 Vulnerability Lifecycle & Finding Triage Endpoints (`/api/findings`)
- `GET /api/findings`: Queries canonical findings with filters (`severity`, `status`, `asset_id`, `category`).
- `PATCH /api/findings/{finding_id}/status`: Updates finding lifecycle state (`OPEN`, `IN_PROGRESS`, `FIXED`, `RISK_ACCEPTED`, etc.) and records audit trail.
- `POST /api/findings/{finding_id}/comments`: Adds collaboration comment or remediation note.
- `GET /api/findings/{finding_id}/occurrences`: Retrieves historical occurrence detections across scans.

### 1.5 Pentester Workbench & Tool Management Endpoints (`/api/tools`)
- `POST /api/tools/repeater`: Executes an authorized HTTP test request with SSRF validation, hop-by-hop redirect verification, and size bounds.
- `POST /api/system/tools/{tool_name}/install`: Initiates privileged tool binary installation (Requires `ADMIN` + audit event).
- `GET /api/system/tools/events`: SSE stream for tool installation progress.

### 1.6 Exporters & Reporting Endpoints (`/api/scans/{scan_id}/export`)
- `GET /api/scans/{scan_id}/export/html`: Standalone offline interactive HTML report with secret masking.
- `GET /api/scans/{scan_id}/export/sarif`: OASIS SARIF v2.1.0 output for CI/CD integration.
- `GET /api/scans/{scan_id}/export/json`: Structured JSON finding archive.
- `GET /api/scans/{scan_id}/export/sbom/cyclonedx`: CycloneDX 1.5 SBOM report.

---

## 2. Multi-Tenant Authorization & IDOR Defense

Every data access operation MUST pass through authoritative authorization services:
- `authorize_asset_access(user, asset, required_permission)`
- `authorize_scan_access(user, scan, required_permission)`
- `authorize_finding_access(user, finding, required_permission)`

Attempting to access an asset, scan, or finding belonging to Organization B with a valid user token from Organization A MUST return `404 Not Found` or `403 Forbidden`, regardless of whether the object UUID is known.

---

## 3. Middleware & Security Controls

1. **Request Correlation ID:** Every request is tagged with a unique `X-Correlation-ID` header, propagated through logs, scan jobs, audit events, and reports.
2. **Restrictive CORS:** `allow_origins` strictly enforces configured `ALLOWED_ORIGINS` domains; wildcard origins with credentials are prohibited in production.
3. **HTTP Security Headers:** Responses include `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and `Content-Security-Policy`.
4. **Safe Error Handling:** Production API errors return generic error messages and error codes, never leaking internal filesystem paths, stack traces, or credentials.
