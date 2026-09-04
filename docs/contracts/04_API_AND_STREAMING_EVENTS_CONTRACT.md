# Contract 04: Control Plane REST API, SSE Streaming & Multi-Tenant Authorization Specification

**Project Name:** CyberAssess Automated Security Assessment & Vulnerability Management Platform  
**Document Version:** 14.0.0 (Control Plane REST/SSE APIs, Per-Link Telemetry Dossiers, 26-Tool Fleet, RFC 8725 JWT & Multi-Layer Authorization)  
**Status:** APPROVED / AUTHORITATIVE SPECIFICATION  
**Scope Authority:** REST Endpoints, Streaming SSE Protocol, Multi-Tenant Authorization, Middleware & API Security Headers  

---

## 1. REST API Endpoint Specifications

### 1.1 Authentication & Identity Endpoints (`/api/auth`)
- `POST /api/auth/bootstrap`: One-time initial platform setup. Creates the initial administrator user when no users exist. Fails with 403 Forbidden once initialized.
- `POST /api/auth/login`: Authenticates username and password against the relational store. Returns signed JWT access token.
- `POST /api/auth/logout`: Revokes current session token in authoritative database.
- `GET /api/auth/me`: Returns current authenticated `UserProfile` with organization, role, and granted scopes context.
- `POST /api/auth/api-keys`: Creates a scoped API Key (Requires `ADMIN` or `SECURITY_ANALYST`). Plaintext key returned once only.
- `GET /api/auth/api-keys`: Lists active API keys for caller's organization.
- `DELETE /api/auth/api-keys/{key_id}`: Revokes an API Key in authoritative database.

### 1.2 Attack Surface & Asset Inventory Endpoints (`/api/assets`)
- `GET /api/assets`: Lists monitored assets belonging to the caller's organization (`asset:read`).
- `POST /api/assets`: Registers a new asset (`asset:write`). Enforces target security gateway validation for all `AssetType` variants.
- `GET /api/assets/{asset_id}`: Retrieves asset details (Enforces database-level tenant isolation `WHERE id = ? AND organization_id = ?`).
- `PUT /api/assets/{asset_id}`: Updates asset metadata (`asset:write`, tenant-scoped).
- `DELETE /api/assets/{asset_id}`: Removes asset from inventory (`asset:delete`, tenant-scoped).

### 1.3 Scan Execution & Lifecycle Endpoints (`/api/scans`)
- `POST /api/scans/start`: Initiates a security assessment (`scan:create`). Enforces universal target security gateway (`assert_safe_target()`) and server-derived workspace sandboxing.
- `GET /api/scans/{scan_id}`: Retrieves full scan job snapshot and findings (`scan:read`, tenant-scoped).
- `GET /api/scans/{scan_id}/telemetry`: Retrieves organized assessment intelligence, per-tool execution logs, per-link grouped security dossiers (`tests_performed`, `tools_executed`, `findings`), and actively resolved subdomain attack surface (`scan:read`, tenant-scoped).
- `POST /api/scans/{scan_id}/cancel`: Cancels an active scan (`scan:cancel`), halts async workers, broadcasts `event: cancelled` SSE, and resets UI state.
- `GET /api/scans` / `GET /api/scans/history`: Lists historical scan summaries for caller's organization.
- `DELETE /api/scans/{scan_id}`: Deletes a scan record (`scan:delete`, tenant-scoped).

### 1.4 Vulnerability Lifecycle & Finding Triage Endpoints (`/api/findings`)
- `GET /api/findings`: Queries canonical findings with filters (`finding:read`, tenant-scoped).
- `PATCH /api/findings/{finding_id}/status`: Updates finding lifecycle state (`OPEN`, `IN_PROGRESS`, `FIXED`, `RISK_ACCEPTED`, etc.) and records tamper-evident audit trail (`finding:triage` or `finding:risk_accept`).
- `POST /api/findings/{finding_id}/comments`: Adds collaboration comment (`finding:write`, tenant-scoped).
- `GET /api/findings/{finding_id}/occurrences`: Retrieves historical occurrence detections across scans (`finding:read`, tenant-scoped).

### 1.5 Pentester Workbench & Tool Management Endpoints (`/api/tools`)
- `POST /api/tools/repeater`: Executes an authorized HTTP test request (`scan:repeater`) with strict connection-level DNS pinning, safe destination binding, hop-by-hop redirect verification, and size bounds. Internal requests require explicit `scan:internal` permission.
- `POST /api/system/tools/{tool_name}/install`: Initiates privileged tool binary installation (`tool:install` + `ADMIN` + audit event).
- `GET /api/system/tools/events`: SSE stream for tool installation progress.

### 1.5.1 Capability Status Snapshot (`/api/system/capabilities`)
- `GET /api/system/capabilities`: Authenticated (`system:read`) observational capability status for the complete 26-tool fleet.
- The default response is served from a process-local, 60-second cache keyed by the effective adapter configuration. Responses identify `capabilities_source` (`LIVE` or `CACHE`), `capabilities_checked_at`, `capabilities_cache_age_seconds`, and `capabilities_cache_ttl_seconds`.
- `GET /api/system/capabilities?refresh=true` deliberately bypasses the cache and performs one live detection for that configuration. Concurrent requests share one live refresh; expired entries are refreshed and are never silently presented as current.
- Detection failures are returned as failures; stale status is not returned as a current or trusted result. Capability registration is observational only and never authorizes tool execution. Scan orchestration performs its own live checks and pre-launch trust/version verification.

### 1.6 Exporters & Reporting Endpoints (`/api/scans/{scan_id}/export`)
- `GET /api/scans/{scan_id}/export/html`: Standalone offline interactive HTML report with secret masking (`report:read`, tenant-scoped).
- `GET /api/scans/{scan_id}/export/sarif`: OASIS SARIF v2.1.0 output for CI/CD integration.
- `GET /api/scans/{scan_id}/export/json`: Structured JSON finding archive.
- `GET /api/scans/{scan_id}/export/sbom/cyclonedx`: CycloneDX 1.5 SBOM report.

---

## 2. Multi-Tenant Authorization & IDOR Defense

All repository and database operations MUST be tenant-constrained at query execution time:
$$\text{SELECT / UPDATE / DELETE} \dots \text{WHERE id} = ? \land \text{organization\_id} = ?$$

Attempting to read, update, delete, cancel, export, stream, comment, or triage an object belonging to Organization B with a token from Organization A MUST return `404 Not Found` or `403 Forbidden`, regardless of whether the object UUID is known.

---

## 3. Middleware & Security Controls

1. **Request Correlation ID:** Every request is tagged with a unique `X-Correlation-ID` header, propagated through logs, scan jobs, audit events, and reports.
2. **Restrictive CORS:** `allow_origins` strictly enforces configured `ALLOWED_ORIGINS` domains; wildcard origins (`*`) with credentials are prohibited in production.
3. **HTTP Security Headers:** Strict Content Security Policy (`default-src 'self'`), `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`.
4. **Secret Sanitization at Data Boundaries:** Sensitive credentials (passwords, tokens, API keys, private keys, cookies) are masked before reaching database persistence, logs, SSE streams, reports, and error messages.
5. **Safe Error Handling:** Production API errors return generic error messages and error codes, never leaking internal filesystem paths, stack traces, or credentials.
