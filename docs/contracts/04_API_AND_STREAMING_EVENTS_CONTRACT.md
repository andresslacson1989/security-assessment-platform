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

#### 1.1.1 Authentication Side-Effect Boundary

`POST /api/auth/login` is an identity operation, not a platform-maintenance operation. A successful or failed login request MUST be limited to credential verification, session/token issuance or rejection, rate-limit accounting, required identity timestamps, and the authenticated audit event. It MUST NOT synchronously invoke tool detection, capability discovery, toolbox refresh, installer work, scan creation, scan-history loading, external-tool processes, or external provider/network activity. Login completion and token issuance MUST NOT depend on the availability, latency, or failure of any tool, capability, cache, scheduler, database-backed scan-history query, or execution-plane worker beyond the identity transaction itself.

The frontend authentication flow MUST treat the login response as complete once the authentication response has been accepted and the authenticated session state is established. Any subsequent observational UI loading MUST be independently initiated, non-blocking, and failure-isolated; it is not part of authentication and MUST never delay, invalidate, or roll back a successful login.

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
- No ordinary scan-history delete endpoint is exposed. Historical records are retained in the authoritative database; any future purge operation MUST be separately governed as specified in §1.3.1.

#### 1.3.1 Historical Scan Persistence and Retention

Scan jobs, test results, findings, telemetry, cancellation state, and failure state MUST be persisted to the authoritative relational database throughout their lifecycle and MUST remain retrievable after browser refresh, logout/login, process restart, cache eviction, and ordinary service redeployment. JSON files are export, backup, or evidence-artifact representations only; they MUST NOT resurrect records absent from the database or replace database reads.

The normal refresh, authentication, capability-refresh, toolbox-refresh, installation, cancellation, and deployment workflows MUST NOT delete historical scan or test records. Historical retrieval MUST use one canonical response envelope: `GET /api/scans` and `GET /api/scans/history` return `{ total, limit, offset, items }`, where `items` is the authoritative list of tenant-scoped summaries. A UI consumer MUST NOT silently substitute a different field name. Any future destructive purge endpoint MUST be separate from ordinary history browsing, explicitly privileged, audited, tenant-constrained, confirmation-protected, and documented with retention/legal-hold behavior; it is not implied by logout or refresh.

### 1.4 Vulnerability Lifecycle & Finding Triage Endpoints (`/api/findings`)
- `GET /api/findings`: Queries canonical findings with filters (`finding:read`, tenant-scoped).
- `PATCH /api/findings/{finding_id}/status`: Updates finding lifecycle state (`OPEN`, `IN_PROGRESS`, `FIXED`, `RISK_ACCEPTED`, etc.) and records tamper-evident audit trail (`finding:triage` or `finding:risk_accept`).
- `POST /api/findings/{finding_id}/comments`: Adds collaboration comment (`finding:write`, tenant-scoped).
- `GET /api/findings/{finding_id}/occurrences`: Retrieves historical occurrence detections across scans (`finding:read`, tenant-scoped).

### 1.5 Pentester Workbench & Tool Management Endpoints (`/api/tools`)
- `POST /api/tools/repeater`: Executes an authorized HTTP test request (`scan:repeater`) with strict connection-level DNS pinning, safe destination binding, hop-by-hop redirect verification, and size bounds. Internal requests require explicit `scan:internal` permission.
- `POST /api/system/tools/{tool_name}/install`: Initiates privileged tool binary installation (`tool:install` + `ADMIN` + audit event).
- `GET /api/system/tools/events`: SSE stream for tool installation progress.
- `GET /api/system/tools`: Authenticated (`tool:read`) list of all 26 toolbox installation/status records. The response is produced by a process-local backend snapshot with a 60-second TTL; `GET /api/system/tools?refresh=true` forces a live backend refresh. Installation success, reinstall, cancellation, and failure invalidate the snapshot before terminal telemetry is emitted.

#### 1.5.1.1 Tool Installation and Full-Capability Execution Requests

`POST /api/system/tools/{tool_name}/install` creates an authenticated, administrator-authorized backend installation job. It MUST be idempotent, serialized per tool, bounded by a job deadline, and observable through sanitized SSE and durable audit events. The endpoint MUST never accept arbitrary download URLs, digests, executable paths, shell commands, provider credentials, or unvalidated arguments from the client.

The complete upstream capability of Metasploit, sqlmap, and Hydra MUST be installable and available after the managed artifact is verified. GTFOBins/LOLBAS MUST be maintained as a complete reviewed native rule catalog rather than represented as an absent external binary. Installation and capability status are observational; an execution request requires a separate authorization decision bound to tenant, project, asset, target seal, tool, requested operation/options, policy version, resource budget, and approving principal.

The API MUST return explicit states for installed capability, authorization required, blocked execution, failed installation, cancelled installation, and degraded coverage. It MUST NOT label a trusted, installed full-capability tool as permanently manual-only merely because the requested operation requires approval.

### 1.5.1 Capability Status Snapshot (`/api/system/capabilities`)
- `GET /api/system/capabilities`: Authenticated (`system:read`) observational capability status for the complete 26-tool fleet.
- The default response is served from a process-local, 60-second cache keyed by the effective adapter configuration. Responses identify `capabilities_source` (`LIVE` or `CACHE`), `capabilities_checked_at`, `capabilities_cache_age_seconds`, and `capabilities_cache_ttl_seconds`.
- `GET /api/system/capabilities?refresh=true` deliberately bypasses the cache and performs one live detection for that configuration. Concurrent requests share one live refresh; expired entries are refreshed and are never silently presented as current.
- Detection failures are returned as failures; stale status is not returned as a current or trusted result. Capability registration is observational only and never authorizes tool execution. Scan orchestration performs its own live checks and pre-launch trust/version verification.
- Toolbox installation status is also observational and does not authorize execution; runtime trust and exact-version checks remain live at the process-launch boundary.

All API, SSE, historical replay, and error responses containing tool output, findings, telemetry, comments, or exception text MUST pass through the canonical recursive evidence sanitizer before serialization. Tenant authorization is applied before sanitization and response emission so that sanitization cannot turn an unauthorized object into an observable object.

#### 1.5.2 Backend-Owned Observation Service

Capability and toolbox status are backend-owned observations. The service MUST provide an autonomous lifecycle-managed observation service that can refresh the complete 26-tool fleet without an authenticated browser session. It MUST begin only after application readiness, MUST NOT block authentication or readiness, and MUST stop and await cancellation during graceful shutdown. The service MUST use an explicit bounded interval, per-tool and aggregate timeouts, bounded output/resource consumption, structured failure telemetry, and a single-flight/concurrency control so overlapping refreshes for the same effective configuration cannot occur.

The observation service populates process-local snapshots; it does not persist tool status as application data and does not grant execution authority. Endpoint authentication and tenant authorization remain mandatory for readers. A failed refresh MUST be represented as failed/unknown with its timestamp and reason, not as a falsely current successful status. Runtime execution MUST repeat live managed-path, integrity, and exact-version checks at the process-launch boundary.

#### 1.5.3 Current Implementation-Gap Register

The current repository evidence establishes the cache, forced-refresh API, installation invalidation, runtime separation, login isolation, history `items` consumption, removal of the ordinary hard-delete path, and lifecycle-managed backend observation service. Runtime deployment evidence MUST still verify scheduler behavior in the target environment; repository tests alone do not constitute production-runtime proof.

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
