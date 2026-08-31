# Contract 05: Deliverables, Acceptance Criteria & Adversarial Security Scenarios

**Project Name:** CyberAssess Automated Security Assessment & Vulnerability Management Platform  
**Document Version:** 13.0.0 (Acceptance Scenarios 1–32 & Adversarial Security Matrix SEC-001 through SEC-030 with Production Path Verification)  
**Status:** APPROVED / AUTHORITATIVE SPECIFICATION  
**Scope Authority:** Verification Criteria, Acceptance Scenarios & Mandatory Adversarial Test Vectors  

---

## 1. Definition of Done

The platform is considered complete ONLY when all following criteria are satisfied:
1. **Security & Identity:** No hardcoded credentials; secure first-run bootstrap; library-backed RFC 8725 JWT enforcement; database-authoritative token and API-key revocation; multi-tenant database-level IDOR prevention; universal target security gateway with connection-level destination binding and fail-closed DNS; server-derived workspace sandboxing; real SHA-256 tool integrity; privileged operation tamper-evident audit logging.
2. **Persistence:** Relational database (SQLite WAL / PostgreSQL) as single source of truth; zero JSON fallback resurrection; transactional scan and finding persistence; zero silent exception swallowing.
3. **Execution & Governance:** Bounded scan concurrency; execution timeout enforcement; scan cancellation killing entire process tree via `ProcessSupervisor`; resource quotas enforced.
4. **Findings & Intelligence:** Canonical findings with historical occurrences; multi-dimensional safe correlation; versioned contextual risk scoring (`contextual_risk_model_v2`); persistent SLA clock without reset on redetections; cryptographic evidence hashing.
5. **Supply Chain:** Pinned tool manifest; real SHA-256 hashes; quarantine-before-promotion pipeline; CycloneDX 1.5 SBOM generation.
6. **API & Frontend:** Restrictive CORS; request correlation IDs; secret masking across all output channels; real auth state in UI.
7. **Verification:** 100% automated test pass rate across unit, integration, contract, and adversarial security test suites.

---

## 2. Mandatory Adversarial Security Matrix (SEC-001 to SEC-030)

| Scenario ID | Test Name | Invariant Under Test |
|---|---|---|
| **SEC-001** | Authentication Bypass | Unauthenticated requests or invalid/revoked tokens to protected endpoints receive HTTP 401 Unauthorized. |
| **SEC-002** | Privilege Escalation & Scope Enforcement | API keys and users lacking required scopes (`tool:install`, `user:write`, etc.) are denied with HTTP 403 Forbidden. |
| **SEC-003** | Cross-Tenant Asset Access | Organization A users cannot read, modify, or delete Organization B assets (database-enforced IDOR denial). |
| **SEC-004** | Cross-Tenant Scan Access | Organization A users cannot access, cancel, or stream Organization B scan jobs. |
| **SEC-005** | Cross-Tenant Finding Access | Organization A users cannot query, comment, or triage Organization B findings. |
| **SEC-006** | SSRF Localhost & Loopback | Targets resolving to `127.0.0.1`, `localhost`, or `::1` are blocked by `assert_safe_target()`. |
| **SEC-007** | SSRF Private Subnet | Targets resolving to RFC 1918 addresses (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) are denied. |
| **SEC-008** | SSRF Cloud Metadata | Targets resolving to `169.254.169.254` or `metadata.google.internal` are denied. |
| **SEC-009** | DNS Rebinding & Fail-Closed DNS | Connection-level IP binding prevents DNS rebinding; DNS resolution failures fail closed. |
| **SEC-010** | Hop-by-Hop Redirect SSRF | HTTP repeater re-validates every redirect hop destination against SSRF policy before connection. |
| **SEC-011** | Workspace Path Jail & Symlinks | Paths outside server-derived authorized workspace root or symlinks escaping jail are rejected. |
| **SEC-012** | Hardcoded Credential Rejection | No default static passwords exist; bootstrap creates unique credentials. |
| **SEC-013** | Database-Authoritative Key Revocation | Revoked API keys and tokens are immediately denied via database state without relying on process memory. |
| **SEC-014** | JWT Algorithm Confusion | Tokens with `alg=none` or unapproved algorithms are rejected by library validator. |
| **SEC-015** | JWT Expiry & Clock Drift | Expired JWT access tokens are rejected with strict RFC 8725 claim verification. |
| **SEC-016** | JWT Issuer/Audience Failure | Tokens with invalid issuer (`iss`) or audience (`aud`) claims are rejected. |
| **SEC-017** | Tool Hash Mismatch | Binary archives with mismatched SHA-256 hashes are quarantined and rejected. |
| **SEC-018** | Unpinned Tool Rejection | Tools missing manifest trust metadata or hashes are blocked from installation. |
| **SEC-019** | Malicious Archive Rejection | Archives containing directory traversal entries (ZipSlip/TarSlip) are aborted. |
| **SEC-020** | Process Tree Termination | Scan cancellation strictly terminates the entire process tree (parent, child, grandchildren) via `ProcessSupervisor`. |
| **SEC-021** | Resource Exhaustion | Bounded concurrency queue and request rate limiters prevent server denial of service. |
| **SEC-022** | Evidence Secret Leakage | Captured credentials, authorization tokens, and private keys are masked before persistence and logging. |
| **SEC-023** | Tamper-Evident Audit Integrity | Audit events are chained with cryptographic SHA-256 hashes (`event_hash = SHA256(canonical_payload + prev_hash)`). |
| **SEC-024** | Risk Acceptance Visibility | Accepted risk findings remain visible with explicit `RISK_ACCEPTED` status and audited rationale. |
| **SEC-025** | SLA Clock Preservation | Redetected findings preserve the original `sla_started_at` and `sla_due_at` timestamps without resetting. |
| **SEC-026** | Correlation False Merge Prevention | Distinct vulnerabilities with different endpoints or parameters are not merged. |
| **SEC-027** | Multi-Tool Finding Deduplication | Identical findings from multiple scanners on the same endpoint are clustered into canonical findings and occurrences. |
| **SEC-028** | Report Secret Leakage | Exported HTML, JSON, and SARIF reports sanitize sensitive credentials. |
| **SEC-029** | Database Inconsistency & No JSON Resurrection | Scan operations execute within transactional boundaries; JSON cannot resurrect deleted records. |
| **SEC-030** | Fail-Closed Startup Configuration | Production mode fails startup if secret keys are missing or insecure. |
```
