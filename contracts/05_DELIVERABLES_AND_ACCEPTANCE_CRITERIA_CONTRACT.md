# Contract 05: Deliverables, Acceptance Criteria & Adversarial Security Scenarios

**Project Name:** CyberAssess Automated Security Assessment & Vulnerability Management Platform  
**Document Version:** 10.0.0 (Acceptance Scenarios 1–32 & Adversarial Security Matrix SEC-001 through SEC-030)  
**Status:** APPROVED / AUTHORITATIVE SPECIFICATION  
**Scope Authority:** Verification Criteria, Acceptance Scenarios & Mandatory Adversarial Test Vectors  

---

## 1. Definition of Done

The platform is considered complete ONLY when all following criteria are satisfied:
1. **Security & Identity:** No hardcoded credentials; secure first-run bootstrap; RFC 8725 JWT enforcement; multi-tenant IDOR prevention; SSRF and DNS-rebinding protection; authorized workspace sandboxing; real SHA-256 tool integrity; privileged operation audit logging.
2. **Persistence:** Relational database (SQLite WAL / PostgreSQL) as single source of truth; transactional scan and finding persistence; zero silent exception swallowing.
3. **Execution & Governance:** Bounded scan concurrency; execution timeout enforcement; scan cancellation killing entire process tree; resource quotas enforced.
4. **Findings & Intelligence:** Canonical findings with historical occurrences; multi-dimensional correlation; versioned contextual risk scoring (`contextual_risk_model_v2`); SLA clock preservation; cryptographic evidence hashing.
5. **Supply Chain:** Pinned tool manifest; real SHA-256 hashes; quarantine-before-promotion pipeline; CycloneDX SBOM generation.
6. **API & Frontend:** Restrictive CORS; request correlation IDs; secret masking across all output channels; real auth state in UI.
7. **Verification:** 100% automated test pass rate across unit, integration, contract, and adversarial security test suites.

---

## 2. Mandatory Adversarial Security Matrix (SEC-001 to SEC-030)

| Scenario ID | Test Name | Invariant Under Test |
|---|---|---|
| **SEC-001** | Authentication Bypass | Unauthenticated requests to protected endpoints receive HTTP 401 Unauthorized. |
| **SEC-002** | Privilege Escalation | Non-admin users cannot trigger privileged tool installations or user role modifications. |
| **SEC-003** | Cross-Tenant Asset Access | Organization A users cannot read, modify, or delete Organization B assets (IDOR denial). |
| **SEC-004** | Cross-Tenant Scan Access | Organization A users cannot access or cancel Organization B scan jobs. |
| **SEC-005** | Cross-Tenant Finding Access | Organization A users cannot query or triage Organization B findings. |
| **SEC-006** | SSRF Localhost | Requests targeting `127.0.0.1`, `localhost`, or `::1` are blocked with SSRF exception. |
| **SEC-007** | SSRF Private Subnet | Requests targeting RFC 1918 addresses (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) are denied. |
| **SEC-008** | SSRF Cloud Metadata | Requests targeting `169.254.169.254` or `metadata.google.internal` are denied. |
| **SEC-009** | DNS Rebinding | DNS pre-resolution verifies resolved IPs against denylist before connection. |
| **SEC-010** | Filesystem Escape | Target paths attempting `../` traversal outside authorized workspace are rejected. |
| **SEC-011** | Symlink Escape | Symlinks resolving outside the authorized workspace are rejected. |
| **SEC-012** | Hardcoded Credential Rejection | No default static passwords exist; bootstrap creates unique credentials. |
| **SEC-013** | API Key Revocation | Revoked or expired API keys are rejected with HTTP 401 Unauthorized. |
| **SEC-014** | JWT Algorithm Confusion | Tokens with `alg=none` or unapproved algorithms are rejected. |
| **SEC-015** | JWT Expiry | Expired JWT access tokens are rejected. |
| **SEC-016** | JWT Issuer/Audience Failure | Tokens with invalid issuer or audience claims are rejected. |
| **SEC-017** | Tool Hash Mismatch | Binary archives with mismatched SHA-256 hashes are quarantined and rejected. |
| **SEC-018** | Unpinned Tool Rejection | Tools missing manifest trust metadata are blocked from installation. |
| **SEC-019** | Malicious Archive Rejection | Archives containing directory traversal entries (ZipSlip/TarSlip) are aborted. |
| **SEC-020** | Scan Cancellation | Cancelling a scan immediately terminates orchestrator tasks and worker subprocesses. |
| **SEC-021** | Resource Exhaustion | Concurrency bounds and request rate limiters prevent server denial of service. |
| **SEC-022** | Evidence Secret Leakage | Captured credentials, authorization tokens, and private keys are masked. |
| **SEC-023** | Audit-Log Integrity | Critical security operations generate append-only audit events. |
| **SEC-024** | Risk Acceptance Misuse | Accepted risk findings remain visible with explicit `RISK_ACCEPTED` status. |
| **SEC-025** | SLA Reset Bug | Correlating subsequent scan findings preserves the original SLA starting clock. |
| **SEC-026** | Correlation False Merge | Distinct vulnerabilities in the same category but different endpoints are not merged. |
| **SEC-027** | Correlation Duplicate Finding | Identical findings from multi-scanners on the same endpoint are clustered. |
| **SEC-028** | Report Secret Leakage | Exported HTML, JSON, and SARIF reports sanitize sensitive credentials. |
| **SEC-029** | Database Inconsistency | Scan and finding database operations execute within transactional boundaries. |
| **SEC-030** | Development Mode Isolation | Development bypass modes never grant privileged administrative access in production. |
