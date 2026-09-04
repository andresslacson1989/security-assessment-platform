# CyberAssess v14 — Enterprise Assessment Methodology, Tool Assurance & Production Readiness Traceability Matrix

## Document Purpose & Authority
This authoritative traceability matrix provides formal cross-verification between the **CyberAssess v14 Security Invariant Specifications**, the authoritative contract clauses, the concrete production implementations, and the dedicated adversarial regression test suite (tests/security/).

In accordance with Rule 0.1 (*Enterprise Security Invariant Closure & Production Path Proof*), passing helper unit tests alone do not constitute evidence of compliance. Each security control is validated against its actual production execution path under adversarial conditions.

---

## 1. Traceability Summary Matrix

| Invariant ID | Security Control Domain | Primary Contract Reference | Implementation Location | Adversarial Verification Test | Compliance Status |
|---|---|---|---|---|---|
| **INV-001** | Multi-Tenant Zero-Trust Identity & RBAC | Contract 01 Section 3, Contract 02 Section 2, Contract 08 Section 1 | backend/app/core/auth.py | tests/security/test_adversarial_sec_matrix.py::test_sec_001_authentication_bypass_rejection, test_sec_002_privilege_escalation_prevention | **VERIFIED** |
| **INV-002** | Multi-Tenant Isolation & IDOR Defenses | Contract 01 Section 3, Contract 02 Section 2-5, Contract 04 Section 2 | backend/app/core/auth.py, backend/app/core/db.py | tests/security/test_adversarial_sec_matrix.py::test_sec_003_cross_tenant_asset_access_idor, test_sec_004_cross_tenant_scan_access_idor, test_sec_005_cross_tenant_finding_access_idor | **VERIFIED** |
| **INV-003** | RFC 8725 JWT Session Governance & DB Revocation | Contract 01 Section 3, Contract 04 Section 2, Contract 08 Section 1 | backend/app/core/auth.py, backend/app/core/db.py | tests/security/test_adversarial_sec_matrix.py::test_sec_014_jwt_algorithm_confusion_rejection, test_sec_015_jwt_expiry_rejection, test_sec_016_jwt_token_revocation | **VERIFIED** |
| **INV-004** | API Key Database Authority & Cryptographic Hashing | Contract 01 Section 3, Contract 02 Section 2, Contract 08 Section 1 | backend/app/core/auth.py, backend/app/core/db.py | tests/security/test_adversarial_sec_matrix.py::test_sec_013_api_key_revocation | **VERIFIED** |
| **INV-005** | Single-Gateway SSRF & IPv4/IPv6 CIDR Blocking | Contract 01 Section 5.1, Contract 04 Section 3, Contract 08 Section 12.1 | backend/app/core/ssrf_protector.py | tests/security/test_adversarial_sec_matrix.py::test_sec_006_ssrf_localhost_blocked, test_sec_007_ssrf_private_subnets_blocked, test_sec_008_ssrf_cloud_metadata_blocked | **VERIFIED** |
| **INV-006** | Pre-Resolution DNS & DNS Rebinding Defenses | Contract 01 Section 5.1, Contract 04 Section 3, Contract 08 Section 12.1 | backend/app/core/ssrf_protector.py | tests/security/test_adversarial_sec_matrix.py::test_sec_009_ssrf_dns_rebinding_pre_resolution | **VERIFIED** |
| **INV-007** | Workspace Jail & Path Traversal / Symlink Containment | Contract 01 Section 6, Contract 08 Section 12.3 | backend/app/core/path_sandbox.py | tests/security/test_adversarial_sec_matrix.py::test_sec_010_filesystem_escape_blocked, test_sec_011_symlink_escape_blocked | **VERIFIED** |
| **INV-008** | Tool Supply Chain Integrity & Pinned SHA-256 Checksums | Contract 01 Section 7, Contract 03 Section 2, Contract 08 Section 4, Contract 09 | backend/app/installers/tool_manifest.py, backend/app/installers/github_release_installer.py | tests/security/test_adversarial_sec_matrix.py::test_sec_017_tool_hash_mismatch_rejection, test_sec_018_unpinned_tool_rejection, test_sec_019_malicious_archive_zipslip_rejection | **VERIFIED** |
| **INV-009** | Process Supervisor & Subprocess Tree Termination | Contract 03 Section 3, Contract 08 Section 8, Contract 09 | backend/app/core/process_supervisor.py, backend/app/core/binary_resolver.py | tests/security/test_adversarial_sec_matrix.py::test_sec_020_scan_cancellation_lifecycle | **VERIFIED** |
| **INV-010** | Resource Governance & Scan Concurrency Bounding | Contract 01 Section 8, Contract 04 Section 1, Contract 09 | backend/app/core/queue.py | tests/security/test_adversarial_sec_matrix.py::test_sec_021_resource_exhaustion_concurrency_governance | **VERIFIED** |
| **INV-011** | Secret Sanitization in Evidence, Logs & Reports | Contract 01 Section 6, Contract 02 Section 4, Contract 09 | backend/app/core/models.py, backend/app/exporters/sarif_exporter.py, backend/app/exporters/html_exporter.py | tests/security/test_adversarial_sec_matrix.py::test_sec_022_evidence_secret_masking, test_sec_028_report_secret_leakage_sanitization | **VERIFIED** |
| **INV-012** | Immutable Chained Cryptographic Audit Logging | Contract 01 Section 4, Contract 02 Section 6, Contract 08 Section 1 | backend/app/core/db.py | tests/security/test_adversarial_sec_matrix.py::test_sec_023_audit_log_integrity | **VERIFIED** |
| **INV-013** | Finding Lifecycle, SLA Clock Preservation & Correlation | Contract 01 Section 5.2, Contract 02 Section 4, Contract 08 Section 2 | backend/app/core/correlator.py, backend/app/core/models.py | tests/security/test_adversarial_sec_matrix.py::test_sec_024_risk_acceptance_visibility, test_sec_025_sla_clock_preservation, test_sec_026_correlation_false_merge_prevention, test_sec_027_correlation_duplicate_merging | **VERIFIED** |
| **INV-014** | Relational Database ACID Persistence | Contract 01 Section 4, Contract 02 Section 3-6 | backend/app/core/db.py, backend/app/core/storage.py | tests/security/test_adversarial_sec_matrix.py::test_sec_029_database_transaction_integrity | **VERIFIED** |
| **INV-015** | Development Mode Privilege Isolation | Contract 01 Section 3, Contract 08 Section 1 | backend/app/core/auth.py | tests/security/test_adversarial_sec_matrix.py::test_sec_030_development_mode_privilege_isolation | **VERIFIED** |

---

## 2. Invariant Implementation Details

### Capability Status Observation (non-authorization)
- The authenticated system capability and toolbox endpoints report the 26-tool fleet using backend-owned process-local 60-second snapshots; capability snapshots are keyed by adapter configuration and each endpoint supports `refresh=true` for deliberate live detection/status refresh.
- Cache metadata distinguishes live and cached observations, expiry triggers a new live check, and failures do not present stale status as current.
- This UI/status cache is not persisted and cannot authorize execution; scan execution retains live discovery plus pre-launch integrity and exact-version verification.

### INV-001 & INV-002: Zero-Trust Multi-Tenancy & Identity
- **Contract Specification:** Contracts 01 Section 3, 02 Section 2, 08 Section 1.
- **Implementation:** 
  - Explicit PrincipalType enum separating SYSTEM_PRINCIPAL (platform super-admins) from TENANT_PRINCIPAL (tenant users and API keys).
  - organization_id TEXT NOT NULL enforced at DB level across users, api_keys, assets, scans, findings, finding_occurrences, and audit_events.
  - Database queries filter explicitly on organization_id (WHERE organization_id = ?) preventing data leakage across tenant boundaries.

### INV-003: PyJWT RFC 8725 Session Governance
- **Contract Specification:** Contracts 01 Section 3, 04 Section 2, 08 Section 1.
- **Implementation:**
  - Migrated to mature jwt (PyJWT) library with algorithm allowlist HS256, RS256.
  - Enforces mandatory RFC 8725 claims (iss, aud, sub, exp, iat, nbf, jti).
  - Rejects alg=none and signature forgery attempts.
  - Revocations recorded in both in-memory set and authoritative relational table revoked_tokens.

### INV-005 & INV-006: Target Security & Pre-Resolution SSRF Gateway
- **Contract Specification:** Contracts 01 Section 5.1, 04 Section 3, 08 Section 12.1.
- **Implementation:**
  - Centralized assert_safe_target(target_type, target_value) gateway.
  - Comprehensive IPv4 and IPv6 blocklist covering loopback, RFC 1918, RFC 4193, link-local, multicast, and cloud metadata (169.254.169.254).
  - Pre-resolution DNS lookup verifying all IP addresses for a hostname before outbound socket connection.
  - Unresolvable targets fail closed.

### INV-007: Filesystem Sandboxing & Symlink Defense
- **Contract Specification:** Contracts 01 Section 6, 08 Section 12.3.
- **Implementation:**
  - Mandatory canonical path resolution (Path.resolve()) before authorization.
  - System directory blacklist (/etc, /root, C:\Windows, C:\Program Files, etc.) and sensitive file patterns (id_rsa, .aws/credentials, .kube/config).
  - Rejects symlink traversal escapes pointing outside authorized workspace roots.

### INV-008: Pinned Tool Supply Chain Integrity
- **Contract Specification:** Contracts 01 Section 7, 03 Section 2, 08 Section 4.
- **Implementation:**
  - PINNED_TOOL_MANIFEST registers exact release tags, exact repository names, and canonical platform SHA-256 digests.
  - Downloaded release archives are validated against SHA-256 digests prior to extraction.
  - Unpinned binaries or mismatched hashes are rejected and aborted.
  - Extraction routines enforce ZipSlip / TarSlip path containment before atomic file promotion.

### INV-009: Central Process Supervision & Subprocess Tree Termination
- **Contract Specification:** Contracts 03 Section 3, 08 Section 8.
- **Implementation:**
  - ProcessSupervisor encapsulates all subprocess execution across adapters and resolvers.
  - Uses CREATE_NEW_PROCESS_GROUP on Windows and process groups on POSIX.
  - Recursively terminates child and grandchild process trees via taskkill /F /T /PID or killpg on timeout or scan cancellation.

### INV-012: Cryptographic Tamper-Evident Audit Logging
- **Contract Specification:** Contracts 01 Section 4, 02 Section 6, 08 Section 1.
- **Implementation:**
  - Each audit event records previous_event_hash and computes event_hash = SHA256(canonical_payload + previous_event_hash).
  - Forms an immutable, unbroken cryptographic hash chain verifiable across the relational audit log.

### INV-013: Subfinder Discovery Does Not Grant Authorization
- **Contract Specification:** Contract 09, TOOL 03 Sections 13, 20, 24, 30 and 36.
- **Implementation:** `backend/app/adapters/subfinder_adapter.py` validates the authorized root, constructs a fixed argument vector, rejects malformed/out-of-scope records, and emits only scoped discovery observations. `backend/app/engines/network/subdomain_recon.py` and `backend/app/engines/network/origin_exposure.py` keep native CT enrichment unresolved and block DNS/takeover/origin HTTP operations without the explicit active-probing grant. It does not perform inventory admission; `/api/assets/admit-discovery` performs the separate tenant-scoped admission decision.
- **Tests:** `tests/security/test_subfinder_assurance.py::test_discovery_never_promotes_out_of_scope_or_resolves_hosts`, `tests/test_origin_exposure.py::test_passive_ct_does_not_resolve_or_probe_without_active_grant`, `tests/test_origin_exposure.py::test_origin_exposure_passive_mode_does_not_resolve_or_probe`.
- **Status:** VERIFIED for the non-escalation and explicit-admission boundaries and for exact destinations in platform-owned CT clients; Prowler assured execution now fails closed for non-AWS providers rather than injecting an incorrect credential namespace, while AWS worker credentials require a typed organization/asset/provider-bound, expiring envelope and cross the durable queue only as authenticated AES-GCM ciphertext. Production queue deployments fail closed without the separately provisioned handoff key. OS-level external-process egress governance and a production external secret-provider backend remain pending capabilities.

### E11.3 Runtime Verification
- **Evidence:** On 2026-09-01, the production adapter executed the approved managed `backend/bin/subfinder.exe` against `example.com`; managed trust verification returned true, the runtime reported `subfinder v2.6.5`, and the adapter completed with normalized state `COMPLETED_NO_FINDINGS`.
- **Additional Evidence:** On 2026-09-03, the Linux image manifest `sha256:6307c07581638a2a149da993aa91708c99e4bce715b6c4da9a51e45a7ff24a4e` ran with a read-only root filesystem, dropped capabilities, `no-new-privileges`, `noexec` temporary storage, and uid 999. Fifteen managed standalone artifacts, six lock-bound package trust records, and the managed Retire.js npm trust record verified; every managed standalone, package, and npm tool version probe launched through `ProcessSupervisor` with pre-launch trust checks. Managed executables, trust sidecars, and package environments were root-owned and not writable by uid 999.
- **Status:** VERIFIED for the managed adapter execution path and the separate tenant-scoped inventory-admission workflow. This does not claim upstream provenance beyond the recorded artifact/install controls, nor does it close provider-egress governance.

---

## 3. Final Verification Assertion
Repository-level controls for the documented invariants are implemented and verified through focused and adversarial tests. Managed Subfinder runtime execution, the managed E13 direct-binary fleet, and complete repository regression are now evidenced; remaining E11 and E13 limitations are recorded explicitly and are not represented as completed capabilities.


---

## 3. Final Verification Assertion
Repository-level controls for the documented invariants are implemented and verified through focused and adversarial tests. Managed Subfinder runtime execution, the managed E13 direct-binary fleet, and complete repository regression are now evidenced; remaining E11 and E13 limitations are recorded explicitly and are not represented as completed capabilities.

### E12 Web DAST Execution Boundary
- **Implementation:** `backend/app/engines/web_dast/engine.py`, `backend/app/core/ssrf_protector.py`, `backend/app/adapters/base_adapter.py`, and the four E12 adapters.
- **Controls:** validated-target transport pinning with ambient proxy bypass, same-origin redirect revalidation, Host preservation, exact approved-version gates, managed-binary checks immediately before version probes and launches, centralized supervised launches, normalized failure states, sanitized reproduction evidence, and API telemetry retention for tools absent from `active_adapters`.
- **Tests:** `tests/security/test_web_dast_assurance.py`, `tests/test_engine_web_dast.py`, `tests/test_api_endpoints.py::test_telemetry_endpoint_structure_and_filters`, and the four E12 adapter test classes.
- **Status:** Repository controls and managed-runtime probes are verified. The Linux production image executed managed Nuclei `3.2.0`, FFuF `2.1.0`, Katana `1.0.5`, and Schemathesis `3.20.0` under uid 999 with valid trust records; no unmanaged runtime is treated as evidence. FFuF and Nuclei are blocked at both adapter and Web DAST production-path boundaries without tenant active-probing authorization. Authenticated external CLI injection remains intentionally fail-closed; governed native HTTP coverage handles tenant credentials until secret-safe subprocess injection exists.

#### E13 Code SAST, Secrets & Dependency Analysis Boundary
- **Implementation:** `backend/app/core/path_sandbox.py`, `backend/app/engines/code_sast/engine.py`, the E13 adapters, native scanners, and `backend/app/core/process_supervisor.py`.
- **Controls:** Canonical tenant-authorized workspace resolution, symlink/reparse-point rejection, supervised Git history execution, exact approved-version gates, managed package/binary checks with pre-launch verification, bounded output/timeouts, explicit parser/failure states, deterministic taint sanitization, and secret-safe evidence.
- **Tests:** `tests/security/test_code_sast_assurance.py`, E13 adapter tests, `tests/test_engine_code_sast.py`, persistence/API tests, and full regression.
- **Status:** `REPOSITORY_VERIFIED` for the corrected shared process-supervision, fallback-provenance, execution-state attribution, evidence-sanitization, authoritative-persistence, explicit discovery-admission boundary, platform-owned provider destination allowlists, observation-only cloud fallback, hardened production containers, and 26-tool registry controls. The current Linux production image verified managed trust records and runtime paths for Nuclei, FFuF, Gitleaks, Subfinder, httpx, Katana, Syft, Grype, OSV-Scanner, TruffleHog, Dockle, kube-bench, Amass, and source-built Nmap, plus Retire.js and the six lock-bound Python environments, all under UID 999. No unmanaged runtime is treated as evidence; Prowler remains fail-closed without a worker-side tenant-scoped credential envelope and provider egress controls, while missing native cloud observations are explicitly degraded rather than treated as clean. OS-level external-process egress governance and diagnostic-only auxiliary tools remain documented limitations.

---

## 4. E13-R3 Final Technical Closure & Truthfulness Invariants

| Rework Invariant ID | Security Control Domain | Primary Specification | Concrete Implementation | Verification Suite | Status |
|---|---|---|---|---|---|
| **INV-R3.1** | Evidence Truthfulness & No False Safe Evidence | Contract 02 §4, Audit R3.1 | `backend/app/api/scans.py`, `backend/app/core/models.py`, `backend/app/engines/web_dast/` | `tests/test_e13_evidence_truthfulness.py` (16/16 PASS) | **VERIFIED** |
| **INV-R3.2** | Enterprise Egress Fail-Closed Wiring & No Facility Bypass | Contract 03 §3, Audit R3.2 | `docker-compose.yml`, `backend/app/core/process_supervisor.py` | `tests/test_e13_egress_env_sanitization.py` (7/7 PASS) | **VERIFIED (Fail-Closed); INFRASTRUCTURE BLOCKED** |
| **INV-R3.3** | Production Bootstrap Secret in Compose & Loopback Hardening | Contract 04 §1.1, Audit R3.3 | `docker-compose.yml`, `backend/app/api/auth.py` | `tests/test_e13_platform_hardening.py` (13/13 PASS) | **VERIFIED** |
| **INV-R3.4** | Complete CSP Hardening & Zero Inline Handlers | Contract 08 §1, Audit R3.4 | `frontend/index.html`, `frontend/js/app.js`, `backend/app/main.py` | `tests/test_e13_platform_hardening.py` | **VERIFIED** |
| **INV-R3.5** | Documentation Truthfulness & Governance Reconciliation | Rule 0.1, Audit R3.5 | `docs/SECURITY_INVARIANT_TRACEABILITY.md`, `docs/E13_ENTERPRISE_AUDIT_CLOSURE.md` | Doc & Code Inspection | **VERIFIED** |
| **INV-R3.6** | Application Image Identity Pinning | Contract 01 §7, Audit R3.6 | `docker-compose.yml` | `docker-compose.yml` Inspection | **VERIFIED** |
| **INV-R3.10** | Repository Governance Policy (Solo-Maintainer) | Rule 0.1, Audit R3.5 / E13.10 | `docs/E13_ENTERPRISE_AUDIT_CLOSURE.md` | Operator Direct-Push Policy Accepted | **OPERATOR-ACCEPTED SOLO-MAINTAINER GOVERNANCE POLICY** |

---

## 5. E13-R4 Final Narrow Acceptance Closure Invariants

| Rework Invariant ID | Security Control Domain | Primary Specification | Concrete Implementation | Verification Suite | Status |
|---|---|---|---|---|---|
| **INV-R4.1** | Form vs Authentication Finding Attribution | Audit R4.1 | `backend/app/engines/web_dast/engine.py` | `tests/test_e13_evidence_truthfulness.py` | **VERIFIED** |
| **INV-R4.2** | Elimination of Synthetic Parameters from SAFE Evidence | Audit R4.2 | `backend/app/engines/web_dast/parameter_fuzzer.py` | `tests/test_e13_evidence_truthfulness.py` | **VERIFIED** |
| **INV-R4.3** | Cleartext Form Transport Truthfulness & DAST-FORM-001 | Audit R4.3 | `backend/app/engines/web_dast/auth_session.py` | `tests/test_e13_evidence_truthfulness.py` | **VERIFIED** |
| **INV-R4.4** | Docker Compose Standalone/Enterprise Profile Isolation | Audit R4.4 | `docker-compose.yml`, `README.md` | `tests/test_e13_platform_hardening.py` | **VERIFIED** |
| **INV-R4.5** | Egress Fail-Closed Documentation Truthfulness | Audit R4.5 | `README.md`, `docs/DOCKER_COMPOSE_DEPLOYMENT.md` | Doc & Code Inspection | **VERIFIED** |
| **INV-R4.6** | Reconciled Supported Python Interpreters (3.11/3.13) | Audit R4.6 | `README.md`, `contracts/09_TOOL_IMPLEMENTATION_CONTRACT.md` | Doc & Code Inspection | **VERIFIED** |
| **INV-R4.7** | Authoritative Linux CI Verification Proof | Audit R4.7 | `.github/workflows/contract-verification.yml` | GitHub Actions CI Run | **PENDING PR RUN** |
| **INV-R4.8** | Production Container Live Health Smoke Verification | Audit R4.8 | `.github/workflows/contract-verification.yml` | GitHub Actions CI Run | **PENDING PR RUN** |

