# Contract 08: Technical Implementation, Authorization Service, Supply Chain & Test Vectors

**Project Name:** CyberAssess Automated Security Assessment & Vulnerability Management Platform  
**Document Version:** 14.3.0 (Enterprise Technical Implementation, 26-Tool Supply Chain, SSRF Rebinding Defense & Adversarial Vectors)  
**Status:** APPROVED / AUTHORITATIVE SPECIFICATION  
**Scope Authority:** Technical Implementations, Authorization Invariants, Hardened Gateways, Supply Chain Hashes & Test Vectors  

---

## 1. Centralized Multi-Layer Authorization Service

All resource operations must be validated against the centralized authorization service:

```python
def authorize_asset_access(user: UserProfile, asset: Asset, action: str = "read") -> bool:
    """Verifies user organization matches asset organization and user has required role/scope."""
    if user.principal_type == PrincipalType.SYSTEM_PRINCIPAL and user.role == UserRole.ADMIN:
        return True  # System administrator principal
    if not asset.organization_id or asset.organization_id != user.organization_id:
        return False  # Cross-tenant access strictly denied
    if action == "write" and user.role not in (UserRole.ADMIN, UserRole.SECURITY_ANALYST, UserRole.DEVELOPER):
        return False
    if action == "delete" and user.role != UserRole.ADMIN:
        return False
    return True

def authorize_scan_access(user: UserProfile, scan: ScanJob, action: str = "read") -> bool:
    """Verifies scan ownership, tenant boundaries, and execution permissions."""
    if user.principal_type == PrincipalType.SYSTEM_PRINCIPAL and user.role == UserRole.ADMIN:
        return True
    if not scan.organization_id or scan.organization_id != user.organization_id:
        return False
    if action in ("control", "cancel", "delete") and user.role not in (UserRole.ADMIN, UserRole.SECURITY_ANALYST, UserRole.DEVELOPER):
        return False
    return True
```

---

## 2. Universal Target Security Gateway & Connection-Level DNS Pinning

1. **Denylisted CIDRs:**
   - Loopback: `127.0.0.0/8`, `::1`
   - RFC 1918 Private: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
   - Link-Local: `169.254.0.0/16`, `fe80::/10`
   - Cloud Metadata: `169.254.169.254`, `metadata.google.internal`
   - Multicast & Broadcast: `224.0.0.0/4`, `255.255.255.255/32`
2. **Universal Target Validation:** `assert_safe_target()` validates all target types (`URL`, `DOMAIN`, `IP`, `LOCAL_PATH`, `DOCKERFILE`, `IAC_MANIFEST`). DNS resolution failures fail closed.
3. **Connection-Level DNS Pinning & Destination Binding:** HTTP connections bind directly to pre-resolved, pre-validated IP addresses to eliminate TOCTOU DNS rebinding vulnerabilities.
4. **Hop-by-Hop Redirect Validation:** Every HTTP redirect hop destination is verified against SSRF policy before the client follows the redirect. Internal addresses require explicit `scan:internal` scope.

---

## 3. Server-Derived Authorized Workspace Jail & Sandbox Invariants

1. **Server-Derived Root:** The workspace root is derived solely from server configuration; clients cannot supply arbitrary execution roots. Missing workspace configuration fails closed.
2. **Path Boundary:** Target local paths are valid if and only if `resolved_path.startswith(authorized_workspace_root)`.
3. **Symlink Resolution:** Symlinks are evaluated with `Path.resolve()` prior to boundary validation to reject breakout attempts.
4. **Sensitive System Path Denylist:** `/etc`, `/root`, `/var/run`, `C:\Windows`, `SAM`, `.ssh`, `.aws`, `.kube` remain strictly forbidden even if located within workspace paths.

---

## 4. Software Supply Chain Pinned Manifest & SHA-256 Checksums

All direct-release binary artifacts in `tool_manifest.py` MUST specify authentic SHA-256 hashes matching official upstream releases. An explicitly approved `SOURCE_BUILD_MODE` entry is permitted only when its immutable source archive, build toolchain, build inputs, and resulting executable are pinned and verified under Contract 03:
- `nuclei`: `v3.2.0` -> `sha256` verified
- `trivy`: `v0.50.0` -> verified source archive and pinned Go toolchain SHA-256 values; reproducible `SOURCE_BUILD_MODE`
- `nmap`: `7.95` -> verified official source archive and pinned GCC toolchain identity; reproducible Linux `SOURCE_BUILD_MODE`
- `gitleaks`: `v8.18.2` -> `sha256` verified
- `ffuf`: `v2.1.0` -> `sha256` verified
- `katana`: `v1.0.5` -> `sha256` verified
- `subfinder`: `v2.6.5` -> `sha256` verified
- `httpx`: `v1.6.0` -> `sha256` verified
- `syft`: `v1.0.1` -> `sha256` verified
- `grype`: `v0.74.0` -> `sha256` verified
- `osv-scanner`: `v1.7.0` -> `sha256` verified
- `dockle`: `v0.4.14` -> `sha256` verified

The approved source-build exceptions are Trivy `v0.50.0` and Nmap `7.95`: their immutable source identities and pinned build toolchains are verified before reproducible builds, and the resulting executables are hashed and bound to their installation records. A verified source build does not claim upstream release-binary provenance and MUST NOT replace an available direct release artifact.

### 4.1 Nmap Dual Trust & Direct Artifact Specification
In addition to the container `SOURCE_BUILD_MODE` exception, Nmap `7.95` provides an official direct-release package mode (`DIRECT_ARTIFACT_MODE`) for supported Linux x86-64 host environments:
- **Official Upstream Package:** `nmap-7.95-1.x86_64.rpm` (`https://nmap.org/dist/nmap-7.95-1.x86_64.rpm`)
- **Package Archive Digest (SHA-256):** `c0465e70217565bd825554e37b5a419221fd688ebcf9ad5633303d69a2287206`
- **Extracted Executable Digest (SHA-256):** `f344bee202f0befb3c2f9cfd7fdd81d6332fe857d0076552f53b3cea115ee80a`
- **Supported Platform:** `linux_amd64` (Linux ELF 64-bit; host unsupported on Windows NT without WSL/container virtualization)

### 4.2 Runtime Resource Tree Integrity Hash-Binding (`RESOURCE_TREE_INTEGRITY_VERIFIED`)
Nmap execution relies extensively on external runtime data files and NSE scripts (`nmap-services`, `nmap-os-db`, `nmap-service-probes`, `scripts/*`). To prevent script-injection and signature tampering:
1. **Deterministic Resource Manifest:** Post-extraction, `build_resource_manifest(resource_dir)` recursively inspects the supporting resource tree (`backend/bin/resources/nmap/`), normalizes relative paths to forward slashes, calculates SHA-256 digests for each file, and produces a byte-for-byte reproducible sorted manifest.
2. **Cryptographic Hash-Binding:** The resource manifest is embedded directly into `nmap.trust.json` accompanied by the `RESOURCE_TREE_INTEGRITY_VERIFIED` claim.
3. **Pre-Launch Verification Gate:** Prior to process execution, `verify_managed_binary_artifact()` invokes `verify_resource_manifest()` to confirm that on-disk resources match the stored manifest exactly. Pre-launch execution fails closed on:
   - Modified file content in any script or data file.
   - Missing or deleted resource file.
   - Extra unexpected file injected into the resource directory tree.
   - Symbolic links inside the resource tree.
4. **Environment Isolation:** During execution, `NMAPDIR` is set to the validated resource directory, ensuring Nmap executes exclusively against verified scripts.

### 4.3 RPM/CPIO Extraction Security Boundary Controls
Direct-artifact unpacking via `_extract_rpm_payload()` enforces strict sandbox boundaries:
- **Directory Traversal Rejection:** Rejects any entry containing `..` in its path tokens and enforces `os.path.commonpath` boundary checks against the target directories.
- **Absolute Path Rejection:** Rejects paths starting with `/`.
- **Symlink Entry Rejection:** Rejects CPIO entries with symbolic link mode (`mode & 0o170000 == 0o120000`).
- **Hardlink Entry Rejection:** Rejects non-directory entries with link count greater than 1 (`nlink > 1`).
- **File Type Whitelist:** Only extracts regular files (`IS_REG`) and directories (`IS_DIR`); safely drops FIFOs, sockets, character devices, and block devices.
- **Duplicate Destination Rejection:** Rejects duplicate destination paths, preventing Zip-Slip overwrite vulnerabilities.
- **Extraction Quotas:** Enforces maximum single file size (100 MiB), maximum decompressed payload (150 MiB), maximum archive entries (8192), and maximum header path length (4096 bytes).
- **Header Parsing Validation:** Strictly verifies hexadecimal formatting of CPIO `070701` / `070702` header fields, failing closed on non-hexadecimal data.

If an archive checksum does not match, the installer MUST abort immediately, delete quarantined files, and emit an audit event.

---

## 5. Security Invariant Traceability Matrix

| Requirement | Contract Section | Implementation Source | Production Test Suite |
|---|---|---|---|
| Identity & RBAC | Contract 01 §3, Contract 04 §2 | `backend/app/core/auth.py`, `backend/app/api/auth.py` | `tests/security/test_adversarial_sec_matrix.py::test_sec_000_production_fails_closed_without_jwt_secret`; `tests/security/test_adversarial_sec_matrix.py::test_sec_001_authentication_bypass_rejection`; `tests/security/test_auth_tenant_boundaries.py` (suite-scoped) |
| Multi-Tenancy & IDOR | Contract 04 §2, Contract 08 §1 | `backend/app/core/auth.py`, `backend/app/api/assets.py` | `tests/security/test_adversarial_sec_matrix.py::test_sec_003_cross_tenant_asset_access_idor`; `tests/security/test_adversarial_sec_matrix.py::test_sec_004_cross_tenant_scan_access_idor`; `tests/security/test_adversarial_sec_matrix.py::test_sec_005_cross_tenant_finding_access_idor` |
| SSRF & DNS Pinning | Contract 01 §3, Contract 08 §2 | `backend/app/core/ssrf_protector.py` | `tests/security/test_adversarial_sec_matrix.py::test_sec_006_ssrf_localhost_blocked`; `tests/security/test_adversarial_sec_matrix.py::test_sec_007_ssrf_private_subnets_blocked`; `tests/security/test_adversarial_sec_matrix.py::test_sec_008_ssrf_cloud_metadata_blocked`; `tests/security/test_adversarial_sec_matrix.py::test_sec_009_ssrf_dns_rebinding_pre_resolution`; `tests/security/test_adversarial_sec_matrix.py::test_sec_009b_ssrf_dns_rebinding_during_validated_target_construction` |
| Hop-by-Hop Redirects | Contract 04 §1.5, Contract 08 §2 | `backend/app/core/ssrf_protector.py`, `backend/app/api/tools.py` | `tests/security/test_adversarial_sec_matrix.py::test_sec_009_ssrf_dns_rebinding_pre_resolution`; `tests/test_e13_repeater_hardening.py` (suite-scoped) |
| Workspace Jail | Contract 01 §3, Contract 08 §3 | `backend/app/core/path_sandbox.py` | `tests/security/test_adversarial_sec_matrix.py::test_sec_010_filesystem_escape_blocked`; `tests/security/test_adversarial_sec_matrix.py::test_sec_011_symlink_escape_blocked`; `tests/test_e13_platform_hardening.py` (suite-scoped) |
| Supply Chain Integrity | Contract 03 §2, Contract 08 §4 | `backend/app/installers/tool_manifest.py` | `tests/security/test_adversarial_sec_matrix.py::test_sec_017_tool_hash_mismatch_rejection`; `tests/security/test_adversarial_sec_matrix.py::test_sec_017_caller_digest_cannot_override_authoritative_manifest`; `tests/security/test_adversarial_sec_matrix.py::test_sec_018_unpinned_tool_rejection`; `tests/test_e13_supply_chain_integrity.py` (suite-scoped) |
| Process Supervisor | Contract 03 §3 | `backend/app/core/process_supervisor.py` | `tests/security/test_process_launch_boundary.py::test_adapters_and_engines_have_no_direct_process_launches`; `tests/test_e13_process_isolation.py` (suite-scoped) |
| DB Authority & Persistence | Contract 01 §3, Contract 02 §4 | `backend/app/core/db.py`, `backend/app/core/storage.py` | `tests/security/test_adversarial_sec_matrix.py::test_database_connections_enable_foreign_keys`; `tests/security/test_adversarial_sec_matrix.py::test_sec_029_database_transaction_integrity`; `tests/security/test_database_backend.py` (suite-scoped) |
| Tamper-Evident Audit Logs | Contract 02 §6, Contract 04 §1 | `backend/app/core/db.py`, `backend/app/api/auth.py` | `tests/security/test_adversarial_sec_matrix.py::test_sec_023_audit_log_integrity`; `tests/security/test_auth_tenant_boundaries.py::test_bootstrap_audit_event_is_chained_and_correlated` |
| Canonical Findings & SLA | Contract 02 §4, Contract 05 §2 | `backend/app/core/correlator.py`, `backend/app/core/db.py` | `tests/security/test_adversarial_sec_matrix.py::test_sec_025_sla_clock_preservation`; `tests/security/test_adversarial_sec_matrix.py::test_sec_026_correlation_false_merge_prevention`; `tests/security/test_adversarial_sec_matrix.py::test_sec_027_correlation_duplicate_merging` |
| Evidence Masking & Health | Contract 01 §3, Contract 04 §3 | `backend/app/core/models.py`, `backend/app/api/export.py` | `tests/security/test_adversarial_sec_matrix.py::test_sec_022_evidence_secret_masking`; `tests/security/test_adversarial_sec_matrix.py::test_sec_028_report_secret_leakage_sanitization`; `tests/security/test_adversarial_sec_matrix.py::test_sec_022_persistence_and_audit_boundaries_redact_sensitive_values` |

Every production test reference in this matrix MUST use the fully qualified
`tests/path/test_file.py::test_function_name` form. CI MUST parse each reference,
verify that the file exists, and verify that the named test symbol exists in that
file. A test file reference without `::test_function_name` is permitted only for
a suite-level coverage row whose file is explicitly marked as suite-scoped.
Bare test names are non-conforming and are not acceptance evidence.

---

## 6. Adversarial Test Vectors & Tool Mock Fixtures (v14.3.0)

### 6.1 Capability Detection Cache Vectors
The authenticated capability endpoint uses a process-local 60-second cache and must be tested for cache hits, expiry-triggered live detection, `refresh=true` bypass, one shared live refresh under concurrency, adapter-configuration isolation, and invalidation after installation success, reinstall, cancellation, or failure. The authenticated toolbox endpoint follows the same backend-owned cache discipline for its 26 installation/status records and accepts `refresh=true` for deliberate live refresh. Responses must expose live-versus-cached source and age metadata where applicable. A failed refresh must not return stale status as current, and cached capability or toolbox status must never bypass runtime binary trust checks. This behavior requires no database schema or persisted tool-status state.

To achieve deterministic CI verification across environments without requiring external binary dependencies, test suites must use the following authoritative mock outputs:

### 6.1.1 Managed Resolution and Probe Vectors
- A package adapter with a valid executable in `backend/.tool-venvs/<tool>/bin` (or `Scripts` on Windows) MUST resolve that executable before the application environment or system `PATH`.
- A configured custom executable MUST remain the selected path for diagnostics and MUST still fail the assurance gate unless its managed trust record validates the exact executable identity.
- A Trivy `v0.50.0` version probe MUST pass a server-selected non-writing config path and MUST not depend on a writable or readable `trivy.yaml` in the service working directory.
- Capability discovery MUST report `ADAPTER_ACTIVE` only after managed resolution, trust verification, and exact runtime version verification all succeed.

### 6.1.2 Authentication Isolation and Backend Observation Vectors

- A login request MUST complete without invoking `/api/system/tools`, `/api/system/capabilities`, scan-history endpoints, installer operations, SSE subscriptions, or external-tool processes. The test MUST observe the actual frontend/backend boundary rather than only mocking helper functions.
- A successful login MUST establish the token/session even when capability detection is slow, unavailable, or fails. A login failure MUST not trigger a capability or toolbox refresh.
- Application startup MUST create an autonomous observation task after readiness, with a bounded interval, per-tool/aggregate timeout, single-flight refresh, structured failure state, and graceful cancellation/await during shutdown. The task MUST operate without a browser session or user token.
- Readiness and authentication latency tests MUST prove that the observation task cannot block either endpoint. Concurrent scheduler ticks MUST not overlap for the same configuration.
- Execution terminalization MUST accept only the canonical bounded reason-code registry. A non-success terminal write with an unknown, overlong, multiline, or free-form reason MUST be rejected. A success terminal write carrying a reason MUST be rejected.
- The reason-code registry MUST be state-aware. Tests MUST reject semantically contradictory pairs such as `FAILED` plus `EXECUTION_CANCELLED` and `TIMED_OUT` plus `PROCESS_EXIT_NONZERO`, while accepting each reviewed state-specific pair.
- Repeating an identical terminal settlement MAY be idempotently successful only when the durable run state, mapped dispatch state, reason code, worker identity, and supplied process identity agree. A conflicting terminal retry MUST be rejected and MUST leave both durable records unchanged except for its rejection audit event.
- A revocation committed before terminal update evaluation MUST prevent both the execution-run and dispatch-intent terminal updates. Tests MUST cover a revoked session and verify that no successful outcome is persisted.
- `revoke_token` MUST propagate session revocation to the linked durable execution authority in the same transaction. PostgreSQL tests MUST cover revoke-versus-finish commit ordering, near-expiry finish after lock acquisition, and verify that no successful settlement occurs after authority loss.
- Reaper eligibility MUST include session-token revocation and MUST close an otherwise active run with a canonical safe outcome while preserving tenant, correlation, and audit invariants.
- The production observation lifecycle MUST invoke the authority reaper on a bounded cadence without authentication, cancel by exact `execution_id`, and atomically close recovered runs. Tests MUST prove startup registration, graceful shutdown/await, exact process identity targeting, and recovery after session revocation or lease expiry.
- Recovery MUST be failure-isolated: bounded database/supervisor calls, per-candidate error handling, retryable backlog for unconfirmed termination, and a persistent/observable recovery error state. Tests MUST prove that `NOT_FOUND`/`FAILED` cancellation does not terminalize a run, one bad candidate does not stop later candidates, and a transient database failure does not kill the lifecycle task.
- Process-tree confirmation MUST verify the root and every captured descendant/group member. PID-only cancellation MUST return the typed confirmation result and retain tracking on failure. A `RUNNING` candidate without durable process identity MUST remain blocked; only `REQUESTED`/`STARTING` candidates proven never to create a process may close without a process confirmation.
- Worker-restart tests MUST prove that a missing in-memory mapping yields `NOT_FOUND`, does not close the durable run, and produces an operator-visible recovery condition; a raw persisted PID MUST never be used without an independently bound process-group identity.

### 6.1.3 Historical Persistence and Retention Vectors

- Start, progress, success, cancellation, timeout, and failure transitions MUST be persisted to the relational database and remain retrievable after a new application process is initialized.
- `GET /api/scans` and `GET /api/scans/history` MUST return the canonical `{total, limit, offset, items}` envelope. An integration test MUST render a non-empty `items` response in the history UI.
- Browser refresh, logout/login, capability-cache invalidation, toolbox installation lifecycle, and service restart MUST NOT delete scan or test history. Tests MUST verify the database row and associated serialized evidence remain available.
- JSON artifacts MUST be treated as export/backup artifacts only. Removing or corrupting an artifact MUST not make a database record disappear; an artifact MUST not recreate a record deleted from the database.
- Any hard-delete path MUST be explicitly privileged, tenant-constrained, audited, confirmation-protected, and covered by retention/legal-hold policy tests. If the product requirement is retention, the default workflow MUST not expose hard deletion.
- Cross-tenant history reads and destructive operations MUST be denied even when a valid foreign scan identifier is supplied.

### 6.1 Metasploit Framework (`MetasploitAdapter`) Mock Fixtures
```python
# Version check mock
MOCK_MSF_VERSION_STDOUT = "Framework Version: 6.4.12-dev\nConsole Version: 6.4.12-dev"

# Heartbleed / SSL Scanner execution mock
MOCK_MSF_HEARTBLEED_STDOUT = """
[*] 192.168.1.50:443 - Scanning 1 of 1 hosts (100% complete)
[+] 192.168.1.50:443 - Vulnerable to Heartbleed OpenSSL TLS heartbeat information disclosure (CVE-2014-0160)
[*] 192.168.1.50:443 - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
"""
```

### 6.2 sqlmap (`SqlmapAdapter`) Mock Fixtures
```python
# Version check mock
MOCK_SQLMAP_VERSION_STDOUT = "sqlmap/1.8.4#stable"

# Injection confirmation mock
MOCK_SQLMAP_STDOUT = """
[INFO] testing connection to the target URL
[INFO] checking if the target is protected by some kind of WAF/IPS
[INFO] testing if the target URL content is stable
[INFO] heuristic (basic) test shows that GET parameter 'id' might be injectable (possible DBMS: 'PostgreSQL')
[INFO] GET parameter 'id' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 42 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 8821=8821
    Type: time-based blind
    Title: PostgreSQL > 8.1 time-based blind
    Payload: id=1 AND 2931=(SELECT 2931 FROM PG_SLEEP(5))
---
[INFO] the back-end DBMS is PostgreSQL
web server operating system: Linux Ubuntu
web application technology: Nginx, Python 3.11.0, FastAPI
back-end DBMS: PostgreSQL 15.2
"""
```

### 6.3 OWASP Amass (`AmassAdapter`) Mock Fixtures
```json
{"name":"api.example.com","domain":"example.com","addresses":[{"ip":"93.184.216.34","cidr":"93.184.216.0/24","asn":15133,"desc":"EDGECAST"}],"tag":"cert","sources":["CertSpotter","Crtsh"]}
{"name":"staging.example.com","domain":"example.com","addresses":[{"ip":"198.51.100.42","cidr":"198.51.100.0/24","asn":13335,"desc":"CLOUDFLARENET"}],"tag":"dns","sources":["Sublist3r","DNS"]}
```

### 6.4 THC-Hydra (`HydraAdapter`) Mock Fixtures
```json
{
  "generator": "hydra",
  "results": [
    {
      "host": "192.168.1.100",
      "port": 22,
      "service": "ssh",
      "login": "admin",
      "password": "password123"
    }
  ]
}
```

### 6.5 GTFOBins Rule Engine Fixture
```python
# Discovered host misconfiguration payload
MOCK_HOST_AUDIT_INPUT = {
    "suid_binaries": ["/usr/bin/find", "/usr/bin/passwd"],
    "sudo_rules": ["(ALL) NOPASSWD: /usr/bin/vim", "(ALL) NOPASSWD: /usr/bin/systemctl"],
    "capabilities": ["/usr/bin/python3.11 = cap_setuid+ep"]
}
# Expected emitted finding check IDs:
# 1. HOST-PRIV-001 (SUID /usr/bin/find -> GTFOBins execution match)
# 2. HOST-SUDO-001 (NOPASSWD /usr/bin/vim -> GTFOBins execution match)
```

### 6.6 Enterprise cross-cutting security and automation vectors

The following vectors are mandatory acceptance evidence. Each vector MUST
exercise the production boundary named below, not only an isolated helper. The
traceability record MUST reference the actual repository test path and test
name; a planned or nonexistent test file is not evidence.

1. **Environment isolation:** `ProcessSupervisor` and every direct caller use a
   deny-by-default environment builder. Secret-like variables, dynamic loader
   variables, interpreter/module path variables, arbitrary tokens, and ambient
   proxy variables are excluded. Allowed variables are operation-specific and
   explicitly reviewed. Direct `os.environ` expansion fails the vector.
2. **Recursive output sanitization:** findings, tool output, telemetry,
   comments, exceptions, API responses, SSE, history replay, and exports all
   pass the same recursive sanitizer after authorization and before emission or
   persistence. Nested mappings, sequences, models, and exception text are
   covered.
3. **IPv6 target binding:** compressed and expanded IPv6 literals, bracketed
   URL forms, Host/SNI, native HTTP, and CLI target paths resolve to one
   canonical identity. No colon-delimited string split may discard IPv6 data.
4. **Internal-target authorization:** the internal-target decision is persisted
   narrowly and bound to tenant, actor, asset, immutable target seal,
   destination, purpose, policy version, and expiry. Downstream engines
   revalidate the decision; a detached boolean is insufficient.
5. **Taxonomy registry:** every emitted `check_id` and ASVS control resolves to
   the versioned Contract 06 registry, and CI reports zero unexplained direct
   literals, missing IDs, deprecated IDs, or unmapped findings.
6. **Evidence vectors:** digest inputs and masking use the exact Contract 06
   canonicalization, including no implicit trim/delimiter and six-prefix,
   four-suffix, literal-six-asterisk masking. Short values are non-reversible.
7. **Toolbox single-flight:** concurrent refreshes for one effective
   configuration share one live operation; each tool has explicit success,
   failure, timeout, and degraded-coverage state and the aggregate snapshot
   includes checked and failure timestamps. Different configurations do not
   share results.
8. **Version authority:** API, UI, exporters, rulesets, migrations, and
   contracts derive metadata from `backend/app/core/version.py`; CI rejects
   stale hardcoded release/schema/contract versions.
9. **Supply-chain manifest:** each managed tool has an evidence-backed,
   platform/architecture-specific acquisition record with approved source,
   digest/signature/provenance/build inputs where applicable. Unknown values
   remain unverified; no digest or provenance claim may be invented.
10. **JWT key normalization:** configured key IDs are normalized consistently
    before lookup and rotation; whitespace variants cannot select a different
    key or bypass rotation policy.
11. **Degraded history coverage:** git-history and other scanners distinguish
    execution failure, unavailable history, and zero findings. Failure MUST NOT
    be converted to an empty successful result.
12. **Deep target immutability:** nested target collections and authorization
    metadata cannot be mutated after sealing, including through retained input
    references.
13. **Relational integrity:** tenant-owned scan, finding, occurrence, and asset
    relationships have database-enforced foreign keys/constraints and
    transactional tests for invalid cross-tenant and orphan writes.
14. **Traceability integrity:** every Contract 08 requirement maps to an actual
    implementation and test path. Stale references are acceptance failures.

### 6.7 Full-capability automated-tool vectors

Metasploit, sqlmap, and Hydra MUST be tested as complete upstream-capability
adapters, not reduced "manual-only" substitutes. GTFOBins/LOLBAS MUST be tested
as the complete reviewed native rule catalog. Vectors MUST prove:

- managed installation is an authenticated, idempotent, serialized,
  deadline-bounded job with quarantine, extraction safety, atomic promotion,
  artifact/executable/provenance claim separation, and fail-closed trust;
- capability availability never authorizes execution, and each request carries
  tenant/project/asset/target-seal/tool/operation/options/policy/budget/principal;
- raw shell strings, executable paths, credential locations, provider selection,
  and unvalidated destinations cannot cross the adapter boundary;
- the complete upstream module/payload/option/protocol/dictionary surface
  remains available to an authorized policy, while default profiles select
  bounded operations without deleting capability;
- exploit, payload, session, shell, persistence, post-exploitation, high-risk
  SQLi options, and credential-resilience operations require explicit elevated
  authorization, isolated worker permissions, resource/account-impact budgets,
  and auditable decisions;
- installation, cancellation, failure, cache invalidation, and post-install
  live detection produce normalized durable telemetry and never trigger from
  login, page refresh, or anonymous requests.

