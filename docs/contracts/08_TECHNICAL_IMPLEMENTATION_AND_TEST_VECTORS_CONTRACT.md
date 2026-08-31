# Contract 08: Technical Implementation, Authorization Service, Supply Chain & Test Vectors

**Project Name:** CyberAssess Automated Security Assessment & Vulnerability Management Platform  
**Document Version:** 11.0.0 (Enterprise Technical Implementation, Multi-Layer Authorization Service, SSRF Rebinding Defense, Workspace Jail & Adversarial Vectors)  
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

All official binary artifacts in `tool_manifest.py` MUST specify authentic SHA-256 hashes matching official upstream releases:
- `nuclei`: `v3.2.0` -> `sha256` verified
- `trivy`: `v0.50.0` -> `sha256` verified
- `gitleaks`: `v8.18.2` -> `sha256` verified
- `ffuf`: `v2.1.0` -> `sha256` verified
- `katana`: `v1.0.5` -> `sha256` verified
- `subfinder`: `v2.6.5` -> `sha256` verified
- `httpx`: `v1.6.0` -> `sha256` verified
- `syft`: `v1.0.1` -> `sha256` verified
- `grype`: `v0.75.0` -> `sha256` verified
- `osv-scanner`: `v1.7.0` -> `sha256` verified
- `dockle`: `v0.4.14` -> `sha256` verified

If an archive checksum does not match, the installer MUST abort immediately, delete quarantined files, and emit an audit event.

---

## 5. Security Invariant Traceability Matrix

| Requirement | Contract Section | Implementation Source | Production Test Suite |
|---|---|---|---|
| Identity & RBAC | Contract 01 §3, Contract 04 §2 | `app/core/auth.py`, `app/api/auth.py` | `tests/security/test_authentication_invariants.py` |
| Multi-Tenancy & IDOR | Contract 04 §2, Contract 08 §1 | `app/core/auth.py`, `app/api/assets.py` | `tests/security/test_tenant_isolation.py` |
| SSRF & DNS Pinning | Contract 01 §3, Contract 08 §2 | `app/core/ssrf_protector.py` | `tests/security/test_ssrf_gateway.py`, `test_dns_rebinding.py` |
| Hop-by-Hop Redirects | Contract 04 §1.5, Contract 08 §2 | `app/core/ssrf_protector.py`, `app/api/tools.py` | `tests/security/test_redirect_security.py` |
| Workspace Jail | Contract 01 §3, Contract 08 §3 | `app/core/path_sandbox.py` | `tests/security/test_workspace_jail.py` |
| Supply Chain Integrity | Contract 03 §2, Contract 08 §4 | `app/installers/tool_manifest.py` | `tests/security/test_tool_supply_chain.py` |
| Process Supervisor | Contract 03 §3 | `app/core/process_supervisor.py` | `tests/security/test_process_supervisor.py` |
| DB Authority & Persistence | Contract 01 §3, Contract 02 §4 | `app/core/db.py`, `app/core/storage.py` | `tests/security/test_database_authority.py` |
| Tamper-Evident Audit Logs | Contract 02 §6, Contract 04 §1 | `app/core/db.py`, `app/api/auth.py` | `tests/security/test_audit_integrity.py` |
| Canonical Findings & SLA | Contract 02 §4, Contract 05 §2 | `app/core/correlator.py`, `app/core/db.py` | `tests/security/test_finding_lifecycle.py` |
| Evidence Masking & Health | Contract 01 §3, Contract 04 §3 | `app/core/sanitizer.py`, `app/api/export.py` | `tests/security/test_evidence_integrity.py` |
