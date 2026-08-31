# Contract 08: Technical Implementation, Authorization Service, Supply Chain & Test Vectors

**Project Name:** CyberAssess Automated Security Assessment & Vulnerability Management Platform  
**Document Version:** 10.0.0 (Enterprise Technical Implementation, Multi-Layer Authorization Service, SSRF Rebinding Defense, Workspace Jail & Adversarial Vectors)  
**Status:** APPROVED / AUTHORITATIVE SPECIFICATION  
**Scope Authority:** Technical Implementations, Authorization Invariants, Hardened Gateways, Supply Chain Hashes & Test Vectors  

---

## 1. Centralized Multi-Layer Authorization Service

All resource operations must be validated against the centralized authorization service:

```python
def authorize_asset_access(user: UserProfile, asset: Asset, action: str = "read") -> bool:
    """Verifies user organization matches asset organization and user has required role."""
    if user.role == UserRole.ADMIN and user.organization_id is None:
        return True  # System super-admin
    if asset.organization_id and asset.organization_id != user.organization_id:
        return False  # Cross-tenant access denied
    if action == "write" and user.role not in (UserRole.ADMIN, UserRole.SECURITY_ANALYST, UserRole.DEVELOPER):
        return False
    if action == "delete" and user.role != UserRole.ADMIN:
        return False
    return True

def authorize_scan_access(user: UserProfile, scan: ScanJob, action: str = "read") -> bool:
    """Verifies scan ownership and permissions."""
    if user.role == UserRole.ADMIN and user.organization_id is None:
        return True
    if scan.organization_id and scan.organization_id != user.organization_id:
        return False
    if action in ("control", "cancel", "delete") and user.role not in (UserRole.ADMIN, UserRole.SECURITY_ANALYST, UserRole.DEVELOPER):
        return False
    return True
```

---

## 2. SSRF Gateway & DNS Rebinding Invariants

1. **Denylisted CIDRs:**
   - Loopback: `127.0.0.0/8`, `::1`
   - RFC 1918 Private: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
   - Link-Local: `169.254.0.0/16`, `fe80::/10`
   - Cloud Metadata: `169.254.169.254`, `metadata.google.internal`
   - Multicast & Broadcast: `224.0.0.0/4`, `255.255.255.255/32`
2. **DNS Pre-Resolution & Pinning:** The validated IP is pinned to prevent time-of-check to time-of-use (TOCTOU) DNS rebinding attacks.
3. **Hop-by-Hop Redirect Validation:** Every HTTP redirect target is re-validated against the SSRF gateway before the client follows the redirect.

---

## 3. Authorized Workspace Jail & Sandbox Invariants

1. **Workspace Boundary:** Target local paths are valid if and only if `resolved_path.startswith(authorized_workspace_root)`.
2. **Symlink Resolution:** Symlinks are evaluated with `Path.resolve()` prior to boundary validation.
3. **Sensitive System Path Denylist:** `/etc`, `/root`, `/var/run`, `C:\Windows`, `SAM`, `.ssh`, `.aws`, `.kube` remain forbidden even within custom paths.

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

## 5. Requirement Traceability Matrix

| Requirement | Contract Section | Implementation Source | Test Module / Scenario |
|---|---|---|---|
| Zero-Trust & RBAC | Contract 01 §3, Contract 04 §2 | `app/core/auth.py`, `app/api/auth.py` | `test_security_hardening.py`, `SEC-001`, `SEC-002` |
| Multi-Tenancy & IDOR | Contract 04 §2, Contract 08 §1 | `app/core/auth.py`, `app/api/assets.py` | `SEC-003`, `SEC-004`, `SEC-005` |
| SSRF & DNS Rebinding | Contract 01 §5, Contract 08 §2 | `app/core/ssrf_protector.py` | `SEC-006`, `SEC-007`, `SEC-008`, `SEC-009` |
| Workspace Sandbox | Contract 01 §5, Contract 08 §3 | `app/core/path_sandbox.py` | `SEC-010`, `SEC-011` |
| Supply Chain Integrity | Contract 03 §2, Contract 08 §4 | `app/installers/tool_manifest.py` | `SEC-017`, `SEC-018`, `SEC-019` |
| Canonical Findings & SLA | Contract 02 §4 | `app/core/correlator.py`, `app/core/db.py` | `SEC-024`, `SEC-025`, `SEC-026`, `SEC-027` |
| Process Cancellation | Contract 03 §3 | `app/core/orchestrator.py`, `app/core/queue.py` | `SEC-020` |
| Audit Logging | Contract 02 §6, Contract 04 §1 | `app/core/db.py`, `app/api/auth.py` | `SEC-023` |
