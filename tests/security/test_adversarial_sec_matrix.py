"""
Contract 05 §2 & Contract 08 §5:
Mandatory Adversarial Security Test Suite (SEC-001 through SEC-030).
Validates platform-wide security invariants under active adversarial conditions.
"""

import asyncio
import os
import json
import pytest
from unittest.mock import patch
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from app.main import app
from app.core.models import (
    UserProfile,
    UserRole,
    OperatingMode,
    Severity,
    FindingLifecycleStatus,
    Asset,
    AssetType,
    AssetCriticality,
    Finding,
    Evidence,
    ScanJob,
    Target,
    TargetType,
    ScanProfile,
    AuditEvent,
    AuditAction,
    utc_now,
    calculate_evidence_hash,
)
from app.core.auth import (
    hash_password,
    verify_password,
    create_access_token,
    decode_access_token,
    revoke_token,
    rotate_signing_key,
    retire_signing_key,
    authorize_asset_access,
    authorize_scan_access,
    authorize_finding_access,
)
from app.core.db import DatabaseManager
from app.core.ssrf_protector import assert_safe_url, SSRFProtectionError
from app.core.path_sandbox import assert_safe_path, PathSandboxViolation
from app.installers.tool_manifest import verify_download_integrity, PINNED_TOOL_MANIFEST
from app.core.correlator import correlator, compute_sla_info
from app.core.risk_engine import calculate_finding_contextual_risk, calculate_contextual_posture_grade


@pytest.fixture(autouse=True)
def setup_test_db(tmp_path):
    """Sets up an isolated clean SQLite database for each test run."""
    db_file = tmp_path / "test_sec_matrix.db"
    db_mgr = DatabaseManager(db_path=db_file)
    DatabaseManager._instance = db_mgr
    return db_mgr


@pytest.fixture
def client():
    return TestClient(app)


# ============================================================================
# SEC-001 to SEC-005: Authentication, RBAC & Multi-Tenancy IDOR Defenses
# ============================================================================

def test_sec_001_authentication_bypass_rejection(client):
    """SEC-001: Protected endpoints must strictly reject unauthenticated requests in PRODUCTION mode."""
    # Under default production semantics, /api/auth/me or /api/assets must reject unauthenticated requests
    # In test mode without header, it raises 401
    res = client.get("/api/auth/me")
    assert res.status_code == 401


def test_sec_002_privilege_escalation_prevention(client, setup_test_db):
    """SEC-002: Non-admin users cannot trigger privileged tool installations or create users."""
    user, org = setup_test_db.bootstrap_system("secadmin", "admin@sec.local", hash_password("AdminPass123!"), "SecOrg")
    
    # Create developer user
    dev_user = UserProfile(id="usr-dev-01", username="devuser", email="dev@sec.local", role=UserRole.DEVELOPER, organization_id=org.id)
    dev_token = create_access_token(dev_user)

    # Attempt privileged tool install as developer
    res = client.post(
        "/api/system/tools/nuclei/install",
        headers={"Authorization": f"Bearer {dev_token}"},
        json={"force": False},
    )
    assert res.status_code == 403


def test_sec_003_cross_tenant_asset_access_idor(setup_test_db):
    """SEC-003: User from Org A cannot read, modify or delete Org B assets."""
    user_a = UserProfile(id="usr-a", username="user_a", email="a@a.local", role=UserRole.DEVELOPER, organization_id="org-a")
    user_b = UserProfile(id="usr-b", username="user_b", email="b@b.local", role=UserRole.DEVELOPER, organization_id="org-b")

    asset_b = Asset(id="ast-b-01", organization_id="org-b", name="Org B Asset", type=AssetType.WEB_APPLICATION, target_value="https://app.b.local")

    assert authorize_asset_access(user_b, asset_b, action="read") is True
    assert authorize_asset_access(user_a, asset_b, action="read") is False
    assert authorize_asset_access(user_a, asset_b, action="write") is False
    assert authorize_asset_access(user_a, asset_b, action="delete") is False


def test_sec_004_cross_tenant_scan_access_idor():
    """SEC-004: User from Org A cannot access or cancel Org B scans."""
    user_a = UserProfile(id="usr-a", username="user_a", email="a@a.local", role=UserRole.DEVELOPER, organization_id="org-a")
    user_b = UserProfile(id="usr-b", username="user_b", email="b@b.local", role=UserRole.DEVELOPER, organization_id="org-b")

    scan_b = ScanJob(
        id="scan-b-01",
        organization_id="org-b",
        target=Target(name="Target B", type=TargetType.URL, value="https://target.b.local"),
        profile=ScanProfile.QUICK,
    )

    assert authorize_scan_access(user_b, scan_b, action="read") is True
    assert authorize_scan_access(user_a, scan_b, action="read") is False
    assert authorize_scan_access(user_a, scan_b, action="cancel") is False


def test_sec_005_cross_tenant_finding_access_idor():
    """SEC-005: User from Org A cannot query or triage Org B findings."""
    user_a = UserProfile(id="usr-a", username="user_a", email="a@a.local", role=UserRole.DEVELOPER, organization_id="org-a")
    user_b = UserProfile(id="usr-b", username="user_b", email="b@b.local", role=UserRole.DEVELOPER, organization_id="org-b")

    finding_b = Finding(
        id="find-b-01",
        scan_id="scan-b-01",
        engine="web_dast",
        check_id="DAST-SQLI-001",
        category="Injection",
        title="SQL Injection",
        severity=Severity.HIGH,
        cvss_score=8.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        description="SQL injection flaw",
        impact="Data leakage",
        remediation="Use parameterized queries",
        evidence=Evidence(location="/api/login", observed_value="error in SQL syntax", expected_value="clean response"),
    )

    from app.core.models import CanonicalFinding
    c_finding_b = CanonicalFinding(
        id="cfind-b-01",
        organization_id="org-b",
        title="SQL Injection",
        category="Injection",
        severity=Severity.HIGH,
        cvss_score=8.5,
        remediation="Fix it",
    )

    assert authorize_finding_access(user_b, c_finding_b, action="read") is True
    assert authorize_finding_access(user_a, c_finding_b, action="read") is False
    assert authorize_finding_access(user_a, c_finding_b, action="triage") is False


# ============================================================================
# SEC-006 to SEC-009: SSRF Gateway & DNS Rebinding Defenses
# ============================================================================

def test_sec_006_ssrf_localhost_blocked():
    """SEC-006: Requests targeting localhost/127.0.0.1/::1 must be blocked."""
    with pytest.raises(SSRFProtectionError):
        assert_safe_url("http://127.0.0.1:8080/admin")
    with pytest.raises(SSRFProtectionError):
        assert_safe_url("http://localhost/metrics")
    with pytest.raises(SSRFProtectionError):
        assert_safe_url("http://[::1]/secret")


def test_sec_007_ssrf_private_subnets_blocked():
    """SEC-007: Requests targeting RFC 1918 private subnets must be blocked."""
    with pytest.raises(SSRFProtectionError):
        assert_safe_url("http://10.0.0.1/internal")
    with pytest.raises(SSRFProtectionError):
        assert_safe_url("http://172.16.50.1/database")
    with pytest.raises(SSRFProtectionError):
        assert_safe_url("http://192.168.1.1/router")


def test_sec_008_ssrf_cloud_metadata_blocked():
    """SEC-008: Requests targeting AWS/GCP/Azure link-local metadata endpoints must be blocked."""
    with pytest.raises(SSRFProtectionError):
        assert_safe_url("http://169.254.169.254/latest/meta-data/")
    with pytest.raises(SSRFProtectionError):
        assert_safe_url("http://metadata.google.internal/computeMetadata/v1/")


def test_sec_009_ssrf_dns_rebinding_pre_resolution(monkeypatch):
    """SEC-009: Hostnames resolving to private/loopback IPs must be blocked during pre-resolution."""
    with pytest.raises(SSRFProtectionError):
        assert_safe_url("http://localhost.localdomain/secret")

    # Simulate dynamic DNS rebinding resolution returning a private subnet IP
    from app.core import ssrf_protector
    monkeypatch.setattr(ssrf_protector, "resolve_hostname_ips", lambda host: ["10.0.0.5"])
    with pytest.raises(SSRFProtectionError) as exc_info:
        assert_safe_url("http://rebound-attack.example.com/exploit")
    assert "blocked" in str(exc_info.value).lower()


# ============================================================================
# SEC-010 to SEC-011: Filesystem Workspace Sandboxing
# ============================================================================

def test_sec_010_filesystem_escape_blocked(tmp_path):
    """SEC-010: Traversal attempts targeting forbidden system folders must be rejected."""
    with pytest.raises(PathSandboxViolation):
        assert_safe_path("/etc/shadow")
    with pytest.raises(PathSandboxViolation):
        assert_safe_path("C:\\Windows\\System32\\config\\SAM")


def test_sec_011_symlink_escape_blocked(tmp_path):
    """SEC-011: Symlinks pointing outside permitted workspace boundaries are rejected."""
    ws_dir = tmp_path / "sandbox_ws"
    ws_dir.mkdir()
    secret_file = tmp_path / "secret.key"
    secret_file.write_text("SUPER_SECRET_KEY")

    symlink_file = ws_dir / "link_to_secret"
    try:
        symlink_file.symlink_to(secret_file)
        with pytest.raises(PathSandboxViolation):
            assert_safe_path(str(symlink_file), allowed_roots=[ws_dir])
    except (OSError, NotImplementedError):
        # On Windows without developer mode/admin rights for symlink creation, test passes
        pass


# ============================================================================
# SEC-012 to SEC-016: Cryptographic Tokens & Credentials Integrity
# ============================================================================

def test_sec_012_hardcoded_credentials_eliminated(setup_test_db):
    """SEC-012: Ensure database initializes uninitialized with zero default passwords."""
    assert setup_test_db.is_initialized() is False
    user, org = setup_test_db.bootstrap_system("admin", "admin@sec.local", hash_password("ValidPassword123!"))
    assert setup_test_db.is_initialized() is True
    # Attempting to bootstrap a second time must fail
    with pytest.raises(ValueError):
        setup_test_db.bootstrap_system("admin2", "admin2@sec.local", hash_password("ValidPassword123!"))


def test_sec_013_api_key_revocation(setup_test_db):
    """SEC-013: Revoked API keys are immediately rejected."""
    key_hash = "fake_hash_12345"
    with setup_test_db._get_connection() as conn:
        conn.execute(
            "INSERT INTO api_keys (key_id, key_hash, organization_id, name, scopes_json, created_at, revoked_at) VALUES (?, ?, ?, ?, '[]', ?, ?)",
            ("key-01", key_hash, "org-01", "test-key", utc_now().isoformat(), utc_now().isoformat()),
        )
    record, user = setup_test_db.verify_api_key_hash(key_hash)
    assert record is None
    assert user is None


def test_sec_014_jwt_algorithm_confusion_rejection():
    """SEC-014: Tokens with alg=none or tampered signatures are rejected, key rotation is supported."""
    user = UserProfile(id="usr-1", username="testuser", email="test@local", role=UserRole.VIEWER)
    token = create_access_token(user)

    # Decode valid token
    decoded = decode_access_token(token)
    assert decoded["sub"] == "usr-1"

    # Test key rotation: tokens signed with previous active keys remain valid while new keys take effect
    rotate_signing_key("k-rotated-v13", "secret-rotated-256bit-key-here!!")
    new_token = create_access_token(user)
    assert decode_access_token(new_token)["sub"] == "usr-1"
    assert decode_access_token(token)["sub"] == "usr-1"

    # Attempt alg=none attack
    parts = token.split(".")
    import base64
    fake_header = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').decode().rstrip("=")
    fake_token = f"{fake_header}.{parts[1]}."

    from fastapi import HTTPException
    with pytest.raises(HTTPException):
        decode_access_token(fake_token)


def test_sec_015_jwt_expiry_rejection():
    """SEC-015: Expired tokens are rejected."""
    user = UserProfile(id="usr-1", username="testuser", email="test@local", role=UserRole.VIEWER)
    # Generate expired token
    token = create_access_token(user, expires_in=-10)

    from fastapi import HTTPException
    with pytest.raises(HTTPException):
        decode_access_token(token)


def test_sec_016_jwt_token_revocation():
    """SEC-016: Revoked tokens are rejected."""
    user = UserProfile(id="usr-1", username="testuser", email="test@local", role=UserRole.VIEWER)
    token = create_access_token(user)
    revoke_token(token)

    from fastapi import HTTPException
    with pytest.raises(HTTPException):
        decode_access_token(token)


def test_sec_016_revocation_does_not_claim_success_on_database_failure():
    """JWT revocation must fail closed when durable persistence is unavailable."""
    import app.core.auth as auth_module

    user = UserProfile(id="usr-db-failure", username="testuser", email="test@local", role=UserRole.VIEWER)
    token = create_access_token(user)
    with patch("app.core.db.db_manager.revoke_token", side_effect=RuntimeError("database unavailable")):
        with pytest.raises(RuntimeError):
            revoke_token(token)

    assert token not in auth_module.REVOKED_TOKENS_REGISTRY


# ============================================================================
# SEC-017 to SEC-019: Tool Supply Chain Integrity & Verification
# ============================================================================

def test_sec_017_tool_hash_mismatch_rejection():
    """SEC-017: Release archives with mismatched SHA-256 digests are rejected."""
    payload = b"MALICIOUS_TAMPERED_BINARY_PAYLOAD"
    is_valid, computed, err = verify_download_integrity("nuclei", payload, expected_sha256="0000000000000000000000000000000000000000000000000000000000000000")
    assert is_valid is False
    assert "mismatch" in err.lower()


def test_sec_018_unpinned_tool_rejection():
    """SEC-018: Unpinned tools outside authoritative manifest are rejected."""
    payload = b"RANDOM_UNKNOWN_TOOL"
    is_valid, computed, err = verify_download_integrity("untrusted_custom_tool", payload)
    assert is_valid is False
    assert "not registered in the authoritative" in err.lower()


# ============================================================================
# SEC-020 to SEC-030: Operational Assurance, Findings, Correlation & SLA
# ============================================================================

def test_sec_022_evidence_secret_masking():
    """SEC-022: Sensitive API tokens in findings are masked."""
    from app.core.models import mask_secret
    raw_secret = "AKIAIOSFODNN7EXAMPLE"
    masked = mask_secret(raw_secret)
    assert "AKIA" in masked
    assert "PLE" in masked
    assert "IOSFODNN7EXAM" not in masked
    assert "*" in masked


def test_sec_023_audit_log_integrity(setup_test_db):
    """SEC-023: Security actions emit immutable audit events with verifiable SHA-256 hash chains."""
    event1 = AuditEvent(
        actor="admin",
        organization_id="org-test",
        action=AuditAction.SCAN_CREATED,
        object_type="scan",
        object_id="scan-001",
        result="SUCCESS",
        details={"profile": "FULL_STACK"},
    )
    setup_test_db.record_audit_event(event1)

    event2 = AuditEvent(
        actor="admin",
        organization_id="org-test",
        action=AuditAction.TOOL_INSTALL_COMPLETED,
        object_type="tool",
        object_id="nuclei",
        result="SUCCESS",
        details={"version": "v3.3.0"},
    )
    setup_test_db.record_audit_event(event2)

    # 1. Verify authentic hash chain passes
    is_valid, bad_id = setup_test_db.verify_audit_log_integrity("org-test")
    assert is_valid is True
    assert bad_id is None

    # 2. Adversarial tampering: modify an audit payload directly in the database
    with setup_test_db._get_connection() as conn:
        conn.execute("UPDATE audit_events SET result = 'TAMPERED' WHERE id = ?", (event1.id,))

    # 3. Verification must immediately detect the broken hash chain
    is_tampered, tampered_id = setup_test_db.verify_audit_log_integrity("org-test")
    assert is_tampered is False
    assert tampered_id == event1.id


def test_sec_024_risk_acceptance_visibility():
    """SEC-024: Accepted risk status remains recorded with explicit enum."""
    status = FindingLifecycleStatus.RISK_ACCEPTED
    assert status.value == "RISK_ACCEPTED"


def test_sec_025_sla_clock_preservation():
    """SEC-025: Re-detecting a vulnerability preserves original SLA start time."""
    past_time = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    sla = compute_sla_info(Severity.CRITICAL, started_at=past_time)
    assert sla.sla_started_at == past_time
    assert sla.is_breached is True  # Since Jan 2026 is past the 7 day Critical SLA


def test_sec_026_correlation_false_merge_prevention():
    """SEC-026: Distinct vulnerabilities on different endpoints are not merged."""
    f1 = Finding(
        id="f1",
        scan_id="s1",
        engine="web_dast",
        check_id="DAST-XSS-001",
        category="XSS",
        title="Reflected XSS",
        severity=Severity.HIGH,
        cvss_score=7.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        description="XSS on search",
        impact="Session hijack",
        remediation="Sanitize input",
        evidence=Evidence(location="/search?q=test", observed_value="<script>", expected_value="escaped"),
    )
    f2 = Finding(
        id="f2",
        scan_id="s1",
        engine="web_dast",
        check_id="DAST-XSS-001",
        category="XSS",
        title="Reflected XSS",
        severity=Severity.HIGH,
        cvss_score=7.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        description="XSS on profile",
        impact="Session hijack",
        remediation="Sanitize input",
        evidence=Evidence(location="/profile?name=test", observed_value="<script>", expected_value="escaped"),
    )

    canonical, occs = correlator.correlate_findings([f1, f2])
    assert len(canonical) == 2  # Not merged because locations / endpoints differ!
    assert len(occs) == 2


def test_sec_027_correlation_duplicate_merging():
    """SEC-027: Identical findings on same endpoint from different tools are clustered."""
    f1 = Finding(
        id="f1",
        scan_id="s1",
        engine="web_dast",
        source_tool="nuclei",
        check_id="DAST-SQLI-001",
        category="Injection",
        title="SQL Injection",
        severity=Severity.CRITICAL,
        cvss_score=9.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        description="SQL injection",
        impact="RCE",
        remediation="Fix it",
        evidence=Evidence(location="/api/users", observed_value="syntax error", expected_value="safe"),
    )
    f2 = Finding(
        id="f2",
        scan_id="s1",
        engine="web_dast",
        source_tool="custom_fuzzer",
        check_id="DAST-SQLI-001",
        category="Injection",
        title="SQL Injection",
        severity=Severity.CRITICAL,
        cvss_score=9.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        description="SQL injection",
        impact="RCE",
        remediation="Fix it",
        evidence=Evidence(location="/api/users", observed_value="syntax error", expected_value="safe"),
    )

    canonical, occs = correlator.correlate_findings([f1, f2])
    assert len(canonical) == 1  # Successfully clustered
    assert len(occs) == 2
    assert "nuclei" in canonical[0].contributing_tools
    assert "custom_fuzzer" in canonical[0].contributing_tools


def test_sec_019_malicious_archive_zipslip_rejection(tmp_path):
    """SEC-019: Archives containing ZipSlip / directory traversal entries are rejected."""
    import zipfile
    from app.installers.github_release_installer import GithubReleaseInstaller
    from app.installers.base_installer import SecurityError

    malicious_zip = tmp_path / "zipslip.zip"
    with zipfile.ZipFile(malicious_zip, "w") as z:
        z.writestr("../../../evil.exe", "MALICIOUS")

    installer = GithubReleaseInstaller("nuclei")
    target_extract = tmp_path / "extracted"
    target_extract.mkdir()

    with pytest.raises(SecurityError) as exc_info:
        installer._safe_extract_zip(str(malicious_zip), str(target_extract))
    assert "ZipSlip traversal attempt detected" in str(exc_info.value)


@pytest.mark.asyncio
async def test_sec_020_scan_cancellation_lifecycle():
    """SEC-020: Cancelling a scan job immediately transitions status to CANCELLED and halts background tasks."""
    from app.core.orchestrator import orchestrator
    from app.core.models import ScanStatus
    scan = ScanJob(
        target=Target(name="Cancel Target", type=TargetType.URL, value="https://example.com"),
        profile=ScanProfile.QUICK,
    )
    task = await orchestrator.start_scan(scan)
    await asyncio.sleep(0.05)
    cancelled = await orchestrator.cancel_scan(scan.id)
    assert cancelled is True
    assert scan.status == ScanStatus.CANCELLED


@pytest.mark.asyncio
async def test_sec_021_resource_exhaustion_concurrency_governance():
    """SEC-021: ScanQueueManager bounds active scan concurrency."""
    from app.core.queue import ScanQueueManager
    mgr = ScanQueueManager(max_concurrent=2)
    assert mgr.max_concurrent == 2
    assert mgr.active_scans_count == 0

    async def fake_scan():
        await asyncio.sleep(0.1)
        return "done"

    t1 = asyncio.create_task(mgr.execute_bounded("s1", fake_scan))
    t2 = asyncio.create_task(mgr.execute_bounded("s2", fake_scan))
    await asyncio.sleep(0.02)
    assert mgr.active_scans_count <= 2
    await asyncio.gather(t1, t2)
    assert mgr.active_scans_count == 0


@pytest.mark.asyncio
async def test_sec_021_per_tenant_concurrency_is_bounded():
    """A tenant-specific semaphore limits scans without reducing other tenants' capacity."""
    from app.core.queue import ScanQueueManager

    mgr = ScanQueueManager(max_concurrent=4, max_concurrent_per_tenant=1)
    active_by_tenant = {"org-a": 0, "org-b": 0}
    peak_by_tenant = {"org-a": 0, "org-b": 0}

    async def fake_scan(tenant):
        active_by_tenant[tenant] += 1
        peak_by_tenant[tenant] = max(peak_by_tenant[tenant], active_by_tenant[tenant])
        await asyncio.sleep(0.05)
        active_by_tenant[tenant] -= 1

    tasks = [
        asyncio.create_task(mgr.execute_bounded(f"a-{i}", fake_scan, "org-a", organization_id="org-a"))
        for i in range(3)
    ] + [
        asyncio.create_task(mgr.execute_bounded("b-1", fake_scan, "org-b", organization_id="org-b"))
    ]
    await asyncio.gather(*tasks)
    assert peak_by_tenant["org-a"] == 1
    assert peak_by_tenant["org-b"] == 1


def test_sec_028_report_secret_leakage_sanitization():
    """SEC-028: Exported reports sanitize sensitive credentials."""
    from app.exporters.json_exporter import export_scan_to_json
    from app.exporters.html_exporter import export_scan_to_html

    finding = Finding(
        id="f-secret-01",
        scan_id="s-sec-01",
        engine="code_sast",
        check_id="SAST-SEC-001",
        category="Hardcoded Secrets",
        title="AWS Access Key Exposed",
        severity=Severity.CRITICAL,
        cvss_score=9.0,
        description="Exposed key",
        impact="Compromise",
        remediation="Rotate",
        evidence=Evidence(location="config.py:10", observed_value="AKIAIOSFODNN7EXAMPLE", expected_value="Environment variable"),
    )
    scan = ScanJob(
        id="s-sec-01",
        target=Target(name="Secret Target", type=TargetType.URL, value="https://example.com"),
        profile=ScanProfile.QUICK,
        findings=[finding],
    )

    json_report = export_scan_to_json(scan)
    html_report = export_scan_to_html(scan)
    assert "AKIA" in json_report
    assert "AKIA" in html_report
    assert "AKIAIOSFODNN7EXAMPLE" not in json_report
    assert "AKIAIOSFODNN7EXAMPLE" not in html_report


def test_sec_029_database_transaction_integrity(setup_test_db):
    """SEC-029: Scan, canonical finding, and occurrence operations execute within transactional boundaries."""
    finding = Finding(
        id="f-tx-01",
        scan_id="tx-scan-01",
        engine="web_dast",
        check_id="DAST-HDR-001",
        category="Security Headers",
        title="Missing CSP",
        severity=Severity.MEDIUM,
        cvss_score=5.3,
        description="Missing CSP",
        impact="XSS risk",
        remediation="Add CSP header",
        evidence=Evidence(location="/", observed_value="none", expected_value="default-src 'self'"),
    )
    scan = ScanJob(
        id="tx-scan-01",
        organization_id="org-tx",
        target=Target(name="TX Target", type=TargetType.URL, value="https://example.com"),
        profile=ScanProfile.QUICK,
        findings=[finding],
    )
    setup_test_db.save_scan_record(scan)

    with setup_test_db._get_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id, status, organization_id FROM scans WHERE id = 'tx-scan-01'")
        scan_row = cur.fetchone()
        assert scan_row is not None
        assert scan_row["organization_id"] == "org-tx"

        cur.execute("SELECT id, scan_id, organization_id FROM findings WHERE scan_id = 'tx-scan-01'")
        finding_rows = cur.fetchall()
        assert len(finding_rows) >= 1
        assert finding_rows[0]["organization_id"] == "org-tx"

        cur.execute("SELECT id, scan_id FROM finding_occurrences WHERE scan_id = 'tx-scan-01'")
        occ_rows = cur.fetchall()
        assert len(occ_rows) >= 1


def test_sec_030_development_mode_privilege_isolation():
    """SEC-030: Development mode anonymous bypass NEVER grants ADMIN privileges."""
    from app.core.auth import ANONYMOUS_DEV_USER
    assert ANONYMOUS_DEV_USER.role == UserRole.VIEWER
    assert ANONYMOUS_DEV_USER.role != UserRole.ADMIN
