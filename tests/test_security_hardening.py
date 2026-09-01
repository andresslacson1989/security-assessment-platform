"""
Contract 01, Contract 04 & Contract 08 §12:
Automated Security Hardening, SSRF Gateway, RBAC, Path Sandbox & Integrity Test Suite.
"""

import pytest
import pytest_asyncio
from pathlib import Path
from app.core.ssrf_protector import is_ip_allowed, validate_target_url, assert_safe_url, SSRFProtectionError
from app.core.path_sandbox import is_path_safe, assert_safe_path, PathSandboxViolation
from app.core.auth import (
    UserProfile,
    UserRole,
    hash_password,
    verify_password,
    create_access_token,
    decode_access_token,
)
from app.installers.tool_manifest import calculate_sha256, verify_download_integrity
from app.core.models import (
    Asset,
    AssetType,
    AssetCriticality,
    Finding,
    Evidence,
    Severity,
    FindingLifecycleStatus,
    CorrelationType,
)
from app.main import _load_allowed_origins


def test_cors_origin_configuration_fails_closed():
    assert _load_allowed_origins("https://console.example.com,http://localhost:3000") == [
        "https://console.example.com", "http://localhost:3000"
    ]
    with pytest.raises(RuntimeError, match="wildcard"):
        _load_allowed_origins("*")
    with pytest.raises(RuntimeError, match="malformed"):
        _load_allowed_origins("https://console.example.com/path")
from app.core.db import DatabaseManager
from app.core.correlator import correlator
from app.core.risk_engine import calculate_finding_contextual_risk, calculate_contextual_posture_grade


def test_frontend_does_not_persist_bearer_tokens_in_browser_storage():
    frontend_js = (Path(__file__).resolve().parents[1] / "frontend" / "js" / "app.js").read_text(encoding="utf-8")
    assert "localStorage." not in frontend_js
    assert "sessionStorage." not in frontend_js
    assert "this.accessToken" in frontend_js


def test_frontend_uses_context_safe_encoding_for_dynamic_inline_handlers():
    frontend_js = (Path(__file__).resolve().parents[1] / "frontend" / "js" / "app.js").read_text(encoding="utf-8")
    assert "encodeInlineArg(value)" in frontend_js
    assert "decodeURIComponent('${this.encodeInlineArg(" in frontend_js
    assert "onclick=\"window.app.handleInstallTool('${t.name}'" not in frontend_js
    assert "onclick=\"window.auditAsset('${this.escapeHtml(" not in frontend_js
    assert "<td><code>${t.category}</code></td>" not in frontend_js


# ============================================================================
# 1. SSRF Protection Gateway Tests
# ============================================================================

def test_ssrf_blocks_loopback_and_private_ips():
    # Loopback
    assert is_ip_allowed("127.0.0.1")[0] is False
    assert is_ip_allowed("127.0.0.2")[0] is False
    assert is_ip_allowed("::1")[0] is False

    # RFC 1918 Private
    assert is_ip_allowed("10.0.0.1")[0] is False
    assert is_ip_allowed("172.16.0.1")[0] is False
    assert is_ip_allowed("192.168.1.100")[0] is False

    # Cloud Metadata
    assert is_ip_allowed("169.254.169.254")[0] is False

    # Public Safe IPs
    assert is_ip_allowed("8.8.8.8")[0] is True
    assert is_ip_allowed("1.1.1.1")[0] is True
    assert is_ip_allowed("93.184.216.34")[0] is True


def test_ssrf_validate_target_url():
    # Blocked URLs
    assert validate_target_url("http://127.0.0.1:8000/admin")[0] is False
    assert validate_target_url("http://localhost:8000/")[0] is False
    assert validate_target_url("http://169.254.169.254/latest/meta-data/")[0] is False
    assert validate_target_url("http://metadata.google.internal/computeMetadata/v1/")[0] is False
    assert validate_target_url("http://10.200.1.5/internal")[0] is False

    # Safe Public URLs
    assert validate_target_url("https://example.com")[0] is True
    assert validate_target_url("https://github.com")[0] is True

    # Admin Override Mode
    assert validate_target_url("http://192.168.1.1", allow_internal=True)[0] is True

    # Exception assertion
    with pytest.raises(SSRFProtectionError):
        assert_safe_url("http://127.0.0.1/secret")


# ============================================================================
# 2. Target Path Sandboxing & Workspace Containment Tests
# ============================================================================

def test_path_sandboxing_blocks_system_and_traversal():
    # Sensitive system files
    assert is_path_safe("/etc/passwd")[0] is False
    assert is_path_safe("/etc/shadow")[0] is False
    assert is_path_safe("/root/.ssh/id_rsa")[0] is False
    assert is_path_safe("C:\\Windows\\System32\\config\\SAM")[0] is False

    # Traversal strings
    assert is_path_safe("../../etc/shadow")[0] is False

    # Exception assertion
    with pytest.raises(PathSandboxViolation):
        assert_safe_path("/etc/passwd")


# ============================================================================
# 3. Authentication, JWT & RBAC Tests
# ============================================================================

def test_password_hashing_and_verification():
    raw_pw = "EnterpriseP@ssword2026!"
    hashed = hash_password(raw_pw)
    assert hashed.startswith("pbkdf2_sha256$")
    assert verify_password(raw_pw, hashed) is True
    assert verify_password("WrongPassword", hashed) is False


def test_jwt_token_lifecycle():
    user = UserProfile(
        id="usr-test-1",
        username="sec_analyst",
        email="analyst@example.com",
        role=UserRole.SECURITY_ANALYST,
    )
    token = create_access_token(user, expires_in=3600)
    assert isinstance(token, str)
    assert len(token.split(".")) == 3

    payload = decode_access_token(token)
    assert payload["sub"] == "usr-test-1"
    assert payload["username"] == "sec_analyst"
    assert payload["role"] == "SECURITY_ANALYST"


# ============================================================================
# 4. Tool Supply Chain & Cryptographic Verification Tests
# ============================================================================

def test_sha256_integrity_verification():
    dummy_data = b"Official Verified Binary Bytes 2026"
    correct_hash = calculate_sha256(dummy_data)

    # Valid Hash
    valid, computed, err = verify_download_integrity("nuclei", dummy_data, expected_sha256=correct_hash)
    assert valid is True
    assert computed == correct_hash
    assert err is None

    # Tampered / Mismatched Hash
    valid_bad, _, err_bad = verify_download_integrity("nuclei", dummy_data, expected_sha256="badhash1234567890")
    assert valid_bad is False
    assert "mismatch" in err_bad.lower()


# ============================================================================
# 5. Finding Correlation & Contextual Risk Engine Tests
# ============================================================================

def test_sast_dast_finding_correlation():
    # 1 DAST finding on /api/login and 1 SAST finding in auth.py with same Category
    dast_f = Finding(
        id="f-dast-1",
        scan_id="s-1",
        engine="web_dast",
        check_id="DAST-INJ-001",
        category="SQL Injection",
        title="SQL Injection Vulnerability in login parameter",
        severity=Severity.HIGH,
        cvss_score=8.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        cwe_id="CWE-89",
        owasp_category="A03:2021-Injection",
        nist_control="SI-10",
        description="SQL injection in login endpoint",
        impact="Database unauthorized data access",
        remediation="Use parameterized statements.",
        evidence=Evidence(
            location="https://example.com/api/login",
            observed_value="Observed time delay on ' OR SLEEP(2)--",
            expected_value="Standard HTTP response within 200ms",
        ),
        fingerprint="fp-dast-1",
        source_tool="nuclei",
    )
    sast_f = Finding(
        id="f-sast-1",
        scan_id="s-1",
        engine="code_sast",
        check_id="SAST-INJ-001",
        category="SQL Injection",
        title="Unsanitized raw SQL concatenation in query()",
        severity=Severity.HIGH,
        cvss_score=8.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        cwe_id="CWE-89",
        owasp_category="A03:2021-Injection",
        nist_control="SI-10",
        description="Unsanitized raw SQL concatenation",
        impact="Database compromise",
        remediation="Use ORM / parameter binding.",
        evidence=Evidence(
            location="auth.py:42",
            observed_value="cursor.execute('SELECT * FROM users WHERE user=' + username)",
            expected_value="Parameterized query or ORM query building",
        ),
        fingerprint="fp-sast-1",
        source_tool="semgrep",
    )

    unified, occs = correlator.correlate_findings([dast_f, sast_f], asset_criticality_factor=1.2)
    assert len(unified) == 1
    assert len(occs) == 2
    u = unified[0]
    assert u.correlation_type == CorrelationType.SAST_DAST_VERIFIED
    assert "[DAST + SAST Verified]" in u.title
    assert "nuclei" in u.contributing_tools
    assert "semgrep" in u.contributing_tools
    assert u.contextual_risk_score > 8.5  # Boosted by confidence & criticality factor


def test_contextual_risk_scoring():
    # Base CVSS 8.0 on Critical Asset (1.5x) vs Low Asset (0.7x)
    crit_risk = calculate_finding_contextual_risk(8.0, criticality=AssetCriticality.CRITICAL, internet_exposed=True)
    low_risk = calculate_finding_contextual_risk(8.0, criticality=AssetCriticality.LOW, internet_exposed=False)
    assert crit_risk > low_risk
    assert crit_risk == 10.0  # Capped at 10.0
    assert low_risk < 5.0


def test_database_asset_and_finding_crud():
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        tmp_db = Path(f.name)

    db = DatabaseManager(db_path=tmp_db)
    asset = Asset(
        name="Production Web API",
        type=AssetType.API_ENDPOINT,
        target_value="https://api.example.com",
        criticality=AssetCriticality.HIGH,
    )
    created = db.create_asset(asset)
    assert created.id == asset.id

    fetched = db.get_asset(asset.id)
    assert fetched is not None
    assert fetched.name == "Production Web API"
    assert fetched.criticality == AssetCriticality.HIGH

    assets_list, count = db.list_assets()
    assert count == 1
    assert len(assets_list) == 1

    deleted = db.delete_asset(asset.id)
    assert deleted is True
    assert db.get_asset(asset.id) is None

    # Clean up temp db
    try:
        tmp_db.unlink(missing_ok=True)
    except Exception:
        pass
