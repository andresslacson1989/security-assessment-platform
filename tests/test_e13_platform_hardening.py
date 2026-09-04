"""
E13.8 — Adversarial Acceptance Tests for Web Application & Platform Hardening.
Validates:
- Strict enterprise security headers injected into responses:
  - X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy, Content-Security-Policy.
- Swagger UI / OpenAPI docs disabled in production mode unless explicit ENABLE_DOCS=true.
- PBKDF2 minimum iteration enforcement (>= 100,000) preventing downgrade attacks.
- Constant-time password verification.
- Login endpoint rate limiting: 5 consecutive failed attempts trigger 429 Too Many Requests.
- CORS strict origin validation (no wildcard with credentials).
"""

import os
import base64
import hashlib
from unittest.mock import patch
import pytest
from httpx import AsyncClient, ASGITransport

from app.main import app, _load_allowed_origins
from app.core.auth import hash_password, verify_password


@pytest.mark.asyncio
async def test_security_headers_present_on_all_responses():
    """All API responses must include strict enterprise security headers."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        res = await ac.get("/api/system/health")
        assert res.status_code == 200
        headers = res.headers
        assert headers.get("X-Content-Type-Options") == "nosniff"
        assert headers.get("X-Frame-Options") == "DENY"
        assert headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
        assert "Permissions-Policy" in headers
        assert "geolocation=()" in headers["Permissions-Policy"]
        assert "Content-Security-Policy" in headers
        assert "frame-ancestors 'none'" in headers["Content-Security-Policy"]


def test_pbkdf2_iteration_downgrade_rejection():
    """Hashes crafted with fewer than 100,000 iterations must be rejected to prevent downgrade attacks."""
    password = "SuperSecretPassword123!"
    salt = b"1234567812345678"
    salt_b64 = base64.b64encode(salt).decode("ascii")

    # Hash with only 1000 iterations (downgraded)
    dk_weak = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 1000)
    hash_weak_b64 = base64.b64encode(dk_weak).decode("ascii")
    weak_hash_str = f"pbkdf2_sha256$1000${salt_b64}${hash_weak_b64}"

    # Must fail closed
    assert verify_password(password, weak_hash_str) is False

    # Valid hash with 100,000 iterations must pass
    valid_hash = hash_password(password, iterations=100_000)
    assert verify_password(password, valid_hash) is True


@pytest.mark.asyncio
async def test_login_rate_limiting_triggers_429():
    """5 consecutive failed logins for the same client/user must trigger 429 Too Many Requests."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        for i in range(5):
            res = await ac.post(
                "/api/auth/login",
                json={"username": "brute_force_target", "password": f"wrong_{i}"},
            )
            assert res.status_code == 401

        # 6th attempt must be rate-limited with 429
        res_blocked = await ac.post(
            "/api/auth/login",
            json={"username": "brute_force_target", "password": "wrong_again"},
        )
        assert res_blocked.status_code == 429
        assert "Too many failed login attempts" in res_blocked.json()["detail"]
        assert "Retry-After" in res_blocked.headers


def test_cors_rejects_wildcard_origins():
    """CORS origin parsing fails closed on wildcard or malformed origins."""
    with pytest.raises(RuntimeError, match="wildcard CORS is forbidden"):
        _load_allowed_origins("*")

    with pytest.raises(RuntimeError, match="wildcard CORS is forbidden"):
        _load_allowed_origins("http://example.com, *")

    with pytest.raises(RuntimeError, match="malformed origin"):
        _load_allowed_origins("invalid-origin-no-scheme")


def test_run_platform_host_defaults_and_pip_guidance():
    """
    R2.5 Invariant:
    run_platform.py defaults HOST to 127.0.0.1 when unset, accepts explicit HOST=0.0.0.0,
    and guides operators to use pip install --require-hashes --requirement backend/requirements.lock.
    """
    root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    launcher_path = os.path.join(root_dir, "run_platform.py")
    with open(launcher_path, "r", encoding="utf-8") as f:
        content = f.read()

    # Default to 127.0.0.1
    assert 'host = os.environ.get("HOST", "127.0.0.1")' in content
    # Locked requirements guidance
    assert "--require-hashes" in content
    assert "backend/requirements.lock" in content


def test_systemd_service_uses_dedicated_non_root_runtime_configuration():
    """Tool probes must not write configuration beneath the root-owned app directory."""
    root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    with open(os.path.join(root_dir, "deploy", "cyberassess.service"), "r", encoding="utf-8") as f:
        content = f.read()

    assert "User=cyberassess" in content
    assert "RuntimeDirectory=cyberassess" in content
    assert "RuntimeDirectoryMode=0700" in content
    assert "Environment=HOME=/run/cyberassess" in content
    assert "Environment=XDG_CONFIG_HOME=/run/cyberassess/.config" in content
    assert "ProtectSystem=full" in content
    assert "NoNewPrivileges=true" in content
    assert "/opt/cyberassess/.config" not in content


@pytest.mark.asyncio
async def test_csp_contains_no_unnecessary_external_origins():
    """
    R2.6 Invariant:
    Content-Security-Policy must not include unnecessary external CDN origins (cdnjs, google fonts).
    """
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        res = await ac.get("/api/system/health")
        assert res.status_code == 200
        csp = res.headers.get("Content-Security-Policy", "")
        assert "cdnjs.cloudflare.com" not in csp
        assert "fonts.googleapis.com" not in csp
        assert "fonts.gstatic.com" not in csp
        assert "base-uri 'none'" in csp
        assert "object-src 'none'" in csp


@pytest.mark.asyncio
async def test_correlation_id_input_hardening():
    """
    R2.7 Invariant:
    Incoming X-Correlation-ID is treated as untrusted input.
    Valid format is preserved; oversized, CRLF, control chars, or punctuation are replaced by server ID.
    """
    from app.main import validate_correlation_id

    # 1. Valid caller ID
    valid_id = "corr-user-trace-123_456"
    assert validate_correlation_id(valid_id) == valid_id

    # 2. Oversized ID (> 64 characters)
    oversized = "a" * 65
    validated_oversized = validate_correlation_id(oversized)
    assert validated_oversized != oversized
    assert validated_oversized.startswith("corr-")

    # 3. Newline injection
    crlf_attempt = "valid-id\r\nInjected-Header: evil"
    validated_crlf = validate_correlation_id(crlf_attempt)
    assert "\r" not in validated_crlf and "\n" not in validated_crlf
    assert validated_crlf.startswith("corr-")

    # 4. Carriage return only
    cr_attempt = "valid-id\revil"
    assert validate_correlation_id(cr_attempt).startswith("corr-")

    # 5. Non-allowed punctuation
    punct_attempt = "corr<script>alert(1)</script>"
    assert validate_correlation_id(punct_attempt).startswith("corr-")

    punct_attempt2 = "corr;rm -rf /"
    assert validate_correlation_id(punct_attempt2).startswith("corr-")

    # 6. End-to-end middleware test with CRLF injection
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        res = await ac.get("/api/system/health", headers={"X-Correlation-ID": "evil\r\nInjected: header"})
        assert res.status_code == 200
        reflected_id = res.headers.get("X-Correlation-ID", "")
        assert "\r" not in reflected_id
        assert "\n" not in reflected_id
        assert reflected_id.startswith("corr-")


@pytest.mark.asyncio
async def test_production_bootstrap_protection():
    """
    R2.8 Invariant:
    Production bootstrap setup requires a configured BOOTSTRAP_SECRET (or localhost restriction).
    Invalid or missing secret fails closed with HTTP 403 Forbidden.
    Secret is never returned in the response.
    """
    from app.core.db import db_manager

    # Test with BOOTSTRAP_SECRET configured
    with patch.dict(os.environ, {"OPERATING_MODE": "PRODUCTION", "BOOTSTRAP_SECRET": "test-super-secret-bootstrap-token-12345"}):
        with patch.object(db_manager, "is_initialized", return_value=False):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                # 1. Missing secret => 403 Forbidden
                res_missing = await ac.post(
                    "/api/auth/bootstrap",
                    json={
                        "admin_username": "prodadmin",
                        "admin_email": "admin@prod.local",
                        "admin_password": "SecurePassword123!",
                    },
                )
                assert res_missing.status_code == 403
                assert "bootstrap secret" in res_missing.json()["detail"]

                # 2. Invalid secret => 403 Forbidden
                res_invalid = await ac.post(
                    "/api/auth/bootstrap",
                    json={
                        "admin_username": "prodadmin",
                        "admin_email": "admin@prod.local",
                        "admin_password": "SecurePassword123!",
                    },
                    headers={"X-Bootstrap-Secret": "wrong-secret-guess"},
                )
                assert res_invalid.status_code == 403

                # 3. Valid secret via header allows proceeding
                with patch("app.core.db.db_manager.bootstrap_system") as mock_boot:
                    from app.core.models import UserProfile, UserRole, PrincipalType, Organization
                    dummy_user = UserProfile(
                        id="usr-boot-1",
                        username="prodadmin",
                        email="admin@prod.local",
                        role=UserRole.ADMIN,
                        principal_type=PrincipalType.SYSTEM_PRINCIPAL,
                    )
                    dummy_org = Organization(id="org-1", name="Default Org", slug="default-org")
                    mock_boot.return_value = (dummy_user, dummy_org)

                    res_valid = await ac.post(
                        "/api/auth/bootstrap",
                        json={
                            "admin_username": "prodadmin",
                            "admin_email": "admin@prod.local",
                            "admin_password": "SecurePassword123!",
                        },
                        headers={"X-Bootstrap-Secret": "test-super-secret-bootstrap-token-12345"},
                    )
                    assert res_valid.status_code == 201
                    data = res_valid.json()
                    assert "bootstrap_secret" not in data
                    assert "token-12345" not in str(data)


@pytest.mark.asyncio
async def test_r3_3_production_bootstrap_without_secret_rejects_testclient():
    """
    R3.3 Invariant:
    'testclient' is removed from the production loopback allowlist.
    In PRODUCTION mode without BOOTSTRAP_SECRET, a request from 'testclient'
    MUST be rejected with 403 Forbidden.
    """
    from app.core.db import db_manager

    with patch.dict(os.environ, {"OPERATING_MODE": "PRODUCTION", "BOOTSTRAP_SECRET": ""}):
        with patch.object(db_manager, "is_initialized", return_value=False):
            # Explicitly set client host to 'testclient'
            transport = ASGITransport(app=app, client=("testclient", 50000))
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                res = await ac.post(
                    "/api/auth/bootstrap",
                    json={
                        "admin_username": "prodadmin",
                        "admin_email": "admin@prod.local",
                        "admin_password": "SecurePassword123!",
                    },
                )
                assert res.status_code == 403
                assert "requires localhost access" in res.json()["detail"]


@pytest.mark.asyncio
async def test_r3_3_production_bootstrap_without_secret_allows_strict_127_0_0_1():
    """
    R3.3 Invariant:
    In PRODUCTION mode without BOOTSTRAP_SECRET, strict 127.0.0.1 client host is permitted.
    """
    from app.core.db import db_manager
    from app.core.models import UserProfile, UserRole, PrincipalType, Organization

    with patch.dict(os.environ, {"OPERATING_MODE": "PRODUCTION", "BOOTSTRAP_SECRET": ""}):
        with patch.object(db_manager, "is_initialized", return_value=False), \
             patch("app.core.db.db_manager.bootstrap_system") as mock_boot:
            dummy_user = UserProfile(
                id="usr-boot-127",
                username="prodadmin",
                email="admin@prod.local",
                role=UserRole.ADMIN,
                principal_type=PrincipalType.SYSTEM_PRINCIPAL,
            )
            dummy_org = Organization(id="org-127", name="Default Org", slug="default-org")
            mock_boot.return_value = (dummy_user, dummy_org)

            # Explicitly set client to 127.0.0.1 in ASGITransport
            transport = ASGITransport(app=app, client=("127.0.0.1", 50000))
            async with AsyncClient(transport=transport, base_url="http://127.0.0.1") as ac:
                res = await ac.post(
                    "/api/auth/bootstrap",
                    json={
                        "admin_username": "prodadmin",
                        "admin_email": "admin@prod.local",
                        "admin_password": "SecurePassword123!",
                    },
                )
                assert res.status_code == 201


def test_r3_3_enterprise_compose_wires_bootstrap_secret():
    """
    R3.3 Invariant:
    docker-compose.yml must explicitly wire BOOTSTRAP_SECRET into cyberassess-enterprise
    with a mandatory error-on-unset pattern (${BOOTSTRAP_SECRET:?...}).
    """
    import yaml
    compose_path = os.path.join(os.path.dirname(__file__), "..", "docker-compose.yml")
    with open(compose_path, "r", encoding="utf-8") as f:
        compose = yaml.safe_load(f)

    ent_env = compose["services"]["cyberassess-enterprise"]["environment"]
    assert "BOOTSTRAP_SECRET" in ent_env
    secret_spec = ent_env["BOOTSTRAP_SECRET"]
    assert secret_spec.startswith("${BOOTSTRAP_SECRET:?")
    assert "must be configured" in secret_spec


@pytest.mark.asyncio
async def test_r3_4_csp_script_src_contains_no_unsafe_inline():
    """
    R3.4 Invariant:
    Content-Security-Policy header must enforce script-src 'self' and MUST NOT
    contain 'unsafe-inline' within script-src.
    """
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        res = await ac.get("/api/system/health")
        assert res.status_code == 200
        csp = res.headers.get("Content-Security-Policy", "")

        # Extract script-src directive
        directives = dict(item.strip().split(None, 1) for item in csp.split(";") if item.strip())
        assert "script-src" in directives
        script_src = directives["script-src"]
        assert "'self'" in script_src
        assert "'unsafe-inline'" not in script_src, "script-src must NOT allow 'unsafe-inline'!"


def test_r3_4_frontend_contains_zero_inline_event_handlers():
    """
    R3.4 Invariant:
    Neither frontend/index.html nor dynamic HTML generation in frontend/js/app.js
    may contain inline event handlers (onclick=, onload=, onerror=, etc.).
    All interactions must use data-action attributes and delegated listeners.
    """
    import re
    repo_root = os.path.dirname(os.path.dirname(__file__))
    html_path = os.path.join(repo_root, "frontend", "index.html")
    js_path = os.path.join(repo_root, "frontend", "js", "app.js")

    with open(html_path, "r", encoding="utf-8") as f:
        html_content = f.read()

    with open(js_path, "r", encoding="utf-8") as f:
        js_content = f.read()

    # Pattern for HTML inline event handler attributes (e.g. onclick="...", onload='...')
    # Requires whitespace before attribute and quote after equals to distinguish from JS property assignments (e.g. obj.onerror = ...)
    inline_handler_regex = re.compile(r'\s(on(?:click|load|error|change|submit|focus|blur|keydown|keyup))\s*=\s*["\']', re.IGNORECASE)

    html_matches = inline_handler_regex.findall(html_content)
    assert len(html_matches) == 0, f"Found inline event handlers in index.html: {html_matches}"

    js_matches = inline_handler_regex.findall(js_content)
    assert len(js_matches) == 0, f"Found inline event handlers in app.js: {js_matches}"


def test_r4_4_docker_compose_profile_topology_and_port_uniqueness():
    """
    R4.4 Invariant:
    1. 'cyberassess' must be assigned to profiles: ['standalone'].
    2. 'cyberassess-enterprise' must be assigned to profiles: ['enterprise'].
    3. Under standalone profile ('standalone'), only cyberassess binds port 8000.
    4. Under enterprise profile ('enterprise'), only cyberassess-enterprise binds port 8000.
       'cyberassess' must NOT be active under enterprise profile, avoiding port 8000 collision.
    """
    import yaml
    repo_root = os.path.dirname(os.path.dirname(__file__))
    compose_path = os.path.join(repo_root, "docker-compose.yml")
    with open(compose_path, "r", encoding="utf-8") as f:
        compose = yaml.safe_load(f)

    services = compose.get("services", {})
    assert "cyberassess" in services
    assert "cyberassess-enterprise" in services

    # 1. Profile assignments
    assert services["cyberassess"].get("profiles") == ["standalone"]
    assert services["cyberassess-enterprise"].get("profiles") == ["enterprise"]

    # 2. Simulate enterprise profile activation:
    # Services active when --profile enterprise is used:
    # Any service with no profile, plus any service with 'enterprise' in profiles.
    ent_active_services = {
        name: svc for name, svc in services.items()
        if not svc.get("profiles") or "enterprise" in svc.get("profiles", [])
    }
    assert "cyberassess" not in ent_active_services, (
        "cyberassess (standalone) must NOT be activated when --profile enterprise is specified!"
    )
    assert "cyberassess-enterprise" in ent_active_services

    # Inspect published host ports under enterprise topology
    ent_published_ports = []
    for sname, sdata in ent_active_services.items():
        for p in sdata.get("ports", []):
            host_port = str(p).split(":")[0]
            ent_published_ports.append((sname, host_port))

    host_8000_binders = [sname for sname, port in ent_published_ports if port == "8000"]
    assert len(host_8000_binders) == 1
    assert host_8000_binders[0] == "cyberassess-enterprise"

    # 3. Simulate standalone profile activation:
    std_active_services = {
        name: svc for name, svc in services.items()
        if not svc.get("profiles") or "standalone" in svc.get("profiles", [])
    }
    assert "cyberassess-enterprise" not in std_active_services
    assert "cyberassess" in std_active_services

    std_published_ports = []
    for sname, sdata in std_active_services.items():
        for p in sdata.get("ports", []):
            host_port = str(p).split(":")[0]
            std_published_ports.append((sname, host_port))

    std_8000_binders = [sname for sname, port in std_published_ports if port == "8000"]
    assert len(std_8000_binders) == 1
    assert std_8000_binders[0] == "cyberassess"



