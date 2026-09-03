"""HTTP/control-plane hardening assurance for the 2026-09-03 audit closure."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app, normalize_correlation_id
import run_platform


def test_valid_correlation_id_is_preserved():
    assert normalize_correlation_id("client-123:abc") == "client-123:abc"


def test_invalid_or_oversized_correlation_id_is_replaced():
    for value in ("bad value", "x" * 65, "\tbad", "bad/segment"):
        normalized = normalize_correlation_id(value)
        assert normalized.startswith("corr-")
        assert normalized != value
        assert len(normalized) <= 64


def test_default_standalone_bind_is_loopback(monkeypatch):
    monkeypatch.delenv("HOST", raising=False)
    assert run_platform.resolve_bind_host() == "127.0.0.1"


def test_non_loopback_bind_requires_explicit_host_env(monkeypatch):
    monkeypatch.setenv("HOST", "0.0.0.0")
    assert run_platform.resolve_bind_host() == "0.0.0.0"


def test_port_validation_fails_closed(monkeypatch):
    import pytest

    for invalid in ("0", "65536", "not-a-port"):
        monkeypatch.setenv("PORT", invalid)
        with pytest.raises(RuntimeError):
            run_platform.resolve_port()


def test_browser_policy_has_no_unneeded_external_origins_or_obsolete_xss_header():
    client = TestClient(app)
    response = client.get("/api/system/health")
    assert response.status_code == 200
    csp = response.headers["content-security-policy"]
    assert "cdnjs.cloudflare.com" not in csp
    assert "fonts.googleapis.com" not in csp
    assert "fonts.gstatic.com" not in csp
    assert "form-action 'self'" in csp
    assert "x-xss-protection" not in response.headers
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["permissions-policy"] == "camera=(), microphone=(), geolocation=()"
