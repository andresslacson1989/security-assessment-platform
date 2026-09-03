"""Adversarial SSRF tests for the 2026-09-03 audit closure."""

from app.core.ssrf_protector import (
    is_ip_allowed,
    validate_target_ip,
    validate_target_url,
)


def test_internal_scope_allows_only_explicit_private_address_space():
    allowed, reason = validate_target_ip("10.20.30.40", allow_internal=True)
    assert allowed is True, reason
    allowed, reason = validate_target_ip("192.168.50.20", allow_internal=True)
    assert allowed is True, reason
    allowed, reason = validate_target_ip("fd00::10", allow_internal=True)
    assert allowed is True, reason


def test_internal_scope_does_not_disable_loopback_or_metadata_protection():
    forbidden = [
        "127.0.0.1",
        "0.0.0.0",
        "169.254.169.254",
        "169.254.1.2",
        "::1",
        "fe80::1",
        "224.0.0.1",
        "240.0.0.1",
    ]
    for address in forbidden:
        allowed, reason = is_ip_allowed(address, allow_internal=True)
        assert allowed is False, (address, reason)


def test_named_metadata_and_localhost_are_always_forbidden():
    for url in (
        "http://localhost/",
        "http://localhost.localdomain/",
        "http://metadata.google.internal/",
        "http://metadata.internal/",
        "http://169.254.169.254/latest/meta-data/",
    ):
        allowed, reason = validate_target_url(url, allow_internal=True)
        assert allowed is False, (url, reason)


def test_private_target_still_requires_explicit_internal_authorization():
    allowed, reason = validate_target_ip("10.20.30.40", allow_internal=False)
    assert allowed is False
    assert "authorization" in (reason or "").lower()


def test_non_global_special_use_ranges_are_not_accidentally_admitted():
    # Documentation/test networks are not RFC1918 internal targets and must
    # remain forbidden even with internal-target authority.
    for address in ("192.0.2.1", "198.51.100.1", "203.0.113.1"):
        allowed, _ = is_ip_allowed(address, allow_internal=True)
        assert allowed is False
