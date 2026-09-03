"""
E13.2 — Adversarial Acceptance Tests for SSRF and Network Classification Closure
Validates central network classification, explicit RFC 1918 handling, strict metadata/loopback
denials even under scan:internal, and DNS resolution validation.
"""

from unittest.mock import patch
import pytest

from app.core.ssrf_protector import (
    NetworkClassification,
    classify_ip,
    is_ip_allowed,
    is_ip_allowed_for_policy,
    validate_target_url,
    validate_target_domain,
    validate_target_ip,
    assert_safe_url,
    assert_safe_target,
    create_validated_target,
    SSRFProtectionError,
)
from app.core.models import Target, TargetType


class TestE13NetworkClassification:
    """Tests for authoritative classification and precedence."""

    def test_classify_public_ipv4(self):
        cls, reason = classify_ip("93.184.216.34")  # example.com
        assert cls == NetworkClassification.PUBLIC
        assert reason is None

    def test_classify_rfc1918_private(self):
        for ip in ("10.0.0.1", "172.16.0.1", "172.31.255.254", "192.168.1.1"):
            cls, reason = classify_ip(ip)
            assert cls == NetworkClassification.PRIVATE, f"Expected {ip} to be PRIVATE"
            assert reason is None

    def test_classify_loopback(self):
        for ip in ("127.0.0.1", "127.0.0.2", "127.255.255.254", "::1"):
            cls, reason = classify_ip(ip)
            assert cls == NetworkClassification.LOOPBACK, f"Expected {ip} to be LOOPBACK"
            assert reason is not None

    def test_classify_metadata(self):
        for ip in ("169.254.169.254", "168.63.129.16", "100.100.100.200"):
            cls, reason = classify_ip(ip)
            assert cls == NetworkClassification.METADATA, f"Expected {ip} to be METADATA"
            assert reason is not None

    def test_classify_link_local(self):
        for ip in ("169.254.1.1", "169.254.254.254", "fe80::1"):
            cls, reason = classify_ip(ip)
            assert cls == NetworkClassification.LINK_LOCAL, f"Expected {ip} to be LINK_LOCAL"
            assert reason is not None

    def test_classify_unspecified(self):
        for ip in ("0.0.0.0", "::"):
            cls, reason = classify_ip(ip)
            assert cls == NetworkClassification.UNSPECIFIED, f"Expected {ip} to be UNSPECIFIED"
            assert reason is not None

    def test_classify_multicast(self):
        for ip in ("224.0.0.1", "239.255.255.250", "ff02::1"):
            cls, reason = classify_ip(ip)
            assert cls == NetworkClassification.MULTICAST, f"Expected {ip} to be MULTICAST"
            assert reason is not None

    def test_classify_reserved_and_documentation(self):
        for ip in ("240.0.0.1", "100.64.0.1", "192.0.2.1", "198.51.100.1", "203.0.113.1", "198.18.0.1", "2001:db8::1"):
            cls, reason = classify_ip(ip)
            assert cls == NetworkClassification.RESERVED, f"Expected {ip} to be RESERVED"
            assert reason is not None

    def test_classify_ipv6_unique_local(self):
        cls, reason = classify_ip("fc00::1")
        assert cls == NetworkClassification.PRIVATE
        assert reason is None


class TestE13PolicyBoundaries:
    """Tests for allow_internal policy behavior across categories."""

    def test_public_allowed_both_modes(self):
        assert is_ip_allowed_for_policy("93.184.216.34", allow_internal=False)[0] is True
        assert is_ip_allowed_for_policy("93.184.216.34", allow_internal=True)[0] is True

    def test_rfc1918_denied_without_internal_capability(self):
        for ip in ("10.0.0.1", "172.16.0.1", "192.168.1.1"):
            allowed, reason = is_ip_allowed_for_policy(ip, allow_internal=False)
            assert allowed is False
            assert "scan:internal" in reason

    def test_rfc1918_allowed_with_internal_capability(self):
        for ip in ("10.0.0.1", "172.16.0.1", "192.168.1.1"):
            allowed, reason = is_ip_allowed_for_policy(ip, allow_internal=True)
            assert allowed is True
            assert reason is None

    def test_ipv6_unique_local_allowed_only_with_internal(self):
        assert is_ip_allowed_for_policy("fc00::1", allow_internal=False)[0] is False
        assert is_ip_allowed_for_policy("fc00::1", allow_internal=True)[0] is True

    def test_loopback_always_denied(self):
        for ip in ("127.0.0.1", "127.0.0.2", "::1"):
            assert is_ip_allowed_for_policy(ip, allow_internal=False)[0] is False
            assert is_ip_allowed_for_policy(ip, allow_internal=True)[0] is False

    def test_metadata_always_denied(self):
        for ip in ("169.254.169.254", "168.63.129.16", "100.100.100.200"):
            assert is_ip_allowed_for_policy(ip, allow_internal=False)[0] is False
            assert is_ip_allowed_for_policy(ip, allow_internal=True)[0] is False

    def test_link_local_always_denied(self):
        for ip in ("169.254.1.1", "fe80::1"):
            assert is_ip_allowed_for_policy(ip, allow_internal=False)[0] is False
            assert is_ip_allowed_for_policy(ip, allow_internal=True)[0] is False

    def test_unspecified_always_denied(self):
        for ip in ("0.0.0.0", "::"):
            assert is_ip_allowed_for_policy(ip, allow_internal=False)[0] is False
            assert is_ip_allowed_for_policy(ip, allow_internal=True)[0] is False

    def test_multicast_always_denied(self):
        for ip in ("224.0.0.1", "ff02::1"):
            assert is_ip_allowed_for_policy(ip, allow_internal=False)[0] is False
            assert is_ip_allowed_for_policy(ip, allow_internal=True)[0] is False

    def test_reserved_always_denied(self):
        for ip in ("240.0.0.1", "100.64.0.1", "192.0.2.1"):
            assert is_ip_allowed_for_policy(ip, allow_internal=False)[0] is False
            assert is_ip_allowed_for_policy(ip, allow_internal=True)[0] is False


class TestE13UrlAndDomainValidation:
    """Tests for URL and Domain validation pipelines."""

    def test_localhost_hostname_always_denied(self):
        for url in ("http://localhost", "http://localhost:8080", "http://localhost.localdomain"):
            assert validate_target_url(url, allow_internal=False)[0] is False
            assert validate_target_url(url, allow_internal=True)[0] is False

    def test_metadata_hostname_always_denied(self):
        for host in ("metadata.google.internal", "metadata.internal", "instance-data"):
            assert validate_target_domain(host, allow_internal=False)[0] is False
            assert validate_target_domain(host, allow_internal=True)[0] is False
            assert validate_target_url(f"http://{host}", allow_internal=True)[0] is False

    def test_url_ip_literals_respect_policy(self):
        assert validate_target_url("http://127.0.0.1:8000", allow_internal=True)[0] is False
        assert validate_target_url("http://169.254.169.254/latest/meta-data", allow_internal=True)[0] is False
        assert validate_target_url("http://192.168.1.10", allow_internal=False)[0] is False
        assert validate_target_url("http://192.168.1.10", allow_internal=True)[0] is True
        assert validate_target_url("http://93.184.216.34", allow_internal=False)[0] is True

    def test_domain_dns_resolution_respects_policy(self):
        with patch("app.core.ssrf_protector.resolve_hostname_ips", return_value=["93.184.216.34"]):
            assert validate_target_domain("example.com", allow_internal=False)[0] is True

        with patch("app.core.ssrf_protector.resolve_hostname_ips", return_value=["192.168.1.50"]):
            assert validate_target_domain("internal.corp", allow_internal=False)[0] is False
            assert validate_target_domain("internal.corp", allow_internal=True)[0] is True

        with patch("app.core.ssrf_protector.resolve_hostname_ips", return_value=["127.0.0.1"]):
            assert validate_target_domain("evil-dns.com", allow_internal=False)[0] is False
            assert validate_target_domain("evil-dns.com", allow_internal=True)[0] is False

        with patch("app.core.ssrf_protector.resolve_hostname_ips", return_value=["169.254.169.254"]):
            assert validate_target_domain("evil-meta.com", allow_internal=True)[0] is False

    def test_mixed_dns_answers_fail_closed(self):
        # One public, one private IP in DNS response
        with patch("app.core.ssrf_protector.resolve_hostname_ips", return_value=["93.184.216.34", "192.168.1.1"]):
            # Without internal authorization, must fail closed
            assert validate_target_domain("split-horizon.com", allow_internal=False)[0] is False
            # With internal authorization, both are acceptable
            assert validate_target_domain("split-horizon.com", allow_internal=True)[0] is True

        # One public, one loopback in DNS response
        with patch("app.core.ssrf_protector.resolve_hostname_ips", return_value=["93.184.216.34", "127.0.0.1"]):
            # Must fail closed in ALL modes
            assert validate_target_domain("rebinding.com", allow_internal=False)[0] is False
            assert validate_target_domain("rebinding.com", allow_internal=True)[0] is False


class TestE13ValidatedTargetIntegration:
    """Tests for create_validated_target and SSRF assertion gates."""

    def test_create_validated_target_rejects_loopback_in_all_modes(self):
        target = Target(name="local", type=TargetType.IP, value="127.0.0.1")
        with pytest.raises(SSRFProtectionError):
            create_validated_target(target, allow_internal=False)
        with pytest.raises(SSRFProtectionError):
            create_validated_target(target, allow_internal=True)

    def test_create_validated_target_rejects_metadata_in_all_modes(self):
        target = Target(name="metadata", type=TargetType.IP, value="169.254.169.254")
        with pytest.raises(SSRFProtectionError):
            create_validated_target(target, allow_internal=False)
        with pytest.raises(SSRFProtectionError):
            create_validated_target(target, allow_internal=True)

    def test_create_validated_target_permits_private_only_with_allow_internal(self):
        target = Target(name="internal-host", type=TargetType.IP, value="10.50.0.5")
        with pytest.raises(SSRFProtectionError):
            create_validated_target(target, allow_internal=False)

        val_target = create_validated_target(target, allow_internal=True)
        assert val_target is not None
        assert val_target.selected_destination == "10.50.0.5"

    def test_create_validated_target_dns_rebinding_gate(self):
        target = Target(name="rebinding-target", type=TargetType.DOMAIN, value="rebind.evil.com")
        # Step 1: Input gate passes (mocked)
        # Step 2: At construction time, DNS resolves to 127.0.0.1
        with patch("app.core.ssrf_protector.resolve_hostname_ips", side_effect=[["93.184.216.34"], ["127.0.0.1"]]):
            with pytest.raises(SSRFProtectionError):
                create_validated_target(target, allow_internal=True)
