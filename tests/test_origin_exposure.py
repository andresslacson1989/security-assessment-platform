"""
Unit and Integration Tests for Certificate Transparency Log IP Discovery & Direct Origin Exposure Auditor.
Authoritative Contract: contracts/06 §1.1 & contracts/08 §2.5.
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock

from app.core.models import ScanConfig, Severity, DiscoveredSubdomain
from app.engines.network.origin_exposure import (
    is_cloudflare_ip,
    is_private_or_loopback_ip,
    audit_origin_exposure,
    fetch_ct_logs,
    safe_probe_exposed_ip,
)
from app.engines.network.subdomain_recon import audit_subdomain_osint


def test_is_cloudflare_ip_ipv4_and_ipv6():
    """
    Verifies that Cloudflare Anycast IPv4 and IPv6 CIDRs are accurately classified.
    """
    # Cloudflare IPv4 ranges
    assert is_cloudflare_ip("172.67.138.195") is True
    assert is_cloudflare_ip("104.21.62.199") is True
    assert is_cloudflare_ip("103.21.244.1") is True
    assert is_cloudflare_ip("108.162.192.50") is True
    assert is_cloudflare_ip("198.41.128.10") is True

    # Cloudflare IPv6 ranges
    assert is_cloudflare_ip("2606:4700:3037::ac43:8ac3") is True
    assert is_cloudflare_ip("2400:cb00:2048:1::c629:d7a2") is True

    # Real origin server IPs (Non-Cloudflare)
    assert is_cloudflare_ip("5.223.46.253") is False
    assert is_cloudflare_ip("5.223.43.70") is False
    assert is_cloudflare_ip("5.223.72.3") is False
    assert is_cloudflare_ip("8.8.8.8") is False
    assert is_cloudflare_ip("1.1.1.1") is True  # 1.1.1.1 is Cloudflare DNS (1.1.1.0/24 in 1.0.0.0/8 or 104 range) -> actually 1.1.1.1 is APNIC/Cloudflare

    # Invalid / empty
    assert is_cloudflare_ip("") is False
    assert is_cloudflare_ip("invalid_ip") is False


def test_is_private_or_loopback_ip():
    """
    Verifies private RFC 1918 and loopback address detection.
    """
    assert is_private_or_loopback_ip("127.0.0.1") is True
    assert is_private_or_loopback_ip("10.0.0.1") is True
    assert is_private_or_loopback_ip("192.168.1.100") is True
    assert is_private_or_loopback_ip("172.16.0.5") is True
    assert is_private_or_loopback_ip("5.223.46.253") is False
    assert is_private_or_loopback_ip("172.67.138.195") is False


@pytest.mark.asyncio
async def test_audit_origin_exposure_with_mock_dataset():
    """
    Verifies CT log origin exposure assessment using the prompt's pre-resolved dataset:
    - 4 exposed 5.223.x.x IPs -> 4 HIGH findings (NET-ORIGIN-001)
    - Cloudflare protected IPs -> 0 findings
    - Wildcard cert -> 1 INFO finding (NET-CERT-004)
    """
    target_domain = "pixelretrobooth.com"
    config = ScanConfig()

    mock_ct_results = [
        {"subdomain": "edge2.pixelretrobooth.com",    "ip": "5.223.46.253",   "cloudflare": False},
        {"subdomain": "evpn2.pixelretrobooth.com",    "ip": "5.223.43.70",    "cloudflare": False},
        {"subdomain": "edgevpn.pixelretrobooth.com",  "ip": "5.223.72.3",     "cloudflare": False},
        {"subdomain": "releases.pixelretrobooth.com", "ip": "5.223.72.3",     "cloudflare": False},
        {"subdomain": "pixelretrobooth.com",          "ip": "172.67.138.195", "cloudflare": True},
        {"subdomain": "www.pixelretrobooth.com",      "ip": "104.21.62.199",  "cloudflare": True},
        {"subdomain": "*.pixelretrobooth.com",        "ip": "",               "cloudflare": True},
    ]

    discovered_subdomains = []
    async def subdomain_cb(sub):
        discovered_subdomains.append(sub)

    findings = await audit_origin_exposure(
        domain=target_domain,
        config=config,
        scan_id="test_scan_001",
        organization_id="org-origin-test",
        emit_subdomain=subdomain_cb,
        mock_ct_results=mock_ct_results,
    )

    # 4 HIGH findings for exposed IPs + 1 INFO finding for wildcard cert
    high_findings = [f for f in findings if f.severity == Severity.HIGH]
    info_findings = [f for f in findings if f.severity == Severity.INFO]

    assert len(high_findings) == 4
    assert len(info_findings) == 1
    assert len(findings) == 5
    assert {finding.organization_id for finding in findings} == {"org-origin-test"}

    # Check high findings check_id and CVSS
    for hf in high_findings:
        assert hf.check_id == "NET-ORIGIN-001"
        assert hf.cvss_score == 7.5
        assert hf.cwe_id == "CWE-200"
        assert hf.owasp_category == "A05:2021-Security Misconfiguration"
        assert hf.nist_control == "AC-3, SC-7"
        assert "Cloudflare" in hf.remediation
        assert "5.223." in hf.evidence.observed_value

    # Check info finding
    assert info_findings[0].check_id == "NET-CERT-004"
    assert info_findings[0].cvss_score == 0.0
    assert "*.pixelretrobooth.com" in info_findings[0].title


@pytest.mark.asyncio
async def test_fetch_ct_logs_mocking_certspotter_and_crtsh():
    """
    Tests dual-source CT log retrieval with mocked HTTP responses.
    """
    domain = "example.com"

    mock_certspotter_data = [
        {
            "dns_names": ["example.com", "admin.example.com", "*.example.com"],
            "issuer": {"name": "Let's Encrypt Authority X3"},
            "not_before": "2026-01-01T00:00:00Z"
        }
    ]

    mock_crtsh_data = [
        {
            "name_value": "dev.example.com\napi.example.com",
            "issuer_name": "DigiCert Global Root CA",
            "entry_timestamp": "2026-02-01T00:00:00Z"
        }
    ]

    with patch("httpx.AsyncClient.get") as mock_get:
        # First call certspotter, second call crt.sh
        resp1 = MagicMock()
        resp1.status_code = 200
        resp1.json.return_value = mock_certspotter_data

        resp2 = MagicMock()
        resp2.status_code = 200
        resp2.json.return_value = mock_crtsh_data

        mock_get.side_effect = [resp1, resp2]

        subs, certs, wildcards = await fetch_ct_logs(domain)

        assert "admin.example.com" in subs
        assert "dev.example.com" in subs
        assert "api.example.com" in subs
        assert "*.example.com" in wildcards
        assert len(certs) >= 1


@pytest.mark.asyncio
async def test_external_ct_and_origin_clients_require_verified_tls_without_redirects():
    """External native clients must not disable TLS or follow arbitrary redirects."""
    client = AsyncMock()
    response = MagicMock(status_code=503)
    client.get.return_value = response
    client.head.return_value = response

    client_context = MagicMock()
    client_context.__aenter__ = AsyncMock(return_value=client)
    client_context.__aexit__ = AsyncMock(return_value=None)

    with patch("app.engines.network.origin_exposure.httpx.AsyncClient", return_value=client_context) as factory:
        await fetch_ct_logs("example.com")
        await safe_probe_exposed_ip("8.8.8.8")

    calls = factory.call_args_list
    assert len(calls) == 2  # CT client and the first non-empty origin probe
    for call in calls:
        assert call.kwargs["verify"] is True
        assert call.kwargs["follow_redirects"] is False


@pytest.mark.asyncio
async def test_ct_subdomain_scope_requires_label_boundary():
    """A look-alike suffix must not be treated as an authorized child domain."""
    response = MagicMock(status_code=200)
    response.json.return_value = [{
        "name_value": "api.example.com\nnotexample.com\nexample.com.evil.test"
    }]
    client = AsyncMock()
    client.get.return_value = response
    context = MagicMock()
    context.__aenter__ = AsyncMock(return_value=client)
    context.__aexit__ = AsyncMock(return_value=None)
    emitted = []

    async def emit(value):
        emitted.append(value)

    async def details(host, _resolver):
        return DiscoveredSubdomain(domain=host, dns_status="NXDOMAIN")

    with patch("app.engines.network.subdomain_recon.httpx.AsyncClient", return_value=context), \
         patch("app.engines.network.subdomain_recon.resolve_subdomain_details", side_effect=details):
        await audit_subdomain_osint(
            "example.com", ScanConfig(), "scan-scope", "org-scope",
            emit_subdomain=emit,
        )

    assert [item.domain for item in emitted] == ["api.example.com"]
