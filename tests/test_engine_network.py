"""
Unit tests for Engine 1: Network Perimeter, TLS/SSL and DNS Auditor.
"""

import asyncio
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import patch, AsyncMock, MagicMock
import pytest

from app.core.models import Target, TargetType, ScanConfig, Severity, LogLevel, ToolAdapterConfig, OSINTConfig, NormalizedExecutionState, Finding, Evidence
from app.engines.network.tls_auditor import (
    extract_host_and_port,
    matches_san,
    audit_tls_certificates,
    audit_tls_protocols_and_ciphers,
)
from app.engines.network.dns_hygiene import (
    extract_apex_domain,
    audit_dns_hygiene,
)
from app.engines.network.port_checker import (
    extract_host,
    check_single_port,
    audit_exposed_ports,
)
from app.engines.network.engine import NetworkAssessmentEngine
from app.engines.network.banner_grabber import audit_service_banners


def test_tls_helpers():
    assert extract_host_and_port("https://example.com") == ("example.com", 443)
    assert extract_host_and_port("http://192.168.1.1:8080") == ("192.168.1.1", 8080)
    assert extract_host_and_port("example.com:8443") == ("example.com", 8443)
    assert extract_host_and_port("example.com") == ("example.com", 443)


@pytest.mark.asyncio
async def test_service_banner_evidence_masks_credentials():
    with patch(
        "app.engines.network.banner_grabber.grab_service_banner",
        new=AsyncMock(return_value="vsftpd 2.3.4 password=super-secret-token"),
    ):
        findings = await audit_service_banners("example.com", [21], scan_id="scan-banner")

    assert len(findings) == 1
    assert "super-secret-token" not in findings[0].evidence.observed_value
    assert "super-secret-token" not in (findings[0].evidence.raw_response_snippet or "")
    assert "[REDACTED]" in findings[0].evidence.raw_response_snippet


@pytest.mark.asyncio
async def test_network_engine_marks_native_tls_results_as_fallback_after_sslyze_failure():
    class FailedSslyze:
        last_execution_state = NormalizedExecutionState.TOOL_EXECUTION_FAILED

        async def is_available(self, _path=None):
            return True

        async def run(self, *_args, **_kwargs):
            return []

    native_finding = Finding(
        scan_id="scan-fallback",
        engine="network",
        check_id="NET-TLS-001",
        category="TLS",
        title="Deprecated TLS protocol detected",
        severity=Severity.HIGH,
        cvss_score=7.5,
        description="Native fallback result",
        impact="Reduced TLS posture",
        remediation="Disable deprecated protocols",
        evidence=Evidence(location="example.com:443", observed_value="TLSv1.0", expected_value="TLSv1.2+"),
    )
    states = []

    async def capture_state(tool, state):
        states.append((tool, state))

    async def noop(*_args, **_kwargs):
        return []

    config = ScanConfig(
        adapters=ToolAdapterConfig(
            enable_nmap=False,
            enable_sslyze=True,
            enable_subfinder=False,
            enable_httpx=False,
            enable_amass=False,
            enable_metasploit=False,
        ),
        osint=OSINTConfig(subdomain_enumeration=False),
    )
    with patch("app.engines.network.engine.SslyzeAdapter", FailedSslyze), \
         patch("app.engines.network.engine.audit_tls_certificates", new_callable=AsyncMock, return_value=[native_finding]), \
         patch("app.engines.network.engine.audit_tls_protocols_and_ciphers", new_callable=AsyncMock, return_value=[]), \
         patch("app.engines.network.engine.audit_dns_hygiene", new_callable=AsyncMock, side_effect=noop), \
         patch("app.core.ssrf_protector.is_ip_allowed", return_value=(True, None)):
        results = await NetworkAssessmentEngine().run(
            Target(name="Target", type=TargetType.IP, value="93.184.216.34"),
            config,
            AsyncMock(),
            AsyncMock(),
            AsyncMock(),
            scan_id="scan-fallback",
            organization_id="org-fallback",
            emit_tool_execution_state=capture_state,
        )

    assert results[0].source_tool == "native"
    assert results[0].is_fallback is True
    assert results[0].primary_tool_failed == "sslyze"
    assert ("sslyze", "TOOL_EXECUTION_FAILED") in states

    assert matches_san("example.com", ["example.com", "api.example.com"]) is True
    assert matches_san("app.example.com", ["*.example.com"]) is True
    assert matches_san("evil.com", ["*.example.com"]) is False


def test_dns_helpers():
    assert extract_apex_domain("https://sub.staging.example.com/api") == "example.com"
    assert extract_apex_domain("example.com") == "example.com"
    assert extract_apex_domain("192.168.1.1") is None


def test_port_helpers():
    assert extract_host("https://app.example.com:8080/test") == "app.example.com"
    assert extract_host("198.51.100.5:3306") == "198.51.100.5"


@pytest.mark.asyncio
async def test_dns_hygiene_findings():
    # Mock dnspython async resolver
    with patch("dns.asyncresolver.Resolver") as mock_resolver_cls:
        mock_resolver = MagicMock()
        mock_resolver_cls.return_value = mock_resolver

        async def mock_resolve(domain, rtype):
            if rtype == "TXT" and domain == "example.com":
                item = MagicMock()
                item.to_text.return_value = '"v=spf1 +all"'
                return [item]
            elif rtype == "TXT" and domain == "_dmarc.example.com":
                item = MagicMock()
                item.to_text.return_value = '"v=DMARC1; p=none;"'
                return [item]
            import dns.resolver
            raise dns.resolver.NXDOMAIN()

        mock_resolver.resolve = AsyncMock(side_effect=mock_resolve)

        findings = await audit_dns_hygiene("example.com")
        check_ids = [f.check_id for f in findings]

        assert "NET-DNS-002" in check_ids  # SPF +all (High)
        assert "NET-DNS-004" in check_ids  # DMARC p=none (Low)
        assert "NET-DNS-005" in check_ids  # Missing CAA (Info)
        assert "NET-DNS-006" in check_ids  # Missing MTA-STS (Low)
        assert "NET-DNS-007" in check_ids  # Missing DNSSEC (Low)


@pytest.mark.asyncio
async def test_port_checker_findings():
    # Mock open_connection to simulate open MySQL (3306) and open Telnet (23)
    async def mock_open_conn(host, port):
        if port in (3306, 23):
            writer = MagicMock()
            writer.close = MagicMock()
            writer.wait_closed = AsyncMock()
            return MagicMock(), writer
        raise ConnectionRefusedError("Closed")

    with patch("asyncio.open_connection", side_effect=mock_open_conn):
        findings = await audit_exposed_ports("example.com")
        check_ids = [f.check_id for f in findings]

        assert "NET-PORT-001" in check_ids  # MySQL 3306
        assert "NET-PORT-003" in check_ids  # Telnet 23


@pytest.mark.asyncio
async def test_network_engine_full_run():
    engine = NetworkAssessmentEngine()
    assert engine.name == "network"
    assert engine.is_applicable(Target(name="Test", type=TargetType.URL, value="https://example.com")) is True
    assert engine.is_applicable(Target(name="Test", type=TargetType.LOCAL_PATH, value="/path/to/code")) is False

    logs = []
    progress_updates = []
    findings_emitted = []

    async def log_cb(lvl, msg):
        logs.append((lvl, msg))

    async def prog_cb(pct, stg):
        progress_updates.append((pct, stg))

    async def find_cb(f):
        findings_emitted.append(f)

    # Mock sub-check calls to return predictable results
    with patch("app.engines.network.engine.audit_tls_certificates", new_callable=AsyncMock) as mock_tls, \
         patch("app.engines.network.engine.audit_tls_protocols_and_ciphers", new_callable=AsyncMock) as mock_proto, \
         patch("app.engines.network.engine.audit_dns_hygiene", new_callable=AsyncMock) as mock_dns, \
         patch("app.engines.network.engine.audit_exposed_ports", new_callable=AsyncMock) as mock_port:

        mock_tls.return_value = []
        mock_proto.return_value = []
        mock_dns.return_value = []
        mock_port.return_value = []

        target = Target(name="Web App", type=TargetType.URL, value="https://example.com")
        config = ScanConfig(
            adapters=ToolAdapterConfig(enable_nmap=False, enable_sslyze=False),
            osint=OSINTConfig(subdomain_enumeration=False),
        )

        results = await engine.run(target, config, log_cb, prog_cb, find_cb)

        assert results == []
        assert len(progress_updates) >= 4
        assert progress_updates[-1][0] == 100
        assert len(logs) >= 2
        # Native fallbacks must connect to the already validated destination,
        # not resolve the user-supplied hostname again.
        assert mock_tls.await_args.kwargs["connection_host"]
        assert mock_proto.await_args.kwargs["connection_host"]
        assert mock_port.await_args.kwargs["connection_host"]


@pytest.mark.asyncio
async def test_network_engine_reaches_governed_extended_adapters():
    """The production network path invokes the governed Amass and Metasploit adapters."""
    calls = {}

    class FakeAmass:
        last_execution_state = NormalizedExecutionState.COMPLETED_NO_FINDINGS

        async def is_available(self, custom_path=None):
            return True

        async def run(self, target, config, emit_log, emit_finding, **kwargs):
            calls["amass"] = kwargs
            assert Path(kwargs["output_file"]).is_absolute()
            return []

    class FakeMetasploit:
        last_execution_state = NormalizedExecutionState.COMPLETED_NO_FINDINGS

        async def is_available(self, custom_path=None):
            return True

        async def run(self, target, config, emit_log, emit_finding, **kwargs):
            calls["metasploit"] = kwargs
            return []

    logs = []

    async def log_cb(level, message):
        logs.append((level, message))

    async def progress_cb(percent, stage):
        pass

    async def finding_cb(finding):
        pass

    with patch("app.engines.network.engine.AmassAdapter", FakeAmass), \
         patch("app.engines.network.engine.MetasploitAdapter", FakeMetasploit), \
         patch("app.engines.network.engine.audit_tls_certificates", new_callable=AsyncMock, return_value=[]), \
         patch("app.engines.network.engine.audit_tls_protocols_and_ciphers", new_callable=AsyncMock, return_value=[]), \
         patch("app.engines.network.engine.audit_dns_hygiene", new_callable=AsyncMock, return_value=[]), \
         patch("app.engines.network.engine.audit_exposed_ports", new_callable=AsyncMock, return_value=[]):
        config = ScanConfig(
            adapters=ToolAdapterConfig(
                enable_nmap=False,
                enable_sslyze=False,
                enable_subfinder=False,
                enable_httpx=False,
                enable_amass=True,
                enable_metasploit=True,
            ),
            osint=OSINTConfig(subdomain_enumeration=False),
        )
        await NetworkAssessmentEngine().run(
            Target(name="Web App", type=TargetType.URL, value="https://example.com"),
            config,
            log_cb,
            progress_cb,
            finding_cb,
            organization_id="org-one",
            scan_id="scan-extended-runtime",
        )

    assert "amass" in calls
    assert "metasploit" in calls
    assert calls["metasploit"]["port"] == 443
