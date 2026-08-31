"""
Authoritative Contract 09 (TOOL-NMAP v14.3.0) & Goal E11.1 Assurance Test Suite.
Verifies all 41 specification points, security boundaries, parameter injection defenses,
exact version pinning, destination binding, NSE allowlists, XML parser hardening, and fallback invariants.
"""

import asyncio
from datetime import datetime, timezone
import os
import pytest
from unittest.mock import patch, AsyncMock, MagicMock

from app.core.models import (
    Target,
    ValidatedTarget,
    Finding,
    Evidence,
    Severity,
    ScanConfig,
    ScanProfile,
    TargetType,
    LogLevel,
    NormalizedExecutionState,
    ToolAdapterConfig,
)
from app.adapters.nmap_adapter import (
    NmapAdapter,
    NmapCommandBuilder,
    NmapExecutionRecord,
    validate_port_specification,
    extract_host,
    sanitize_banner_or_script,
    TOOL_ID,
    TOOL_NAME,
    APPROVED_VERSION,
    TRUST_MODE,
    APPROVED_NSE_SCRIPTS,
    FORBIDDEN_SCRIPT_CATEGORIES,
)
from app.core.ssrf_protector import create_validated_target, SSRFProtectionError
from app.engines.network.engine import NetworkAssessmentEngine


# ============================================================================
# 1. Identity, Version Enforcement & Trust Mode
# ============================================================================

class TestNmapIdentityAndVersion:
    def test_nmap_identity_and_trust_mode(self):
        adapter = NmapAdapter()
        assert adapter.tool_id == "TOOL-NMAP"
        assert adapter.tool_name == "nmap"
        assert adapter.approved_version == "7.95"
        assert adapter.trust_mode == "PACKAGE_MANAGER_MODE"

    @pytest.mark.asyncio
    async def test_exact_version_pinning_matrix(self):
        adapter = NmapAdapter()
        with patch.object(adapter, "resolve_binary_path", return_value="/usr/bin/nmap"):
            # Test 7.95 - Exactly approved
            with patch.object(adapter, "execute_command", return_value=(0, "Nmap version 7.95 ( https://nmap.org )\nPlatform: x86_64-pc-linux-gnu", "")):
                v = await adapter.get_version()
                assert v == "Nmap 7.95"
                ok, err = adapter.verify_version(v)
                assert ok is True
                assert err is None

            # Test 7.94 - Incompatible older release
            with patch.object(adapter, "execute_command", return_value=(0, "Nmap version 7.94 ( https://nmap.org )\nPlatform: x86_64-pc-linux-gnu", "")):
                v = await adapter.get_version()
                assert v == "Nmap 7.94"
                ok, err = adapter.verify_version(v)
                assert ok is False
                assert "INVALID_VERSION" in err

            # Test 7.96 - Incompatible newer release
            with patch.object(adapter, "execute_command", return_value=(0, "Nmap version 7.96 ( https://nmap.org )\nPlatform: x86_64-pc-linux-gnu", "")):
                v = await adapter.get_version()
                assert v == "Nmap 7.96"
                ok, err = adapter.verify_version(v)
                assert ok is False
                assert "INVALID_VERSION" in err

            # Test Empty / Error output
            ok, err = adapter.verify_version(None)
            assert ok is False
            assert "empty" in err.lower()


# ============================================================================
# 2. ValidatedTarget & Connection Destination Binding
# ============================================================================

class TestNmapDestinationBinding:
    def test_validated_target_destination_binding(self):
        target = Target(name="Domain Target", type=TargetType.DOMAIN, value="example.com")
        with patch("app.core.ssrf_protector.resolve_hostname_ips", return_value=["93.184.216.34"]):
            val_target = create_validated_target(target)

        assert val_target.canonical_value == "example.com"
        assert val_target.selected_destination == "93.184.216.34"
        assert len(val_target.target_id) == 64
        assert len(val_target.authorization_decision_id) == 64
        assert len(val_target.integrity_seal) == 64

        config = ScanConfig(port_list=[80, 443])
        cmd, ports, scripts, err = NmapCommandBuilder.build_command(
            nmap_path="/usr/bin/nmap",
            target=val_target,
            config=config,
            dns_zone_authorized=True,
        )
        assert err is None
        # Destination argument MUST be the pre-resolved IP
        assert cmd[-1] == "93.184.216.34"
        # Script args MUST inject Host header context
        assert "--script-args" in cmd
        assert "http.host=example.com" in cmd

    def test_ssrf_forbidden_target_blocked(self):
        target = Target(name="Internal AWS Metadata", type=TargetType.IP, value="169.254.169.254")
        with pytest.raises(SSRFProtectionError):
            create_validated_target(target, allow_internal=False)


# ============================================================================
# 3. Port Validation & Command Injection Defense
# ============================================================================

class TestNmapPortValidation:
    def test_valid_port_specifications(self):
        ok, ports, err = validate_port_specification([22, 80, 443, 8080])
        assert ok is True
        assert ports == [22, 80, 443, 8080]
        assert err is None

        ok, ports, err = validate_port_specification("21, 22, 80, 8080")
        assert ok is True
        assert ports == [21, 22, 80, 8080]

        ok, ports, err = validate_port_specification("80-84")
        assert ok is True
        assert ports == [80, 81, 82, 83, 84]

    def test_rejection_of_injection_payloads(self):
        # Shell chaining attempt
        ok, ports, err = validate_port_specification("80; cat /etc/passwd")
        assert ok is False

        # Shell pipe attempt
        ok, ports, err = validate_port_specification("80 | nc -e /bin/sh")
        assert ok is False

        # Command flag injection attempt
        ok, ports, err = validate_port_specification("80 --script=vuln")
        assert ok is False

        # Newline flag injection attempt
        ok, ports, err = validate_port_specification("80\n-sC")
        assert ok is False

        # Negative and out-of-range ports
        ok, ports, err = validate_port_specification([-1, 0, 70000])
        assert ok is False


# ============================================================================
# 4. NSE Script Allowlist & Scope Restriction
# ============================================================================

class TestNmapNSEPolicy:
    def test_approved_scripts_allowlist(self):
        target = Target(name="Domain Target", type=TargetType.DOMAIN, value="example.com")
        with patch("app.core.ssrf_protector.resolve_hostname_ips", return_value=["93.184.216.34"]):
            val_target = create_validated_target(target)

        config = ScanConfig()
        # Custom approved script
        cmd, ports, scripts, err = NmapCommandBuilder.build_command(
            nmap_path="/usr/bin/nmap",
            target=val_target,
            config=config,
            custom_scripts=["banner", "ssl-cert", "http-title"],
        )
        assert err is None
        assert scripts == ["banner", "ssl-cert", "http-title"]

        # Disapproved custom script rejected
        cmd_bad, _, _, err_bad = NmapCommandBuilder.build_command(
            nmap_path="/usr/bin/nmap",
            target=val_target,
            config=config,
            custom_scripts=["http-vuln-cve2017-5638"],
        )
        assert err_bad is not None
        assert "not on the approved allowlist" in err_bad

    def test_dns_nsec_enum_scope_policy(self):
        # 1. Target is DOMAIN and dns_zone_authorized=True -> ALLOWED
        domain_target = Target(name="Domain Target", type=TargetType.DOMAIN, value="example.com")
        with patch("app.core.ssrf_protector.resolve_hostname_ips", return_value=["93.184.216.34"]):
            val_domain = create_validated_target(domain_target)

        _, _, scripts_domain, _ = NmapCommandBuilder.build_command(
            nmap_path="/usr/bin/nmap",
            target=val_domain,
            config=ScanConfig(),
            dns_zone_authorized=True,
        )
        assert "dns-nsec-enum" in scripts_domain

        # 2. Target is DOMAIN and dns_zone_authorized=False -> EXCLUDED
        _, _, scripts_domain_unauth, _ = NmapCommandBuilder.build_command(
            nmap_path="/usr/bin/nmap",
            target=val_domain,
            config=ScanConfig(),
            dns_zone_authorized=False,
        )
        assert "dns-nsec-enum" not in scripts_domain_unauth

        # 3. Target is IP -> ALWAYS EXCLUDED
        ip_target = Target(name="IP Target", type=TargetType.IP, value="93.184.216.34")
        val_ip = create_validated_target(ip_target)
        _, _, scripts_ip, _ = NmapCommandBuilder.build_command(
            nmap_path="/usr/bin/nmap",
            target=val_ip,
            config=ScanConfig(),
            dns_zone_authorized=True,
        )
        assert "dns-nsec-enum" not in scripts_ip


# ============================================================================
# 5. Three-Tier Authorization Gate
# ============================================================================

class TestNmapThreeTierAuthorization:
    def test_profile_authorization_matrix(self):
        adapter = NmapAdapter()
        target = Target(name="Test", type=TargetType.IP, value="192.168.1.50")
        with patch("app.core.ssrf_protector.is_ip_allowed", return_value=(True, None)):
            val_target = create_validated_target(target, allow_internal=True)

        # Allowed profiles
        for prof in [ScanProfile.FULL_STACK, ScanProfile.NETWORK_ONLY, ScanProfile.NETWORK_TLS, ScanProfile.QUICK, ScanProfile.EASM_EXPANDED]:
            cfg = ScanConfig(profile=prof)
            ok, _ = adapter.evaluate_three_tier_authorization(val_target, cfg)
            assert ok is True

        # Prohibited profiles
        for prof in [ScanProfile.SAST_ONLY, ScanProfile.DAST_ONLY, ScanProfile.INFRA_ONLY, ScanProfile.SUPPLY_CHAIN_SBOM]:
            cfg = ScanConfig(profile=prof)
            ok, err = adapter.evaluate_three_tier_authorization(val_target, cfg)
            assert ok is False
            assert "prohibits Nmap" in err


# ============================================================================
# 6. Hardened XML Parser & Secret Sanitization
# ============================================================================

class TestNmapXMLParserHardening:
    def test_xml_parser_resilience(self):
        adapter = NmapAdapter()
        target = Target(name="Test", type=TargetType.IP, value="192.168.1.50")
        with patch("app.core.ssrf_protector.is_ip_allowed", return_value=(True, None)):
            val_target = create_validated_target(target, allow_internal=True)

        # 1. Malformed XML
        findings, state, _ = adapter.parse_nmap_xml("<nmaprun><unclosed>", val_target, "test-scan")
        assert len(findings) == 0
        assert state == NormalizedExecutionState.PARTIAL_RESULTS_WITH_WARNING

        # 2. Empty XML
        findings, state, _ = adapter.parse_nmap_xml("", val_target, "test-scan")
        assert len(findings) == 0
        assert state == NormalizedExecutionState.TOOL_EXECUTION_FAILED

        # 3. Non-nmap root
        findings, state, _ = adapter.parse_nmap_xml("<otherroot><port/></otherroot>", val_target, "test-scan")
        assert len(findings) == 0
        assert state == NormalizedExecutionState.PARTIAL_RESULTS_WITH_WARNING

    def test_secret_and_credential_sanitization(self):
        raw_text = "Server: Apache/2.4.41 password: super_secret_pass_123 token=abc123xyz456"
        sanitized = sanitize_banner_or_script(raw_text)
        assert "super_secret_pass_123" not in sanitized
        assert "abc123xyz456" not in sanitized
        assert "[MASKED]" in sanitized
        assert "Apache/2.4.41" in sanitized

    def test_xml_finding_classification_and_deduplication(self):
        xml_with_dupes_and_services = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" version="7.95">
<host>
    <status state="up"/>
    <address addr="192.168.1.50" addrtype="ipv4"/>
    <ports>
        <port protocol="tcp" portid="3306"><state state="open"/><service name="mysql" product="MySQL" version="8.0.35"/></port>
        <port protocol="tcp" portid="3306"><state state="open"/><service name="mysql" product="MySQL" version="8.0.35"/></port>
        <port protocol="tcp" portid="6379"><state state="open"/><service name="redis" product="Redis"/></port>
        <port protocol="tcp" portid="21"><state state="open"/><service name="ftp" product="vsftpd"/></port>
        <port protocol="tcp" portid="443"><state state="open"/><service name="https" product="nginx" version="1.24"/></port>
        <port protocol="tcp" portid="80"><state state="closed"/></port>
    </ports>
</host>
</nmaprun>
"""
        adapter = NmapAdapter()
        target = Target(name="Test", type=TargetType.IP, value="192.168.1.50")
        with patch("app.core.ssrf_protector.is_ip_allowed", return_value=(True, None)):
            val_target = create_validated_target(target, allow_internal=True)

        findings, state, hashes = adapter.parse_nmap_xml(xml_with_dupes_and_services, val_target, "test-scan")

        # 4 unique open ports (Port 3306 duplicate deduped, Port 80 closed ignored)
        assert len(findings) == 4
        assert state == NormalizedExecutionState.COMPLETED_WITH_FINDINGS
        assert len(hashes) == 4

        check_map = {f.check_id: f for f in findings}
        assert "NET-PORT-001" in check_map  # MySQL 3306 (High)
        assert "NET-PORT-002" in check_map  # Redis 6379 (High)
        assert "NET-PORT-003" in check_map  # FTP 21 (Medium)
        assert "NET-SVC-001" in check_map   # HTTPS 443 (Info)


# ============================================================================
# 7. Fallback Preservation & Engine Degradation
# ============================================================================

class TestNmapFallbackPreservation:
    @pytest.mark.asyncio
    async def test_network_engine_nmap_fallback(self):
        engine = NetworkAssessmentEngine()
        target = Target(name="Test Target", type=TargetType.DOMAIN, value="example.com")
        config = ScanConfig(adapters=ToolAdapterConfig(enable_nmap=True, enable_sslyze=False))

        logs = []
        findings = []

        async def log_cb(lvl, msg):
            logs.append((lvl, msg))

        async def prog_cb(pct, stg):
            pass

        async def find_cb(f):
            findings.append(f)

        # Simulate Nmap binary missing
        with patch("app.adapters.nmap_adapter.NmapAdapter.resolve_binary_path", return_value=None):
            with patch("app.engines.network.engine.audit_tls_certificates", new_callable=AsyncMock, return_value=[]), \
                 patch("app.engines.network.engine.audit_tls_protocols_and_ciphers", new_callable=AsyncMock, return_value=[]), \
                 patch("app.engines.network.engine.audit_dns_hygiene", new_callable=AsyncMock, return_value=[]), \
                 patch("app.engines.network.engine.audit_exposed_ports", new_callable=AsyncMock) as mock_port:

                dummy_port_finding = Finding(
                    scan_id="test",
                    engine="network",
                    check_id="NET-PORT-001",
                    category="Network",
                    title="Exposed Port",
                    severity=Severity.HIGH,
                    cvss_score=7.5,
                    cwe_id="CWE-284",
                    description="Port open",
                    impact="Exposed database daemon allows unauthorized access.",
                    remediation="Block port",
                    evidence=Evidence(location="example.com:3306", observed_value="Open", expected_value="Closed"),
                    fingerprint="fp123",
                )
                mock_port.return_value = [dummy_port_finding]

                results = await engine.run(target, config, log_cb, prog_cb, find_cb)

                # Verify native port checker ran and tagged finding as native
                assert len(results) >= 1
                native_f = next(f for f in results if f.check_id == "NET-PORT-001")
                assert native_f.source_tool == "native"
                assert any("fallback" in l[1].lower() for l in logs)
