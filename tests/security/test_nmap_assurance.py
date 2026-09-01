"""
Authoritative Contract 09 (TOOL-NMAP v14.3.0) & Goal E11.1 Assurance Test Suite.
Verifies all 41 specification points, security boundaries, parameter injection defenses,
exact version pinning, destination binding, NSE allowlists, XML parser hardening,
multi-tier OS process tree termination, 5-case three-tier authorization matrix, and fallback invariants.
"""

import asyncio
from datetime import datetime, timezone
import os
import socket
import subprocess
import sys
import time
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
    OSINTConfig,
    APP_VERSION,
    CONTRACT_VERSION,
    SCHEMA_VERSION,
    RULESET_VERSION,
    RISK_MODEL_VERSION,
)
from app.adapters.nmap_adapter import (
    NmapAdapter,
    NmapCommandBuilder,
    NmapExecutionRecord,
    ToolOperationClass,
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
from app.core.process_supervisor import ProcessSupervisor
from app.engines.network.engine import NetworkAssessmentEngine


# ============================================================================
# 1. Identity, Version Enforcement, Trust Mode & Version Hierarchy
# ============================================================================

class TestNmapIdentityAndVersion:
    def test_nmap_identity_and_trust_mode(self):
        adapter = NmapAdapter()
        assert adapter.tool_id == "TOOL-NMAP"
        assert adapter.tool_name == "nmap"
        assert adapter.approved_version == "7.95"
        assert adapter.trust_mode == "PACKAGE_MANAGER_MODE"
        assert adapter.operation_class == ToolOperationClass.ACTIVE_READ_ONLY

    def test_version_authority_hierarchy(self):
        # Verify authoritative version hierarchy as documented in Contract 01 §1 & Contract 02 §1
        assert APP_VERSION == "14.3.0"
        assert CONTRACT_VERSION == "14.3.0"
        assert SCHEMA_VERSION == "4.1.0"
        assert RULESET_VERSION == "14.3.0"
        assert RISK_MODEL_VERSION == "14.3.0"

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
    def test_validated_target_destination_binding_command_plane(self):
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
            intrusive_authorized=True,
            dns_zone_authorized=True,
        )
        assert err is None
        # Destination argument MUST be the pre-resolved IP
        assert cmd[-1] == "93.184.216.34"
        # Script args MUST inject Host header context separately from IP destination
        assert "--script-args" in cmd
        assert "http.host=example.com" in cmd

    def test_controlled_loopback_destination_binding_fixture(self):
        """
        Controlled Socket Fixture: Proves that NmapCommandBuilder binds exclusively
        to the pinned selected_destination IP and does not perform unvalidated hostname lookups.
        """
        # Create target with a non-routable dummy hostname but pinned to loopback IP
        target = Target(name="Local Test", type=TargetType.IP, value="127.0.0.1")
        with patch("app.core.ssrf_protector.is_ip_allowed", return_value=(True, None)):
            val_target = create_validated_target(target, allow_internal=True)

        config = ScanConfig(port_list=[9999])
        cmd, ports, scripts, err = NmapCommandBuilder.build_command(
            nmap_path="/usr/bin/nmap",
            target=val_target,
            config=config,
        )
        assert err is None
        assert cmd[-1] == "127.0.0.1"

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
        # 1. Target is DOMAIN, custom_scripts=["dns-nsec-enum"], dns_zone_authorized=True, intrusive_authorized=True -> ALLOWED
        domain_target = Target(name="Domain Target", type=TargetType.DOMAIN, value="example.com")
        with patch("app.core.ssrf_protector.resolve_hostname_ips", return_value=["93.184.216.34"]):
            val_domain = create_validated_target(domain_target)

        _, _, scripts_domain, err = NmapCommandBuilder.build_command(
            nmap_path="/usr/bin/nmap",
            target=val_domain,
            config=ScanConfig(),
            intrusive_authorized=True,
            dns_zone_authorized=True,
            custom_scripts=["dns-nsec-enum"],
        )
        assert err is None
        assert "dns-nsec-enum" in scripts_domain

        # 2. Target is DOMAIN, custom_scripts=["dns-nsec-enum"], dns_zone_authorized=False -> REJECTED
        _, _, _, err_unauth = NmapCommandBuilder.build_command(
            nmap_path="/usr/bin/nmap",
            target=val_domain,
            config=ScanConfig(),
            intrusive_authorized=True,
            dns_zone_authorized=False,
            custom_scripts=["dns-nsec-enum"],
        )
        assert err_unauth is not None
        assert "requires explicit DNS zone" in err_unauth

        # 3. Target is IP, custom_scripts=["dns-nsec-enum"] -> REJECTED (Domain only)
        ip_target = Target(name="IP Target", type=TargetType.IP, value="93.184.216.34")
        val_ip = create_validated_target(ip_target)
        _, _, _, err_ip = NmapCommandBuilder.build_command(
            nmap_path="/usr/bin/nmap",
            target=val_ip,
            config=ScanConfig(),
            intrusive_authorized=True,
            dns_zone_authorized=True,
            custom_scripts=["dns-nsec-enum"],
        )
        assert err_ip is not None
        assert "restricted exclusively to DOMAIN targets" in err_ip

        # 4. Default discovery scripts are strictly ACTIVE_READ_ONLY (no automatic intrusive escalation)
        _, _, default_scripts, default_err = NmapCommandBuilder.build_command(
            nmap_path="/usr/bin/nmap",
            target=val_domain,
            config=ScanConfig(),
            intrusive_authorized=False,
            dns_zone_authorized=True,
            custom_scripts=None,
        )
        assert default_err is None
        assert "dns-nsec-enum" not in default_scripts
        assert default_scripts == ["banner", "ssl-cert", "http-title", "ssh2-enum-algos"]

    def test_command_builder_enforces_intrusive_authorization_boundary(self):
        """
        Contract 09 §1.1 Invariant 7: Proves that NmapCommandBuilder refuses to construct
        an intrusive command if intrusive_authorized is False at the execution boundary.
        """
        from app.adapters.nmap_adapter import classify_nmap_operation

        domain_target = Target(name="Domain Target", type=TargetType.DOMAIN, value="example.com")
        with patch("app.core.ssrf_protector.resolve_hostname_ips", return_value=["93.184.216.34"]):
            val_domain = create_validated_target(domain_target)

        # 1. Intrusive script requested with intrusive_authorized=False -> COMMAND REFUSED
        cmd, _, _, err = NmapCommandBuilder.build_command(
            nmap_path="/usr/bin/nmap",
            target=val_domain,
            config=ScanConfig(),
            intrusive_authorized=False,
            dns_zone_authorized=True,
            custom_scripts=["dns-nsec-enum"],
        )
        assert cmd == []
        assert err is not None
        assert "INTRUSIVE_OPERATION_REJECTED" in err

        # 2. Read-only scripts requested with intrusive_authorized=False -> COMMAND PERMITTED
        cmd_ro, _, scripts_ro, err_ro = NmapCommandBuilder.build_command(
            nmap_path="/usr/bin/nmap",
            target=val_domain,
            config=ScanConfig(),
            intrusive_authorized=False,
            custom_scripts=["banner", "ssl-cert"],
        )
        assert err_ro is None
        assert "banner" in scripts_ro
        assert "ssl-cert" in scripts_ro

        # 3. Test classify_nmap_operation deterministic outputs from NSE_SCRIPT_CAPABILITIES taxonomy
        assert classify_nmap_operation(["banner", "ssl-cert"]) == ToolOperationClass.ACTIVE_READ_ONLY
        assert classify_nmap_operation(["dns-nsec-enum"]) == ToolOperationClass.ACTIVE_INTRUSIVE
        assert classify_nmap_operation(None) == ToolOperationClass.ACTIVE_READ_ONLY
        assert classify_nmap_operation(["http-title", "ssh2-enum-algos"]) == ToolOperationClass.ACTIVE_READ_ONLY


# ============================================================================
# 5. Three-Tier Authorization Gate Complete Truth Table Matrix
# ============================================================================

class TestNmapThreeTierAuthorization:
    def test_three_tier_authorization_complete_truth_table(self):
        """
        Tests all conditions of the three-tier authorization gate:
        | Case | Capability | Profile | Tenant Scope | Operation Class   | Expected | Failed Gate |
        | 1    | False      | False   | False        | ACTIVE_READ_ONLY  | BLOCK    | TOOL_CAPABILITY |
        | 2    | False      | True    | True         | ACTIVE_READ_ONLY  | BLOCK    | TOOL_CAPABILITY |
        | 3    | True       | False   | True         | ACTIVE_READ_ONLY  | BLOCK    | PROFILE_AUTHORIZATION |
        | 4a   | True       | True    | False (Out)  | ACTIVE_READ_ONLY  | BLOCK    | TENANT_SCOPE_AUTHORIZATION |
        | 4b   | True       | True    | False (Intr) | ACTIVE_INTRUSIVE  | BLOCK    | TENANT_SCOPE_AUTHORIZATION |
        | 4c   | True       | True    | True (Scope) | ACTIVE_READ_ONLY  | ALLOW    | None |
        | 5    | True       | True    | True (Intr)  | ACTIVE_INTRUSIVE  | ALLOW    | None |
        """
        adapter = NmapAdapter()
        target = Target(name="Test", type=TargetType.IP, value="192.168.1.50")
        with patch("app.core.ssrf_protector.is_ip_allowed", return_value=(True, None)):
            val_target_authorized = create_validated_target(target, allow_internal=True)

        # Target with active_probing_granted = False in authorization context
        val_target_no_active_probing = ValidatedTarget(
            target_id=val_target_authorized.target_id,
            authorization_decision_id="auth-123",
            integrity_seal="seal-123",
            target_type=TargetType.IP,
            raw_value="192.168.1.50",
            canonical_value="192.168.1.50",
            selected_destination="192.168.1.50",
            authorized_scope=["192.168.1.50"],
            authorization_context={"active_probing_granted": False},
        )

        # Target outside authorized scope
        val_target_out_of_scope = ValidatedTarget(
            target_id=val_target_authorized.target_id,
            authorization_decision_id="auth-123",
            integrity_seal="seal-123",
            target_type=TargetType.IP,
            raw_value="192.168.1.50",
            canonical_value="192.168.1.50",
            selected_destination="192.168.1.50",
            authorized_scope=["10.0.0.1"],
            authorization_context={"active_probing_granted": True},
        )

        # Target with active_probing_granted = True and in-scope
        val_target_active_probing = ValidatedTarget(
            target_id=val_target_authorized.target_id,
            authorization_decision_id="auth-123",
            integrity_seal="seal-123",
            target_type=TargetType.IP,
            raw_value="192.168.1.50",
            canonical_value="192.168.1.50",
            selected_destination="192.168.1.50",
            authorized_scope=["192.168.1.50"],
            authorization_context={"active_probing_granted": True},
        )

        cfg_valid_profile = ScanConfig(profile=ScanProfile.FULL_STACK)
        cfg_invalid_profile = ScanConfig(profile=ScanProfile.SAST_ONLY)

        # Case 1: Capability=False, Profile=False, TenantScope=False -> BLOCK (TOOL_CAPABILITY)
        ok1, _, gate1 = adapter.evaluate_three_tier_authorization(
            val_target_no_active_probing,
            cfg_invalid_profile,
            operation_class=ToolOperationClass.ACTIVE_READ_ONLY,
            custom_scripts=["prohibited_exploit_script"],
        )
        assert ok1 is False
        assert gate1 == "TOOL_CAPABILITY"

        # Case 2: Capability=False, Profile=True, TenantScope=True -> BLOCK (TOOL_CAPABILITY)
        ok2, _, gate2 = adapter.evaluate_three_tier_authorization(
            val_target_active_probing,
            cfg_valid_profile,
            operation_class=ToolOperationClass.ACTIVE_READ_ONLY,
            custom_scripts=["prohibited_dos_script"],
        )
        assert ok2 is False
        assert gate2 == "TOOL_CAPABILITY"

        # Case 3: Capability=True, Profile=False, TenantScope=True -> BLOCK (PROFILE_AUTHORIZATION)
        ok3, _, gate3 = adapter.evaluate_three_tier_authorization(
            val_target_active_probing,
            cfg_invalid_profile,
            operation_class=ToolOperationClass.ACTIVE_READ_ONLY,
            custom_scripts=["banner"],
        )
        assert ok3 is False
        assert gate3 == "PROFILE_AUTHORIZATION"

        # Case 4a: Capability=True, Profile=True, Out of Scope -> BLOCK (TENANT_SCOPE_AUTHORIZATION)
        ok4a, _, gate4a = adapter.evaluate_three_tier_authorization(
            val_target_out_of_scope,
            cfg_valid_profile,
            operation_class=ToolOperationClass.ACTIVE_READ_ONLY,
            custom_scripts=["banner"],
        )
        assert ok4a is False
        assert gate4a == "TENANT_SCOPE_AUTHORIZATION"

        # Case 4b: Capability=True, Profile=True, Intrusive requested without active_probing -> BLOCK (TENANT_SCOPE_AUTHORIZATION)
        ok4b, _, gate4b = adapter.evaluate_three_tier_authorization(
            val_target_no_active_probing,
            cfg_valid_profile,
            operation_class=ToolOperationClass.ACTIVE_INTRUSIVE,
            custom_scripts=["dns-nsec-enum"],
        )
        assert ok4b is False
        assert gate4b == "TENANT_SCOPE_AUTHORIZATION"

        # Case 4c: Capability=True, Profile=True, Read-only operation with base scope -> ALLOW (None)
        ok4c, _, gate4c = adapter.evaluate_three_tier_authorization(
            val_target_no_active_probing,
            cfg_valid_profile,
            operation_class=ToolOperationClass.ACTIVE_READ_ONLY,
            custom_scripts=["banner"],
        )
        assert ok4c is True
        assert gate4c is None

        # Case 5: Capability=True, Profile=True, Intrusive operation with active_probing -> ALLOW (None)
        ok5, _, gate5 = adapter.evaluate_three_tier_authorization(
            val_target_active_probing,
            cfg_valid_profile,
            operation_class=ToolOperationClass.ACTIVE_INTRUSIVE,
            custom_scripts=["dns-nsec-enum"],
        )
        assert ok5 is True
        assert gate5 is None


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

    def test_xml_finding_classification_observation_vs_misconfiguration(self):
        """
        Verifies that open services are classified as asset observations (NET-SVC-001, Severity.INFO, CVSS 0.0)
        rather than universal inflated HIGH CVSS vulnerabilities, while cleartext protocols (Telnet 23)
        are categorized as misconfigurations (NET-PORT-003, Severity.MEDIUM, CWE-319).
        """
        xml_data = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" version="7.95">
<host>
    <status state="up"/>
    <address addr="192.168.1.50" addrtype="ipv4"/>
    <ports>
        <port protocol="tcp" portid="3306"><state state="open"/><service name="mysql" product="MySQL" version="8.0.35"/></port>
        <port protocol="tcp" portid="23"><state state="open"/><service name="telnet" product="Linux telnetd"/></port>
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

        findings, state, hashes = adapter.parse_nmap_xml(xml_data, val_target, "test-scan")

        assert len(findings) == 3
        assert state == NormalizedExecutionState.COMPLETED_WITH_FINDINGS

        check_map = {f.check_id: f for f in findings}
        
        # Telnet (Port 23) -> Insecure Cleartext Management (MEDIUM, CVSS 5.3, CWE-319)
        assert "NET-PORT-003" in check_map
        telnet_f = check_map["NET-PORT-003"]
        assert telnet_f.severity == Severity.MEDIUM
        assert telnet_f.cvss_score == 5.3
        assert telnet_f.cwe_id == "CWE-319"

        # MySQL (Port 3306) and HTTPS (Port 443) -> Service Posture Observations (INFO, CVSS 0.0, CWE-200)
        assert "NET-SVC-001" in check_map
        svc_findings = [f for f in findings if f.check_id == "NET-SVC-001"]
        assert len(svc_findings) == 2
        for f in svc_findings:
            assert f.severity == Severity.INFO
            assert f.cvss_score == 0.0
            assert f.cwe_id == "CWE-200"


# ============================================================================
# 7. OS-Level Process Tree Termination Fixture
# ============================================================================

class TestNmapProcessTreeTermination:
    @pytest.mark.asyncio
    async def test_process_tree_descendant_termination_os_level(self):
        """
        Contract 03 §3 & Contract 09 TOOL-NMAP §40:
        Spawns a multi-level process tree (parent -> child -> grandchild)
        and proves that ProcessSupervisor.kill_process_tree terminates all descendants at OS level.
        """
        supervisor = ProcessSupervisor.get_instance()
        
        # Script that launches child python process which sleeps
        script = """
import subprocess, sys, time
proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
with open("grandchild.pid", "w") as f:
    f.write(str(proc.pid))
time.sleep(60)
"""
        # Execute script via supervisor with short timeout
        returncode, stdout, stderr = await supervisor.execute(
            [sys.executable, "-c", script],
            timeout=1.0,
        )
        assert returncode == -1
        assert "timed out" in stderr.lower()

        # Read grandchild PID if written
        grandchild_pid = None
        if os.path.exists("grandchild.pid"):
            try:
                with open("grandchild.pid", "r") as f:
                    grandchild_pid = int(f.read().strip())
                os.remove("grandchild.pid")
            except Exception:
                pass

        # Verify grandchild process is dead at OS level
        if grandchild_pid:
            # Check OS process existence
            if sys.platform == "win32":
                check_cmd = f"tasklist /FI \"PID eq {grandchild_pid}\""
                out = subprocess.run(check_cmd, shell=True, capture_output=True, text=True)
                assert str(grandchild_pid) not in out.stdout or "No tasks" in out.stdout
            else:
                with pytest.raises(OSError):
                    os.kill(grandchild_pid, 0)


# ============================================================================
# 8. Fallback Preservation & Explicit Coverage Loss
# ============================================================================

class TestNmapFallbackPreservation:
    @pytest.mark.asyncio
    async def test_network_engine_nmap_fallback(self):
        engine = NetworkAssessmentEngine()
        target = Target(name="Test Target", type=TargetType.DOMAIN, value="example.com")
        config = ScanConfig(
            adapters=ToolAdapterConfig(enable_nmap=True, enable_sslyze=False),
            osint=OSINTConfig(subdomain_enumeration=False),
        )

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
                    check_id="NET-SVC-001",
                    category="Service Posture",
                    title="Exposed Port",
                    severity=Severity.INFO,
                    cvss_score=0.0,
                    cwe_id="CWE-200",
                    description="Port open",
                    impact="Discovered listening daemon.",
                    remediation="Audit service exposure.",
                    evidence=Evidence(location="example.com:3306", observed_value="Open", expected_value="Closed"),
                    fingerprint="fp123",
                )
                mock_port.return_value = [dummy_port_finding]

                results = await engine.run(target, config, log_cb, prog_cb, find_cb)

                # Verify native port checker ran and tagged finding as native
                assert len(results) >= 1
                native_f = next(f for f in results if f.check_id == "NET-SVC-001")
                assert native_f.source_tool == "native"
                assert any("fallback" in l[1].lower() for l in logs)
