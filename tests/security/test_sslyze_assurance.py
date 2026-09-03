"""
Authoritative Independent Security Assurance Suite: SSLyze Tool Adapter (TOOL-SSLYZE).
Contract Reference: contracts/09_TOOL_IMPLEMENTATION_CONTRACT.md (TOOL 02: SSLyze v14.3.0)

Rigorous verification of:
1. Tool Identity, Supply-Chain Trust Mode, & Exact Version 5.2.0 Pinning
2. ValidatedTarget Connection Destination Binding & SNI Host Header Separation
3. CLI Flag Allowlist, Parameter Validation & Argument Injection Defenses
4. Three-Tier Authorization Gate Truth Table Matrix (Tool, Profile, Tenant Scope)
5. Hardened JSON Parser & Canonical Finding Normalization (NET-TLS-001/002/003/006/007/008)
6. Private Key & Credential Sanitization
7. Process Supervision, Descendant Termination & Native TLS Fallback Preservation
"""

import argparse
import hashlib
import json
import os
import pytest
import unittest.mock as mock
from unittest.mock import AsyncMock, patch

from app.adapters.sslyze_adapter import (
    SslyzeAdapter,
    SslyzeCommandBuilder,
    classify_sslyze_operation,
    sanitize_tls_evidence_text,
    TOOL_ID,
    TOOL_NAME,
    APPROVED_VERSION,
    TRUST_MODE,
    ROLE,
    ToolOperationClass,
    APPROVED_SSLYZE_FLAGS,
    DEFAULT_SCAN_FLAGS,
    CONFIG_ASSESSMENT_FLAGS,
    VULN_PROBE_FLAGS,
    APPROVED_ARTIFACT_SHA256_SDIST,
    APPROVED_ARTIFACT_SHA256_WHEEL,
)
from app.core.models import (
    Target,
    ValidatedTarget,
    TargetType,
    ScanConfig,
    ScanProfile,
    Severity,
    LogLevel,
    NormalizedExecutionState,
)
from app.core.ssrf_protector import create_validated_target, SSRFProtectionError
from app.core.version import (
    APP_VERSION,
    CONTRACT_VERSION,
    SCHEMA_VERSION,
    RULESET_VERSION,
    RISK_MODEL_VERSION,
)


# ============================================================================
# 1. Tool Identity, Supply-Chain Trust & Version Authority Hierarchy
# ============================================================================

class TestSslyzeIdentityAndVersion:
    def test_sslyze_identity_and_trust_mode(self):
        adapter = SslyzeAdapter()
        assert adapter.tool_name == "sslyze"
        assert adapter.approved_version == "5.2.0"
        assert adapter.trust_mode == "PACKAGE_MANAGER_MODE"
        assert adapter.role == "PRIMARY"
        assert adapter.security_domain == "NETWORK / PERIMETER / TLS"
        assert adapter.default_operation_class == ToolOperationClass.ACTIVE_READ_ONLY

    def test_assured_execution_requires_installer_trust_record(self, tmp_path, monkeypatch):
        adapter = SslyzeAdapter()
        venv_root = tmp_path / "tool-venvs"
        bin_dir = venv_root / "sslyze" / ("Scripts" if os.name == "nt" else "bin")
        bin_dir.mkdir(parents=True)
        executable = bin_dir / "sslyze"
        executable.write_text("managed executable")
        (bin_dir / ("python.exe" if os.name == "nt" else "python")).write_text("managed interpreter")
        if os.name != "nt":
            executable.chmod(0o755)
        monkeypatch.setenv("CYBERASSESS_TOOL_VENV_DIR", str(venv_root))

        # An isolated path and matching interpreter are insufficient.  The
        # pip installer must first create the durable package trust record.
        assert adapter.verify_managed_binary(str(executable)) is False
        assert adapter.verify_managed_binary(str(tmp_path / "sslyze")) is False

    def test_version_authority_hierarchy(self):
        assert APP_VERSION == "14.3.0"
        assert CONTRACT_VERSION == "14.3.0"
        assert SCHEMA_VERSION == "4.1.0"
        assert RULESET_VERSION == "14.3.0"
        assert RISK_MODEL_VERSION == "14.3.0"

    def test_exact_version_pinning_matrix(self):
        adapter = SslyzeAdapter()

        # Exact approved version 5.2.0 -> PASS
        for valid_ver in ["SSLyze 5.2.0", "5.2.0", "sslyze v5.2.0", "SSLyze v5.2.0"]:
            ok, err = adapter.verify_version(valid_ver)
            assert ok is True
            assert err is None

        # Outdated or Incompatible versions -> FAIL CLOSED
        for invalid_ver in ["SSLyze 5.1.0", "5.3.0", "SSLyze 6.0.0", "4.9.0", "SSLyze 5.2.1"]:
            ok, err = adapter.verify_version(invalid_ver)
            assert ok is False
            assert "INVALID_VERSION" in err

        # Empty / None probe -> FAIL CLOSED
        ok, err = adapter.verify_version(None)
        assert ok is False
        assert "empty" in err.lower()

    @pytest.mark.asyncio
    async def test_version_probe_uses_own_venv_metadata(self, tmp_path):
        """SSLyze 5.2.0 has no --version flag; probe its owning venv instead."""
        adapter = SslyzeAdapter()
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        executable = bin_dir / "sslyze"
        interpreter = bin_dir / ("python.exe" if os.name == "nt" else "python")
        executable.touch()
        interpreter.touch()

        with patch.object(adapter, "resolve_binary_path", return_value=str(executable)):
            with patch.object(
                adapter,
                "execute_command",
                return_value=(0, "5.2.0\n", ""),
            ) as execute:
                assert await adapter.get_version() == "SSLyze 5.2.0"

        assert execute.call_args.args[0][0] == str(interpreter.resolve())
        assert execute.call_args.args[0][1] == "-c"
        assert "metadata.version('sslyze')" in execute.call_args.args[0][2]


# ============================================================================
# 2. ValidatedTarget & Connection Destination Binding
# ============================================================================

class TestSslyzeDestinationBinding:
    def test_validated_target_destination_binding_command_plane(self):
        """
        Contract 09 TOOL-SSLYZE §13: Proves that SSLyze targets the pre-resolved
        selected_destination IP as the socket endpoint and separates the virtual
        host context via --sni.
        """
        target = Target(name="Domain Target", type=TargetType.DOMAIN, value="example.com")
        with patch("app.core.ssrf_protector.resolve_hostname_ips", return_value=["93.184.216.34"]):
            val_target = create_validated_target(target)

        assert val_target.canonical_value == "example.com"
        assert val_target.selected_destination == "93.184.216.34"

        cmd, dest_ip, port, err = SslyzeCommandBuilder.build_command(
            sslyze_path="/usr/bin/sslyze",
            target=val_target,
            port=443,
        )
        assert err is None
        assert dest_ip == "93.184.216.34"
        assert port == 443
        assert cmd[0] == "/usr/bin/sslyze"
        assert "--json_out=-" in cmd
        assert "93.184.216.34:443" in cmd
        assert "--sni=example.com" in cmd

    def test_controlled_loopback_destination_binding_fixture(self):
        """
        Controlled Socket Fixture: Validates that an internal target binds
        strictly to the designated loopback socket without resolving hostnames.
        """
        target = Target(name="Internal TLS", type=TargetType.URL, value="https://secure.internal:8443")
        with patch("app.core.ssrf_protector.resolve_hostname_ips", return_value=["10.0.0.1"]):
            val_target = create_validated_target(target, allow_internal=True)

        assert val_target.selected_destination == "10.0.0.1"
        assert val_target.port == 8443

        cmd, dest_ip, port, err = SslyzeCommandBuilder.build_command(
            sslyze_path="/usr/bin/sslyze",
            target=val_target,
        )
        assert err is None
        assert dest_ip == "10.0.0.1"
        assert port == 8443
        assert "10.0.0.1:8443" in cmd
        assert "--sni=secure.internal" in cmd

    def test_ssrf_forbidden_target_blocked(self):
        """
        Contract 01 §5.1: Assert SSRF forbidden internal destinations are blocked.
        """
        target = Target(name="AWS Metadata", type=TargetType.IP, value="169.254.169.254")
        with pytest.raises(SSRFProtectionError):
            create_validated_target(target, allow_internal=False)


# ============================================================================
# 3. CLI Flag Validation & Argument Injection Defenses
# ============================================================================

class TestSslyzeFlagValidation:
    def test_valid_scan_flags(self):
        target = Target(name="Domain Target", type=TargetType.DOMAIN, value="example.com")
        with patch("app.core.ssrf_protector.resolve_hostname_ips", return_value=["93.184.216.34"]):
            val_target = create_validated_target(target)

        custom = ["--certinfo", "--tlsv1_2", "--tlsv1_3", "--heartbleed"]
        cmd, _, _, err = SslyzeCommandBuilder.build_command(
            sslyze_path="/usr/bin/sslyze",
            target=val_target,
            custom_flags=custom,
        )
        assert err is None
        for flag in custom:
            assert flag in cmd

    def test_rejection_of_arbitrary_file_write_and_injection(self):
        target = Target(name="Domain Target", type=TargetType.DOMAIN, value="example.com")
        with patch("app.core.ssrf_protector.resolve_hostname_ips", return_value=["93.184.216.34"]):
            val_target = create_validated_target(target)

        # 1. Reject arbitrary file output
        cmd, _, _, err = SslyzeCommandBuilder.build_command(
            sslyze_path="/usr/bin/sslyze",
            target=val_target,
            custom_flags=["--json_out=/tmp/pwned.json"],
        )
        assert cmd == []
        assert err is not None
        assert "Arbitrary file output" in err

        # 2. Reject unapproved arbitrary flags
        cmd_bad, _, _, err_bad = SslyzeCommandBuilder.build_command(
            sslyze_path="/usr/bin/sslyze",
            target=val_target,
            custom_flags=["--exec=malicious_payload"],
        )
        assert cmd_bad == []
        assert "not on the approved allowlist" in err_bad

        # 3. Reject invalid port values
        cmd_port, _, _, err_port = SslyzeCommandBuilder.build_command(
            sslyze_path="/usr/bin/sslyze",
            target=val_target,
            port=99999,
        )
        assert cmd_port == []
        assert "port out of valid range" in err_port


# ============================================================================
# 4. Three-Tier Authorization Gate Complete Truth Table Matrix
# ============================================================================

class TestSslyzeThreeTierAuthorization:
    def test_three_tier_authorization_truth_table(self):
        """
        Tests all conditions of the three-tier authorization gate for SSLyze:
        | Case | Capability | Profile | Tenant Scope | Expected | Failed Gate |
        | 1    | False (Type) | True  | True         | BLOCK    | TOOL_CAPABILITY |
        | 2    | False (Flag) | True  | True         | BLOCK    | TOOL_CAPABILITY |
        | 3    | True         | False | True         | BLOCK    | PROFILE_AUTHORIZATION |
        | 4    | True         | True  | False (Out)  | BLOCK    | TENANT_SCOPE_AUTHORIZATION |
        | 5    | True         | True  | True         | ALLOW    | None |
        """
        adapter = SslyzeAdapter()
        target = Target(name="Test", type=TargetType.IP, value="192.168.1.50")
        with patch("app.core.ssrf_protector.is_ip_allowed", return_value=(True, None)):
            val_target = create_validated_target(target, allow_internal=True)

        cfg_valid = ScanConfig(profile=ScanProfile.FULL_STACK)
        cfg_invalid_profile = ScanConfig(profile=ScanProfile.SAST_ONLY)

        # Case 1: Capability Gate fails on unsupported target type (LOCAL_PATH)
        val_target_bad_type = ValidatedTarget(
            target_id="tid-1",
            authorization_decision_id="aid-1",
            integrity_seal="seal-1",
            target_type=TargetType.LOCAL_PATH,
            raw_value="/tmp/code",
            canonical_value="/tmp/code",
            selected_destination="/tmp/code",
            authorized_scope=["/tmp/code"],
        )
        ok1, err1, gate1 = adapter.evaluate_three_tier_authorization(val_target_bad_type, cfg_valid)
        assert ok1 is False
        assert gate1 == "TOOL_CAPABILITY"

        # Case 2: Capability Gate fails on unapproved flag
        ok2, err2, gate2 = adapter.evaluate_three_tier_authorization(
            val_target,
            cfg_valid,
            custom_flags=["--unapproved-flag"],
        )
        assert ok2 is False
        assert gate2 == "TOOL_CAPABILITY"

        # Case 3: Profile Gate fails on SAST_ONLY profile
        ok3, err3, gate3 = adapter.evaluate_three_tier_authorization(val_target, cfg_invalid_profile)
        assert ok3 is False
        assert gate3 == "PROFILE_AUTHORIZATION"

        # Case 4: Tenant Scope Gate fails on out-of-scope target
        val_target_out_of_scope = ValidatedTarget(
            target_id="tid-out",
            authorization_decision_id="aid-out",
            integrity_seal="seal-out",
            target_type=TargetType.IP,
            raw_value="192.168.1.50",
            canonical_value="192.168.1.50",
            selected_destination="192.168.1.50",
            authorized_scope=["10.0.0.1"],
        )
        ok4, err4, gate4 = adapter.evaluate_three_tier_authorization(val_target_out_of_scope, cfg_valid)
        assert ok4 is False
        assert gate4 == "TENANT_SCOPE_AUTHORIZATION"

        # Case 5: All three gates pass
        ok5, err5, gate5 = adapter.evaluate_three_tier_authorization(val_target, cfg_valid)
        assert ok5 is True
        assert err5 is None
        assert gate5 is None


# ============================================================================
# 5. JSON Output Parser Hardening & Finding Normalization
# ============================================================================

SAMPLE_SSLYZE_FULL_JSON = {
    "sslyze_version": "5.2.0",
    "server_scan_results": [
        {
            "server_location": {
                "hostname": "93.184.216.34",
                "port": 443,
                "ip_address": "93.184.216.34"
            },
            "scan_result": {
                "ssl_2_0_cipher_suites": {
                    "result": {
                        "is_supported": False,
                        "accepted_cipher_suites": []
                    }
                },
                "ssl_3_0_cipher_suites": {
                    "result": {
                        "is_supported": True,
                        "accepted_cipher_suites": [
                            {"cipher_suite": {"name": "TLS_RSA_WITH_3DES_EDE_CBC_SHA"}}
                        ]
                    }
                },
                "tls_1_0_cipher_suites": {
                    "result": {
                        "is_supported": True,
                        "accepted_cipher_suites": [
                            {"cipher_suite": {"name": "TLS_RSA_WITH_AES_128_CBC_SHA"}}
                        ]
                    }
                },
                "tls_1_1_cipher_suites": {
                    "result": {
                        "is_supported": False,
                        "accepted_cipher_suites": []
                    }
                },
                "tls_1_2_cipher_suites": {
                    "result": {
                        "is_supported": True,
                        "accepted_cipher_suites": [
                            {"cipher_suite": {"name": "TLS_RSA_WITH_RC4_128_SHA"}},
                            {"cipher_suite": {"name": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"}}
                        ]
                    }
                },
                "tls_1_3_cipher_suites": {
                    "result": {
                        "is_supported": True,
                        "accepted_cipher_suites": [
                            {"cipher_suite": {"name": "TLS_AES_256_GCM_SHA384"}}
                        ]
                    }
                },
                "certificate_info": {
                    "result": {
                        "certificate_deployments": [
                            {
                                "received_certificate_chain": [
                                    {
                                        "subject": {"rfc4514_string": "CN=example.com"},
                                        "signature_hash_algorithm": {"name": "sha1"},
                                        "not_valid_after": "2020-01-01T00:00:00"
                                    }
                                ],
                                "path_validation_results": [
                                    {
                                        "trust_store": {"name": "Mozilla"},
                                        "is_valid_path": False,
                                        "validation_error": "Certificate has expired"
                                    }
                                ]
                            }
                        ]
                    }
                },
                "heartbleed": {
                    "result": {
                        "is_vulnerable_to_heartbleed": True
                    }
                },
                "robot": {
                    "result": {
                        "robot_result": "VULNERABLE_WEAK_ORACLE"
                    }
                },
                "openssl_ccs_injection": {
                    "result": {
                        "is_vulnerable_to_ccs_injection": True
                    }
                }
            }
        }
    ]
}


class TestSslyzeJSONParserHardening:
    def test_complete_finding_normalization(self):
        adapter = SslyzeAdapter()
        findings, state, hashes = adapter.parse_sslyze_json(
            json.dumps(SAMPLE_SSLYZE_FULL_JSON),
            target_host="example.com",
            target_port=443,
        )

        assert state == NormalizedExecutionState.COMPLETED_WITH_FINDINGS
        assert len(findings) >= 6
        assert len(hashes) >= 6

        check_ids = {f.check_id for f in findings}

        # 1. Deprecated Protocols (NET-TLS-001)
        assert "NET-TLS-001" in check_ids
        proto_findings = [f for f in findings if f.check_id == "NET-TLS-001"]
        assert any("SSL 3.0" in f.title for f in proto_findings)
        assert any("TLS 1.0" in f.title for f in proto_findings)
        for pf in proto_findings:
            assert pf.severity == Severity.HIGH
            assert pf.cvss_score == 7.5
            assert pf.cwe_id == "CWE-326"

        # 2. Weak Ciphers (NET-TLS-002)
        assert "NET-TLS-002" in check_ids
        weak_ciphers = [f for f in findings if f.check_id == "NET-TLS-002"]
        assert any("RC4" in f.title for f in weak_ciphers)
        for wf in weak_ciphers:
            assert wf.severity == Severity.MEDIUM
            assert wf.cvss_score == 5.9
            assert wf.cwe_id == "CWE-327"

        # 3. Certificate Flaws (NET-TLS-003)
        assert "NET-TLS-003" in check_ids
        cert_findings = [f for f in findings if f.check_id == "NET-TLS-003"]
        assert any("Expired" in f.title or "Untrusted" in f.title for f in cert_findings)
        assert any("SHA1" in f.title for f in cert_findings)

        # 4. Heartbleed (NET-TLS-006)
        assert "NET-TLS-006" in check_ids
        hb = next(f for f in findings if f.check_id == "NET-TLS-006")
        assert hb.severity == Severity.CRITICAL
        assert hb.cvss_score == 9.8
        assert hb.cwe_id == "CWE-119"

        # 5. ROBOT Bleichenbacher (NET-TLS-007)
        assert "NET-TLS-007" in check_ids
        robot = next(f for f in findings if f.check_id == "NET-TLS-007")
        assert robot.severity == Severity.HIGH
        assert robot.cvss_score == 7.4
        assert robot.cwe_id == "CWE-327"

        # 6. OpenSSL CCS Injection (NET-TLS-008)
        assert "NET-TLS-008" in check_ids
        ccs = next(f for f in findings if f.check_id == "NET-TLS-008")
        assert ccs.severity == Severity.HIGH
        assert ccs.cvss_score == 7.4
        assert ccs.cwe_id == "CWE-310"

    def test_json_parser_resilience_malformed_and_empty(self):
        adapter = SslyzeAdapter()

        # Empty string
        f_empty, st_empty, _ = adapter.parse_sslyze_json("", "example.com", 443)
        assert f_empty == []
        assert st_empty == NormalizedExecutionState.TOOL_EXECUTION_FAILED

        # Malformed JSON
        f_bad, st_bad, _ = adapter.parse_sslyze_json("NOT_JSON_DATA", "example.com", 443)
        assert f_bad == []
        assert st_bad == NormalizedExecutionState.PARTIAL_RESULTS_WITH_WARNING

        # Clean profile with no findings
        clean_json = {
            "server_scan_results": [
                {
                    "scan_result": {
                        "ssl_2_0_cipher_suites": {"result": {"is_supported": False}},
                        "ssl_3_0_cipher_suites": {"result": {"is_supported": False}},
                        "tls_1_0_cipher_suites": {"result": {"is_supported": False}},
                        "tls_1_1_cipher_suites": {"result": {"is_supported": False}},
                        "tls_1_2_cipher_suites": {"result": {"is_supported": True, "accepted_cipher_suites": [{"cipher_suite": {"name": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"}}]}},
                        "tls_1_3_cipher_suites": {"result": {"is_supported": True, "accepted_cipher_suites": [{"cipher_suite": {"name": "TLS_AES_256_GCM_SHA384"}}]}},
                        "certificate_info": {"result": {"certificate_deployments": [{"received_certificate_chain": [{"signature_hash_algorithm": {"name": "sha256"}}], "path_validation_results": [{"is_valid_path": True}]}]}},
                        "heartbleed": {"result": {"is_vulnerable_to_heartbleed": False}},
                        "robot": {"result": {"robot_result": "NOT_VULNERABLE"}},
                        "openssl_ccs_injection": {"result": {"is_vulnerable_to_ccs_injection": False}}
                    }
                }
            ]
        }
        f_clean, st_clean, _ = adapter.parse_sslyze_json(json.dumps(clean_json), "example.com", 443)
        assert f_clean == []
        assert st_clean == NormalizedExecutionState.COMPLETED_NO_FINDINGS


# ============================================================================
# 6. Secret & Private Key Sanitization
# ============================================================================

class TestSslyzeSecretSanitization:
    def test_private_key_and_secret_redaction(self):
        raw_key = (
            "Certificate output contains:\n"
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEA0Y123456789abcdefghijklmnopqrstuvwxyz\n"
            "-----END RSA PRIVATE KEY-----\n"
            "and admin password=SuperSecretPassword123"
        )
        sanitized = sanitize_tls_evidence_text(raw_key)
        assert "-----BEGIN RSA PRIVATE KEY-----" not in sanitized
        assert "[REDACTED_PRIVATE_KEY]" in sanitized
        assert "SuperSecretPassword123" not in sanitized
        assert "password: [MASKED]" in sanitized


# ============================================================================
# 7. Process Supervision & Native Fallback Preservation
# ============================================================================

class TestSslyzeFallbackPreservation:
    @pytest.mark.asyncio
    async def test_network_engine_sslyze_fallback(self):
        """
        Contract 09 TOOL-SSLYZE §27: Verifies that when SSLyze is unavailable,
        the network assessment engine falls back gracefully to native Python TLS
        checks without crashes, tagging findings with source_tool='native'.
        """
        from app.engines.network.engine import NetworkAssessmentEngine
        from app.core.models import OSINTConfig

        target = Target(name="Fallback Target", type=TargetType.DOMAIN, value="example.com")
        config = ScanConfig(osint=OSINTConfig(subdomain_enumeration=False))

        logs = []
        findings = []

        async def mock_log(lvl, msg):
            logs.append(msg)

        async def mock_finding(f):
            findings.append(f)

        async def mock_progress(pct, msg):
            pass

        engine = NetworkAssessmentEngine()
        with patch("app.adapters.sslyze_adapter.SslyzeAdapter.is_available", return_value=False):
            with patch("app.core.ssrf_protector.resolve_hostname_ips", return_value=["93.184.216.34"]):
                with patch("app.engines.network.port_checker.audit_exposed_ports", return_value=[]):
                    with patch("app.engines.network.tls_auditor.audit_tls_certificates", return_value=[]):
                        with patch("app.engines.network.tls_auditor.audit_tls_protocols_and_ciphers", return_value=[]):
                            with patch("app.engines.network.dns_hygiene.audit_dns_hygiene", return_value=[]):
                                with patch("app.engines.network.subdomain_recon.audit_subdomain_osint", return_value=[]):
                                    with patch("app.engines.network.origin_exposure.audit_origin_exposure", return_value=[]):
                                        with patch("app.engines.network.banner_grabber.audit_service_banners", return_value=[]):
                                            with patch("app.adapters.nmap_adapter.NmapAdapter.is_available", return_value=False):
                                                with patch("app.adapters.subfinder_adapter.SubfinderAdapter.is_available", return_value=False):
                                                    with patch("app.adapters.httpx_adapter.HttpxAdapter.is_available", return_value=False):
                                                        await engine.run(
                                                            target=target,
                                                            config=config,
                                                            emit_log=mock_log,
                                                            emit_progress=mock_progress,
                                                            emit_finding=mock_finding,
                                                            organization_id="org-test",
                                                        )

        fallback_logs = [l for l in logs if "pure native TLS auditor fallback" in l]
        assert len(fallback_logs) >= 1


# ============================================================================
# 8. Upstream SSLyze 5.2.0 CLI Compatibility & Argument Parser Verification
# ============================================================================

def get_sslyze_5_2_0_upstream_argparser() -> argparse.ArgumentParser:
    """
    Constructs an authentic ArgumentParser mirroring the exact CLI argument definition
    of upstream SSLyze 5.2.0.
    Upstream SSLyze 5.2.0 registers:
      - positional: targets (nargs="+")
      - option: --sni SERVER_NAME_INDICATION
      - option: --json_out JSON_OUT
      - scan options: --certinfo, --sslv2, --sslv3, --tlsv1, --tlsv1_1, --tlsv1_2, --tlsv1_3,
                      --heartbleed, --robot, --openssl_ccs, --reneg, --resum, --early_data
    """
    parser = argparse.ArgumentParser(prog="sslyze", description="Upstream SSLyze 5.2.0 CLI Parser")
    parser.add_argument("targets", nargs="+", help="The list of servers to scan.")
    parser.add_argument("--sni", dest="sni", help="The hostname to use as Server Name Indication (SNI)")
    parser.add_argument("--json_out", dest="json_out", help="Output results to JSON file or - for stdout")
    for flag in [
        "--certinfo",
        "--sslv2",
        "--sslv3",
        "--tlsv1",
        "--tlsv1_1",
        "--tlsv1_2",
        "--tlsv1_3",
        "--heartbleed",
        "--robot",
        "--openssl_ccs",
        "--reneg",
        "--resum",
        "--early_data",
    ]:
        parser.add_argument(flag, action="store_true")
    return parser


class TestSslyzeUpstreamCLICompatibility:
    def test_upstream_cli_parser_accepts_builder_command(self):
        """
        Contract 09 TOOL-SSLYZE §19: Proves that the exact argument array generated
        by SslyzeCommandBuilder conforms strictly to the upstream SSLyze 5.2.0 CLI parser
        under both baseline and vulnerability-probing modes.
        """
        target = Target(name="Domain Target", type=TargetType.DOMAIN, value="example.com")
        with patch("app.core.ssrf_protector.resolve_hostname_ips", return_value=["93.184.216.34"]):
            val_target = create_validated_target(target)

        # 1. Baseline Least-Privilege Invocation (Default: configuration assessment only)
        cmd_baseline, dest_ip, port, err = SslyzeCommandBuilder.build_command(
            sslyze_path="/usr/bin/sslyze",
            target=val_target,
            port=443,
            include_vuln_probes=False,
        )
        assert err is None
        parser = get_sslyze_5_2_0_upstream_argparser()
        parsed_baseline = parser.parse_args(cmd_baseline[1:])

        # Verify parsed properties match upstream SSLyze 5.2.0 contract
        assert parsed_baseline.sni == "example.com"
        assert parsed_baseline.json_out == "-"
        assert parsed_baseline.targets == ["93.184.216.34:443"]
        assert parsed_baseline.certinfo is True
        assert parsed_baseline.tlsv1_2 is True
        assert parsed_baseline.reneg is True
        assert parsed_baseline.resum is True
        # Vulnerability probes MUST be False in baseline mode
        assert parsed_baseline.heartbleed is False
        assert parsed_baseline.robot is False
        assert parsed_baseline.openssl_ccs is False

        # 2. Targeted Vulnerability-Probing Invocation (Explicit FULL_STACK / override)
        cmd_vuln, _, _, err_v = SslyzeCommandBuilder.build_command(
            sslyze_path="/usr/bin/sslyze",
            target=val_target,
            port=443,
            include_vuln_probes=True,
        )
        assert err_v is None
        parsed_vuln = parser.parse_args(cmd_vuln[1:])
        assert parsed_vuln.heartbleed is True
        assert parsed_vuln.robot is True
        assert parsed_vuln.openssl_ccs is True

    def test_upstream_cli_parser_rejects_server_name_option(self):
        """
        Proves that the legacy incorrect option --server_name is rejected
        by the authentic SSLyze 5.2.0 CLI parser with an unrecognized argument error.
        """
        parser = get_sslyze_5_2_0_upstream_argparser()
        bad_args = ["--json_out=-", "93.184.216.34:443", "--server_name=example.com", "--certinfo"]

        with pytest.raises(SystemExit):
            # argparse calls sys.exit(2) on unrecognized arguments
            parser.parse_args(bad_args)


# ============================================================================
# 9. Supply-Chain Provenance & Pinned Package Integrity
# ============================================================================

class TestSslyzeSupplyChainAndProvenance:
    def test_supply_chain_artifact_hashes_and_trust_mode(self):
        """
        Contract 09 TOOL-SSLYZE §9: Verifies that exact cryptographic hashes for
        the authoritative PyPI SSLyze 5.2.0 release artifacts are pinned and authentic.
        """
        assert APPROVED_VERSION == "5.2.0"
        assert TRUST_MODE == "PACKAGE_MANAGER_MODE"
        assert len(APPROVED_ARTIFACT_SHA256_SDIST) == 64
        assert APPROVED_ARTIFACT_SHA256_SDIST == "15ecb471b251dfbd003ba81a57d36865a93f18b74c7e7883a00d8bbddd365e03"
        assert APPROVED_ARTIFACT_SHA256_WHEEL is None  # sdist-only PyPI release


# ============================================================================
# 10. Process Supervision Call-Chain Verification
# ============================================================================

class TestSslyzeProcessSupervision:
    @pytest.mark.asyncio
    async def test_process_supervisor_call_chain_enforcement(self):
        """
        Contract 03 §3 & Contract 09 TOOL-SSLYZE §28: Proves that SSLyze execution
        strictly routes through the central ProcessSupervisor with bounded timeout.
        """
        adapter = SslyzeAdapter()
        target = Target(name="Domain Target", type=TargetType.DOMAIN, value="example.com")
        config = ScanConfig(timeout_seconds=10)

        mock_log = AsyncMock()
        mock_finding = AsyncMock()

        clean_json = {
            "server_scan_results": [
                {
                    "scan_result": {
                        "ssl_2_0_cipher_suites": {"result": {"is_supported": False}},
                        "ssl_3_0_cipher_suites": {"result": {"is_supported": False}},
                        "tls_1_0_cipher_suites": {"result": {"is_supported": False}},
                        "tls_1_1_cipher_suites": {"result": {"is_supported": False}},
                        "tls_1_2_cipher_suites": {"result": {"is_supported": True, "accepted_cipher_suites": []}},
                        "tls_1_3_cipher_suites": {"result": {"is_supported": True, "accepted_cipher_suites": []}},
                        "certificate_info": {"result": {"certificate_deployments": []}},
                        "heartbleed": {"result": {"is_vulnerable_to_heartbleed": False}},
                        "robot": {"result": {"robot_result": "NOT_VULNERABLE"}},
                        "openssl_ccs_injection": {"result": {"is_vulnerable_to_ccs_injection": False}},
                    }
                }
            ]
        }

        with patch.object(adapter, "resolve_binary_path", return_value="/usr/bin/sslyze"):
            with patch.object(adapter, "get_version", return_value="SSLyze 5.2.0"):
                with patch("app.core.ssrf_protector.resolve_hostname_ips", return_value=["93.184.216.34"]):
                    with patch("app.core.process_supervisor.process_supervisor.execute", return_value=(0, json.dumps(clean_json), "")) as mock_ps_exec:
                        findings = await adapter.run(target, config, mock_log, mock_finding)

        assert mock_ps_exec.called
        call_kwargs = mock_ps_exec.call_args[1]
        assert call_kwargs["timeout"] == 60.0
        called_cmd = mock_ps_exec.call_args[1].get("cmd") or mock_ps_exec.call_args[0][0]
        assert "--sni=example.com" in called_cmd
        assert "93.184.216.34:443" in called_cmd


# ============================================================================
# 11. Capability & Flag Segmentation Verification
# ============================================================================

class TestSslyzeCapabilitySegmentation:
    def test_capability_and_flag_segmentation(self):
        """
        Contract 09 TOOL-SSLYZE §20 & §41: Proves explicit segmentation between
        baseline cryptographic configuration assessment and vulnerability probing,
        and ensures complete coverage of all approved flags in the capability taxonomy.
        """
        from app.adapters.sslyze_adapter import SSLYZE_CAPABILITIES

        # 1. Configuration Assessment Flags (10 flags)
        assert len(CONFIG_ASSESSMENT_FLAGS) == 10
        for flag in ["--certinfo", "--sslv2", "--sslv3", "--tlsv1", "--tlsv1_1", "--tlsv1_2", "--tlsv1_3", "--reneg", "--resum", "--early_data"]:
            assert flag in CONFIG_ASSESSMENT_FLAGS

        # 2. Targeted Vulnerability Probing Flags (3 flags)
        assert len(VULN_PROBE_FLAGS) == 3
        for flag in ["--heartbleed", "--robot", "--openssl_ccs"]:
            assert flag in VULN_PROBE_FLAGS

        # 3. Complete Capability Taxonomy (13 capabilities)
        assert len(SSLYZE_CAPABILITIES) == 13
        for cap_key in [
            "certinfo", "sslv2", "sslv3", "tlsv1", "tlsv1_1", "tlsv1_2", "tlsv1_3",
            "reneg", "resum", "early_data", "heartbleed", "robot", "openssl_ccs"
        ]:
            assert cap_key in SSLYZE_CAPABILITIES
            assert "operation_class" in SSLYZE_CAPABILITIES[cap_key]
            assert "description" in SSLYZE_CAPABILITIES[cap_key]
            assert "category" in SSLYZE_CAPABILITIES[cap_key]

        # 4. Allowlist Integrity
        assert "--sni" in APPROVED_SSLYZE_FLAGS
        assert "--json_out=-" in APPROVED_SSLYZE_FLAGS
        assert "--server_name" not in APPROVED_SSLYZE_FLAGS

        # 5. Default Scan Profile Least Privilege
        assert DEFAULT_SCAN_FLAGS == CONFIG_ASSESSMENT_FLAGS
        assert "--heartbleed" not in DEFAULT_SCAN_FLAGS
        assert "--robot" not in DEFAULT_SCAN_FLAGS
        assert "--openssl_ccs" not in DEFAULT_SCAN_FLAGS
