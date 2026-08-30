"""
Contract 03 (Section 4.2), Contract 06 (Section 2) & Contract 08 (Section 8.2) SSLyze Tool Adapter.
Authoritative Reference: contracts/03_ENGINE_PLUGIN_INTERFACE_CONTRACT.md
"""

from __future__ import annotations
import json
import re
import urllib.parse
from typing import Optional, List, Callable, Awaitable

from app.core.models import (
    Target,
    Finding,
    Evidence,
    Severity,
    ScanConfig,
    LogLevel,
    calculate_fingerprint,
)
from app.adapters.base_adapter import BaseToolAdapter


def extract_host_port(target_value: str) -> tuple[str, int]:
    """
    Extracts hostname and port from target value.
    """
    if "://" in target_value:
        parsed = urllib.parse.urlparse(target_value)
        host = parsed.hostname or target_value
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        return host, port
    if ":" in target_value and not target_value.count(":") > 1:
        parts = target_value.split(":")
        try:
            return parts[0].strip(), int(parts[1].strip())
        except ValueError:
            return parts[0].strip(), 443
    return target_value.strip(), 443


class SslyzeAdapter(BaseToolAdapter):
    """
    Hybrid tool adapter for SSLyze deep TLS/SSL configuration scanner.
    Normalizes JSON output into canonical NET-TLS-xxx findings.
    """

    @property
    def tool_name(self) -> str:
        return "sslyze"

    async def get_version(self, custom_path: Optional[str] = None) -> Optional[str]:
        """
        Retrieves SSLyze version string via `sslyze --version`.
        """
        path = self.resolve_binary_path(custom_path)
        if not path:
            return None

        returncode, stdout, _ = await self.execute_command([path, "--version"], timeout=5.0)
        if returncode == 0 and stdout:
            first_line = stdout.splitlines()[0].strip()
            match = re.search(r"(\d+\.\d+(\.\d+)?)", first_line)
            if match:
                return f"SSLyze {match.group(1)}"
            return first_line
        return None

    async def run(
        self,
        target: Target,
        config: ScanConfig,
        emit_log: Callable[[LogLevel, str], Awaitable[None]],
        emit_finding: Callable[[Finding], Awaitable[None]],
        **kwargs,
    ) -> List[Finding]:
        """
        Executes SSLyze: sslyze --json_out=- <target_host>:<target_port>
        Parses JSON results and generates canonical NET-TLS findings.
        """
        findings: List[Finding] = []
        custom_path = getattr(config.adapters, "sslyze_path", None) or getattr(config.adapters, "custom_sslyze_path", None)
        sslyze_path = self.resolve_binary_path(custom_path)

        if not sslyze_path:
            await emit_log(LogLevel.WARNING, "SSLyze binary not found on host. Skipping SSLyze execution.")
            return findings

        host, port = extract_host_port(target.value)
        if not host:
            await emit_log(LogLevel.WARNING, "Invalid target host for SSLyze scan.")
            return findings

        cmd = [sslyze_path, "--json_out=-", f"{host}:{port}"]
        await emit_log(LogLevel.INFO, f"Starting SSLyze deep TLS audit on target '{host}:{port}'...")

        returncode, stdout, stderr = await self.execute_command(
            cmd,
            timeout=float(min(60.0, config.timeout_seconds * 6)),
            emit_log=emit_log,
        )

        if not stdout.strip():
            if returncode != 0:
                await emit_log(LogLevel.WARNING, f"SSLyze scan completed with non-zero exit code {returncode}: {stderr[:200]}")
            return findings

        try:
            data = json.loads(stdout)
            server_results = data.get("server_scan_results", [])
            for res in server_results:
                scan_commands = res.get("scan_result") or res.get("scan_commands_results") or res
                
                # 1. Check for deprecated SSL 2.0/3.0 & TLS 1.0/1.1 (NET-TLS-001)
                for proto_key, proto_name in [
                    ("ssl_2_0_cipher_suites", "SSL 2.0"),
                    ("ssl_3_0_cipher_suites", "SSL 3.0"),
                    ("tls_1_0_cipher_suites", "TLS 1.0"),
                    ("tls_1_1_cipher_suites", "TLS 1.1"),
                ]:
                    proto_res = scan_commands.get(proto_key, {})
                    result_data = proto_res.get("result", proto_res) if isinstance(proto_res, dict) else {}
                    accepted = result_data.get("accepted_cipher_suites", [])
                    is_supported = result_data.get("is_supported", bool(accepted))
                    if is_supported or accepted:
                        ciphers_str = ", ".join(c.get("cipher_suite", {}).get("name", "unknown") for c in accepted[:5]) if accepted else "Supported"
                        evidence = Evidence(
                            location=f"{host}:{port}",
                            observed_value=f"Accepted deprecated protocol {proto_name}: {ciphers_str}",
                            expected_value="TLS 1.2 or TLS 1.3 only",
                            raw_response_snippet=json.dumps(accepted[:3]) if accepted else None,
                        )
                        f = Finding(
                            scan_id=kwargs.get("scan_id", "manual"),
                            engine="network",
                            source_tool="sslyze",
                            check_id="NET-TLS-001",
                            category="TLS/SSL Security",
                            title=f"Deprecated {proto_name} Protocol Supported",
                            severity=Severity.HIGH,
                            cvss_score=7.5,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                            cwe_id="CWE-326",
                            owasp_category="A02:2021-Cryptographic Failures",
                            nist_control="SC-8, SC-13",
                            description=f"The server negotiated {proto_name} which contains known structural cryptographic weaknesses.",
                            impact="Man-in-the-middle attackers may decrypt or tamper with encrypted communication.",
                            remediation=f"Disable {proto_name} in server configuration and require TLS 1.2 or TLS 1.3 minimum.",
                            remediation_code_snippet="ssl_protocols TLSv1.2 TLSv1.3;",
                            references=["https://datatracker.ietf.org/doc/html/rfc8996"],
                            evidence=evidence,
                            fingerprint=calculate_fingerprint("NET-TLS-001", f"{host}:{port}", proto_name),
                        )
                        findings.append(f)
                        await emit_finding(f)

                # 2. Check for certificate info (NET-TLS-003)
                cert_res = scan_commands.get("certificate_info", {})
                cert_data = cert_res.get("result", cert_res) if isinstance(cert_res, dict) else {}
                deployments = cert_data.get("certificate_deployments", [])
                for dep in deployments:
                    # Path validation errors
                    for validation in dep.get("path_validation_results", []):
                        if not validation.get("is_valid_path", True):
                            error_msg = validation.get("validation_error", "Certificate validation failed")
                            evidence = Evidence(
                                location=f"{host}:{port}",
                                observed_value=f"Certificate validation error: {error_msg}",
                                expected_value="Valid trusted CA certificate path",
                            )
                            f = Finding(
                                scan_id=kwargs.get("scan_id", "manual"),
                                engine="network",
                                source_tool="sslyze",
                                check_id="NET-TLS-003",
                                category="TLS/SSL Security",
                                title="Untrusted / Self-Signed SSL/TLS Certificate Path",
                                severity=Severity.HIGH,
                                cvss_score=7.4,
                                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                                cwe_id="CWE-295",
                                owasp_category="A02:2021-Cryptographic Failures",
                                nist_control="SC-8, SC-13",
                                description=f"The SSL/TLS certificate presented by {host}:{port} could not be validated against trusted root stores.",
                                impact="Users will see browser security warnings and are vulnerable to interception.",
                                remediation="Install a valid SSL/TLS certificate issued by a recognized Certificate Authority (e.g., Let's Encrypt).",
                                references=["https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html"],
                                evidence=evidence,
                                fingerprint=calculate_fingerprint("NET-TLS-003", f"{host}:{port}", error_msg),
                            )
                            findings.append(f)
                            await emit_finding(f)

                    # Chain inspection for weak signature algorithm or expiry
                    for cert in dep.get("received_certificate_chain", []):
                        sig_alg = cert.get("signature_hash_algorithm", {}).get("name", "").lower()
                        if "sha1" in sig_alg or "md5" in sig_alg:
                            evidence = Evidence(
                                location=f"{host}:{port}",
                                observed_value=f"Certificate signed with weak algorithm: {sig_alg}",
                                expected_value="SHA-256 or stronger signature algorithm",
                            )
                            f = Finding(
                                scan_id=kwargs.get("scan_id", "manual"),
                                engine="network",
                                source_tool="sslyze",
                                check_id="NET-TLS-003",
                                category="TLS/SSL Security",
                                title="Weak Signature Algorithm in SSL/TLS Certificate",
                                severity=Severity.HIGH,
                                cvss_score=7.4,
                                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                                cwe_id="CWE-327",
                                owasp_category="A02:2021-Cryptographic Failures",
                                nist_control="SC-8, SC-13",
                                description=f"The SSL/TLS certificate uses weak signature algorithm '{sig_alg}'.",
                                impact="Attackers may forge certificates due to hash collision vulnerabilities.",
                                remediation="Reissue certificate with SHA-256 or higher signature algorithm.",
                                references=["https://datatracker.ietf.org/doc/html/rfc9155"],
                                evidence=evidence,
                                fingerprint=calculate_fingerprint("NET-TLS-003", f"{host}:{port}", sig_alg),
                            )
                            findings.append(f)
                            await emit_finding(f)

                # 3. Check for Heartbleed vulnerability (NET-TLS-006)
                hb_res = scan_commands.get("heartbleed", {})
                hb_data = hb_res.get("result", hb_res) if isinstance(hb_res, dict) else {}
                if hb_data.get("is_vulnerable_to_heartbleed") or hb_data.get("is_vulnerable"):
                    evidence = Evidence(
                        location=f"{host}:{port}",
                        observed_value="Server is vulnerable to OpenSSL Heartbleed (CVE-2014-0160)",
                        expected_value="Patched OpenSSL version not vulnerable to Heartbleed",
                    )
                    f = Finding(
                        scan_id=kwargs.get("scan_id", "manual"),
                        engine="network",
                        source_tool="sslyze",
                        check_id="NET-TLS-006",
                        category="TLS/SSL Security",
                        title="OpenSSL TLS Heartbleed Vulnerability (CVE-2014-0160)",
                        severity=Severity.CRITICAL,
                        cvss_score=9.8,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        cwe_id="CWE-119",
                        owasp_category="A06:2021-Vulnerable and Outdated Components",
                        nist_control="SI-2",
                        description=f"Server at {host}:{port} is vulnerable to OpenSSL Heartbleed, allowing remote memory disclosure.",
                        impact="Remote attackers can read private cryptographic keys, user session tokens, and passwords from memory.",
                        remediation="Upgrade OpenSSL to a patched version immediately.",
                        references=["https://nvd.nist.gov/vuln/detail/CVE-2014-0160"],
                        evidence=evidence,
                        fingerprint=calculate_fingerprint("NET-TLS-006", f"{host}:{port}", "Heartbleed"),
                    )
                    findings.append(f)
                    await emit_finding(f)

        except Exception as e:
            await emit_log(LogLevel.WARNING, f"Failed to parse SSLyze output: {str(e)}")

        return findings
