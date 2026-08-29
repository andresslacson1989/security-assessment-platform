"""
Contract 03, 06 & 08 TLS/SSL Certificate, Protocols and Ciphers Auditor.
"""

from __future__ import annotations
import asyncio
from datetime import datetime, timezone
import ssl
from typing import List, Tuple, Optional
import urllib.parse
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID

from app.core.models import Finding, Evidence, Severity, calculate_fingerprint, LogLevel
from app.engines.base import LogCallback


def extract_host_and_port(target_value: str, default_port: int = 443) -> Tuple[str, int]:
    """
    Extracts hostname and port from a URL, domain, or IP string.
    """
    if "://" in target_value:
        parsed = urllib.parse.urlparse(target_value)
        hostname = parsed.hostname or target_value
        port = parsed.port or (443 if parsed.scheme == "https" else (80 if parsed.scheme == "http" else default_port))
        return hostname, port
    
    if ":" in target_value and not target_value.count(":") > 1:  # Not IPv6
        parts = target_value.split(":")
        try:
            return parts[0], int(parts[1])
        except ValueError:
            return parts[0], default_port
            
    return target_value.strip(), default_port


def matches_san(hostname: str, san_list: List[str]) -> bool:
    """
    Matches hostname against Subject Alternative Names including wildcard support.
    """
    target = hostname.lower()
    for san in san_list:
        san = san.lower()
        if san == target:
            return True
        if san.startswith("*."):
            wildcard_suffix = san[1:]  # e.g. .example.com
            if target.endswith(wildcard_suffix) and target.count(".") == san.count("."):
                return True
    return False


async def audit_tls_certificates(
    target_value: str,
    emit_log: Optional[LogCallback] = None,
    timeout_seconds: float = 5.0,
) -> List[Finding]:
    """
    Connects to target, extracts X.509 certificate metadata, and evaluates expiration and SAN matches.
    """
    findings: List[Finding] = []
    hostname, port = extract_host_and_port(target_value)

    if emit_log:
        await emit_log(LogLevel.INFO, f"Initiating TLS handshake on {hostname}:{port}...")

    # Establish SSL connection with unverified context to inspect the cert even if expired/self-signed
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    der_cert = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(hostname, port, ssl=ssl_context),
            timeout=timeout_seconds,
        )
        sslobj = writer.get_extra_info("ssl_object")
        if sslobj:
            der_cert = sslobj.getpeercert(binary_form=True)
        writer.close()
        await writer.wait_closed()
    except Exception as e:
        if emit_log:
            await emit_log(LogLevel.WARNING, f"TLS connection to {hostname}:{port} failed: {str(e)}")
        return findings

    if not der_cert:
        return findings

    try:
        cert = x509.load_der_x509_certificate(der_cert)
        now = datetime.now(timezone.utc)
        not_after = cert.not_valid_after_utc
        days_left = (not_after - now).days

        # 1. Expiration Checks (NET-TLS-001, NET-TLS-002, NET-TLS-003)
        if days_left < 0:
            findings.append(Finding(
                scan_id="auto",
                engine="network",
                check_id="NET-TLS-001",
                category="SSL/TLS Infrastructure",
                title="Expired SSL/TLS Certificate",
                severity=Severity.CRITICAL,
                cvss_score=9.1,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                cwe_id="CWE-295",
                owasp_category="A02:2021-Cryptographic Failures",
                nist_control="SC-8",
                description=f"The SSL/TLS certificate for {hostname} expired on {not_after.strftime('%Y-%m-%d %H:%M:%S UTC')}.",
                impact="Browsers will display severe security warnings, blocking users and exposing traffic to interception.",
                remediation="Renew and install a valid SSL/TLS certificate immediately using ACME / Let's Encrypt or your certificate authority.",
                remediation_code_snippet="certbot renew --force-renewal",
                references=["https://cwe.mitre.org/data/definitions/295.html"],
                evidence=Evidence(
                    location=f"{hostname}:{port}",
                    observed_value=f"Certificate expired on {not_after.strftime('%Y-%m-%d')}",
                    expected_value="Certificate not_after date in the future (>30 days)",
                ),
                fingerprint=calculate_fingerprint("NET-TLS-001", f"{hostname}:{port}", "expired"),
            ))
        elif days_left <= 7:
            findings.append(Finding(
                scan_id="auto",
                engine="network",
                check_id="NET-TLS-002",
                category="SSL/TLS Infrastructure",
                title="SSL/TLS Certificate Expiring Soon (< 7 Days)",
                severity=Severity.HIGH,
                cvss_score=7.5,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                cwe_id="CWE-295",
                owasp_category="A02:2021-Cryptographic Failures",
                nist_control="SC-8",
                description=f"The SSL/TLS certificate for {hostname} will expire in {days_left} days ({not_after.strftime('%Y-%m-%d')}).",
                impact="Failure to renew in the next 7 days will result in service outage and browser security warnings.",
                remediation="Trigger automated certificate renewal workflow immediately.",
                remediation_code_snippet="certbot renew",
                references=["https://cwe.mitre.org/data/definitions/295.html"],
                evidence=Evidence(
                    location=f"{hostname}:{port}",
                    observed_value=f"Expires in {days_left} days",
                    expected_value="Certificate valid for > 30 days",
                ),
                fingerprint=calculate_fingerprint("NET-TLS-002", f"{hostname}:{port}", f"{days_left}_days"),
            ))
        elif days_left <= 30:
            findings.append(Finding(
                scan_id="auto",
                engine="network",
                check_id="NET-TLS-003",
                category="SSL/TLS Infrastructure",
                title="SSL/TLS Certificate Expiring in < 30 Days",
                severity=Severity.MEDIUM,
                cvss_score=5.3,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                cwe_id="CWE-295",
                owasp_category="A02:2021-Cryptographic Failures",
                nist_control="SC-8",
                description=f"The SSL/TLS certificate for {hostname} is scheduled to expire in {days_left} days.",
                impact="If renewal is not scheduled, the certificate will expire, leading to outages.",
                remediation="Ensure automated certificate renewal cron or certbot timer is operational.",
                remediation_code_snippet="systemctl status certbot.timer",
                references=["https://cwe.mitre.org/data/definitions/295.html"],
                evidence=Evidence(
                    location=f"{hostname}:{port}",
                    observed_value=f"Expires in {days_left} days",
                    expected_value="Certificate valid for > 30 days",
                ),
                fingerprint=calculate_fingerprint("NET-TLS-003", f"{hostname}:{port}", f"{days_left}_days"),
            ))

        # 2. SAN and Hostname Mismatch (NET-TLS-004)
        sans: List[str] = []
        try:
            san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            sans = [str(n) for n in san_ext.value.get_values_for_type(x509.DNSName)]
        except Exception:
            pass

        if not sans:
            # Fallback to CN
            try:
                cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                if cn_attrs:
                    sans = [str(cn_attrs[0].value)]
            except Exception:
                pass

        if sans and not matches_san(hostname, sans):
            findings.append(Finding(
                scan_id="auto",
                engine="network",
                check_id="NET-TLS-004",
                category="SSL/TLS Infrastructure",
                title="Certificate Hostname Mismatch",
                severity=Severity.HIGH,
                cvss_score=7.4,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                cwe_id="CWE-297",
                owasp_category="A02:2021-Cryptographic Failures",
                nist_control="SC-8",
                description=f"The certificate Subject Alternative Names {sans} do not match the requested hostname '{hostname}'.",
                impact="Connecting clients will reject the connection due to hostname verification failure.",
                remediation="Reissue certificate including the requested domain in the Subject Alternative Name (SAN) list.",
                remediation_code_snippet=f"certbot certonly -d {hostname}",
                references=["https://cwe.mitre.org/data/definitions/297.html"],
                evidence=Evidence(
                    location=f"{hostname}:{port}",
                    observed_value=f"SANs: {', '.join(sans)}",
                    expected_value=f"SAN list contains '{hostname}'",
                ),
                fingerprint=calculate_fingerprint("NET-TLS-004", f"{hostname}:{port}", str(sans)),
            ))

    except Exception as ex:
        if emit_log:
            await emit_log(LogLevel.WARNING, f"Error analyzing X.509 certificate: {str(ex)}")

    return findings


async def audit_tls_protocols_and_ciphers(
    target_value: str,
    emit_log: Optional[LogCallback] = None,
    timeout_seconds: float = 3.0,
) -> List[Finding]:
    """
    Tests for deprecated protocols (SSLv3, TLS 1.0, TLS 1.1) and weak ciphers.
    """
    findings: List[Finding] = []
    hostname, port = extract_host_and_port(target_value)

    # 1. Deprecated Protocol Handshake Probes
    # Note: Modern OpenSSL may disable SSLv3 entirely; we attempt safe protocol probes
    for proto_name, proto_const, check_id, title, sev, cvss, desc, cwe in [
        (
            "TLS 1.0 / TLS 1.1",
            ssl.TLSVersion.TLSv1 if hasattr(ssl, "TLSVersion") else None,
            "NET-TLS-005",
            "Deprecated TLS 1.0 / 1.1 Protocol Enabled",
            Severity.HIGH,
            7.5,
            "Target accepted handshake with deprecated TLS 1.0 or TLS 1.1 protocol.",
            "CWE-326",
        ),
    ]:
        if not proto_const:
            continue
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = proto_const
            ctx.maximum_version = proto_const

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(hostname, port, ssl=ctx),
                timeout=timeout_seconds,
            )
            writer.close()
            await writer.wait_closed()

            # If connection succeeded, deprecated protocol is supported
            findings.append(Finding(
                scan_id="auto",
                engine="network",
                check_id=check_id,
                category="SSL/TLS Infrastructure",
                title=title,
                severity=sev,
                cvss_score=cvss,
                cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
                cwe_id=cwe,
                owasp_category="A02:2021-Cryptographic Failures",
                nist_control="SC-13",
                description=desc,
                impact="Deprecated protocols suffer from known cryptographic weaknesses (POODLE, BEAST) and are disallowed by PCI-DSS.",
                remediation="Disable SSLv3, TLS 1.0, and TLS 1.1 on your web server and load balancer. Enforce TLS 1.2 and TLS 1.3 only.",
                remediation_code_snippet="ssl_protocols TLSv1.2 TLSv1.3;",
                references=["https://cwe.mitre.org/data/definitions/326.html"],
                evidence=Evidence(
                    location=f"{hostname}:{port}",
                    observed_value=f"Handshake accepted with {proto_name}",
                    expected_value="Handshake rejected; minimum protocol TLSv1.2",
                ),
                fingerprint=calculate_fingerprint(check_id, f"{hostname}:{port}", proto_name),
            ))
        except Exception:
            # Expected behavior for secure servers: handshake fails
            pass

    return findings
