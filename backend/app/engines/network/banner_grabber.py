"""
Contract 03 §3.1 & Contract 08 §2.3: Service Daemon Banner Grabbing & Vulnerability Detection.
Connects to open service ports, extracts daemon banners, and identifies deprecated or vulnerable daemon versions.
"""

from __future__ import annotations
import asyncio
import re
from typing import List, Tuple, Optional
from app.core.models import Finding, Evidence, Severity, calculate_fingerprint

# Known deprecated or vulnerable daemon version patterns
VULNERABLE_BANNER_PATTERNS = [
    (r"vsftpd\s+2\.3\.4", "vsftpd 2.3.4", "Backdoor Command Execution Vulnerability (CVE-2011-2523)"),
    (r"OpenSSH[_-](([1-6]\.)|(7\.[0-4]))", "OpenSSH < 7.5", "Outdated OpenSSH daemon with known vulnerabilities"),
    (r"Apache/2\.(0|2)\.", "Apache HTTPD 2.0/2.2", "End-of-life Apache HTTP Server branch"),
    (r"nginx/1\.([0-9]\.|1[0-7]\.)", "nginx < 1.18.0", "Outdated Nginx web server version"),
    (r"ProFTPD\s+1\.3\.[0-3]", "ProFTPD <= 1.3.3", "Outdated ProFTPD daemon with known vulnerabilities"),
    (r"MySQL\s+5\.[0-5]\.", "MySQL 5.0-5.5", "End-of-life MySQL database server"),
]


async def grab_service_banner(host: str, port: int, timeout: float = 1.5) -> Optional[str]:
    """
    Attempts to read the initial banner string from an open TCP service socket.
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout
        )
        try:
            # Some services (HTTP, Redis, etc.) require a newline probe to reply
            if port in (80, 8080, 8000, 443, 8443):
                writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
                await writer.drain()
            elif port in (21, 22, 23, 25, 110, 143):
                # Greeting is sent automatically by server
                pass
            else:
                writer.write(b"\r\n")
                await writer.drain()

            raw_data = await asyncio.wait_for(reader.read(256), timeout=timeout)
            banner = raw_data.decode("utf-8", errors="ignore").strip()
            return banner if banner else None
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
    except Exception:
        return None


async def audit_service_banners(
    host: str,
    open_ports: List[int],
    scan_id: str,
    connection_host: Optional[str] = None,
) -> List[Finding]:
    """
    Audits banners of open ports and emits NET-SVC-001 if vulnerable daemon version signatures are detected.
    """
    findings: List[Finding] = []

    for port in open_ports:
        banner = await grab_service_banner(connection_host or host, port)
        if not banner:
            continue

        for pattern, daemon_name, reason in VULNERABLE_BANNER_PATTERNS:
            if re.search(pattern, banner, re.IGNORECASE):
                loc = f"tcp://{host}:{port}"
                obs = f"Port {port} Banner: '{banner}' ({daemon_name})"
                findings.append(
                    Finding(
                        scan_id=scan_id,
                        engine="network",
                        check_id="NET-SVC-001",
                        category="Service Posture",
                        title=f"Deprecated or Vulnerable Service Daemon on Port {port} ({daemon_name})",
                        severity=Severity.HIGH,
                        cvss_score=7.5,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        cwe_id="CWE-200",
                        owasp_category="A05:2021-Security Misconfiguration",
                        nist_control="CM-6",
                        description=(
                            f"The service listening on port {port} exposed the daemon banner '{banner}', "
                            f"which identifies {reason}. Running outdated service daemons exposes the host "
                            "to known remote exploits and unpatched vulnerabilities."
                        ),
                        impact="Potential remote code execution, denial of service, or unauthorized access.",
                        remediation=f"Upgrade the service listening on port {port} to a modern, supported, and patched release.",
                        remediation_code_snippet=f"# Update daemon on port {port} via package manager:\nsudo apt-get update && sudo apt-get --only-upgrade install <package_name>",
                        references=[
                            "https://cwe.mitre.org/data/definitions/200.html",
                            "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"
                        ],
                        evidence=Evidence(
                            location=loc,
                            observed_value=obs,
                            expected_value="Current, actively supported daemon version without public CVEs",
                            raw_response_snippet=banner,
                        ),
                        fingerprint=calculate_fingerprint("NET-SVC-001", loc, obs),
                        source_tool="native",
                    )
                )
                break

    return findings
