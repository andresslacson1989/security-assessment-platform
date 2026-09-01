"""
Contract 03, 06 & 08 Safe Sensitive Port Scanner.
"""

from __future__ import annotations
import asyncio
from typing import List, Tuple, Optional, Dict
import urllib.parse

from app.core.models import Finding, Evidence, Severity, calculate_fingerprint, LogLevel
from app.engines.base import LogCallback


# Sensitive port catalog
SENSITIVE_PORTS: Dict[int, Tuple[str, str, str, str, Severity, float, str, str]] = {
    21: (
        "NET-PORT-003",
        "Exposed Unencrypted FTP Service (Port 21)",
        "FTP",
        "Unencrypted FTP transmits credentials and files in plaintext over the wire.",
        Severity.HIGH,
        7.5,
        "CWE-319",
        "Disable plaintext FTP and migrate to SFTP (SSH File Transfer Protocol) or FTPS with TLS.",
    ),
    23: (
        "NET-PORT-003",
        "Exposed Unencrypted Telnet Service (Port 23)",
        "Telnet",
        "Telnet sends all terminal session keystrokes, passwords, and data in cleartext.",
        Severity.HIGH,
        7.5,
        "CWE-319",
        "Disable Telnet daemon and enforce SSH key-based authentication exclusively.",
    ),
    3306: (
        "NET-PORT-001",
        "Exposed MySQL Database Port (Port 3306)",
        "MySQL Database",
        "Database is directly reachable from public networks, creating an attack surface for authentication bypass or credential stuffing.",
        Severity.HIGH,
        7.5,
        "CWE-284",
        "Bind MySQL to 127.0.0.1 or internal VPC subnet; block public access via firewall.",
    ),
    5432: (
        "NET-PORT-001",
        "Exposed PostgreSQL Database Port (Port 5432)",
        "PostgreSQL Database",
        "Database is directly reachable from the public internet.",
        Severity.HIGH,
        7.5,
        "CWE-284",
        "Configure pg_hba.conf and firewall security groups to allow access only from trusted application hosts.",
    ),
    6379: (
        "NET-PORT-002",
        "Exposed Redis In-Memory Datastore (Port 6379)",
        "Redis Cache",
        "Redis instances exposed publicly without authentication can be completely controlled or wiped remotely.",
        Severity.HIGH,
        7.5,
        "CWE-284",
        "Bind Redis to 127.0.0.1, enable 'requirepass', and restrict firewall access.",
    ),
    27017: (
        "NET-PORT-002",
        "Exposed MongoDB NoSQL Database (Port 27017)",
        "MongoDB",
        "MongoDB is exposed to public networks, exposing document stores to unauthorized exfiltration.",
        Severity.HIGH,
        7.5,
        "CWE-284",
        "Bind MongoDB to localhost or internal network, and enforce authentication.",
    ),
    9200: (
        "NET-PORT-002",
        "Exposed Elasticsearch HTTP Interface (Port 9200)",
        "Elasticsearch",
        "Elasticsearch cluster API is reachable publicly, allowing full index searches and data modification.",
        Severity.HIGH,
        7.5,
        "CWE-284",
        "Enable X-Pack security authentication and place Elasticsearch behind an authenticated reverse proxy.",
    ),
}


def extract_host(target_value: str) -> str:
    if "://" in target_value:
        return urllib.parse.urlparse(target_value).hostname or target_value
    if ":" in target_value and not target_value.count(":") > 1:
        return target_value.split(":")[0]
    return target_value.strip()


async def check_single_port(
    host: str,
    port: int,
    timeout: float = 1.5,
) -> Optional[int]:
    """
    Attempts a TCP connection to a single port and immediately closes it.
    Returns the port number if open, None otherwise.
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
        writer.close()
        await writer.wait_closed()
        return port
    except Exception:
        return None


async def audit_exposed_ports(
    target_value: str,
    custom_ports: Optional[List[int]] = None,
    emit_log: Optional[LogCallback] = None,
    timeout_seconds: float = 1.5,
    connection_host: Optional[str] = None,
) -> List[Finding]:
    """
    Concurrently probes sensitive database, cache, and management ports.
    """
    findings: List[Finding] = []
    host = connection_host or extract_host(target_value)
    ports_to_check = custom_ports or list(SENSITIVE_PORTS.keys())

    if emit_log:
        await emit_log(LogLevel.INFO, f"Scanning {len(ports_to_check)} critical ports on {host}...")

    # Execute all port checks concurrently with asyncio.gather
    tasks = [
        check_single_port(host, p, timeout=timeout_seconds)
        for p in ports_to_check
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    for res in results:
        if isinstance(res, int) and res in SENSITIVE_PORTS:
            check_id, title, service_name, desc, sev, cvss, cwe, remediation = SENSITIVE_PORTS[res]
            findings.append(Finding(
                scan_id="auto",
                engine="network",
                check_id=check_id,
                category="Network Perimeter Exposure",
                title=title,
                severity=sev,
                cvss_score=cvss,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                cwe_id=cwe,
                owasp_category="A01:2021-Broken Access Control",
                nist_control="AC-3, SC-7",
                description=f"Port {res} ({service_name}) is publicly reachable on {host}. {desc}",
                impact="Unauthenticated or weakly authenticated attackers can connect directly to internal data services.",
                remediation=remediation,
                remediation_code_snippet=f"# UFW Firewall Rule:\nsudo ufw deny {res}/tcp",
                references=["https://cwe.mitre.org/data/definitions/284.html"],
                evidence=Evidence(
                    location=f"{host}:{res}",
                    observed_value=f"TCP connection established on port {res}",
                    expected_value="Port closed or blocked by firewall",
                ),
                fingerprint=calculate_fingerprint(check_id, f"{host}:{res}", "port_open"),
            ))

    return findings
