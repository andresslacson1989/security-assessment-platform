"""
Contract 03, 06 & 08 Network & TLS Assessment Engine Coordinator.
"""

from __future__ import annotations
from typing import List

from app.core.models import Target, Finding, ScanConfig, TargetType, LogLevel
from app.engines.base import BaseAssessmentEngine, LogCallback, ProgressCallback, FindingCallback
from app.engines.network.tls_auditor import audit_tls_certificates, audit_tls_protocols_and_ciphers
from app.engines.network.dns_hygiene import audit_dns_hygiene
from app.engines.network.port_checker import audit_exposed_ports


class NetworkAssessmentEngine(BaseAssessmentEngine):
    """
    Coordinator engine for Network Perimeter, TLS/SSL and DNS hygiene security assessments.
    """

    @property
    def name(self) -> str:
        return "network"

    @property
    def display_name(self) -> str:
        return "Network & TLS Infrastructure Auditor"

    @property
    def description(self) -> str:
        return (
            "Audits SSL/TLS certificates for expiration and SAN validity, deprecated protocols "
            "(TLS 1.0/1.1, SSLv3), DNS email security (SPF, DMARC, MTA-STS, BIMI), DNSSEC, "
            "and sensitive database/management port exposure."
        )

    def is_applicable(self, target: Target) -> bool:
        """
        Applicable to web URLs, domain names, and IP addresses.
        """
        return target.type in (TargetType.URL, TargetType.DOMAIN, TargetType.IP)

    async def run(
        self,
        target: Target,
        config: ScanConfig,
        emit_log: LogCallback,
        emit_progress: ProgressCallback,
        emit_finding: FindingCallback,
    ) -> List[Finding]:
        findings: List[Finding] = []

        # --- Stage 1: TLS / SSL Audit (0% - 35%) ---
        await emit_progress(10, "Auditing SSL/TLS certificate validity and expiration...")
        await emit_log(LogLevel.INFO, "Starting TLS/SSL certificate and cipher suite inspection.")

        tls_cert_findings = await audit_tls_certificates(
            target.value,
            emit_log=emit_log,
            timeout_seconds=min(5.0, config.timeout_seconds),
        )
        for f in tls_cert_findings:
            f.scan_id = "active"
            findings.append(f)
            await emit_finding(f)

        await emit_progress(25, "Testing for deprecated TLS protocols and ciphers...")
        tls_proto_findings = await audit_tls_protocols_and_ciphers(
            target.value,
            emit_log=emit_log,
            timeout_seconds=min(3.0, config.timeout_seconds),
        )
        for f in tls_proto_findings:
            f.scan_id = "active"
            findings.append(f)
            await emit_finding(f)

        # --- Stage 2: DNS & Email Hygiene (35% - 70%) ---
        await emit_progress(45, "Auditing DNS email security records (SPF, DMARC, MTA-STS, DNSSEC)...")
        dns_findings = await audit_dns_hygiene(
            target.value,
            emit_log=emit_log,
            timeout_seconds=min(3.0, config.timeout_seconds),
        )
        for f in dns_findings:
            f.scan_id = "active"
            findings.append(f)
            await emit_finding(f)

        # --- Stage 3: Port Exposure Scanner (70% - 100%) ---
        await emit_progress(75, "Scanning for exposed database and management ports...")
        port_findings = await audit_exposed_ports(
            target.value,
            custom_ports=config.port_list or None,
            emit_log=emit_log,
            timeout_seconds=min(2.0, config.timeout_seconds),
        )
        for f in port_findings:
            f.scan_id = "active"
            findings.append(f)
            await emit_finding(f)

        await emit_progress(100, "Network & TLS audit completed.")
        await emit_log(LogLevel.INFO, f"Network engine finished with {len(findings)} total findings.")

        return findings
