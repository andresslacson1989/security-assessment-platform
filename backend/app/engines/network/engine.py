"""
Contract 03, 06 & 08 Network & TLS Assessment Engine Coordinator.
"""

from __future__ import annotations
from typing import List

from app.core.models import Target, Finding, ScanConfig, TargetType, LogLevel
from app.engines.base import BaseAssessmentEngine, LogCallback, ProgressCallback, FindingCallback
from app.engines.network.tls_auditor import audit_tls_certificates, audit_tls_protocols_and_ciphers, extract_host_and_port
from app.engines.network.dns_hygiene import audit_dns_hygiene
from app.engines.network.port_checker import audit_exposed_ports
from app.engines.network.subdomain_recon import audit_subdomain_osint
from app.engines.network.banner_grabber import audit_service_banners
from app.adapters.nmap_adapter import NmapAdapter


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
        **kwargs,
    ) -> List[Finding]:
        findings: List[Finding] = []
        scan_id = kwargs.get("scan_id", "active")

        # --- Stage 1: TLS / SSL Audit (0% - 35%) ---
        await emit_progress(10, "Auditing SSL/TLS certificate validity and expiration...")
        await emit_log(LogLevel.INFO, "Starting TLS/SSL certificate and cipher suite inspection.")

        tls_cert_findings = await audit_tls_certificates(
            target.value,
            emit_log=emit_log,
            timeout_seconds=min(5.0, config.timeout_seconds),
        )
        for f in tls_cert_findings:
            f.scan_id = scan_id
            findings.append(f)
            await emit_finding(f)

        await emit_progress(25, "Testing for deprecated TLS protocols and ciphers...")
        tls_proto_findings = await audit_tls_protocols_and_ciphers(
            target.value,
            emit_log=emit_log,
            timeout_seconds=min(3.0, config.timeout_seconds),
        )
        for f in tls_proto_findings:
            f.scan_id = scan_id
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
            f.scan_id = scan_id
            findings.append(f)
            await emit_finding(f)

        # --- Stage 3: Port Exposure Scanner & Hybrid Nmap Adapter (70% - 100%) ---
        await emit_progress(75, "Scanning for exposed database and management ports...")

        nmap_executed = False
        enable_nmap = getattr(config.adapters, "enable_nmap", True)
        if enable_nmap:
            nmap_adapter = NmapAdapter()
            custom_path = getattr(config.adapters, "nmap_path", None) or getattr(config.adapters, "custom_nmap_path", None)
            try:
                if await nmap_adapter.is_available(custom_path):
                    await emit_log(LogLevel.INFO, "Executing Nmap CLI adapter for deep port and service auditing...")
                    nmap_findings = await nmap_adapter.run(
                        target,
                        config,
                        emit_log,
                        emit_finding,
                        scan_id=scan_id,
                    )
                    await emit_log(LogLevel.INFO, "Nmap active scan completed successfully")
                    for f in nmap_findings:
                        f.source_tool = "nmap"
                        f.scan_id = scan_id
                        findings.append(f)
                    nmap_executed = True
                else:
                    await emit_log(LogLevel.INFO, "Nmap CLI not available - using pure native port checker & banner grabber fallback")
            except Exception as e:
                await emit_log(LogLevel.WARNING, f"Nmap CLI execution error: {e}")
                await emit_log(LogLevel.INFO, "Nmap CLI not available - using pure native port checker & banner grabber fallback")
        else:
            await emit_log(LogLevel.INFO, "Nmap CLI not available - using pure native port checker & banner grabber fallback")

        if not nmap_executed:
            port_findings = await audit_exposed_ports(
                target.value,
                custom_ports=config.port_list or None,
                emit_log=emit_log,
                timeout_seconds=min(2.0, config.timeout_seconds),
            )
            for f in port_findings:
                f.scan_id = scan_id
                findings.append(f)
                await emit_finding(f)

            # Native Banner Grabbing for detected open ports (NET-SVC-001)
            host, _ = extract_host_and_port(target.value)
            open_port_nums = []
            for f in port_findings:
                try:
                    # Extract port from location string e.g. "example.com:3306"
                    p_str = f.evidence.location.split(":")[-1]
                    open_port_nums.append(int(p_str))
                except Exception:
                    pass
            if open_port_nums:
                banner_findings = await audit_service_banners(host, open_port_nums, scan_id=scan_id)
                for f in banner_findings:
                    findings.append(f)
                    await emit_finding(f)

        # --- Stage 4: Passive OSINT Subdomain Recon & Takeover (85% - 100%) ---
        if config.osint.subdomain_enumeration:
            await emit_progress(85, "Performing passive Certificate Transparency OSINT & subdomain takeover checks...")
            await emit_log(LogLevel.INFO, "Harvesting public subdomains via crt.sh Certificate Transparency logs.")
            
            subdomain_cb = kwargs.get("emit_subdomain_discovered")
            osint_findings = await audit_subdomain_osint(
                target.value,
                config=config,
                scan_id=scan_id,
                emit_subdomain=subdomain_cb,
                emit_finding=emit_finding,
                emit_log=emit_log,
            )
            for f in osint_findings:
                f.scan_id = scan_id
                findings.append(f)
                await emit_finding(f)

        await emit_progress(100, "Network & TLS audit completed.")
        await emit_log(LogLevel.INFO, f"Network engine finished with {len(findings)} total findings.")

        return findings
