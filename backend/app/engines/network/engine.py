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
from app.adapters.sslyze_adapter import SslyzeAdapter
from app.adapters.subfinder_adapter import SubfinderAdapter
from app.adapters.httpx_adapter import HttpxAdapter


class NetworkAssessmentEngine(BaseAssessmentEngine):
    """
    Coordinator engine for Network Perimeter, TLS/SSL, EASM and DNS hygiene security assessments.
    Follows Adapters First-in-Line Architecture (SSLyze + Nmap + Subfinder + Httpx primary, native DNS/OSINT enrichment, native fallback).
    """

    @property
    def name(self) -> str:
        return "network"

    @property
    def display_name(self) -> str:
        return "Network Perimeter & EASM Auditor"

    @property
    def description(self) -> str:
        return (
            "Audits SSL/TLS certificates for expiration and SAN validity, deprecated protocols "
            "(TLS 1.0/1.1, SSLv3), DNS email security (SPF, DMARC, MTA-STS, BIMI), DNSSEC, "
            "external attack surface subdomains (Subfinder, crt.sh), HTTP exposure (Httpx), and port exposure (Nmap)."
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
        subdomain_cb = kwargs.get("emit_subdomain_discovered")
        endpoint_cb = kwargs.get("emit_endpoint_discovered")

        # --- Stage 1: TLS / SSL Audit (SSLyze Adapter First -> Native Fallback) (0% - 30%) ---
        await emit_progress(10, "Auditing SSL/TLS certificate validity and ciphers...")

        sslyze_executed = False
        enable_sslyze = getattr(config.adapters, "enable_sslyze", True)
        if enable_sslyze:
            sslyze_adapter = SslyzeAdapter()
            custom_path = getattr(config.adapters, "sslyze_path", None) or getattr(config.adapters, "custom_sslyze_path", None)
            try:
                if await sslyze_adapter.is_available(custom_path):
                    await emit_log(LogLevel.INFO, "Executing SSLyze CLI adapter as primary deep TLS auditor...")
                    sslyze_findings = await sslyze_adapter.run(
                        target,
                        config,
                        emit_log,
                        emit_finding,
                        scan_id=scan_id,
                    )
                    await emit_log(LogLevel.INFO, f"SSLyze audit completed successfully with {len(sslyze_findings)} findings.")
                    for f in sslyze_findings:
                        f.source_tool = "sslyze"
                        f.scan_id = scan_id
                        findings.append(f)
                    sslyze_executed = True
                else:
                    await emit_log(LogLevel.INFO, "SSLyze CLI not available - using pure native TLS auditor fallback")
            except Exception as e:
                await emit_log(LogLevel.WARNING, f"SSLyze CLI execution error: {e}")
                await emit_log(LogLevel.INFO, "SSLyze CLI not available - using pure native TLS auditor fallback")
        else:
            await emit_log(LogLevel.INFO, "SSLyze disabled - using pure native TLS auditor fallback")

        # If SSLyze wasn't executed, run full native TLS auditor
        if not sslyze_executed:
            tls_cert_findings = await audit_tls_certificates(
                target.value,
                emit_log=emit_log,
                timeout_seconds=min(5.0, config.timeout_seconds),
            )
            for f in tls_cert_findings:
                f.scan_id = scan_id
                findings.append(f)
                await emit_finding(f)

            await emit_progress(20, "Testing for deprecated TLS protocols and ciphers...")
            tls_proto_findings = await audit_tls_protocols_and_ciphers(
                target.value,
                emit_log=emit_log,
                timeout_seconds=min(3.0, config.timeout_seconds),
            )
            for f in tls_proto_findings:
                f.scan_id = scan_id
                findings.append(f)
                await emit_finding(f)

        # --- Stage 2: DNS & Email Hygiene (Proprietary Native Enrichment) (30% - 50%) ---
        await emit_progress(35, "Auditing DNS email security records (SPF, DMARC, MTA-STS, DNSSEC)...")
        dns_findings = await audit_dns_hygiene(
            target.value,
            emit_log=emit_log,
            timeout_seconds=min(3.0, config.timeout_seconds),
        )
        for f in dns_findings:
            f.scan_id = scan_id
            findings.append(f)
            await emit_finding(f)

        # --- Stage 3: Port Exposure Scanner (Nmap Adapter First -> Native Fallback) (50% - 70%) ---
        await emit_progress(55, "Scanning for exposed database and management ports...")

        nmap_executed = False
        enable_nmap = getattr(config.adapters, "enable_nmap", True)
        if enable_nmap:
            nmap_adapter = NmapAdapter()
            custom_path = getattr(config.adapters, "nmap_path", None) or getattr(config.adapters, "custom_nmap_path", None)
            try:
                if await nmap_adapter.is_available(custom_path):
                    await emit_log(LogLevel.INFO, "Executing Nmap CLI adapter as primary port and service scanner...")
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

            host, _ = extract_host_and_port(target.value)
            open_port_nums = []
            for f in port_findings:
                try:
                    p_str = f.evidence.location.split(":")[-1]
                    open_port_nums.append(int(p_str))
                except Exception:
                    pass
            if open_port_nums:
                banner_findings = await audit_service_banners(host, open_port_nums, scan_id=scan_id)
                for f in banner_findings:
                    findings.append(f)
                    await emit_finding(f)

        # --- Stage 4: High-Speed EASM & Tech Fingerprinting (Subfinder + Httpx) (70% - 85%) ---
        if getattr(config.adapters, "enable_subfinder", True):
            subfinder_adapter = SubfinderAdapter()
            custom_path = getattr(config.adapters, "subfinder_path", None) or getattr(config.adapters, "custom_subfinder_path", None)
            try:
                if await subfinder_adapter.is_available(custom_path):
                    await emit_progress(72, "Executing Subfinder passive subdomain reconnaissance...")
                    sf_findings = await subfinder_adapter.run(
                        target,
                        config,
                        emit_log,
                        emit_finding,
                        scan_id=scan_id,
                        emit_subdomain=subdomain_cb,
                    )
                    findings.extend(sf_findings)
            except Exception as e:
                await emit_log(LogLevel.WARNING, f"Subfinder adapter error: {e}")

        if getattr(config.adapters, "enable_httpx", True):
            httpx_adapter = HttpxAdapter()
            custom_path = getattr(config.adapters, "httpx_path", None) or getattr(config.adapters, "custom_httpx_path", None)
            try:
                if await httpx_adapter.is_available(custom_path):
                    await emit_progress(78, "Executing Httpx web port & tech stack probe...")
                    hx_findings = await httpx_adapter.run(
                        target,
                        config,
                        emit_log,
                        emit_finding,
                        scan_id=scan_id,
                        emit_endpoint=endpoint_cb,
                    )
                    findings.extend(hx_findings)
            except Exception as e:
                await emit_log(LogLevel.WARNING, f"Httpx adapter error: {e}")

        # --- Stage 5: Passive OSINT Subdomain Recon & Takeover (85% - 100%) ---
        if config.osint.subdomain_enumeration:
            await emit_progress(85, "Performing passive Certificate Transparency OSINT & subdomain takeover checks...")
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
