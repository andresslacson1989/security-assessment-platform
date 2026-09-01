"""
Contract 03, 06 & 08 Network & TLS Assessment Engine Coordinator.
"""

from __future__ import annotations
from typing import List
from tempfile import TemporaryDirectory
from pathlib import Path

from app.core.models import Target, Finding, ScanConfig, TargetType, LogLevel, NormalizedExecutionState
from app.engines.base import BaseAssessmentEngine, LogCallback, ProgressCallback, FindingCallback
from app.engines.network.tls_auditor import audit_tls_certificates, audit_tls_protocols_and_ciphers, extract_host_and_port
from app.engines.network.dns_hygiene import audit_dns_hygiene
from app.engines.network.port_checker import audit_exposed_ports
from app.engines.network.subdomain_recon import audit_subdomain_osint
from app.engines.network.origin_exposure import audit_origin_exposure
from app.engines.network.banner_grabber import audit_service_banners
from app.adapters.nmap_adapter import NmapAdapter
from app.adapters.sslyze_adapter import SslyzeAdapter
from app.adapters.subfinder_adapter import SubfinderAdapter
from app.adapters.httpx_adapter import HttpxAdapter
from app.adapters.amass_adapter import AmassAdapter
from app.adapters.metasploit_adapter import MetasploitAdapter
from app.core.ssrf_protector import create_validated_target
from app.core.path_sandbox import get_default_workspace_dir


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
        organization_id = kwargs.get("organization_id")
        subdomain_cb = kwargs.get("emit_subdomain_discovered")
        rejected_discovery_cb = kwargs.get("emit_rejected_discovery")
        tool_state_cb = kwargs.get("emit_tool_execution_state")
        endpoint_cb = kwargs.get("emit_endpoint_discovered")

        if not isinstance(organization_id, str) or not organization_id.strip():
            await emit_log(LogLevel.ERROR, "Network assessment blocked: authoritative organization context is required.")
            if tool_state_cb:
                for tool_name in ("nmap", "sslyze", "subfinder", "httpx", "amass", "metasploit"):
                    await tool_state_cb(tool_name, NormalizedExecutionState.EXECUTION_BLOCKED.value)
            return findings

        def mark_fallback(findings_to_mark: List[Finding], primary_tool: str) -> None:
            """Attach the mandatory provenance when native coverage follows a tool failure."""
            for finding in findings_to_mark:
                finding.source_tool = "native"
                finding.is_fallback = True
                finding.primary_tool_failed = primary_tool

        # Establish one authoritative target identity before any active network
        # adapter is allowed to run. Passive Subfinder remains on the original
        # domain value because it must not resolve or connect to discoveries.
        try:
            validated_target = create_validated_target(
                target,
                organization_id=organization_id,
                project_id=kwargs.get("project_id"),
                asset_id=kwargs.get("asset_id"),
                active_probing_granted=kwargs.get("active_probing_granted", False),
            )
        except Exception as exc:
            await emit_log(LogLevel.ERROR, f"Network assessment blocked by target validation: {exc}")
            if tool_state_cb:
                for tool_name in ("nmap", "sslyze", "httpx"):
                    await tool_state_cb(tool_name, NormalizedExecutionState.EXECUTION_BLOCKED.value)
            return findings

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
                        validated_target,
                        config,
                        emit_log,
                        emit_finding,
                        scan_id=scan_id,
                        require_managed_binary=True,
                    )
                    await emit_log(LogLevel.INFO, f"SSLyze audit completed successfully with {len(sslyze_findings)} findings.")
                    for f in sslyze_findings:
                        f.source_tool = "sslyze"
                        f.scan_id = scan_id
                        findings.append(f)
                    state = getattr(sslyze_adapter, "last_execution_state", None)
                    if tool_state_cb:
                        await tool_state_cb("sslyze", (state or (NormalizedExecutionState.COMPLETED_WITH_FINDINGS if sslyze_findings else NormalizedExecutionState.COMPLETED_NO_FINDINGS)).value)
                    sslyze_executed = state in (None, NormalizedExecutionState.COMPLETED_WITH_FINDINGS, NormalizedExecutionState.COMPLETED_NO_FINDINGS)
                else:
                    if tool_state_cb:
                        await tool_state_cb("sslyze", "TOOL_EXECUTION_FAILED")
                    await emit_log(LogLevel.INFO, "SSLyze CLI not available - using pure native TLS auditor fallback")
            except Exception as e:
                if tool_state_cb:
                    await tool_state_cb("sslyze", "TOOL_EXECUTION_FAILED")
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
                connection_host=validated_target.selected_destination,
            )
            for f in tls_cert_findings:
                f.scan_id = scan_id
                if not sslyze_executed:
                    mark_fallback([f], "sslyze")
                findings.append(f)
                await emit_finding(f)

            await emit_progress(20, "Testing for deprecated TLS protocols and ciphers...")
            tls_proto_findings = await audit_tls_protocols_and_ciphers(
                target.value,
                emit_log=emit_log,
                timeout_seconds=min(3.0, config.timeout_seconds),
                connection_host=validated_target.selected_destination,
            )
            for f in tls_proto_findings:
                f.scan_id = scan_id
                if not sslyze_executed:
                    mark_fallback([f], "sslyze")
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
                        validated_target,
                        config,
                        emit_log,
                        emit_finding,
                        scan_id=scan_id,
                        require_managed_binary=True,
                    )
                    await emit_log(LogLevel.INFO, "Nmap active scan completed successfully")
                    for f in nmap_findings:
                        f.source_tool = "nmap"
                        f.scan_id = scan_id
                        findings.append(f)
                    state = getattr(nmap_adapter, "last_execution_state", None)
                    if tool_state_cb:
                        await tool_state_cb("nmap", (state or (NormalizedExecutionState.COMPLETED_WITH_FINDINGS if nmap_findings else NormalizedExecutionState.COMPLETED_NO_FINDINGS)).value)
                    nmap_executed = state in (None, NormalizedExecutionState.COMPLETED_WITH_FINDINGS, NormalizedExecutionState.COMPLETED_NO_FINDINGS)
                else:
                    if tool_state_cb:
                        await tool_state_cb("nmap", "TOOL_EXECUTION_FAILED")
                    await emit_log(LogLevel.INFO, "Nmap CLI not available - using pure native port checker & banner grabber fallback")
            except Exception as e:
                if tool_state_cb:
                    await tool_state_cb("nmap", "TOOL_EXECUTION_FAILED")
                await emit_log(LogLevel.WARNING, f"Nmap CLI execution error: {e}")
                await emit_log(LogLevel.INFO, "Nmap CLI execution failed - using pure native port checker & banner grabber fallback")
        else:
            await emit_log(LogLevel.INFO, "Nmap disabled in configuration - using pure native port checker & banner grabber fallback")

        if not nmap_executed:
            port_findings = await audit_exposed_ports(
                target.value,
                custom_ports=config.port_list or None,
                emit_log=emit_log,
                timeout_seconds=min(2.0, config.timeout_seconds),
                connection_host=validated_target.selected_destination,
            )
            for f in port_findings:
                f.scan_id = scan_id
                f.source_tool = "native"
                if not nmap_executed:
                    mark_fallback([f], "nmap")
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
                banner_findings = await audit_service_banners(
                    host,
                    open_port_nums,
                    scan_id=scan_id,
                    connection_host=validated_target.selected_destination,
                )
                for f in banner_findings:
                    f.source_tool = "native"
                    if not nmap_executed:
                        mark_fallback([f], "nmap")
                    findings.append(f)
                    await emit_finding(f)

        if getattr(config.adapters, "enable_metasploit", True) and target.type in (TargetType.URL, TargetType.DOMAIN, TargetType.IP):
            metasploit_adapter = MetasploitAdapter()
            custom_path = getattr(config.adapters, "metasploit_path", None) or getattr(config.adapters, "custom_metasploit_path", None)
            try:
                if await metasploit_adapter.is_available(custom_path):
                    await emit_progress(68, "Executing governed Metasploit auxiliary verification...")
                    _, target_port = extract_host_and_port(target.value)
                    metasploit_findings = await metasploit_adapter.run(
                        target,
                        config,
                        emit_log,
                        emit_finding,
                        scan_id=scan_id,
                        organization_id=organization_id,
                        port=target_port or 443,
                    )
                    findings.extend(metasploit_findings)
                    if tool_state_cb:
                        await tool_state_cb("metasploit", metasploit_adapter.last_execution_state.value)
                elif tool_state_cb:
                    await tool_state_cb("metasploit", "TOOL_EXECUTION_FAILED")
                    await emit_log(LogLevel.WARNING, "Metasploit unavailable: auxiliary verification was not assessed.")
            except Exception as e:
                if tool_state_cb:
                    await tool_state_cb("metasploit", "TOOL_EXECUTION_FAILED")
                await emit_log(LogLevel.WARNING, f"Metasploit adapter error: {e}")

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
                        organization_id=organization_id,
                        emit_subdomain=subdomain_cb,
                        emit_rejected_discovery=rejected_discovery_cb,
                    )
                    findings.extend(sf_findings)
                    if tool_state_cb:
                        await tool_state_cb("subfinder", subfinder_adapter.last_execution_state.value)
                elif tool_state_cb:
                    await tool_state_cb("subfinder", "TOOL_EXECUTION_FAILED")
                    await emit_log(LogLevel.WARNING, "Subfinder unavailable: passive discovery was not assessed.")
            except Exception as e:
                if tool_state_cb:
                    await tool_state_cb("subfinder", "TOOL_EXECUTION_FAILED")
                await emit_log(LogLevel.WARNING, f"Subfinder adapter error: {e}")

        if getattr(config.adapters, "enable_amass", True) and target.type in (TargetType.URL, TargetType.DOMAIN):
            amass_adapter = AmassAdapter()
            custom_path = getattr(config.adapters, "amass_path", None) or getattr(config.adapters, "custom_amass_path", None)
            try:
                if await amass_adapter.is_available(custom_path):
                    await emit_progress(75, "Executing Amass passive attack-surface reconnaissance...")
                    with TemporaryDirectory(
                        prefix=f"amass-{scan_id}-",
                        dir=str(get_default_workspace_dir()),
                    ) as workspace:
                        output_file = str(Path(workspace) / "amass.jsonl")
                        amass_findings = await amass_adapter.run(
                            target,
                            config,
                            emit_log,
                            emit_finding,
                            scan_id=scan_id,
                            organization_id=organization_id,
                            output_file=output_file,
                            emit_subdomain=subdomain_cb,
                        )
                        findings.extend(amass_findings)
                    if tool_state_cb:
                        await tool_state_cb("amass", amass_adapter.last_execution_state.value)
                elif tool_state_cb:
                    await tool_state_cb("amass", "TOOL_EXECUTION_FAILED")
                    await emit_log(LogLevel.WARNING, "Amass unavailable: passive discovery was not assessed.")
            except Exception as e:
                if tool_state_cb:
                    await tool_state_cb("amass", "TOOL_EXECUTION_FAILED")
                await emit_log(LogLevel.WARNING, f"Amass adapter error: {e}")

        if getattr(config.adapters, "enable_httpx", True):
            httpx_adapter = HttpxAdapter()
            custom_path = getattr(config.adapters, "httpx_path", None) or getattr(config.adapters, "custom_httpx_path", None)
            try:
                if await httpx_adapter.is_available(custom_path):
                    await emit_progress(78, "Executing Httpx web port & tech stack probe...")
                    hx_findings = await httpx_adapter.run(
                        validated_target,
                        config,
                        emit_log,
                        emit_finding,
                        scan_id=scan_id,
                        emit_endpoint=endpoint_cb,
                        validated_target=validated_target,
                        require_managed_binary=True,
                    )
                    findings.extend(hx_findings)
                    if tool_state_cb:
                        await tool_state_cb("httpx", httpx_adapter.last_execution_state.value)
                elif tool_state_cb:
                    await tool_state_cb("httpx", "TOOL_EXECUTION_FAILED")
                    await emit_log(LogLevel.WARNING, "Httpx unavailable: HTTP validation was not assessed.")
            except Exception as e:
                if tool_state_cb:
                    await tool_state_cb("httpx", "TOOL_EXECUTION_FAILED")
                await emit_log(LogLevel.WARNING, f"Httpx adapter error: {e}")

        # --- Stage 5: Passive OSINT Subdomain Recon, Origin Exposure & Takeover (85% - 100%) ---
        if config.osint.subdomain_enumeration:
            await emit_progress(85, "Performing Certificate Transparency OSINT & direct origin exposure checks...")
            origin_findings = await audit_origin_exposure(
                target.value,
                config=config,
                scan_id=scan_id,
                organization_id=organization_id,
                emit_subdomain=subdomain_cb,
                emit_finding=emit_finding,
                emit_log=emit_log,
            )
            for f in origin_findings:
                f.scan_id = scan_id
                findings.append(f)

            await emit_progress(92, "Evaluating dangling CNAME subdomain takeover risks...")
            osint_findings = await audit_subdomain_osint(
                target.value,
                config=config,
                scan_id=scan_id,
                organization_id=organization_id,
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
