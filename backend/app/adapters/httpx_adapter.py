"""
Httpx Tool Adapter for Web Port & Technology Stack Fingerprinting.
Authoritative Reference: contracts/03_ENGINE_PLUGIN_INTERFACE_CONTRACT.md (Section 4.2)
"""

from __future__ import annotations
import json
import re
from typing import Optional, List, Callable, Awaitable, Dict, Any
from urllib.parse import urlparse

from app.core.models import (
    Target, Finding, Evidence, ScanConfig, LogLevel, Severity,
    calculate_fingerprint, DiscoveredEndpoint, NormalizedExecutionState
)
from app.adapters.base_adapter import BaseToolAdapter
from app.core.ssrf_protector import bind_url_to_validated_target


class HttpxAdapter(BaseToolAdapter):
    """
    Adapter for ProjectDiscovery's Httpx fast HTTP probing and technology fingerprinting tool.
    """

    @property
    def tool_name(self) -> str:
        return "httpx"

    approved_version = "1.6.0"

    def __init__(self):
        self.last_execution_state = NormalizedExecutionState.COMPLETED_NO_FINDINGS

    async def get_version(self, custom_path: Optional[str] = None) -> Optional[str]:
        binary = self.resolve_binary_path(custom_path)
        if not binary:
            return None
        code, stdout, stderr = await self.execute_command([binary, "-version"], timeout=10.0)
        output = stdout + " " + stderr
        # Reject Python pip httpx CLI (which fails on -version with 'Usage: httpx')
        if "projectdiscovery" in output.lower() or "httpx" in output.lower():
            if code == 0 or "v" in output:
                match = re.search(r"(?<![0-9A-Za-z.-])v?(\d+\.\d+\.\d+)(?![0-9A-Za-z.-])", output, re.IGNORECASE)
                if match:
                    return f"httpx v{match.group(1)}"
                return "httpx" if code == 0 else None
        return None

    async def is_available(self, custom_path: Optional[str] = None) -> bool:
        ver = await self.get_version(custom_path)
        return ver is not None

    async def run(
        self,
        target: Target,
        config: ScanConfig,
        emit_log: Callable[[LogLevel, str], Awaitable[None]],
        emit_finding: Callable[[Finding], Awaitable[None]],
        **kwargs,
    ) -> List[Finding]:
        findings: List[Finding] = []
        self.last_execution_state = NormalizedExecutionState.COMPLETED_NO_FINDINGS
        scan_id = kwargs.get("scan_id", "local-scan")
        emit_endpoint: Optional[Callable[[DiscoveredEndpoint], Awaitable[None]]] = kwargs.get("emit_endpoint")

        binary = self.resolve_binary_path(config.adapters.httpx_path or config.adapters.custom_httpx_path)
        if not binary:
            self.last_execution_state = NormalizedExecutionState.TOOL_EXECUTION_FAILED
            await emit_log(LogLevel.WARNING, "Httpx binary not found. Skipping Httpx probe.")
            return findings

        require_managed = bool(kwargs.get("require_managed_binary"))
        if require_managed and not self.verify_managed_binary(binary):
            self.last_execution_state = NormalizedExecutionState.EXECUTION_BLOCKED
            await emit_log(LogLevel.ERROR, "Httpx execution blocked: executable is not a valid managed installation.")
            return findings

        if not await self.ensure_approved_version(config.adapters.httpx_path or config.adapters.custom_httpx_path, emit_log):
            return findings

        target_url = getattr(target, "canonical_value", None) or target.value
        if not target_url.startswith("http://") and not target_url.startswith("https://"):
            target_url = f"https://{target_url}"

        host_header = None
        validated_target = kwargs.get("validated_target")
        if validated_target is not None:
            target_url, host_header = bind_url_to_validated_target(target_url, validated_target)

        await emit_log(LogLevel.INFO, f"Executing Httpx HTTP probe and tech stack identification on: {target_url}")
        cmd = [binary, "-u", target_url, "-json", "-silent", "-title", "-tech-detect", "-status-code", "-follow-redirects"]
        if host_header:
            cmd.extend(["-H", f"Host: {host_header}", "-sni", host_header])

        code, stdout, stderr = await self.execute_command(
            cmd, timeout=45.0, emit_log=emit_log,
            pre_launch_check=(lambda: self.verify_managed_binary(binary)) if require_managed else None,
        )
        if code != 0 and not stdout:
            self.last_execution_state = NormalizedExecutionState.EXECUTION_TIMED_OUT if "timed out" in stderr.lower() else NormalizedExecutionState.TOOL_EXECUTION_FAILED
            await emit_log(LogLevel.WARNING, f"Httpx exited with code {code}: {stderr.strip()[:200]}")
            return findings

        probed_results = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                url = data.get("url") or data.get("input") or target_url
                status_code = data.get("status_code", 200)
                title = data.get("title", "")
                tech_list = data.get("tech", [])
                webserver = data.get("webserver", "")

                probed_results.append(data)

                # Emit discovered endpoint
                if emit_endpoint:
                    endpoint_model = DiscoveredEndpoint(
                        url=url,
                        method="GET",
                        status_code=status_code,
                        content_type=data.get("content_type", "text/html"),
                    )
                    await emit_endpoint(endpoint_model)

                # If exposed technologies or outdated webserver
                observed_info = []
                if webserver:
                    observed_info.append(f"Server: {webserver}")
                if tech_list:
                    observed_info.append(f"Technologies: {', '.join(tech_list)}")
                if title:
                    observed_info.append(f"Page Title: {title}")

                if observed_info:
                    evidence = Evidence(
                        location=url,
                        observed_value=" | ".join(observed_info),
                        expected_value="Server banners and framework fingerprints minimized or masked",
                        raw_response_snippet=json.dumps(data, indent=2),
                    )
                    finding = Finding(
                        scan_id=scan_id,
                        engine="network",
                        source_tool="httpx",
                        check_id="EASM-EXPOSURE-001",
                        category="Attack Surface Recon",
                        title=f"Web Service Fingerprinted: {url}",
                        severity=Severity.INFO,
                        cvss_score=0.0,
                        cwe_id="CWE-200",
                        description=f"Httpx successfully probed web endpoint {url} (HTTP {status_code}). Identified components: {', '.join(observed_info)}.",
                        impact="Detailed technology stack disclosure assists attackers in mapping known CVEs and tailored exploits.",
                        remediation="Suppress verbose Server headers and application framework signatures (e.g. X-Powered-By).",
                        references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server"],
                        evidence=evidence,
                        fingerprint=calculate_fingerprint("EASM-EXPOSURE-001", url, " | ".join(observed_info)),
                    )
                    findings.append(finding)
                    await emit_finding(finding)
            except Exception as e:
                self.last_execution_state = NormalizedExecutionState.PARTIAL_RESULTS_WITH_WARNING
                continue

        await emit_log(LogLevel.INFO, f"Httpx completed probe: {len(probed_results)} HTTP responses analyzed.")
        if code != 0 or any(line.strip() and line.strip() not in {""} for line in stdout.splitlines() if not line.strip().startswith("{") ):
            self.last_execution_state = NormalizedExecutionState.PARTIAL_RESULTS_WITH_WARNING
        elif findings:
            self.last_execution_state = NormalizedExecutionState.COMPLETED_WITH_FINDINGS
        return findings
