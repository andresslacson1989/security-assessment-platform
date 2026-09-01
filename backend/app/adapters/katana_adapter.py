"""
Katana Tool Adapter for Headless SPA JavaScript Dynamic Web Crawling.
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

APPROVED_VERSION = "1.0.5"


class KatanaAdapter(BaseToolAdapter):
    """
    Adapter for ProjectDiscovery's Katana next-generation crawling engine.
    """

    def __init__(self):
        super().__init__()
        self.approved_version = APPROVED_VERSION
        self.last_execution_state = NormalizedExecutionState.COMPLETED_NO_FINDINGS

    @property
    def tool_name(self) -> str:
        return "katana"

    async def get_version(self, custom_path: Optional[str] = None) -> Optional[str]:
        binary = self.resolve_binary_path(custom_path)
        if not binary:
            return None
        code, stdout, stderr = await self.execute_command([binary, "-version"], timeout=10.0)
        output = stdout + " " + stderr
        match = re.search(r"v\d+\.\d+\.\d+", output, re.IGNORECASE)
        if match:
            return f"katana {match.group(0)}"
        return "katana" if code == 0 else None

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

        binary = self.resolve_binary_path(config.adapters.katana_path or config.adapters.custom_katana_path)
        if not binary:
            self.last_execution_state = NormalizedExecutionState.TOOL_EXECUTION_FAILED
            await emit_log(LogLevel.WARNING, "Katana binary not found. Skipping Katana SPA crawler.")
            return findings

        if not await self.ensure_approved_version(config.adapters.katana_path or config.adapters.custom_katana_path, emit_log):
            return findings

        target_url = target.value
        if not target_url.startswith("http://") and not target_url.startswith("https://"):
            target_url = f"https://{target_url}"
        host_header = None
        if kwargs.get("validated_target") is not None:
            target_url, host_header = bind_url_to_validated_target(target_url, kwargs["validated_target"])

        await emit_log(LogLevel.INFO, f"Executing Katana dynamic crawler on: {target_url}")
        # Standard fast crawl command
        cmd = [binary, "-u", target_url, "-jsonl", "-silent", "-d", str(min(config.crawler.max_depth, 3)), "-c", "5"]
        if host_header:
            cmd.extend(["-H", f"Host: {host_header}"])

        code, stdout, stderr = await self.execute_command(cmd, timeout=60.0, emit_log=emit_log)
        if code != 0 and not stdout:
            self.last_execution_state = NormalizedExecutionState.EXECUTION_TIMED_OUT if "timed out" in stderr.lower() else NormalizedExecutionState.TOOL_EXECUTION_FAILED
            await emit_log(LogLevel.WARNING, f"Katana exited with code {code}: {stderr.strip()[:200]}")
            return findings

        discovered_urls = set()
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                endpoint_url = None
                method = "GET"
                if "request" in data and isinstance(data["request"], dict):
                    endpoint_url = data["request"].get("endpoint") or data["request"].get("url")
                    method = data["request"].get("method", "GET").upper()
                elif "url" in data:
                    endpoint_url = data["url"]

                if endpoint_url and endpoint_url not in discovered_urls:
                    discovered_urls.add(endpoint_url)
                    if emit_endpoint:
                        endpoint_model = DiscoveredEndpoint(
                            url=endpoint_url,
                            method=method,
                            depth=1,
                            status_code=data.get("response", {}).get("status_code", 200) if isinstance(data.get("response"), dict) else 200,
                        )
                        await emit_endpoint(endpoint_model)
            except Exception:
                # Handle raw URL strings
                if line.startswith("http://") or line.startswith("https://"):
                    if line not in discovered_urls:
                        discovered_urls.add(line)
                        if emit_endpoint:
                            await emit_endpoint(DiscoveredEndpoint(url=line, method="GET", depth=1))

        if discovered_urls:
            evidence = Evidence(
                location=target_url,
                observed_value=f"{len(discovered_urls)} dynamic SPA/API endpoints discovered",
                expected_value="All accessible web routes enumerated and secured",
                raw_response_snippet=json.dumps(list(discovered_urls)[:25], indent=2),
            )
            finding = Finding(
                scan_id=scan_id,
                engine="web_dast",
                source_tool="katana",
                check_id="DAST-SPA-001",
                category="Endpoint Discovery",
                title=f"Discovered {len(discovered_urls)} Dynamic Web Endpoints via Katana",
                severity=Severity.INFO,
                cvss_score=0.0,
                cwe_id="CWE-200",
                description=f"Katana crawler parsed client-side JavaScript bundles and DOM events to discover {len(discovered_urls)} interactive application endpoints.",
                impact="Discovered endpoints feed directly into active vulnerability checks and parameter fuzzing.",
                remediation="Ensure proper authorization checks on all exposed API routes and backend handlers.",
                references=["https://github.com/projectdiscovery/katana"],
                evidence=evidence,
                fingerprint=calculate_fingerprint("DAST-SPA-001", target_url, f"{len(discovered_urls)} endpoints"),
            )
            findings.append(finding)
            await emit_finding(finding)
            await emit_log(LogLevel.INFO, f"Katana crawler discovered {len(discovered_urls)} unique routes.")

        if code != 0:
            self.last_execution_state = NormalizedExecutionState.PARTIAL_RESULTS_WITH_WARNING if discovered_urls else NormalizedExecutionState.TOOL_EXECUTION_FAILED
        elif findings:
            self.last_execution_state = NormalizedExecutionState.COMPLETED_WITH_FINDINGS
        return findings
