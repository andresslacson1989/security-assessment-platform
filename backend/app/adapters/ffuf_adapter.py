"""
Contract 03 (Section 4.2), Contract 06 (Section 2) & Contract 08 (Section 8.4) FFuF Tool Adapter.
Authoritative Reference: contracts/03_ENGINE_PLUGIN_INTERFACE_CONTRACT.md
"""

from __future__ import annotations
import json
import logging
import os
import re
import tempfile
from typing import Optional, List, Callable, Awaitable

from app.core.models import (
    Target,
    Finding,
    Evidence,
    Severity,
    ScanConfig,
    LogLevel,
    DiscoveredEndpoint,
    calculate_fingerprint,
    NormalizedExecutionState,
    sanitize_reproduction_curl,
)
from app.adapters.base_adapter import BaseToolAdapter

logger = logging.getLogger("cyberassess.adapters.ffuf")
from app.core.ssrf_protector import bind_url_to_validated_target, is_url_in_validated_origin

# Built-in lightweight fuzzing dictionary for non-destructive discovery
DEFAULT_FUZZ_PATHS = [
    ".env",
    ".git/HEAD",
    ".git/config",
    "wp-config.php.bak",
    "config.json",
    "backup.sql",
    "admin",
    "api/v1/users",
    "swagger.json",
    "actuator/health",
    "actuator/env",
    "server-status",
    "phpinfo.php",
    "debug",
    "console",
]

APPROVED_VERSION = "2.1.0"


class FfufAdapter(BaseToolAdapter):
    """
    Hybrid tool adapter for FFuF high-speed content and endpoint discovery.
    Normalizes JSON output into canonical DAST-EXP-xxx findings and DiscoveredEndpoints.
    """

    def __init__(self):
        super().__init__()
        self.approved_version = APPROVED_VERSION
        self.last_execution_state = NormalizedExecutionState.COMPLETED_NO_FINDINGS

    @property
    def tool_name(self) -> str:
        return "ffuf"

    async def get_version(self, custom_path: Optional[str] = None, pre_launch_check=None) -> Optional[str]:
        """
        Retrieves FFuF version string via `ffuf -V`.
        """
        path = self.resolve_binary_path(custom_path)
        if not path:
            return None

        returncode, stdout, stderr = await self.execute_command(
            [path, "-V"], timeout=5.0, pre_launch_check=pre_launch_check,
        )
        output = stdout.strip() or stderr.strip()
        if output:
            match = re.search(r"(\d+\.\d+(\.\d+)?)", output)
            if match:
                return f"FFuF {match.group(1)}"
            return output.splitlines()[0]
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
        Executes FFuF against target URL using rate-limited non-destructive parameters.
        """
        findings: List[Finding] = []
        self.last_execution_state = NormalizedExecutionState.COMPLETED_NO_FINDINGS
        custom_path = getattr(config.adapters, "ffuf_path", None) or getattr(config.adapters, "custom_ffuf_path", None)
        ffuf_path = self.resolve_binary_path(custom_path)

        if not ffuf_path:
            self.last_execution_state = NormalizedExecutionState.TOOL_EXECUTION_FAILED
            await emit_log(LogLevel.WARNING, "FFuF binary not found on host. Skipping FFuF execution.")
            return findings

        validated_target = self.require_validated_target(kwargs)
        if kwargs.get("require_managed_binary") and validated_target is None:
            await emit_log(LogLevel.ERROR, "FFuF execution blocked: a gateway-issued ValidatedTarget is required.")
            return findings

        if (
            kwargs.get("require_managed_binary")
            and not validated_target.authorization_context.get("active_probing_granted", False)
        ):
            self.last_execution_state = NormalizedExecutionState.EXECUTION_BLOCKED
            await emit_log(LogLevel.ERROR, "FFuF execution blocked: explicit tenant active-probing authorization is required.")
            return findings

        if kwargs.get("require_managed_binary") and not self.verify_managed_binary(ffuf_path):
            self.last_execution_state = NormalizedExecutionState.EXECUTION_BLOCKED
            await emit_log(LogLevel.ERROR, "FFuF execution blocked: executable is not a trusted managed installation.")
            return findings

        managed_check = (lambda: self.verify_managed_binary(ffuf_path)) if kwargs.get("require_managed_binary") else None
        if not await self.ensure_approved_version(custom_path, emit_log, pre_launch_check=managed_check):
            return findings

        target_url = target.value.strip()
        if not target_url.startswith("http://") and not target_url.startswith("https://"):
            target_url = f"http://{target_url}"
        host_header = None
        if validated_target is not None:
            target_url, host_header = bind_url_to_validated_target(target_url, validated_target)

        emit_endpoint = kwargs.get("emit_endpoint")

        # Create temporary wordlist
        temp_wordlist = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
                f.write("\n".join(DEFAULT_FUZZ_PATHS))
                temp_wordlist = f.name

            cmd = [
                ffuf_path,
                "-u", f"{target_url.rstrip('/')}/FUZZ",
                "-w", temp_wordlist,
                "-mc", "200,204,301,302,307,401,403",
                "-o", "-",
                "-of", "json",
                "-t", "5",
                "-rate", str(min(10, config.rate_limit_rps * 2)),
                "-s",
            ]
            if host_header:
                cmd.extend(["-H", f"Host: {host_header}"])

            await emit_log(LogLevel.INFO, f"Starting FFuF content discovery on '{target_url}'...")
            returncode, stdout, stderr = await self.execute_command(
                cmd,
                timeout=float(min(60.0, config.timeout_seconds * 6)),
                emit_log=emit_log,
                pre_launch_check=(lambda: self.verify_managed_binary(ffuf_path)) if kwargs.get("require_managed_binary") else None,
            )

            if not stdout.strip():
                self.last_execution_state = NormalizedExecutionState.EXECUTION_TIMED_OUT if "timed out" in stderr.lower() else (NormalizedExecutionState.TOOL_EXECUTION_FAILED if returncode != 0 else NormalizedExecutionState.COMPLETED_NO_FINDINGS)
                if returncode != 0:
                    await emit_log(LogLevel.WARNING, f"FFuF completed with code {returncode}: {stderr[:200]}")
                return findings

            data = json.loads(stdout)
            results = data.get("results", [])

            for item in results:
                fuzz_path = item.get("input", {}).get("FUZZ", "")
                status = item.get("status", 0)
                length = item.get("length", 0)
                url = item.get("url", f"{target_url}/{fuzz_path}")

                if validated_target is not None and not is_url_in_validated_origin(url, validated_target):
                    await emit_log(LogLevel.WARNING, f"Blocked out-of-origin FFuF endpoint observation: '{url}'.")
                    continue

                if emit_endpoint and callable(emit_endpoint):
                    try:
                        ep = DiscoveredEndpoint(
                            url=url,
                            method="GET",
                            depth=1,
                            status_code=status,
                            content_type="text/html",
                        )
                        await emit_endpoint(ep)
                    except Exception as exc:
                        logger.debug("FFuF JSON result item could not be normalized: error_type=%s", type(exc).__name__)

                # Check if it's a sensitive exposure
                if status == 200:
                    check_id = "DAST-EXP-001"
                    severity = Severity.HIGH
                    cvss = 7.5
                    title = f"Exposed Sensitive File or Endpoint: /{fuzz_path}"
                    
                    if ".env" in fuzz_path or "config" in fuzz_path:
                        check_id = "DAST-EXP-001"
                        severity = Severity.CRITICAL
                        cvss = 9.8
                        title = f"Publicly Exposed Environment / Configuration File: /{fuzz_path}"
                    elif ".git" in fuzz_path:
                        check_id = "DAST-EXP-002"
                        severity = Severity.CRITICAL
                        cvss = 9.8
                        title = f"Publicly Exposed Git Repository Directory: /{fuzz_path}"
                    elif "admin" in fuzz_path or "console" in fuzz_path:
                        check_id = "DAST-EXP-003"
                        severity = Severity.HIGH
                        cvss = 7.5
                        title = f"Unauthenticated Administrative Console Exposed: /{fuzz_path}"

                    evidence = Evidence(
                        location=url,
                        observed_value=f"HTTP status {status}, response length {length} bytes",
                        expected_value="HTTP 404 Not Found or HTTP 403 Forbidden",
                        raw_response_snippet=f"GET {url} HTTP/1.1\nHost: {target_url}\n\nHTTP/1.1 {status} OK\nContent-Length: {length}",
                        request_details={"method": "GET", "url": url},
                        response_details={"status_code": status},
                    )

                    f = Finding(
                        scan_id=kwargs.get("scan_id", "manual"),
                        engine="web_dast",
                        source_tool="ffuf",
                        check_id=check_id,
                        category="Sensitive Exposure",
                        title=title,
                        severity=severity,
                        cvss_score=cvss,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        cwe_id="CWE-552",
                        owasp_category="A01:2021-Broken Access Control",
                        nist_control="AC-3, SC-7",
                        description=f"FFuF content discovery identified accessible sensitive resource at {url}.",
                        impact="Attackers can download configuration files containing passwords, API tokens, or source code.",
                        remediation="Restrict public access to this path using web server rules (e.g. Nginx location block denial) or remove the file from web root.",
                        remediation_code_snippet=f"location /{fuzz_path} {{\n    deny all;\n    return 404;\n}}",
                        references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure_and_Application_Admin_Interfaces"],
                        evidence=evidence,
                        reproduction_curl=sanitize_reproduction_curl(f"curl -s -i '{url}'"),
                        fingerprint=calculate_fingerprint(check_id, url, str(status)),
                    )
                    findings.append(f)
                    await emit_finding(f)

        except Exception as e:
            self.last_execution_state = NormalizedExecutionState.PARTIAL_RESULTS_WITH_WARNING
            await emit_log(LogLevel.WARNING, f"Failed to parse FFuF results: {str(e)}")
        finally:
            if temp_wordlist and os.path.exists(temp_wordlist):
                try:
                    os.remove(temp_wordlist)
                except Exception as exc:
                    logger.debug("FFuF output cleanup failed: error_type=%s", type(exc).__name__)

        if returncode != 0:
            self.last_execution_state = NormalizedExecutionState.PARTIAL_RESULTS_WITH_WARNING if findings else NormalizedExecutionState.TOOL_EXECUTION_FAILED
        elif findings:
            self.last_execution_state = NormalizedExecutionState.COMPLETED_WITH_FINDINGS
        return findings
