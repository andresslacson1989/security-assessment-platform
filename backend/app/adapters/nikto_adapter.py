"""
Contract 03 (Section 4.2), Contract 06 (Section 2) & Contract 08 (Section 8.5) Nikto Tool Adapter.
Authoritative Reference: contracts/03_ENGINE_PLUGIN_INTERFACE_CONTRACT.md
"""

from __future__ import annotations
import json
import re
from typing import Optional, List, Callable, Awaitable

from app.core.models import (
    Target,
    Finding,
    Evidence,
    Severity,
    ScanConfig,
    LogLevel,
    calculate_fingerprint,
)
from app.adapters.base_adapter import BaseToolAdapter


class NiktoAdapter(BaseToolAdapter):
    """
    Hybrid tool adapter for Nikto web server scanner.
    Normalizes JSON output into canonical DAST-HDR-xxx, NET-SVC-001, and DAST-EXP-xxx findings.
    """

    @property
    def tool_name(self) -> str:
        return "nikto"

    async def is_available(self, custom_path: Optional[str] = None) -> bool:
        """
        Checks if Nikto executable is present AND the underlying Perl runtime has required modules.
        """
        path = self.resolve_binary_path(custom_path)
        if not path:
            return False
        version = await self.get_version(custom_path)
        return version is not None

    async def get_version(self, custom_path: Optional[str] = None) -> Optional[str]:
        """
        Retrieves Nikto version string via `nikto -Version`.
        """
        path = self.resolve_binary_path(custom_path)
        if not path:
            return None

        returncode, stdout, _ = await self.execute_command([path, "-Version"], timeout=5.0)
        if returncode == 0 and stdout:
            match = re.search(r"Nikto\s+v?([0-9\.]+)", stdout, re.IGNORECASE)
            if match:
                return f"Nikto {match.group(1)}"
            first_line = stdout.splitlines()[0].strip()
            if not any(err in first_line.lower() for err in ["error", "not found", "can't locate", "failed"]):
                return first_line
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
        Executes Nikto web server scan and parses JSON output.
        """
        findings: List[Finding] = []
        custom_path = getattr(config.adapters, "nikto_path", None) or getattr(config.adapters, "custom_nikto_path", None)
        nikto_path = self.resolve_binary_path(custom_path)

        if not nikto_path:
            await emit_log(LogLevel.WARNING, "Nikto binary not found on host. Skipping Nikto execution.")
            return findings

        target_url = target.value.strip()
        if not target_url.startswith("http://") and not target_url.startswith("https://"):
            target_url = f"http://{target_url}"

        cmd = [
            nikto_path,
            "-h", target_url,
            "-Format", "json",
            "-output", "-",
            "-Tuning", "1,2,3,4,8,9,a,b,c",
        ]

        await emit_log(LogLevel.INFO, f"Starting Nikto server assessment on '{target_url}'...")
        returncode, stdout, stderr = await self.execute_command(
            cmd,
            timeout=float(min(60.0, config.timeout_seconds * 6)),
            emit_log=emit_log,
        )

        if not stdout.strip():
            if returncode != 0:
                await emit_log(LogLevel.WARNING, f"Nikto finished with code {returncode}: {stderr[:200]}")
            return findings

        try:
            data = json.loads(stdout)
            # Nikto output format: {"vulnerabilities": [{"id": "...", "msg": "...", "url": "...", "method": "..."}]}
            items = data.get("vulnerabilities", []) if isinstance(data, dict) else (data if isinstance(data, list) else [])

            for item in items:
                msg = item.get("msg", "") or item.get("description", "")
                uri = item.get("url", "") or item.get("uri", "")
                full_url = f"{target_url.rstrip('/')}/{uri.lstrip('/')}" if uri else target_url
                osvdb = item.get("id", "") or item.get("osvdb", "")

                # Classify Nikto finding
                check_id = "DAST-HDR-001"
                severity = Severity.LOW
                cvss = 3.1
                category = "Security Misconfiguration"

                if "X-Frame-Options" in msg or "clickjack" in msg.lower():
                    check_id = "DAST-HDR-002"
                    severity = Severity.MEDIUM
                    cvss = 5.3
                    category = "Security Headers"
                elif "Strict-Transport-Security" in msg or "HSTS" in msg:
                    check_id = "DAST-HDR-001"
                    severity = Severity.MEDIUM
                    cvss = 5.3
                    category = "Security Headers"
                elif "Content-Security-Policy" in msg or "CSP" in msg:
                    check_id = "DAST-HDR-003"
                    severity = Severity.MEDIUM
                    cvss = 5.3
                    category = "Security Headers"
                elif "server banner" in msg.lower() or "retrieved server" in msg.lower() or "apache/" in msg.lower() or "nginx/" in msg.lower():
                    check_id = "NET-SVC-001"
                    severity = Severity.LOW
                    cvss = 3.1
                    category = "Service Posture"
                elif "TRAC" in msg or "PUT" in msg or "method" in msg.lower():
                    check_id = "DAST-METH-001"
                    severity = Severity.MEDIUM
                    cvss = 4.3
                    category = "HTTP Method Posture"
                elif "sensitive" in msg.lower() or "exposed" in msg.lower() or "backup" in msg.lower():
                    check_id = "DAST-EXP-001"
                    severity = Severity.HIGH
                    cvss = 7.5
                    category = "Sensitive Exposure"

                evidence = Evidence(
                    location=full_url,
                    observed_value=msg,
                    expected_value="Hardened web server configuration without banner leaks or dangerous endpoints",
                    raw_response_snippet=f"Nikto item: OSVDB-{osvdb} | {msg}",
                )

                f = Finding(
                    scan_id=kwargs.get("scan_id", "manual"),
                    engine="web_dast",
                    source_tool="nikto",
                    check_id=check_id,
                    category=category,
                    title=f"Web Server Flaw: {msg[:80]}",
                    severity=severity,
                    cvss_score=cvss,
                    cwe_id="CWE-200" if severity == Severity.LOW else "CWE-16",
                    owasp_category="A05:2021-Security Misconfiguration",
                    nist_control="CM-6, SC-8",
                    description=f"Nikto web server inspection observed: {msg}",
                    impact="Information disclosure or misconfiguration enabling further reconnaissance.",
                    remediation="Apply web server hardening guidelines and disable unneeded headers/modules.",
                    references=["https://github.com/sullo/nikto"],
                    evidence=evidence,
                    reproduction_curl=f"curl -s -i '{full_url}'",
                    fingerprint=calculate_fingerprint(check_id, full_url, msg),
                )
                findings.append(f)
                await emit_finding(f)

        except Exception as e:
            await emit_log(LogLevel.WARNING, f"Failed to parse Nikto results: {str(e)}")

        return findings
