"""Native GTFOBins/LOLBAS privilege-rule evaluator.

The evaluator is deliberately data-driven: it never executes a discovered
binary, invokes sudo, or attempts privilege escalation. It only classifies
already-observed host metadata supplied by the controlled inventory path.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, List, Optional

from app.adapters.base_adapter import BaseToolAdapter
from app.core.models import (
    Evidence,
    Finding,
    LogLevel,
    NormalizedExecutionState,
    ScanConfig,
    Severity,
    Target,
    TargetType,
    calculate_fingerprint,
    sanitize_sensitive_text,
)


GTFOBINS_CATALOG = frozenset({
    "awk", "bash", "env", "find", "less", "more", "nmap", "perl",
    "python", "ruby", "tar", "vim", "zip",
})


def _binary_name(value: str) -> str:
    return Path(value.strip()).name.lower()


def _catalog_match(value: str) -> bool:
    name = _binary_name(value)
    return name in GTFOBINS_CATALOG or bool(re.fullmatch(r"python3(?:\.\d+)?", name))


def evaluate_host_audit(
    audit_input: Dict[str, Any],
    *,
    scan_id: str,
    organization_id: Optional[str] = None,
) -> List[Finding]:
    """Convert observed SUID/capability/sudo metadata into canonical findings."""
    findings: List[Finding] = []
    seen: set[tuple[str, str]] = set()

    def add_finding(check_id: str, title: str, location: str, observed: str, description: str) -> None:
        key = (check_id, location)
        if key in seen:
            return
        seen.add(key)
        evidence = Evidence(
            location=sanitize_sensitive_text(location),
            observed_value=sanitize_sensitive_text(observed),
            expected_value="No exploitable GTFOBins/LOLBAS privilege path is present.",
            raw_response_snippet=sanitize_sensitive_text(observed),
        )
        finding = Finding(
            scan_id=scan_id,
            organization_id=organization_id or "org-default",
            engine="infra_iac",
            source_tool="gtfobins",
            check_id=check_id,
            category="Host Privilege Escalation",
            title=title,
            severity=Severity.HIGH,
            cvss_score=7.8,
            cwe_id="CWE-250",
            owasp_category="A01:2021-Broken Access Control",
            nist_control="AC-6",
            description=description,
            impact="A local attacker may abuse an over-privileged executable or rule to execute commands with elevated rights.",
            remediation="Remove the unnecessary SUID/capability or NOPASSWD permission and apply least privilege.",
            evidence=evidence,
            fingerprint=calculate_fingerprint(check_id, location, observed),
        )
        findings.append(finding)

    for raw_path in audit_input.get("suid_binaries", []) or []:
        if isinstance(raw_path, str) and _catalog_match(raw_path):
            add_finding(
                "HOST-PRIV-001",
                "GTFOBins-Matched SUID Binary",
                raw_path,
                f"SUID binary: {raw_path}",
                f"The observed SUID binary '{raw_path}' matches a known GTFOBins execution primitive.",
            )

    for raw_rule in audit_input.get("sudo_rules", []) or []:
        if not isinstance(raw_rule, str) or "nopasswd:" not in raw_rule.lower():
            continue
        command = raw_rule.rsplit(":", 1)[-1].strip().split()[0] if ":" in raw_rule else ""
        if command and _catalog_match(command):
            add_finding(
                "HOST-SUDO-001",
                "GTFOBins-Matched NOPASSWD Rule",
                command,
                raw_rule,
                f"The NOPASSWD sudo rule '{raw_rule}' grants passwordless access to a GTFOBins execution primitive.",
            )

    for raw_capability in audit_input.get("capabilities", []) or []:
        if not isinstance(raw_capability, str):
            continue
        command = raw_capability.split("=", 1)[0].strip()
        if _catalog_match(command):
            add_finding(
                "HOST-PRIV-001",
                "GTFOBins-Matched File Capability",
                command,
                raw_capability,
                f"The observed file capability '{raw_capability}' matches a known GTFOBins execution primitive.",
            )

    return findings


class GTFOBinsAdapter(BaseToolAdapter):
    """Native host privilege-rule adapter; no external executable is used."""

    @property
    def tool_name(self) -> str:
        return "gtfobins"

    async def is_available(self, custom_path: Optional[str] = None) -> bool:
        return True

    def resolve_binary_path(self, custom_path: Optional[str] = None) -> Optional[str]:
        return None

    async def get_version(self, custom_path: Optional[str] = None, pre_launch_check=None) -> Optional[str]:
        return "native-rule-engine"

    async def run(
        self,
        target: Target,
        config: ScanConfig,
        emit_log: Callable[[LogLevel, str], Awaitable[None]],
        emit_finding: Callable[[Finding], Awaitable[None]],
        **kwargs,
    ) -> List[Finding]:
        if target.type not in (TargetType.LOCAL_PATH, TargetType.IAC_MANIFEST, TargetType.DOCKERFILE):
            self.last_execution_state = NormalizedExecutionState.EXECUTION_BLOCKED
            await emit_log(LogLevel.INFO, "GTFOBins evaluation requires a local host/inventory target.")
            return []
        audit_input = kwargs.get("host_audit_input")
        if not isinstance(audit_input, dict):
            self.last_execution_state = NormalizedExecutionState.COMPLETED_NO_FINDINGS
            await emit_log(LogLevel.INFO, "No host privilege metadata was supplied; GTFOBins evaluation produced no findings.")
            return []
        organization_id = kwargs.get("organization_id")
        if not isinstance(organization_id, str) or not organization_id.strip():
            self.last_execution_state = NormalizedExecutionState.EXECUTION_BLOCKED
            await emit_log(LogLevel.ERROR, "GTFOBins evaluation blocked: authoritative organization context is required.")
            return []
        findings = evaluate_host_audit(
            audit_input,
            scan_id=kwargs.get("scan_id", "local-scan"),
            organization_id=organization_id,
        )
        self._record_execution(0, "", "", findings_count=len(findings))
        for finding in findings:
            await emit_finding(finding)
        await emit_log(LogLevel.INFO, f"GTFOBins rule evaluation completed with {len(findings)} findings.")
        return findings
