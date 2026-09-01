"""
Contract 03 (Section 4.2), Contract 06 (Section 2) & Contract 08 (Section 8.10) Checkov Tool Adapter.
Authoritative Reference: contracts/03_ENGINE_PLUGIN_INTERFACE_CONTRACT.md
"""

from __future__ import annotations
import json
import os
import re
from typing import Optional, List, Callable, Awaitable

from app.core.models import (
    Target,
    Finding,
    Evidence,
    Severity,
    ScanConfig,
    LogLevel,
    NormalizedExecutionState,
    calculate_fingerprint,
)
from app.adapters.base_adapter import BaseToolAdapter


class CheckovAdapter(BaseToolAdapter):
    """
    Hybrid tool adapter for Checkov Infrastructure-as-Code (IaC) policy scanner.
    Normalizes JSON findings for Terraform, Kubernetes, Dockerfile, and Compose into canonical IAC-xxx findings.
    """
    approved_version = "3.2.0"
    package_name = "checkov"

    @property
    def tool_name(self) -> str:
        return "checkov"

    async def get_version(self, custom_path: Optional[str] = None, pre_launch_check=None) -> Optional[str]:
        """
        Retrieves Checkov version string via `checkov -v`.
        """
        path = self.resolve_binary_path(custom_path)
        if not path:
            return None

        returncode, stdout, stderr = await self.execute_command([path, "-v"], timeout=5.0, pre_launch_check=pre_launch_check)
        output = stdout.strip() or stderr.strip()
        if output:
            match = re.search(r"(\d+\.\d+(\.\d+)?)", output)
            if match:
                return f"Checkov {match.group(1)}"
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
        Executes Checkov against IaC manifests or directory.
        """
        findings: List[Finding] = []
        custom_path = getattr(config.adapters, "checkov_path", None) or getattr(config.adapters, "custom_checkov_path", None)
        checkov_path = self.resolve_binary_path(custom_path)

        if not checkov_path:
            await emit_log(LogLevel.WARNING, "Checkov binary not found on host. Skipping Checkov execution.")
            return findings

        managed_check = (lambda: self.verify_managed_binary(checkov_path)) if kwargs.get("require_managed_binary") else None
        if kwargs.get("require_managed_binary") and not managed_check():
            self.last_execution_state = NormalizedExecutionState.EXECUTION_BLOCKED
            await emit_log(LogLevel.ERROR, "Checkov execution blocked: executable is not a trusted managed installation.")
            return findings
        if kwargs.get("require_managed_binary") and not await self.ensure_approved_version(custom_path, emit_log, pre_launch_check=managed_check):
            return findings

        repo_path = target.value.strip()
        if not os.path.exists(repo_path):
            await emit_log(LogLevel.WARNING, f"Target path '{repo_path}' does not exist for Checkov scan.")
            return findings

        cmd = [
            checkov_path,
            "-d" if os.path.isdir(repo_path) else "-f", repo_path,
            "-o", "json",
            "--compact",
            "--quiet",
        ]

        await emit_log(LogLevel.INFO, f"Starting Checkov IaC policy engine on '{repo_path}'...")
        returncode, stdout, stderr = await self.execute_command(
            cmd,
            timeout=float(min(60.0, config.timeout_seconds * 6)),
            emit_log=emit_log,
            pre_launch_check=managed_check,
        )

        if not stdout.strip():
            if returncode not in (0, 1):
                await emit_log(LogLevel.WARNING, f"Checkov completed with exit code {returncode}: {stderr[:200]}")
            return findings

        try:
            data = json.loads(stdout)
            # Checkov returns either a single result dict or a list of result dicts for multiple frameworks
            result_list = data if isinstance(data, list) else [data]

            for item in result_list:
                failed_checks = item.get("results", {}).get("failed_checks", [])
                for check in failed_checks:
                    c_id = check.get("check_id", "CKV_GENERIC")
                    c_name = check.get("check_name", "IaC Policy Violation")
                    file_path = check.get("file_path", "unknown")
                    line_range = check.get("file_line_range", [1, 1])
                    start_line = line_range[0] if line_range else 1
                    resource = check.get("resource", "resource")
                    guideline = check.get("guideline", "https://docs.bridgecrew.io/")

                    check_type = item.get("check_type", "terraform").lower()
                    c_id_upper = c_id.upper()
                    if "docker" in check_type or "dockerfile" in file_path.lower() or c_id_upper.startswith("CKV_DOCKER"):
                        canonical_id = "IAC-DOCK-001"
                        category = "Container Posture"
                    elif "k8s" in check_type or "kubernetes" in check_type or c_id_upper.startswith("CKV_K8S"):
                        canonical_id = "IAC-K8S-001"
                        category = "Container Posture"
                    else:
                        canonical_id = "IAC-TF-001"
                        category = "Infrastructure-as-Code"

                    severity = Severity.HIGH
                    cvss = 7.8

                    evidence = Evidence(
                        location=f"{file_path}:{start_line}",
                        observed_value=f"Checkov {c_id} Failed: {c_name} on {resource}",
                        expected_value="Compliance with CIS and Bridgecrew IaC security baselines",
                        raw_response_snippet=json.dumps(check.get("code_block", []), indent=2),
                        line_number=start_line,
                    )

                    f = Finding(
                        scan_id=kwargs.get("scan_id", "manual"),
                        engine="infra_iac",
                        source_tool="checkov",
                        check_id=canonical_id,
                        category=category,
                        title=f"Checkov ({c_id}): {c_name}",
                        severity=severity,
                        cvss_score=cvss,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        cwe_id="CWE-284" if "TF" in canonical_id else "CWE-250",
                        owasp_category="A05:2021-Security Misconfiguration",
                        nist_control="CM-6, AC-6",
                        description=f"Checkov failed policy check '{c_id}' ({c_name}) for resource '{resource}' in {file_path}:{start_line}.",
                        impact="Insecure cloud infrastructure provisioning leading to unauthorized access or exposure.",
                        remediation=f"Modify infrastructure manifest according to the policy guideline: {guideline}",
                        references=[guideline] if guideline else ["https://www.checkov.io/"],
                        evidence=evidence,
                        fingerprint=calculate_fingerprint(canonical_id, f"{file_path}:{start_line}", c_id),
                    )
                    findings.append(f)
                    await emit_finding(f)

        except Exception as e:
            await emit_log(LogLevel.WARNING, f"Failed to parse Checkov JSON results: {str(e)}")

        return findings
