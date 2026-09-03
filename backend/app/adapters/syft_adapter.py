"""
Syft Tool Adapter for Software Bill of Materials (SBOM) Generation.
Authoritative Reference: contracts/03_ENGINE_PLUGIN_INTERFACE_CONTRACT.md (Section 4.2)
"""

from __future__ import annotations
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Optional, List, Callable, Awaitable, Dict, Any

from app.core.models import (
    Target, Finding, Evidence, ScanConfig, LogLevel, Severity,
    calculate_fingerprint, SBOMReport, SBOMComponent, SBOMExportFormat,
    NormalizedExecutionState,
)
from app.adapters.base_adapter import BaseToolAdapter


class SyftAdapter(BaseToolAdapter):
    """
    Adapter for Anchore Syft SBOM generator (CycloneDX and SPDX).
    """
    approved_version = "1.0.1"

    @property
    def tool_name(self) -> str:
        return "syft"

    async def get_version(self, custom_path: Optional[str] = None, pre_launch_check=None) -> Optional[str]:
        binary = self.resolve_binary_path(custom_path)
        if not binary:
            return None
        code, stdout, stderr = await self.execute_command([binary, "--version"], timeout=10.0, pre_launch_check=pre_launch_check)
        output = stdout + " " + stderr
        match = re.search(r"\d+\.\d+\.\d+", output)
        if match:
            return f"syft {match.group(0)}"
        return "syft" if code == 0 else None

    async def run(
        self,
        target: Target,
        config: ScanConfig,
        emit_log: Callable[[LogLevel, str], Awaitable[None]],
        emit_finding: Callable[[Finding], Awaitable[None]],
        **kwargs,
    ) -> List[Finding]:
        findings: List[Finding] = []
        scan_id = kwargs.get("scan_id", "local-scan")
        record_sbom_report: Optional[Callable[[SBOMReport], None]] = kwargs.get("record_sbom_report")

        binary = self.resolve_binary_path(config.adapters.syft_path or config.adapters.custom_syft_path)
        if not binary:
            self.last_execution_state = NormalizedExecutionState.TOOL_EXECUTION_FAILED
            await emit_log(LogLevel.WARNING, "Syft binary not found. Skipping SBOM generation.")
            return findings

        scan_path = target.value
        if not os.path.exists(scan_path):
            self.last_execution_state = NormalizedExecutionState.EXECUTION_BLOCKED
            await emit_log(LogLevel.WARNING, f"Target directory not accessible: {scan_path}")
            return findings

        await emit_log(LogLevel.INFO, f"Executing Syft SBOM cataloging on: {scan_path}")
        managed_check = (lambda: self.verify_managed_binary(binary)) if kwargs.get("require_managed_binary") else None
        if kwargs.get("require_managed_binary") and not managed_check():
            self.last_execution_state = NormalizedExecutionState.EXECUTION_BLOCKED
            await emit_log(LogLevel.ERROR, "Syft execution blocked: executable is not a trusted managed installation.")
            return findings
        if kwargs.get("require_managed_binary") and not await self.ensure_approved_version(
            config.adapters.syft_path or config.adapters.custom_syft_path, emit_log, pre_launch_check=managed_check
        ):
            return findings
        output_path = None
        try:
            output_fd, output_path = tempfile.mkstemp(prefix="cyberassess-syft-", suffix=".json")
            os.close(output_fd)
            cmd = [binary, f"dir:{scan_path}", "-o", f"cyclonedx-json={output_path}"]

            code, stdout, stderr = await self.execute_command(cmd, timeout=60.0, emit_log=emit_log, pre_launch_check=managed_check)
            report_output = stdout
            if output_path and Path(output_path).is_file() and Path(output_path).stat().st_size:
                report_output = Path(output_path).read_text(encoding="utf-8")
        finally:
            if output_path:
                try:
                    Path(output_path).unlink()
                except FileNotFoundError:
                    pass
        if code != 0 and not stdout:
            await emit_log(LogLevel.WARNING, f"Syft exited with code {code}: {stderr.strip()[:200]}")
            return findings

        try:
            sbom_data = json.loads(report_output)
            raw_components = sbom_data.get("components", [])

            components: List[SBOMComponent] = []
            for comp in raw_components:
                name = comp.get("name", "Unknown")
                version = comp.get("version", "0.0.0")
                comp_type = comp.get("type", "library")
                purl = comp.get("purl")
                licenses_list = comp.get("licenses", [])
                license_id = None
                if licenses_list and isinstance(licenses_list, list):
                    first_lic = licenses_list[0]
                    if isinstance(first_lic, dict):
                        license_id = first_lic.get("license", {}).get("id") or first_lic.get("license", {}).get("name")
                cpe = comp.get("cpe")

                components.append(SBOMComponent(
                    name=name,
                    version=version,
                    type=comp_type,
                    purl=purl,
                    license=license_id,
                    cpe=cpe,
                ))

            sbom_report = SBOMReport(
                format=SBOMExportFormat.CYCLONEDX_JSON,
                spec_version="1.5",
                components=components,
                raw_document=report_output,
            )

            if record_sbom_report:
                record_sbom_report(sbom_report)

            evidence = Evidence(
                location=scan_path,
                observed_value=f"Generated CycloneDX 1.5 SBOM with {len(components)} cataloged software components",
                expected_value="Maintain comprehensive Software Bill of Materials for supply chain transparency",
                raw_response_snippet=json.dumps({"total_components": len(components), "sample": [c.name for c in components[:10]]}, indent=2),
            )

            finding = Finding(
                scan_id=scan_id,
                engine="code_sast",
                source_tool="syft",
                check_id="SCA-SBOM-001",
                category="Supply Chain Security",
                title=f"Software Bill of Materials (SBOM) Generated: {len(components)} Packages Cataloged",
                severity=Severity.INFO,
                cvss_score=0.0,
                cwe_id="CWE-1395",
                description=f"Syft successfully mapped all third-party dependencies, packages, and licenses across `{scan_path}` into a CycloneDX 1.5 standard inventory.",
                impact="Comprehensive SBOM visibility enables rapid zero-day dependency triage and NTIA minimum element compliance.",
                remediation="Incorporate automated SBOM generation into CI/CD build pipelines and monitor for upstream supply chain updates.",
                references=["https://github.com/anchore/syft", "https://cyclonedx.org/"],
                evidence=evidence,
                fingerprint=calculate_fingerprint("SCA-SBOM-001", scan_path, f"syft-{len(components)}"),
            )
            findings.append(finding)
            await emit_finding(finding)
            await emit_log(LogLevel.INFO, f"Syft cataloged {len(components)} software components into CycloneDX SBOM.")

        except Exception as e:
            self._record_execution(code, report_output, stderr, parser_error=True)
            await emit_log(LogLevel.WARNING, f"Syft SBOM processing error: {e}")

        self._record_execution(code, report_output, stderr, findings_count=len(findings))
        return findings
