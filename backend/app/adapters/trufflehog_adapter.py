"""
TruffleHog Tool Adapter for High-Entropy Secret Detection & Live Credential Verification.
Authoritative Reference: contracts/03_ENGINE_PLUGIN_INTERFACE_CONTRACT.md (Section 4.2)
"""

from __future__ import annotations
import json
import os
import re
from typing import Optional, List, Callable, Awaitable, Dict, Any

from app.core.models import (
    Target, Finding, Evidence, ScanConfig, LogLevel, Severity,
    calculate_fingerprint, mask_secret, VerifiedSecretEvidence
)
from app.adapters.base_adapter import BaseToolAdapter


class TruffleHogAdapter(BaseToolAdapter):
    """
    Adapter for TruffleHog deep secret scanner with live verification probes.
    """

    @property
    def tool_name(self) -> str:
        return "trufflehog"

    async def get_version(self, custom_path: Optional[str] = None) -> Optional[str]:
        binary = self.resolve_binary_path(custom_path)
        if not binary:
            return None
        code, stdout, stderr = await self.execute_command([binary, "--version"], timeout=10.0)
        output = stdout + " " + stderr
        match = re.search(r"\d+\.\d+\.\d+", output)
        if match:
            return f"trufflehog {match.group(0)}"
        return "trufflehog" if code == 0 else None

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

        binary = self.resolve_binary_path(config.adapters.trufflehog_path or config.adapters.custom_trufflehog_path)
        if not binary:
            await emit_log(LogLevel.WARNING, "TruffleHog binary not found. Skipping verified secret audit.")
            return findings

        scan_path = target.value
        if not os.path.exists(scan_path):
            await emit_log(LogLevel.WARNING, f"Target directory not accessible: {scan_path}")
            return findings

        await emit_log(LogLevel.INFO, f"Executing TruffleHog secret scan with live verification on: {scan_path}")
        cmd = [binary, "filesystem", scan_path, "--json"]

        code, stdout, stderr = await self.execute_command(cmd, timeout=60.0, emit_log=emit_log)

        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                detector_name = data.get("DetectorName", "Generic Secret")
                verified = bool(data.get("Verified", False))
                raw_secret = data.get("Raw", "")
                masked = mask_secret(raw_secret) if raw_secret else "********"
                file_path = "Unknown"

                # Extract file path
                src_meta = data.get("SourceMetadata", {}).get("Data", {})
                if "Filesystem" in src_meta:
                    file_path = src_meta["Filesystem"].get("file", "Unknown")
                elif "Git" in src_meta:
                    file_path = src_meta["Git"].get("file", "Git Repository")

                line_num = data.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("line", 1)
                location = f"{file_path}:{line_num}" if line_num else file_path

                check_id = "SEC-VERIFIED-001" if verified else "SAST-SEC-001"
                title = f"Verified Live Secret Leaked: {detector_name}" if verified else f"Hardcoded Secret Detected: {detector_name}"
                severity = Severity.CRITICAL if verified else Severity.HIGH
                cvss_score = 10.0 if verified else 8.5

                verified_evidence = None
                if verified:
                    verified_evidence = VerifiedSecretEvidence(
                        secret_type=detector_name,
                        is_live=True,
                        permissions_summary="Active credential confirmed via non-destructive API probe",
                    )

                evidence = Evidence(
                    location=location,
                    observed_value=f"{detector_name} Token [{masked}] (Verified Live: {verified})",
                    expected_value="Zero credentials committed to source code or configuration files",
                    raw_response_snippet=f"Detector: {detector_name}\nVerified: {verified}\nSecret: {masked}",
                )

                finding = Finding(
                    scan_id=scan_id,
                    engine="code_sast",
                    source_tool="trufflehog",
                    check_id=check_id,
                    category="Verified Credentials" if verified else "Hardcoded Secrets",
                    title=title,
                    severity=severity,
                    cvss_score=cvss_score,
                    cwe_id="CWE-798",
                    description=f"TruffleHog detected a {detector_name} secret in `{location}`. Live verification status: {'ACTIVE/VERIFIED' if verified else 'Unverified/Potential'}.",
                    impact="Compromised credentials allow attackers unauthorized access to cloud infrastructure, databases, or third-party APIs.",
                    remediation="Immediately revoke and rotate the exposed credential. Remove all occurrences from git history and employ a secrets manager.",
                    references=["https://trufflesecurity.com/trufflehog"],
                    evidence=evidence,
                    verified_secret=verified_evidence,
                    fingerprint=calculate_fingerprint(check_id, location, detector_name),
                )
                findings.append(finding)
                await emit_finding(finding)
            except Exception:
                continue

        await emit_log(LogLevel.INFO, f"TruffleHog completed scan: {len(findings)} secrets identified.")
        return findings
