"""
Contract 03, 06 & 08 Static Code Analysis, Secrets & SCA Engine Coordinator.
"""

from __future__ import annotations
from typing import List

from app.core.models import Target, Finding, ScanConfig, TargetType, LogLevel
from app.engines.base import BaseAssessmentEngine, LogCallback, ProgressCallback, FindingCallback
from app.engines.code_sast.secret_scanner import audit_code_secrets
from app.engines.code_sast.crypto_lint import audit_crypto_patterns
from app.engines.code_sast.injection_lint import audit_injection_patterns
from app.engines.code_sast.dependency_auditor import audit_dependencies
from app.adapters.semgrep_adapter import SemgrepAdapter
from app.adapters.trivy_adapter import TrivyAdapter


class CodeSastAssessmentEngine(BaseAssessmentEngine):
    """
    Coordinator engine for Static Application Security Testing (SAST), Secret Scanning, and SCA.
    """

    @property
    def name(self) -> str:
        return "code_sast"

    @property
    def display_name(self) -> str:
        return "Static Code Analysis, Secrets & Dependency SCA"

    @property
    def description(self) -> str:
        return (
            "Analyzes local repositories and source directories for hardcoded credentials (AWS, GitHub, Stripe), "
            "weak cryptography (MD5, SHA-1, insecure PRNG, AES-ECB), injection flaws (SQLi, Command Injection, "
            "unsafe deserialization), and outdated dependencies with known CVEs."
        )

    def is_applicable(self, target: Target) -> bool:
        """
        Applicable to local file and directory paths.
        """
        return target.type == TargetType.LOCAL_PATH

    async def run(
        self,
        target: Target,
        config: ScanConfig,
        emit_log: LogCallback,
        emit_progress: ProgressCallback,
        emit_finding: FindingCallback,
    ) -> List[Finding]:
        findings: List[Finding] = []
        repo_path = target.value

        # --- Stage 1: Secret & Credential Scanning (0% - 40%) ---
        await emit_progress(10, "Scanning repository for high-entropy secrets and hardcoded API tokens...")
        await emit_log(LogLevel.INFO, f"Initiating secret and credential pattern audit in '{repo_path}'.")

        secret_findings = await audit_code_secrets(repo_path, emit_log=emit_log)
        for f in secret_findings:
            f.scan_id = "active"
            findings.append(f)
            await emit_finding(f)

        # --- Stage 2: Insecure Cryptography & AST Injection Linting (40% - 75%) ---
        await emit_progress(45, "Linting source code for weak crypto, insecure PRNG, and injection flaws...")
        await emit_log(LogLevel.INFO, "Analyzing cryptographic primitives and dangerous shell/deserialization calls.")

        crypto_findings = await audit_crypto_patterns(repo_path, emit_log=emit_log)
        for f in crypto_findings:
            f.scan_id = "active"
            findings.append(f)
            await emit_finding(f)

        inj_findings = await audit_injection_patterns(repo_path, emit_log=emit_log)
        for f in inj_findings:
            f.scan_id = "active"
            findings.append(f)
            await emit_finding(f)

        # --- Stage 3: Dependency Software Composition Analysis (75% - 100%) ---
        await emit_progress(80, "Auditing dependency manifests (requirements.txt, package.json) for CVEs...")
        await emit_log(LogLevel.INFO, "Parsing dependency manifests for unpinned packages and known vulnerabilities.")

        dep_findings = await audit_dependencies(repo_path, emit_log=emit_log)
        for f in dep_findings:
            f.scan_id = "active"
            findings.append(f)
            await emit_finding(f)

        # --- Stage 4: Semgrep Adapter (AST Rule-Based SAST) ---
        enable_semgrep = getattr(config.adapters, "enable_semgrep", True)
        if enable_semgrep:
            semgrep_adapter = SemgrepAdapter()
            custom_path = getattr(config.adapters, "semgrep_path", None)
            try:
                if await semgrep_adapter.is_available(custom_path):
                    await emit_progress(87, "Running Semgrep AST rule-based static analysis...")
                    await emit_log(LogLevel.INFO, "Executing Semgrep adapter for deep AST-based taint and injection analysis...")
                    existing_fps = {f.fingerprint for f in findings}
                    semgrep_findings = await semgrep_adapter.run(
                        target,
                        config,
                        emit_log,
                        emit_finding,
                        scan_id="active",
                    )
                    for f in semgrep_findings:
                        if f.fingerprint not in existing_fps:
                            existing_fps.add(f.fingerprint)
                            f.source_tool = "semgrep"
                            f.scan_id = "active"
                            findings.append(f)
                else:
                    await emit_log(LogLevel.INFO, "Semgrep CLI not available - native AST taint and secret scanner results used as fallback")
            except Exception as e:
                await emit_log(LogLevel.WARNING, f"Semgrep adapter error: {e} - continuing with native SAST results")
        else:
            await emit_log(LogLevel.INFO, "Semgrep adapter disabled - native SAST checks used as fallback")

        # --- Stage 5: Trivy Adapter (Deep SCA & Container CVE Scanning) ---
        enable_trivy = getattr(config.adapters, "enable_trivy", True)
        if enable_trivy:
            trivy_adapter = TrivyAdapter()
            custom_path = getattr(config.adapters, "trivy_path", None)
            try:
                if await trivy_adapter.is_available(custom_path):
                    await emit_progress(93, "Running Trivy deep SCA and CVE analysis...")
                    await emit_log(LogLevel.INFO, "Executing Trivy adapter for deep dependency CVE and container posture analysis...")
                    existing_fps = {f.fingerprint for f in findings}
                    trivy_findings = await trivy_adapter.run(
                        target,
                        config,
                        emit_log,
                        emit_finding,
                        scan_id="active",
                    )
                    for f in trivy_findings:
                        if f.fingerprint not in existing_fps:
                            existing_fps.add(f.fingerprint)
                            f.source_tool = "trivy"
                            f.scan_id = "active"
                            findings.append(f)
                else:
                    await emit_log(LogLevel.INFO, "Trivy CLI not available - native dependency auditor results used as fallback")
            except Exception as e:
                await emit_log(LogLevel.WARNING, f"Trivy adapter error: {e} - continuing with native SCA results")
        else:
            await emit_log(LogLevel.INFO, "Trivy adapter disabled - native SCA checks used as fallback")

        await emit_progress(100, "Code SAST and SCA assessment completed.")
        await emit_log(LogLevel.INFO, f"Code SAST engine completed with {len(findings)} total findings.")

        return findings
