"""
Contract 03, 06 & 08 Static Code Analysis, Secrets & SCA Engine Coordinator.
"""

from __future__ import annotations
from typing import List

from app.core.models import Target, Finding, ScanConfig, TargetType, LogLevel
from app.engines.base import BaseAssessmentEngine, LogCallback, ProgressCallback, FindingCallback
from app.engines.code_sast.secret_scanner import audit_code_secrets
from app.engines.code_sast.git_history_scanner import audit_git_commit_history
from app.engines.code_sast.crypto_lint import audit_crypto_patterns
from app.engines.code_sast.injection_lint import audit_injection_patterns
from app.engines.code_sast.ast_taint_analyzer import audit_ast_taint_flow
from app.engines.code_sast.dependency_auditor import audit_dependencies
from app.adapters.semgrep_adapter import SemgrepAdapter
from app.adapters.gitleaks_adapter import GitleaksAdapter
from app.adapters.bandit_adapter import BanditAdapter
from app.adapters.trivy_adapter import TrivyAdapter


class CodeSastAssessmentEngine(BaseAssessmentEngine):
    """
    Coordinator engine for Static Application Security Testing (SAST), Secret Scanning, and SCA.
    Follows Adapters First-in-Line Architecture (Gitleaks + Bandit + Semgrep + Trivy primary, native AST Taint & Entropy enrichment).
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
        existing_fps = set()
        repo_path = target.value

        # --- Stage 0: Primary External Tool Adapters First-in-Line ---
        await emit_progress(5, "Running primary external SAST & Secret tool adapters...")

        # 0.1 Gitleaks Adapter (Dedicated Git History Secret Scanner)
        if getattr(config.adapters, "enable_gitleaks", True):
            gitleaks_adapter = GitleaksAdapter()
            custom_path = getattr(config.adapters, "gitleaks_path", None) or getattr(config.adapters, "custom_gitleaks_path", None)
            try:
                if await gitleaks_adapter.is_available(custom_path):
                    await emit_log(LogLevel.INFO, "Executing Gitleaks CLI adapter for git secret detection...")
                    gitleaks_findings = await gitleaks_adapter.run(
                        target,
                        config,
                        emit_log,
                        emit_finding,
                        scan_id="active",
                    )
                    for f in gitleaks_findings:
                        if f.fingerprint not in existing_fps:
                            existing_fps.add(f.fingerprint)
                            f.source_tool = "gitleaks"
                            f.scan_id = "active"
                            findings.append(f)
                else:
                    await emit_log(LogLevel.INFO, "Gitleaks CLI not available - using native secret & git history scanner")
            except Exception as e:
                await emit_log(LogLevel.WARNING, f"Gitleaks adapter error: {e}")

        # 0.2 Bandit Adapter (Python AST Security Linter)
        if getattr(config.adapters, "enable_bandit", True):
            bandit_adapter = BanditAdapter()
            custom_path = getattr(config.adapters, "bandit_path", None) or getattr(config.adapters, "custom_bandit_path", None)
            try:
                if await bandit_adapter.is_available(custom_path):
                    await emit_log(LogLevel.INFO, "Executing Bandit CLI adapter for Python AST security linting...")
                    bandit_findings = await bandit_adapter.run(
                        target,
                        config,
                        emit_log,
                        emit_finding,
                        scan_id="active",
                    )
                    for f in bandit_findings:
                        if f.fingerprint not in existing_fps:
                            existing_fps.add(f.fingerprint)
                            f.source_tool = "bandit"
                            f.scan_id = "active"
                            findings.append(f)
                else:
                    await emit_log(LogLevel.INFO, "Bandit CLI not available - using native AST crypto & injection linters")
            except Exception as e:
                await emit_log(LogLevel.WARNING, f"Bandit adapter error: {e}")

        # 0.3 Semgrep Adapter (Multi-Language AST SAST)
        if getattr(config.adapters, "enable_semgrep", True):
            semgrep_adapter = SemgrepAdapter()
            custom_path = getattr(config.adapters, "semgrep_path", None) or getattr(config.adapters, "custom_semgrep_path", None)
            try:
                if await semgrep_adapter.is_available(custom_path):
                    await emit_log(LogLevel.INFO, "Executing Semgrep CLI adapter for multi-language AST SAST...")
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
                    await emit_log(LogLevel.INFO, "Semgrep CLI not available - using native AST taint & injection linters")
            except Exception as e:
                await emit_log(LogLevel.WARNING, f"Semgrep adapter error: {e}")

        # 0.4 Trivy Adapter (SCA Dependency Vulnerabilities)
        if getattr(config.adapters, "enable_trivy", True):
            trivy_adapter = TrivyAdapter()
            custom_path = getattr(config.adapters, "trivy_path", None) or getattr(config.adapters, "custom_trivy_path", None)
            try:
                if await trivy_adapter.is_available(custom_path):
                    await emit_log(LogLevel.INFO, "Executing Trivy CLI adapter for filesystem SCA vulnerability auditing...")
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
                    await emit_log(LogLevel.INFO, "Trivy CLI not available - using native dependency SCA manifest auditor")
            except Exception as e:
                await emit_log(LogLevel.WARNING, f"Trivy adapter error: {e}")

        # --- Stage 1: Native Secret & Credential Scanning (Entropy + Regex) ---
        await emit_progress(35, "Scanning repository for high-entropy secrets and hardcoded API tokens...")
        secret_findings = await audit_code_secrets(repo_path, emit_log=emit_log)
        for f in secret_findings:
            if f.fingerprint not in existing_fps:
                existing_fps.add(f.fingerprint)
                f.scan_id = "active"
                findings.append(f)
                await emit_finding(f)

        # Historical Git Commit Secret Scanning (SAST-GIT-001)
        git_findings = await audit_git_commit_history(repo_path)
        for f in git_findings:
            if f.fingerprint not in existing_fps:
                existing_fps.add(f.fingerprint)
                f.scan_id = "active"
                findings.append(f)
                await emit_finding(f)

        # --- Stage 2: Insecure Cryptography & AST Injection Linting ---
        await emit_progress(55, "Linting source code for weak crypto, insecure PRNG, and injection flaws...")
        crypto_findings = await audit_crypto_patterns(repo_path, emit_log=emit_log)
        for f in crypto_findings:
            if f.fingerprint not in existing_fps:
                existing_fps.add(f.fingerprint)
                f.scan_id = "active"
                findings.append(f)
                await emit_finding(f)

        inj_findings = await audit_injection_patterns(repo_path, emit_log=emit_log)
        for f in inj_findings:
            if f.fingerprint not in existing_fps:
                existing_fps.add(f.fingerprint)
                f.scan_id = "active"
                findings.append(f)
                await emit_finding(f)

        # Interprocedural AST Taint Flow Analysis (SAST-TAINT-001, SAST-TAINT-002)
        taint_findings = audit_ast_taint_flow(repo_path)
        for f in taint_findings:
            if f.fingerprint not in existing_fps:
                existing_fps.add(f.fingerprint)
                f.scan_id = "active"
                findings.append(f)
                await emit_finding(f)

        # --- Stage 3: Native Dependency SCA Fallback ---
        await emit_progress(80, "Auditing dependency manifests (requirements.txt, package.json) for CVEs...")
        dep_findings = await audit_dependencies(repo_path, emit_log=emit_log)
        for f in dep_findings:
            if f.fingerprint not in existing_fps:
                existing_fps.add(f.fingerprint)
                f.scan_id = "active"
                findings.append(f)
                await emit_finding(f)

        await emit_progress(100, "Static code assessment completed.")
        await emit_log(LogLevel.INFO, f"Code SAST engine finished with {len(findings)} total findings.")

        return findings
