"""
Contract 03, 06 & 08 Static Code Analysis, Secrets & SCA Engine Coordinator.
"""

from __future__ import annotations
from typing import List

from app.core.models import Target, Finding, ScanConfig, TargetType, LogLevel, NormalizedExecutionState
from app.core.path_sandbox import resolve_authorized_workspace, PathSandboxViolation
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
from app.adapters.trufflehog_adapter import TruffleHogAdapter
from app.adapters.retirejs_adapter import RetireJSAdapter
from app.adapters.syft_adapter import SyftAdapter
from app.adapters.grype_adapter import GrypeAdapter
from app.adapters.osv_scanner_adapter import OSVScannerAdapter


class CodeSastAssessmentEngine(BaseAssessmentEngine):
    """
    Coordinator engine for Static Application Security Testing (SAST), Verified Secret Scanning, and Software Supply Chain (SCA & SBOM).
    Follows Adapters First-in-Line Architecture (Gitleaks + TruffleHog + Bandit + Semgrep + RetireJS + Syft + Grype + OSV-Scanner + Trivy primary, native AST Taint & Entropy enrichment).
    """

    @property
    def name(self) -> str:
        return "code_sast"

    @property
    def display_name(self) -> str:
        return "Static Code Analysis, Secrets & Supply Chain"

    @property
    def description(self) -> str:
        return (
            "Analyzes local repositories and source directories for hardcoded credentials (AWS, GitHub, Stripe), "
            "verified live secrets (TruffleHog), weak cryptography (MD5, SHA-1, insecure PRNG, AES-ECB), "
            "injection flaws (SQLi, Command Injection, unsafe deserialization), vulnerable front-end JS (Retire.js), "
            "Software Bill of Materials generation (Syft CycloneDX/SPDX), Google OSV advisories, and package CVEs."
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
        **kwargs,
    ) -> List[Finding]:
        findings: List[Finding] = []
        existing_fps = set()
        tool_state_cb = kwargs.get("emit_tool_execution_state")
        try:
            workspace = resolve_authorized_workspace(
                target.value,
                allowed_roots=kwargs.get("workspace_roots"),
            )
        except PathSandboxViolation as exc:
            await emit_log(LogLevel.ERROR, f"Code SAST execution blocked by workspace policy: {exc}")
            if tool_state_cb:
                for tool_name in ("semgrep", "bandit", "gitleaks", "trufflehog", "retirejs"):
                    await tool_state_cb(tool_name, NormalizedExecutionState.EXECUTION_BLOCKED.value)
            return findings

        repo_path = str(workspace)
        scan_target = target.model_copy(update={"value": repo_path})
        record_sbom = kwargs.get("record_sbom_report")
        require_managed_binary = kwargs.get("require_managed_binary", True)

        async def report_tool_state(tool_name: str, adapter, finding_count: int = 0) -> None:
            if not tool_state_cb:
                return
            state = getattr(adapter, "last_execution_state", NormalizedExecutionState.TOOL_EXECUTION_FAILED)
            if finding_count and state == NormalizedExecutionState.COMPLETED_NO_FINDINGS:
                state = NormalizedExecutionState.COMPLETED_WITH_FINDINGS
            await tool_state_cb(tool_name, state.value)

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
                        scan_target,
                        config,
                        emit_log,
                        emit_finding,
                        scan_id="active",
                        require_managed_binary=require_managed_binary,
                    )
                    await report_tool_state("gitleaks", gitleaks_adapter, len(gitleaks_findings))
                    for f in gitleaks_findings:
                        if f.fingerprint not in existing_fps:
                            existing_fps.add(f.fingerprint)
                            f.source_tool = "gitleaks"
                            f.scan_id = "active"
                            findings.append(f)
                else:
                    if tool_state_cb:
                        await tool_state_cb("gitleaks", NormalizedExecutionState.TOOL_EXECUTION_FAILED.value)
                    await emit_log(LogLevel.INFO, "Gitleaks CLI not available - using native secret & git history scanner")
            except Exception as e:
                if tool_state_cb:
                    await tool_state_cb("gitleaks", NormalizedExecutionState.TOOL_EXECUTION_FAILED.value)
                await emit_log(LogLevel.WARNING, f"Gitleaks adapter error: {e}")

        # 0.2 TruffleHog Adapter (Verified Live Secret Scanner)
        if getattr(config.adapters, "enable_trufflehog", True):
            trufflehog_adapter = TruffleHogAdapter()
            custom_path = getattr(config.adapters, "trufflehog_path", None) or getattr(config.adapters, "custom_trufflehog_path", None)
            try:
                if await trufflehog_adapter.is_available(custom_path):
                    await emit_log(LogLevel.INFO, "Executing TruffleHog CLI adapter for verified secret detection...")
                    th_findings = await trufflehog_adapter.run(
                        scan_target,
                        config,
                        emit_log,
                        emit_finding,
                        scan_id="active",
                        require_managed_binary=require_managed_binary,
                        allow_live_verification=kwargs.get("allow_live_secret_verification", False),
                    )
                    await report_tool_state("trufflehog", trufflehog_adapter, len(th_findings))
                    for f in th_findings:
                        if f.fingerprint not in existing_fps:
                            existing_fps.add(f.fingerprint)
                            f.source_tool = "trufflehog"
                            f.scan_id = "active"
                            findings.append(f)
                else:
                    if tool_state_cb:
                        await tool_state_cb("syft", NormalizedExecutionState.TOOL_EXECUTION_FAILED.value)
                    await emit_log(LogLevel.INFO, "Syft CLI not available")
            except Exception as e:
                if tool_state_cb:
                    await tool_state_cb("trufflehog", NormalizedExecutionState.TOOL_EXECUTION_FAILED.value)
                await emit_log(LogLevel.WARNING, f"TruffleHog adapter error: {e}")

        # 0.3 Bandit Adapter (Python AST Security Linter)
        if getattr(config.adapters, "enable_bandit", True):
            bandit_adapter = BanditAdapter()
            custom_path = getattr(config.adapters, "bandit_path", None) or getattr(config.adapters, "custom_bandit_path", None)
            try:
                if await bandit_adapter.is_available(custom_path):
                    await emit_log(LogLevel.INFO, "Executing Bandit CLI adapter for Python AST security linting...")
                    bandit_findings = await bandit_adapter.run(
                        scan_target,
                        config,
                        emit_log,
                        emit_finding,
                        scan_id="active",
                        require_managed_binary=require_managed_binary,
                    )
                    await report_tool_state("bandit", bandit_adapter, len(bandit_findings))
                    for f in bandit_findings:
                        if f.fingerprint not in existing_fps:
                            existing_fps.add(f.fingerprint)
                            f.source_tool = "bandit"
                            f.scan_id = "active"
                            findings.append(f)
                else:
                    if tool_state_cb:
                        await tool_state_cb("bandit", NormalizedExecutionState.TOOL_EXECUTION_FAILED.value)
                    await emit_log(LogLevel.INFO, "Bandit CLI not available - using native AST crypto & injection linters")
            except Exception as e:
                if tool_state_cb:
                    await tool_state_cb("bandit", NormalizedExecutionState.TOOL_EXECUTION_FAILED.value)
                await emit_log(LogLevel.WARNING, f"Bandit adapter error: {e}")

        # 0.4 Semgrep Adapter (Multi-Language AST SAST)
        if getattr(config.adapters, "enable_semgrep", True):
            semgrep_adapter = SemgrepAdapter()
            custom_path = getattr(config.adapters, "semgrep_path", None) or getattr(config.adapters, "custom_semgrep_path", None)
            try:
                if await semgrep_adapter.is_available(custom_path):
                    await emit_log(LogLevel.INFO, "Executing Semgrep CLI adapter for multi-language AST SAST...")
                    semgrep_findings = await semgrep_adapter.run(
                        scan_target,
                        config,
                        emit_log,
                        emit_finding,
                        scan_id="active",
                        require_managed_binary=require_managed_binary,
                    )
                    await report_tool_state("semgrep", semgrep_adapter, len(semgrep_findings))
                    for f in semgrep_findings:
                        if f.fingerprint not in existing_fps:
                            existing_fps.add(f.fingerprint)
                            f.source_tool = "semgrep"
                            f.scan_id = "active"
                            findings.append(f)
                else:
                    if tool_state_cb:
                        await tool_state_cb("semgrep", NormalizedExecutionState.TOOL_EXECUTION_FAILED.value)
                    await emit_log(LogLevel.INFO, "Semgrep CLI not available - using native AST taint & injection linters")
            except Exception as e:
                if tool_state_cb:
                    await tool_state_cb("semgrep", NormalizedExecutionState.TOOL_EXECUTION_FAILED.value)
                await emit_log(LogLevel.WARNING, f"Semgrep adapter error: {e}")

        # 0.5 Retire.js Adapter (Client-Side JavaScript Vulnerabilities)
        if getattr(config.adapters, "enable_retirejs", True):
            retire_adapter = RetireJSAdapter()
            custom_path = getattr(config.adapters, "retirejs_path", None) or getattr(config.adapters, "custom_retirejs_path", None)
            try:
                if await retire_adapter.is_available(custom_path):
                    await emit_log(LogLevel.INFO, "Executing Retire.js adapter for client-side JS CVEs...")
                    retire_findings = await retire_adapter.run(
                        scan_target,
                        config,
                        emit_log,
                        emit_finding,
                        scan_id="active",
                        require_managed_binary=require_managed_binary,
                    )
                    await report_tool_state("retirejs", retire_adapter, len(retire_findings))
                    for f in retire_findings:
                        if f.fingerprint not in existing_fps:
                            existing_fps.add(f.fingerprint)
                            f.source_tool = "retirejs"
                            f.scan_id = "active"
                            findings.append(f)
                else:
                    if tool_state_cb:
                        await tool_state_cb("grype", NormalizedExecutionState.TOOL_EXECUTION_FAILED.value)
                    await emit_log(LogLevel.INFO, "Grype CLI not available")
            except Exception as e:
                if tool_state_cb:
                    await tool_state_cb("retirejs", NormalizedExecutionState.TOOL_EXECUTION_FAILED.value)
                await emit_log(LogLevel.WARNING, f"Retire.js adapter error: {e}")

        # 0.6 Syft Adapter (Software Bill of Materials Generation)
        if getattr(config.adapters, "enable_syft", True):
            syft_adapter = SyftAdapter()
            custom_path = getattr(config.adapters, "syft_path", None) or getattr(config.adapters, "custom_syft_path", None)
            try:
                if await syft_adapter.is_available(custom_path):
                    await emit_log(LogLevel.INFO, "Executing Syft SBOM generator...")
                    syft_findings = await syft_adapter.run(
                        scan_target,
                        config,
                        emit_log,
                        emit_finding,
                        scan_id="active",
                        record_sbom_report=record_sbom,
                        require_managed_binary=require_managed_binary,
                    )
                    await report_tool_state("syft", syft_adapter, len(syft_findings))
                    for f in syft_findings:
                        if f.fingerprint not in existing_fps:
                            existing_fps.add(f.fingerprint)
                            f.source_tool = "syft"
                            f.scan_id = "active"
                            findings.append(f)
                else:
                    if tool_state_cb:
                        await tool_state_cb("osv_scanner", NormalizedExecutionState.TOOL_EXECUTION_FAILED.value)
                    await emit_log(LogLevel.INFO, "OSV-Scanner CLI not available")
            except Exception as e:
                if tool_state_cb:
                    await tool_state_cb("syft", NormalizedExecutionState.TOOL_EXECUTION_FAILED.value)
                await emit_log(LogLevel.WARNING, f"Syft adapter error: {e}")

        # 0.7 Grype Adapter (SBOM & Filesystem Vulnerability Matcher)
        if getattr(config.adapters, "enable_grype", True):
            grype_adapter = GrypeAdapter()
            custom_path = getattr(config.adapters, "grype_path", None) or getattr(config.adapters, "custom_grype_path", None)
            try:
                if await grype_adapter.is_available(custom_path):
                    await emit_log(LogLevel.INFO, "Executing Grype supply chain vulnerability matcher...")
                    grype_findings = await grype_adapter.run(
                        scan_target,
                        config,
                        emit_log,
                        emit_finding,
                        scan_id="active",
                        require_managed_binary=require_managed_binary,
                    )
                    await report_tool_state("grype", grype_adapter, len(grype_findings))
                    for f in grype_findings:
                        if f.fingerprint not in existing_fps:
                            existing_fps.add(f.fingerprint)
                            f.source_tool = "grype"
                            f.scan_id = "active"
                            findings.append(f)
            except Exception as e:
                if tool_state_cb:
                    await tool_state_cb("grype", NormalizedExecutionState.TOOL_EXECUTION_FAILED.value)
                await emit_log(LogLevel.WARNING, f"Grype adapter error: {e}")

        # 0.8 OSV-Scanner Adapter (Google OSV Database)
        if getattr(config.adapters, "enable_osv_scanner", True):
            osv_adapter = OSVScannerAdapter()
            custom_path = getattr(config.adapters, "osv_scanner_path", None) or getattr(config.adapters, "custom_osv_scanner_path", None)
            try:
                if await osv_adapter.is_available(custom_path):
                    await emit_log(LogLevel.INFO, "Executing Google OSV-Scanner dependency audit...")
                    osv_findings = await osv_adapter.run(
                        scan_target,
                        config,
                        emit_log,
                        emit_finding,
                        scan_id="active",
                        require_managed_binary=require_managed_binary,
                    )
                    await report_tool_state("osv_scanner", osv_adapter, len(osv_findings))
                    for f in osv_findings:
                        if f.fingerprint not in existing_fps:
                            existing_fps.add(f.fingerprint)
                            f.source_tool = "osv_scanner"
                            f.scan_id = "active"
                            findings.append(f)
            except Exception as e:
                if tool_state_cb:
                    await tool_state_cb("osv_scanner", NormalizedExecutionState.TOOL_EXECUTION_FAILED.value)
                await emit_log(LogLevel.WARNING, f"OSV-Scanner adapter error: {e}")

        # 0.9 Trivy Adapter (SCA Dependency Vulnerabilities)
        if getattr(config.adapters, "enable_trivy", True):
            trivy_adapter = TrivyAdapter()
            custom_path = getattr(config.adapters, "trivy_path", None) or getattr(config.adapters, "custom_trivy_path", None)
            try:
                if await trivy_adapter.is_available(custom_path):
                    await emit_log(LogLevel.INFO, "Executing Trivy CLI adapter for filesystem SCA vulnerability auditing...")
                    trivy_findings = await trivy_adapter.run(
                        scan_target,
                        config,
                        emit_log,
                        emit_finding,
                        scan_id="active",
                        require_managed_binary=require_managed_binary,
                    )
                    await report_tool_state("trivy", trivy_adapter, len(trivy_findings))
                    for f in trivy_findings:
                        if f.fingerprint not in existing_fps:
                            existing_fps.add(f.fingerprint)
                            f.source_tool = "trivy"
                            f.scan_id = "active"
                            findings.append(f)
                else:
                    if tool_state_cb:
                        await tool_state_cb("trivy", NormalizedExecutionState.TOOL_EXECUTION_FAILED.value)
                    await emit_log(LogLevel.INFO, "Trivy CLI not available - using native dependency SCA manifest auditor")
            except Exception as e:
                if tool_state_cb:
                    await tool_state_cb("trivy", NormalizedExecutionState.TOOL_EXECUTION_FAILED.value)
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

        # Stamp the authoritative tenant/workspace provenance after all
        # adapters and native fallbacks have normalized their findings.
        for finding in findings:
            finding.organization_id = kwargs.get("organization_id") or "org-default"
            finding.workspace_id = kwargs.get("workspace_id") or str(workspace)

        await emit_progress(100, "Static code assessment completed.")
        await emit_log(LogLevel.INFO, f"Code SAST engine finished with {len(findings)} total findings.")

        return findings
