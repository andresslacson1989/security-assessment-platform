"""
Contract 03, 06 & 08 Web Application, Browser & API DAST Engine Coordinator.
"""

from __future__ import annotations
from typing import List
import httpx

from app.core.models import Target, Finding, ScanConfig, TargetType, LogLevel
from app.core.rate_limiter import TokenBucketRateLimiter
from app.engines.base import BaseAssessmentEngine, LogCallback, ProgressCallback, FindingCallback
from app.engines.web_dast.headers_cookies import audit_security_headers_and_cookies
from app.engines.web_dast.cors_analyzer import audit_cors_policies
from app.engines.web_dast.api_inspector import audit_sensitive_exposure_and_methods
from app.engines.web_dast.browser_posture import audit_browser_posture
from app.engines.web_dast.graphql_auditor import audit_graphql_endpoints


class WebDastAssessmentEngine(BaseAssessmentEngine):
    """
    Coordinator engine for Web Application, REST API, and Modern Browser DAST assessments.
    """

    @property
    def name(self) -> str:
        return "web_dast"

    @property
    def display_name(self) -> str:
        return "Web Application & REST API DAST"

    @property
    def description(self) -> str:
        return (
            "Evaluates OWASP Top 10 security response headers (CSP, HSTS, X-Frame), cookie security flags "
            "(HttpOnly, Secure, SameSite), Cross-Origin Resource Sharing (CORS) misconfigurations, "
            "exposed environment/git files (.env, .git/HEAD), OpenAPI schemas, Subresource Integrity, "
            "and public GraphQL introspection."
        )

    def is_applicable(self, target: Target) -> bool:
        """
        Applicable to web URLs and domain names.
        """
        return target.type in (TargetType.URL, TargetType.DOMAIN)

    async def run(
        self,
        target: Target,
        config: ScanConfig,
        emit_log: LogCallback,
        emit_progress: ProgressCallback,
        emit_finding: FindingCallback,
    ) -> List[Finding]:
        findings: List[Finding] = []
        rate_limiter = TokenBucketRateLimiter(rate_rps=config.rate_limit_rps)

        headers = {
            "User-Agent": config.custom_headers.get(
                "User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) CyberAssess-Security-Scanner/3.0"
            )
        }
        headers.update(config.custom_headers)

        timeout = httpx.Timeout(
            timeout=float(min(10.0, config.timeout_seconds)),
            connect=5.0,
        )

        async with httpx.AsyncClient(headers=headers, timeout=timeout, verify=False) as client:
            # --- Stage 1: Security Headers & Cookie Flags (0% - 30%) ---
            await emit_progress(10, "Auditing OWASP security headers, cookies, and cache control...")
            await emit_log(LogLevel.INFO, "Analyzing HTTP response security headers and Set-Cookie directives.")
            await rate_limiter.acquire()

            header_findings = await audit_security_headers_and_cookies(
                target.value,
                client=client,
                emit_log=emit_log,
            )
            for f in header_findings:
                f.scan_id = "active"
                findings.append(f)
                await emit_finding(f)

            # --- Stage 2: CORS Policies (30% - 50%) ---
            await emit_progress(35, "Testing CORS policies and origin reflection...")
            await rate_limiter.acquire()

            cors_findings = await audit_cors_policies(
                target.value,
                client=client,
                emit_log=emit_log,
            )
            for f in cors_findings:
                f.scan_id = "active"
                findings.append(f)
                await emit_finding(f)

            # --- Stage 3: Sensitive File & API Exposure (50% - 75%) ---
            await emit_progress(55, "Scanning for exposed environment, git, and actuator endpoints...")
            await rate_limiter.acquire()

            exp_findings = await audit_sensitive_exposure_and_methods(
                target.value,
                client=client,
                emit_log=emit_log,
            )
            for f in exp_findings:
                f.scan_id = "active"
                findings.append(f)
                await emit_finding(f)

            # --- Stage 4: Browser Posture & GraphQL (75% - 100%) ---
            await emit_progress(80, "Auditing Subresource Integrity, Mixed Content, and GraphQL schemas...")
            await rate_limiter.acquire()

            browser_findings = await audit_browser_posture(
                target.value,
                client=client,
                emit_log=emit_log,
            )
            for f in browser_findings:
                f.scan_id = "active"
                findings.append(f)
                await emit_finding(f)

            gql_findings = await audit_graphql_endpoints(
                target.value,
                client=client,
                emit_log=emit_log,
            )
            for f in gql_findings:
                f.scan_id = "active"
                findings.append(f)
                await emit_finding(f)

        await emit_progress(100, "Web DAST assessment completed.")
        await emit_log(LogLevel.INFO, f"Web DAST engine finished with {len(findings)} total findings.")

        return findings
