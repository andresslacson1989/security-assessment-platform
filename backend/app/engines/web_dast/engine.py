"""
Contract 03, 06 & 08 Web Application, Browser & API DAST Engine Coordinator (v3.1.0).
Integrates scoped BFS web crawling, session authentication, and comprehensive vulnerability checks.
"""

from __future__ import annotations
from typing import List, Optional, Dict
import httpx

from app.core.models import (
    Target,
    Finding,
    ScanConfig,
    TargetType,
    LogLevel,
    DiscoveredEndpoint,
)
from app.core.rate_limiter import TokenBucketRateLimiter
from app.engines.base import (
    BaseAssessmentEngine,
    LogCallback,
    ProgressCallback,
    FindingCallback,
    AuthStatusCallback,
    EndpointDiscoveredCallback,
)
from app.engines.web_dast.crawler import WebCrawler
from app.engines.web_dast.auth_session import AuthSessionManager
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
            "public GraphQL introspection, authenticated session security, and anti-CSRF form posture."
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
        emit_auth_status: Optional[AuthStatusCallback] = None,
        emit_endpoint_discovered: Optional[EndpointDiscoveredCallback] = None,
        **kwargs,
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
            # --- Stage 1: Authentication & Session Initialization (0% - 15%) ---
            await emit_progress(5, "Initializing authentication and session manager...")
            auth_manager = AuthSessionManager(
                target_url=target.value,
                config=config.auth,
                client=client,
                scan_id="active",
                emit_log=emit_log,
            )
            auth_success = await auth_manager.authenticate()

            if emit_auth_status:
                await emit_auth_status({
                    "auth_type": config.auth.auth_type.value,
                    "authenticated": auth_success,
                    "session_active": auth_manager.is_authenticated,
                    "message": "Authenticated session established." if auth_success else "Authentication failed or not configured.",
                })

            # --- Stage 2: Web Crawling & Attack Surface Discovery (15% - 35%) ---
            await emit_progress(15, "Discovering attack surface and crawling endpoints...")
            discovered_endpoints: List[DiscoveredEndpoint] = []
            html_contents: Dict[str, str] = {}

            if config.crawler.enabled:
                async def _on_ep_discovered(ep: DiscoveredEndpoint) -> None:
                    discovered_endpoints.append(ep)
                    if emit_endpoint_discovered:
                        await emit_endpoint_discovered(ep)

                crawler = WebCrawler(
                    target_url=target.value,
                    config=config.crawler,
                    client=client,
                    rate_limiter=rate_limiter,
                    emit_log=emit_log,
                    on_endpoint_discovered=_on_ep_discovered,
                    is_authenticated=auth_manager.is_authenticated,
                )
                discovered_endpoints = await crawler.crawl()
            else:
                initial_ep = DiscoveredEndpoint(
                    url=target.value,
                    method="GET",
                    depth=0,
                    is_authenticated=auth_manager.is_authenticated,
                )
                discovered_endpoints = [initial_ep]
                if emit_endpoint_discovered:
                    await emit_endpoint_discovered(initial_ep)

            # --- Stage 3: Security Headers, Cookies & Form Audits (35% - 55%) ---
            await emit_progress(35, "Auditing OWASP security headers, cookies, and forms...")
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

            # Fetch HTML for root and top discovered endpoints for form analysis
            try:
                root_resp = await client.get(target.value, follow_redirects=True)
                if "text/html" in root_resp.headers.get("content-type", "").lower():
                    html_contents[target.value] = root_resp.text
            except Exception:
                pass

            auth_form_findings = await auth_manager.audit_auth_and_forms(
                discovered_endpoints=discovered_endpoints,
                html_contents=html_contents,
            )
            for f in auth_form_findings:
                f.scan_id = "active"
                findings.append(f)
                await emit_finding(f)

            # --- Stage 4: CORS Policies (55% - 70%) ---
            await emit_progress(55, "Testing CORS policies and origin reflection...")
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

            # --- Stage 5: Sensitive File & API Exposure (70% - 85%) ---
            await emit_progress(70, "Scanning for exposed environment, git, and actuator endpoints...")
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

            # --- Stage 6: Browser Posture & GraphQL (85% - 100%) ---
            await emit_progress(85, "Auditing Subresource Integrity, Mixed Content, and GraphQL schemas...")
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
