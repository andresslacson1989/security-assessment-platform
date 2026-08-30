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
from app.engines.web_dast.parameter_fuzzer import audit_parameter_fuzzing
from app.adapters.nuclei_adapter import NucleiAdapter
from app.adapters.ffuf_adapter import FfufAdapter
from app.adapters.nikto_adapter import NiktoAdapter
from app.adapters.katana_adapter import KatanaAdapter
from app.adapters.schemathesis_adapter import SchemathesisAdapter


class WebDastAssessmentEngine(BaseAssessmentEngine):
    """
    Coordinator engine for Web Application, REST API, SPA, and Modern Browser DAST assessments.
    Follows Adapters First-in-Line Architecture (Nuclei + FFuF + Nikto + Katana + Schemathesis primary, native active parameter fuzzing, crawler, and browser posture enrichment).
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
            "public GraphQL introspection, authenticated session security, dynamic SPA crawling (Katana), "
            "property-based API fuzzing (Schemathesis), and anti-CSRF form posture."
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
        existing_fps = set()
        rate_limiter = TokenBucketRateLimiter(rate_rps=config.rate_limit_rps)

        headers = {
            "User-Agent": config.custom_headers.get(
                "User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) CyberAssess-Security-Scanner/5.0"
            )
        }
        headers.update(config.custom_headers)

        timeout = httpx.Timeout(
            timeout=float(min(10.0, config.timeout_seconds)),
            connect=5.0,
        )

        # --- Stage 0: Primary Tool Adapters First-in-Line (FFuF, Nikto, Nuclei, Katana, Schemathesis) ---
        await emit_progress(5, "Running primary external DAST tool adapters...")

        # 0.1 FFuF Adapter (High-Speed Content Discovery)
        if getattr(config.adapters, "enable_ffuf", True):
            ffuf_adapter = FfufAdapter()
            custom_path = getattr(config.adapters, "ffuf_path", None) or getattr(config.adapters, "custom_ffuf_path", None)
            try:
                if await ffuf_adapter.is_available(custom_path):
                    await emit_log(LogLevel.INFO, "Executing FFuF CLI adapter for endpoint and content discovery...")
                    ffuf_findings = await ffuf_adapter.run(
                        target,
                        config,
                        emit_log,
                        emit_finding,
                        emit_endpoint=emit_endpoint_discovered,
                        scan_id="active",
                    )
                    for f in ffuf_findings:
                        if f.fingerprint not in existing_fps:
                            existing_fps.add(f.fingerprint)
                            f.source_tool = "ffuf"
                            f.scan_id = "active"
                            findings.append(f)
                else:
                    await emit_log(LogLevel.INFO, "FFuF CLI not available - using native crawler and API inspector")
            except Exception as e:
                await emit_log(LogLevel.WARNING, f"FFuF adapter error: {e}")

        # 0.2 Nikto Adapter (Web Server Misconfigurations)
        if getattr(config.adapters, "enable_nikto", True):
            nikto_adapter = NiktoAdapter()
            custom_path = getattr(config.adapters, "nikto_path", None) or getattr(config.adapters, "custom_nikto_path", None)
            try:
                if await nikto_adapter.is_available(custom_path):
                    await emit_log(LogLevel.INFO, "Executing Nikto CLI adapter for server misconfiguration scanning...")
                    nikto_findings = await nikto_adapter.run(
                        target,
                        config,
                        emit_log,
                        emit_finding,
                        scan_id="active",
                    )
                    for f in nikto_findings:
                        if f.fingerprint not in existing_fps:
                            existing_fps.add(f.fingerprint)
                            f.source_tool = "nikto"
                            f.scan_id = "active"
                            findings.append(f)
                else:
                    await emit_log(LogLevel.INFO, "Nikto CLI not available - using native headers & methods auditors")
            except Exception as e:
                await emit_log(LogLevel.WARNING, f"Nikto adapter error: {e}")

        # 0.3 Nuclei Adapter (Community CVE and Template Scanning)
        if getattr(config.adapters, "enable_nuclei", True):
            nuclei_adapter = NucleiAdapter()
            custom_path = getattr(config.adapters, "nuclei_path", None) or getattr(config.adapters, "custom_nuclei_path", None)
            try:
                if await nuclei_adapter.is_available(custom_path):
                    await emit_log(LogLevel.INFO, "Executing Nuclei CVE/misconfiguration template scanner...")
                    nuclei_findings = await nuclei_adapter.run(
                        target,
                        config,
                        emit_log,
                        emit_finding,
                        scan_id="active",
                    )
                    for f in nuclei_findings:
                        if f.fingerprint not in existing_fps:
                            existing_fps.add(f.fingerprint)
                            f.source_tool = "nuclei"
                            f.scan_id = "active"
                            findings.append(f)
                else:
                    await emit_log(LogLevel.INFO, "Nuclei CLI not available - using native parameter fuzzer fallback")
            except Exception as e:
                await emit_log(LogLevel.WARNING, f"Nuclei adapter error: {e}")

        # 0.4 Katana Adapter (Headless SPA Dynamic Crawler)
        if getattr(config.adapters, "enable_katana", True):
            katana_adapter = KatanaAdapter()
            custom_path = getattr(config.adapters, "katana_path", None) or getattr(config.adapters, "custom_katana_path", None)
            try:
                if await katana_adapter.is_available(custom_path):
                    await emit_log(LogLevel.INFO, "Executing Katana headless SPA crawler...")
                    katana_findings = await katana_adapter.run(
                        target,
                        config,
                        emit_log,
                        emit_finding,
                        emit_endpoint=emit_endpoint_discovered,
                        scan_id="active",
                    )
                    for f in katana_findings:
                        if f.fingerprint not in existing_fps:
                            existing_fps.add(f.fingerprint)
                            f.source_tool = "katana"
                            f.scan_id = "active"
                            findings.append(f)
            except Exception as e:
                await emit_log(LogLevel.WARNING, f"Katana adapter error: {e}")

        # 0.5 Schemathesis Adapter (API Contract & Fuzz Testing)
        if getattr(config.adapters, "enable_schemathesis", True):
            schemathesis_adapter = SchemathesisAdapter()
            custom_path = getattr(config.adapters, "schemathesis_path", None) or getattr(config.adapters, "custom_schemathesis_path", None)
            try:
                if await schemathesis_adapter.is_available(custom_path):
                    await emit_log(LogLevel.INFO, "Executing Schemathesis API contract fuzzer...")
                    schema_findings = await schemathesis_adapter.run(
                        target,
                        config,
                        emit_log,
                        emit_finding,
                        scan_id="active",
                    )
                    for f in schema_findings:
                        if f.fingerprint not in existing_fps:
                            existing_fps.add(f.fingerprint)
                            f.source_tool = "schemathesis"
                            f.scan_id = "active"
                            findings.append(f)
            except Exception as e:
                await emit_log(LogLevel.WARNING, f"Schemathesis adapter error: {e}")

        async with httpx.AsyncClient(headers=headers, timeout=timeout, verify=False) as client:
            # --- Stage 1: Authentication & Session Initialization (15% - 25%) ---
            await emit_progress(15, "Initializing authentication and session manager...")
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

            # --- Stage 2: Web Crawling & Attack Surface Discovery (25% - 45%) ---
            await emit_progress(25, "Discovering attack surface and crawling endpoints...")
            discovered_endpoints: List[DiscoveredEndpoint] = []
            html_contents: Dict[str, str] = {}
            page_responses: Dict[str, httpx.Response] = {}

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
                html_contents.update(crawler.page_html)
                page_responses.update(crawler.page_responses)
            else:
                initial_ep = DiscoveredEndpoint(
                    url=target.value,
                    method="GET",
                    depth=0,
                )
                discovered_endpoints.append(initial_ep)
                if emit_endpoint_discovered:
                    await emit_endpoint_discovered(initial_ep)

                try:
                    resp = await client.get(target.value)
                    html_contents[target.value] = resp.text
                    page_responses[target.value] = resp
                except Exception:
                    pass

            # --- Stage 3: HTTP Security Headers & Cookies (45% - 60%) ---
            await emit_progress(50, f"Auditing HTTP security headers and cookies across {len(discovered_endpoints)} endpoints...")
            for ep in discovered_endpoints:
                cached_resp = page_responses.get(ep.url)
                header_findings = await audit_security_headers_and_cookies(
                    ep.url,
                    client=client,
                    response=cached_resp,
                )
                for f in header_findings:
                    if f.fingerprint not in existing_fps:
                        existing_fps.add(f.fingerprint)
                        f.scan_id = "active"
                        findings.append(f)
                        await emit_finding(f)

            # Form & authentication audits across all crawled HTML pages
            auth_form_findings = await auth_manager.audit_auth_and_forms(
                discovered_endpoints=discovered_endpoints,
                html_contents=html_contents,
            )
            for f in auth_form_findings:
                if f.fingerprint not in existing_fps:
                    existing_fps.add(f.fingerprint)
                    f.scan_id = "active"
                    findings.append(f)
                    await emit_finding(f)

            # --- Stage 4: CORS Policy Analyzer (60% - 70%) ---
            await emit_progress(60, "Testing Cross-Origin Resource Sharing (CORS) configurations...")
            for ep in discovered_endpoints[:10]:
                cors_findings = await audit_cors_policies(
                    ep.url,
                    client=client,
                    emit_log=emit_log,
                )
                for f in cors_findings:
                    if f.fingerprint not in existing_fps:
                        existing_fps.add(f.fingerprint)
                        f.scan_id = "active"
                        findings.append(f)
                        await emit_finding(f)

            # --- Stage 5: Sensitive Exposure & API Inspector (70% - 80%) ---
            await emit_progress(70, "Inspecting sensitive files, debug consoles, and HTTP methods...")
            exposure_findings = await audit_sensitive_exposure_and_methods(
                target.value,
                client=client,
                emit_log=emit_log,
            )
            for f in exposure_findings:
                if f.fingerprint not in existing_fps:
                    existing_fps.add(f.fingerprint)
                    f.scan_id = "active"
                    findings.append(f)
                    await emit_finding(f)

            # --- Stage 6: Browser Posture & GraphQL (80% - 85%) ---
            await emit_progress(80, f"Auditing Subresource Integrity & Mixed Content across {len(html_contents) or 1} HTML pages...")
            for page_url, html_str in html_contents.items():
                browser_findings = await audit_browser_posture(
                    page_url,
                    client=client,
                    html_content=html_str,
                )
                for f in browser_findings:
                    if f.fingerprint not in existing_fps:
                        existing_fps.add(f.fingerprint)
                        f.scan_id = "active"
                        findings.append(f)
                        await emit_finding(f)

            gql_findings = await audit_graphql_endpoints(
                target.value,
                client=client,
                emit_log=emit_log,
            )
            for f in gql_findings:
                if f.fingerprint not in existing_fps:
                    existing_fps.add(f.fingerprint)
                    f.scan_id = "active"
                    findings.append(f)
                    await emit_finding(f)

            # --- Stage 7: Active Parameter Fuzzing & Injection Probes (85% - 95%) ---
            if config.fuzzing.enabled:
                await emit_progress(85, "Executing benign parameter fuzzing (SQLi, XSS, LFI, SSTI, Open Redirect)...")
                await emit_log(LogLevel.INFO, "Fuzzing discovered query parameters and forms with non-destructive payloads.")
                fuzz_findings = await audit_parameter_fuzzing(
                    target.value,
                    discovered_endpoints=discovered_endpoints,
                    client=client,
                    config=config,
                    scan_id="active",
                    emit_finding=emit_finding,
                    emit_log=emit_log,
                )
                for f in fuzz_findings:
                    if f.fingerprint not in existing_fps:
                        existing_fps.add(f.fingerprint)
                        f.scan_id = "active"
                        findings.append(f)

        await emit_progress(100, "Web DAST assessment completed.")
        await emit_log(LogLevel.INFO, f"Web DAST engine finished with {len(findings)} total findings.")

        return findings
