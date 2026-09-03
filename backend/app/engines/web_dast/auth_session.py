"""
Contract 01, 03, 06 & 08 Authentication & Session Manager and Form Auditor.
Handles session establishment (Header, Cookie, Form Login), active session verification,
and audits for authentication security (DAST-AUTH-001 to 004) and form vulnerabilities (DAST-FORM-001 to 002).
"""

from __future__ import annotations
import logging
import re
import urllib.parse
from typing import List, Optional, Dict, Any, Tuple, Callable
from bs4 import BeautifulSoup
import httpx

from app.core.models import (
    AuthConfig,
    AuthType,
    DiscoveredEndpoint,
    EndpointTestStatus,
    Finding,
    Evidence,
    Severity,
    calculate_fingerprint,
    mask_secret,
    LogLevel,
)
from app.engines.base import LogCallback

logger = logging.getLogger("cyberassess.engines.auth_session")


class FormCheckExecution:
    """
    Authoritative per-page form check execution record.
    """
    def __init__(
        self,
        page_url: str,
        forms_inspected: int = 0,
        parse_failed: bool = False,
        error_message: str = "",
        findings: Optional[List[Finding]] = None,
    ):
        self.page_url = page_url
        self.forms_inspected = forms_inspected
        self.parse_failed = parse_failed
        self.error_message = error_message
        self.findings = findings or []

    @property
    def status(self) -> EndpointTestStatus:
        if self.findings:
            return EndpointTestStatus.VULNERABLE
        if self.parse_failed:
            return EndpointTestStatus.SKIPPED
        if self.forms_inspected > 0:
            return EndpointTestStatus.SAFE
        return EndpointTestStatus.NOT_EXECUTED


class AuthFormAuditResult(list):
    """
    Subclass of list holding authentication and form findings, while preserving
    authoritative per-endpoint form inspection execution records.
    """
    def __init__(
        self,
        findings: List[Finding],
        form_executions: Optional[Dict[str, FormCheckExecution]] = None,
    ):
        super().__init__(findings)
        self.findings = findings
        self.form_executions = form_executions or {}

CSRF_FIELD_NAMES = {
    "csrf_token", "_csrf", "authenticity_token", "_token", "csrf-token",
    "csrf", "anti-csrf", "user_token", "csrftoken", "xsrf_token", "_xsrf"
}

SENSITIVE_PARAM_REGEX = re.compile(
    r"(?i)^(token|bearer|jwt|session|sessionid|key|secret|password|passwd|auth|access_token|apikey)$"
)


class AuthSessionManager:
    """
    Manages session establishment, session verification, and audits authenticated/form attack surfaces.
    """

    def __init__(
        self,
        target_url: str,
        config: AuthConfig,
        client: httpx.AsyncClient,
        scan_id: str = "auto",
        emit_log: Optional[LogCallback] = None,
        transport_factory: Optional[Callable[[], httpx.AsyncBaseTransport]] = None,
    ):
        self.target_url = target_url.strip()
        self.config = config
        self.client = client
        self.scan_id = scan_id
        self.emit_log = emit_log
        self.transport_factory = transport_factory
        self.is_authenticated: bool = False

    async def authenticate(self) -> bool:
        """
        Establishes authenticated session based on configured AuthType.
        """
        if self.config.auth_type in (AuthType.NONE, AuthType.NO_AUTH):
            self.is_authenticated = False
            return True

        if self.config.auth_type == AuthType.HEADER:
            if self.config.headers:
                self.client.headers.update(self.config.headers)
                self.is_authenticated = True
                if self.emit_log:
                    await self.emit_log(LogLevel.INFO, "Injected custom authentication headers into HTTP client.")
            return True

        if self.config.auth_type == AuthType.COOKIE:
            if self.config.cookies:
                self.client.cookies.update(self.config.cookies)
                self.is_authenticated = True
                if self.emit_log:
                    await self.emit_log(LogLevel.INFO, "Injected session cookies into HTTP client.")
            return True

        if self.config.auth_type == AuthType.FORM_LOGIN:
            login_url = self.config.login_url or self.target_url
            if self.emit_log:
                await self.emit_log(LogLevel.INFO, f"Attempting automated form-based login at '{login_url}'...")

            try:
                # 1. GET login page to obtain cookies and anti-CSRF token
                get_resp = await self.client.get(login_url, follow_redirects=True)
                csrf_token = None
                if "text/html" in get_resp.headers.get("content-type", "").lower():
                    soup = BeautifulSoup(get_resp.text, "html.parser")
                    # Search for hidden csrf token input
                    for inp in soup.find_all("input", type="hidden"):
                        inp_name = (inp.get("name") or "").lower()
                        if inp_name in CSRF_FIELD_NAMES or (self.config.csrf_token_field and inp_name == self.config.csrf_token_field.lower()):
                            csrf_token = (inp.get("name"), inp.get("value") or "")
                            break

                # 2. Build form POST payload
                form_data = {}
                if self.config.username_field and self.config.username:
                    form_data[self.config.username_field] = self.config.username
                if self.config.password_field and self.config.password:
                    form_data[self.config.password_field] = self.config.password
                if csrf_token:
                    form_data[csrf_token[0]] = csrf_token[1]

                # 3. Submit credentials
                post_resp = await self.client.post(login_url, data=form_data, follow_redirects=True)

                # 4. Verify login success
                if self.config.logged_in_indicator:
                    if self.config.logged_in_indicator in post_resp.text:
                        self.is_authenticated = True
                        if self.emit_log:
                            await self.emit_log(LogLevel.INFO, f"Form login successful: verified '{self.config.logged_in_indicator}'.")
                        return True
                    else:
                        if self.emit_log:
                            await self.emit_log(LogLevel.WARNING, "Form login failed: logged-in indicator not found in response.")
                        return False
                else:
                    # Fallback: check status code and cookies
                    if post_resp.status_code in (200, 302, 303):
                        self.is_authenticated = True
                        if self.emit_log:
                            await self.emit_log(LogLevel.INFO, "Form login completed successfully.")
                        return True

            except Exception as e:
                if self.emit_log:
                    await self.emit_log(LogLevel.ERROR, f"Form login encountered an error: {str(e)}")
                return False

        return False

    async def verify_session(self, response: httpx.Response) -> bool:
        """
        Validates if current response indicates an active authenticated session.
        """
        if not self.is_authenticated:
            return True

        if response.status_code in (401, 403):
            return False

        if self.config.logged_in_indicator and "text/html" in response.headers.get("content-type", "").lower():
            if self.config.logged_in_indicator not in response.text:
                return False

        return True

    async def audit_auth_and_forms(
        self,
        discovered_endpoints: List[DiscoveredEndpoint],
        html_contents: Dict[str, str],
    ) -> List[Finding]:
        """
        Audits authentication posture (DAST-AUTH-001 to 004) and HTML forms (DAST-FORM-001 to 002).
        """
        findings: List[Finding] = []

        # --- 1. DAST-AUTH-001: Insecure Authentication over Cleartext HTTP ---
        if self.config.auth_type != AuthType.NONE:
            login_url = self.config.login_url or self.target_url
            if login_url.startswith("http://"):
                findings.append(Finding(
                    scan_id=self.scan_id,
                    engine="web_dast",
                    check_id="DAST-AUTH-001",
                    category="Authentication Security",
                    title="Insecure Authentication over Cleartext HTTP",
                    severity=Severity.HIGH,
                    cvss_score=7.5,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    cwe_id="CWE-319",
                    owasp_category="A02:2021-Cryptographic Failures",
                    nist_control="SC-8, IA-5",
                    description=f"Authentication requests or credentials are submitted over unencrypted HTTP: '{login_url}'.",
                    impact="Credentials, session tokens, and sensitive headers can be intercepted in plaintext via network sniffing or Man-in-the-Middle (MitM) attacks.",
                    remediation="Migrate all authentication workflows and endpoints strictly to HTTPS with HSTS enabled.",
                    remediation_code_snippet="# Redirect all HTTP traffic to HTTPS:\nserver {\n    listen 80;\n    server_name example.com;\n    return 301 https://$host$request_uri;\n}",
                    references=["https://cwe.mitre.org/data/definitions/319.html"],
                    evidence=Evidence(
                        location=login_url,
                        observed_value=f"AuthType: {self.config.auth_type.value} over unencrypted scheme '{login_url}'",
                        expected_value="HTTPS (TLS 1.2/1.3) scheme for all authentication operations",
                    ),
                    fingerprint=calculate_fingerprint("DAST-AUTH-001", login_url, "cleartext_auth"),
                ))

        # --- 2. DAST-AUTH-002: Session Cookie Missing Security Flags post-Login ---
        if self.is_authenticated and self.client.cookies:
            for cookie in self.client.cookies.jar:
                cookie_name = cookie.name
                cookie_flags = []
                is_secure = cookie.secure
                is_httponly = cookie.has_nonstandard_attr("HttpOnly") or cookie.has_nonstandard_attr("httponly")
                is_https = self.target_url.startswith("https://")

                missing_flags = []
                if not is_httponly:
                    missing_flags.append("HttpOnly")
                if is_https and not is_secure:
                    missing_flags.append("Secure")

                if missing_flags:
                    findings.append(Finding(
                        scan_id=self.scan_id,
                        engine="web_dast",
                        check_id="DAST-AUTH-002",
                        category="Cookie Security",
                        title=f"Authenticated Session Cookie Missing Security Flags: '{cookie_name}'",
                        severity=Severity.HIGH,
                        cvss_score=7.4,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
                        cwe_id="CWE-614",
                        owasp_category="A05:2021-Security Misconfiguration",
                        nist_control="SC-28",
                        description=f"The authenticated session cookie '{cookie_name}' lacks critical security flags: {', '.join(missing_flags)}.",
                        impact="Lack of HttpOnly allows XSS payloads to extract active sessions. Lack of Secure exposes sessions over cleartext transitions.",
                        remediation="Configure the application session manager to append HttpOnly, Secure, and SameSite=Lax attributes to all authenticated session cookies.",
                        remediation_code_snippet=f"Set-Cookie: {cookie_name}=...; HttpOnly; Secure; SameSite=Lax; Path=/",
                        references=["https://owasp.org/www-community/controls/SecureFlag"],
                        evidence=Evidence(
                            location=f"{self.target_url} [Session Cookie: {cookie_name}]",
                            observed_value=f"Missing flags: {', '.join(missing_flags)}",
                            expected_value="Set-Cookie: HttpOnly; Secure; SameSite=Lax",
                        ),
                        fingerprint=calculate_fingerprint("DAST-AUTH-002", self.target_url, f"{cookie_name}_{','.join(missing_flags)}"),
                    ))

        # --- 3. DAST-AUTH-003: Broken Access Control / Sensitive Endpoint Unprotected ---
        sensitive_patterns = [
            "/admin", "/dashboard", "/account", "/settings", "/profile",
            "/manage", "/portal", "/console", "/api/user", "/api/v1/admin"
        ]
        test_candidates = [
            ep.url for ep in discovered_endpoints
            if any(p in ep.url.lower() for p in sensitive_patterns) or ep.is_authenticated
        ]

        if test_candidates:
            unauth_transport = self.transport_factory() if self.transport_factory else None
            async with httpx.AsyncClient(timeout=8.0, trust_env=False, transport=unauth_transport) as unauth_client:
                for target_endpoint in test_candidates[:5]:  # Limit check to first 5 sensitive endpoints
                    try:
                        unauth_resp = await unauth_client.get(target_endpoint, follow_redirects=False)
                        # If unauthenticated client gets 200 OK without redirecting to login
                        if unauth_resp.status_code == 200 and len(unauth_resp.text.strip()) >= 20:
                            # Verify it's not a generic login form
                            is_login_page = "login" in unauth_resp.text.lower() and "<form" in unauth_resp.text.lower()
                            if not is_login_page:
                                findings.append(Finding(
                                    scan_id=self.scan_id,
                                    engine="web_dast",
                                    check_id="DAST-AUTH-003",
                                    category="Broken Access Control",
                                    title=f"Sensitive Authenticated Endpoint Accessible Without Credentials",
                                    severity=Severity.HIGH,
                                    cvss_score=8.5,
                                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
                                    cwe_id="CWE-284",
                                    owasp_category="A01:2021-Broken Access Control",
                                    nist_control="AC-3, AC-6",
                                    description=f"The endpoint '{target_endpoint}' returned HTTP 200 OK without valid session credentials or login redirection.",
                                    impact="Unauthenticated external attackers can access sensitive internal user dashboards, data, or administrative functionalities.",
                                    remediation="Enforce mandatory session authentication checks on all non-public controller routes and API endpoints.",
                                    remediation_code_snippet="# Middleware authentication guard:\nif not request.user.is_authenticated:\n    return RedirectResponse(url='/login', status_code=302)",
                                    references=["https://owasp.org/Top10/A01_2021-Broken_Access_Control/"],
                                    evidence=Evidence(
                                        location=target_endpoint,
                                        observed_value=f"HTTP 200 OK returned to unauthenticated client (Response length: {len(unauth_resp.text)} bytes)",
                                        expected_value="HTTP 401 Unauthorized or HTTP 302 Redirect to /login",
                                    ),
                                    fingerprint=calculate_fingerprint("DAST-AUTH-003", target_endpoint, "unauth_200"),
                                ))
                    except Exception as exc:
                        logger.debug("Authentication response inspection failed: error_type=%s", type(exc).__name__)

        # --- 4. DAST-AUTH-004: Sensitive Data in Authenticated Query Strings ---
        for ep in discovered_endpoints:
            parsed = urllib.parse.urlparse(ep.url)
            if parsed.query:
                query_params = urllib.parse.parse_qs(parsed.query)
                sensitive_keys = [k for k in query_params if SENSITIVE_PARAM_REGEX.match(k)]
                if sensitive_keys:
                    masked_query = []
                    for k, vals in query_params.items():
                        if SENSITIVE_PARAM_REGEX.match(k):
                            masked_query.append(f"{k}={mask_secret(vals[0]) if vals else '***'}")
                        else:
                            masked_query.append(f"{k}={vals[0] if vals else ''}")

                    findings.append(Finding(
                        scan_id=self.scan_id,
                        engine="web_dast",
                        check_id="DAST-AUTH-004",
                        category="Information Disclosure",
                        title=f"Sensitive Credentials or Token in Query Parameters: '{', '.join(sensitive_keys)}'",
                        severity=Severity.MEDIUM,
                        cvss_score=5.3,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                        cwe_id="CWE-598",
                        owasp_category="A04:2021-Insecure Design",
                        nist_control="IA-5, SC-28",
                        description=f"The URL '{ep.url}' contains sensitive credential parameters in the query string: {', '.join(sensitive_keys)}.",
                        impact="Query parameters are logged in plaintext across browser history, web server access logs, reverse proxy logs, and Referer headers.",
                        remediation="Transmit sensitive authentication tokens and credentials in HTTP Request Headers (e.g. Authorization: Bearer <token>) or POST body payloads.",
                        remediation_code_snippet="# Send via Authorization Header instead of URL parameter:\nfetch('/api/data', {\n    headers: { 'Authorization': `Bearer ${token}` }\n});",
                        references=["https://cwe.mitre.org/data/definitions/598.html"],
                        evidence=Evidence(
                            location=ep.url,
                            observed_value="?" + "&".join(masked_query),
                            expected_value="Query parameters contain zero authentication tokens or secrets",
                        ),
                        fingerprint=calculate_fingerprint("DAST-AUTH-004", ep.url, ",".join(sorted(sensitive_keys))),
                    ))

        # --- 5. DAST-FORM-001 & DAST-FORM-002: HTML Form Security ---
        form_executions: Dict[str, FormCheckExecution] = {}
        for page_url, html_str in html_contents.items():
            exec_record = FormCheckExecution(page_url=page_url)
            form_executions[page_url] = exec_record
            try:
                soup = BeautifulSoup(html_str, "html.parser")
                forms = soup.find_all("form")
                exec_record.forms_inspected = len(forms)

                for form_idx, form in enumerate(forms, start=1):
                    action_raw = form.get("action", "")
                    method = (form.get("method") or "GET").upper()
                    resolved_action = urllib.parse.urljoin(page_url, action_raw)

                    # DAST-FORM-001: Insecure Cleartext Form Action
                    # R4.3: Ensure form transport assessment cannot say "secure submission" for a state-changing
                    # form whose resolved action uses plain HTTP. Trigger DAST-FORM-001 if action uses http://
                    # either on an HTTPS page (mixed-content downgrade) or for any state-changing form / cleartext HTTP form.
                    is_insecure_transport = resolved_action.startswith("http://") and (
                        page_url.startswith("https://") or method in ("POST", "PUT", "DELETE")
                    )
                    if is_insecure_transport:
                        is_https_origin = page_url.startswith("https://")
                        title = (
                            f"Insecure Cleartext Form Action on HTTPS Page: '{resolved_action}'"
                            if is_https_origin
                            else f"Insecure Cleartext State-Changing Form Action: '{resolved_action}'"
                        )
                        desc = (
                            f"A form on secure page '{page_url}' submits form data to unencrypted destination '{resolved_action}'."
                            if is_https_origin
                            else f"A state-changing form ({method}) on '{page_url}' submits form data to unencrypted destination '{resolved_action}'."
                        )
                        f = Finding(
                            scan_id=self.scan_id,
                            engine="web_dast",
                            check_id="DAST-FORM-001",
                            category="Insecure Transmission",
                            title=title,
                            severity=Severity.HIGH,
                            cvss_score=7.5,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
                            cwe_id="CWE-319",
                            owasp_category="A02:2021-Cryptographic Failures",
                            nist_control="SC-8",
                            description=desc,
                            impact="User inputs submitted through this form will be transmitted in plaintext across the network, vulnerable to interception.",
                            remediation="Ensure form action attributes use HTTPS URLs or relative path references.",
                            remediation_code_snippet='<form action="/api/submit" method="POST">',
                            references=["https://cwe.mitre.org/data/definitions/319.html"],
                            evidence=Evidence(
                                location=f"{page_url} [Form #{form_idx}]",
                                observed_value=f'<form action="{resolved_action}" method="{method}">',
                                expected_value="Form action uses secure HTTPS destination",
                            ),
                            fingerprint=calculate_fingerprint("DAST-FORM-001", page_url, f"{resolved_action}_{method}"),
                        )
                        findings.append(f)
                        exec_record.findings.append(f)

                    # DAST-FORM-002: Missing Anti-CSRF Token in State-Changing Form
                    if method in ("POST", "PUT", "DELETE"):
                        # Check inputs for CSRF tokens
                        has_csrf = False
                        for hidden_inp in form.find_all("input", type="hidden"):
                            name = (hidden_inp.get("name") or "").lower()
                            if name in CSRF_FIELD_NAMES or any(token_key in name for token_key in ("csrf", "xsrf", "token")):
                                has_csrf = True
                                break

                        if not has_csrf:
                            f = Finding(
                                scan_id=self.scan_id,
                                engine="web_dast",
                                check_id="DAST-FORM-002",
                                category="Cross-Site Request Forgery",
                                title=f"State-Changing Form Missing Anti-CSRF Token: '{resolved_action}'",
                                severity=Severity.MEDIUM,
                                cvss_score=6.5,
                                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
                                cwe_id="CWE-352",
                                owasp_category="A01:2021-Broken Access Control",
                                nist_control="SC-23",
                                description=f"The state-changing form ({method}) targeting '{resolved_action}' lacks a hidden anti-CSRF token input.",
                                impact="Attackers can craft malicious third-party websites that trigger unwanted actions on behalf of authenticated users (CSRF).",
                                remediation="Include a cryptographically secure, unpredictable anti-CSRF token in all state-changing forms.",
                                remediation_code_snippet="<form action=\"/submit\" method=\"POST\">\n  <input type=\"hidden\" name=\"_csrf\" value=\"{{ csrf_token }}\">\n  ...\n</form>",
                                references=["https://owasp.org/www-community/attacks/csrf"],
                                evidence=Evidence(
                                    location=f"{page_url} [Form #{form_idx} -> {resolved_action}]",
                                    observed_value=f"Form method='{method}' without anti-CSRF token input",
                                    expected_value="Hidden input containing valid anti-CSRF token",
                                ),
                                fingerprint=calculate_fingerprint("DAST-FORM-002", page_url, f"{resolved_action}_{form_idx}"),
                            )
                            findings.append(f)
                            exec_record.findings.append(f)

            except Exception as exc:
                exec_record.parse_failed = True
                exec_record.error_message = str(exc)
                continue

        return AuthFormAuditResult(findings=findings, form_executions=form_executions)
