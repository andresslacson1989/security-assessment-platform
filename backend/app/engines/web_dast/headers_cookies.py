"""
Contract 03, 06 & 08 OWASP Security Headers, Cookie Attributes and Cache-Control Auditor.
"""

from __future__ import annotations
import re
from typing import List, Optional
import httpx

from app.core.models import Finding, Evidence, Severity, calculate_fingerprint, LogLevel
from app.engines.base import LogCallback


def normalize_target_url(target_value: str) -> str:
    if not target_value.startswith("http://") and not target_value.startswith("https://"):
        return f"https://{target_value}"
    return target_value


async def audit_security_headers_and_cookies(
    target_value: str,
    client: httpx.AsyncClient,
    emit_log: Optional[LogCallback] = None,
    response: Optional[httpx.Response] = None,
) -> List[Finding]:
    """
    Inspects HTTP response headers, Set-Cookie attributes, and caching policies.
    """
    findings: List[Finding] = []
    url = normalize_target_url(target_value)
    is_https = url.startswith("https://")

    if response is None:
        if emit_log:
            await emit_log(LogLevel.INFO, f"Fetching HTTP response headers from {url}...")

        try:
            response = await client.get(url, follow_redirects=True)
        except Exception as e:
            if emit_log:
                await emit_log(LogLevel.WARNING, f"HTTP request to {url} failed: {str(e)}")
            return findings

    headers = response.headers
    raw_headers_snippet = "\n".join([f"{k}: {v}" for k, v in headers.items()])

    # --- 1. Content-Security-Policy (DAST-HDR-001) ---
    csp = headers.get("content-security-policy")
    if not csp:
        findings.append(Finding(
            scan_id="auto",
            engine="web_dast",
            check_id="DAST-HDR-001",
            category="Security Headers",
            title="Missing Content-Security-Policy (CSP) Header",
            severity=Severity.MEDIUM,
            cvss_score=5.0,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
            cwe_id="CWE-1021",
            owasp_category="A05:2021-Security Misconfiguration",
            nist_control="SC-18, SI-10",
            description="The Content-Security-Policy (CSP) header is not sent by the server. CSP prevents Cross-Site Scripting (XSS), clickjacking, and data injection attacks by restricting allowed asset sources.",
            impact="Vulnerabilities in application code can be leveraged to inject and execute arbitrary inline or external malicious scripts in users' browsers.",
            remediation="Configure the web server or application middleware to return a strict Content-Security-Policy header.",
            remediation_code_snippet="add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self';\" always;",
            references=[
                "https://owasp.org/www-project-secure-headers/#content-security-policy",
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
            ],
            evidence=Evidence(
                location=url,
                observed_value="Content-Security-Policy header is missing in response",
                expected_value="Content-Security-Policy: default-src 'self'",
                raw_response_snippet=raw_headers_snippet[:500],
            ),
            fingerprint=calculate_fingerprint("DAST-HDR-001", url, "missing_csp"),
        ))
    elif "unsafe-inline" in csp or "unsafe-eval" in csp:
        findings.append(Finding(
            scan_id="auto",
            engine="web_dast",
            check_id="DAST-HDR-001",
            category="Security Headers",
            title="Insecure Directives in Content-Security-Policy (unsafe-inline / unsafe-eval)",
            severity=Severity.LOW,
            cvss_score=3.5,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
            cwe_id="CWE-1021",
            owasp_category="A05:2021-Security Misconfiguration",
            nist_control="SC-18",
            description=f"The CSP header contains insecure keywords: '{csp}'.",
            impact="Allowing 'unsafe-inline' or 'unsafe-eval' undermines XSS protection.",
            remediation="Use cryptographic nonces or hashes for inline scripts instead of 'unsafe-inline'.",
            remediation_code_snippet="Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-rAnd0m123';",
            references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"],
            evidence=Evidence(
                location=url,
                observed_value=csp,
                expected_value="Strict CSP without unsafe-inline or unsafe-eval",
            ),
            fingerprint=calculate_fingerprint("DAST-HDR-001", url, csp),
        ))

    # --- 2. Strict-Transport-Security (HSTS) (DAST-HDR-002, DAST-HDR-003) ---
    if is_https:
        hsts = headers.get("strict-transport-security")
        if not hsts:
            findings.append(Finding(
                scan_id="auto",
                engine="web_dast",
                check_id="DAST-HDR-002",
                category="Security Headers",
                title="Missing Strict-Transport-Security (HSTS) Header",
                severity=Severity.MEDIUM,
                cvss_score=5.3,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                cwe_id="CWE-319",
                owasp_category="A05:2021-Security Misconfiguration",
                nist_control="SC-8, SC-13",
                description="The Strict-Transport-Security header is not present on an HTTPS endpoint. HSTS instructs browsers to automatically convert all insecure HTTP requests to HTTPS.",
                impact="Users connecting on insecure public networks are vulnerable to SSL-stripping and downgrade attacks.",
                remediation="Enable HSTS with a minimum max-age of 1 year (31536000 seconds) including subdomains.",
                remediation_code_snippet="add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;",
                references=["https://owasp.org/www-project-secure-headers/#strict-transport-security"],
                evidence=Evidence(
                    location=url,
                    observed_value="Strict-Transport-Security header missing",
                    expected_value="Strict-Transport-Security: max-age=31536000; includeSubDomains",
                ),
                fingerprint=calculate_fingerprint("DAST-HDR-002", url, "missing_hsts"),
            ))
        else:
            max_age_match = re.search(r"max-age=(\d+)", hsts, re.IGNORECASE)
            if max_age_match:
                max_age = int(max_age_match.group(1))
                if max_age < 15552000:  # < 6 months
                    findings.append(Finding(
                        scan_id="auto",
                        engine="web_dast",
                        check_id="DAST-HDR-003",
                        category="Security Headers",
                        title="Insufficient HSTS Max-Age Duration",
                        severity=Severity.LOW,
                        cvss_score=3.1,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                        cwe_id="CWE-319",
                        owasp_category="A05:2021-Security Misconfiguration",
                        nist_control="SC-8",
                        description=f"The HSTS max-age is set to {max_age} seconds, which is less than the recommended 6 months (15552000s).",
                        impact="Short HSTS duration reduces the window of protection against downgrade attacks.",
                        remediation="Increase HSTS max-age to at least 31536000 seconds (1 year).",
                        remediation_code_snippet="add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;",
                        references=["https://hstspreload.org/"],
                        evidence=Evidence(
                            location=url,
                            observed_value=hsts,
                            expected_value="max-age >= 15552000 (minimum 6 months)",
                        ),
                        fingerprint=calculate_fingerprint("DAST-HDR-003", url, hsts),
                    ))

    # --- 3. Anti-Clickjacking X-Frame-Options (DAST-HDR-004) ---
    x_frame = headers.get("x-frame-options")
    frame_ancestors = "frame-ancestors" in (csp or "")
    if not x_frame and not frame_ancestors:
        findings.append(Finding(
            scan_id="auto",
            engine="web_dast",
            check_id="DAST-HDR-004",
            category="Security Headers",
            title="Missing Anti-Clickjacking Protection (X-Frame-Options)",
            severity=Severity.MEDIUM,
            cvss_score=4.3,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
            cwe_id="CWE-1021",
            owasp_category="A05:2021-Security Misconfiguration",
            nist_control="SC-18",
            description="The server lacks both X-Frame-Options and CSP frame-ancestors headers, allowing the application to be embedded in an <iframe> on third-party sites.",
            impact="Attackers can overlay deceptive UI elements to trick users into executing unauthorized actions (clickjacking).",
            remediation="Set X-Frame-Options to DENY or SAMEORIGIN, or configure CSP frame-ancestors 'self'.",
            remediation_code_snippet="add_header X-Frame-Options \"DENY\" always;",
            references=["https://owasp.org/www-project-secure-headers/#x-frame-options"],
            evidence=Evidence(
                location=url,
                observed_value="X-Frame-Options and frame-ancestors missing",
                expected_value="X-Frame-Options: DENY or SAMEORIGIN",
            ),
            fingerprint=calculate_fingerprint("DAST-HDR-004", url, "missing_x_frame"),
        ))

    # --- 4. X-Content-Type-Options (DAST-HDR-005) ---
    x_content_type = headers.get("x-content-type-options")
    if not x_content_type or "nosniff" not in x_content_type.lower():
        findings.append(Finding(
            scan_id="auto",
            engine="web_dast",
            check_id="DAST-HDR-005",
            category="Security Headers",
            title="Missing X-Content-Type-Options: nosniff Header",
            severity=Severity.LOW,
            cvss_score=3.1,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
            cwe_id="CWE-79",
            owasp_category="A05:2021-Security Misconfiguration",
            nist_control="SI-10",
            description="The X-Content-Type-Options header is not set to 'nosniff'. This prevents MIME-sniffing vulnerabilities where browsers execute non-executable MIME types as scripts.",
            impact="User-uploaded non-script files (e.g. avatars) could be interpreted by browsers as JavaScript.",
            remediation="Configure your web server to always return 'X-Content-Type-Options: nosniff'.",
            remediation_code_snippet="add_header X-Content-Type-Options \"nosniff\" always;",
            references=["https://owasp.org/www-project-secure-headers/#x-content-type-options"],
            evidence=Evidence(
                location=url,
                observed_value=str(x_content_type or "Header missing"),
                expected_value="X-Content-Type-Options: nosniff",
            ),
            fingerprint=calculate_fingerprint("DAST-HDR-005", url, "missing_nosniff"),
        ))

    # --- 5. Referrer-Policy (DAST-HDR-006) ---
    referrer = headers.get("referrer-policy")
    if not referrer or referrer.lower() in ("unsafe-url", "no-referrer-when-downgrade"):
        findings.append(Finding(
            scan_id="auto",
            engine="web_dast",
            check_id="DAST-HDR-006",
            category="Security Headers",
            title="Permissive or Missing Referrer-Policy Header",
            severity=Severity.LOW,
            cvss_score=3.1,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            cwe_id="CWE-200",
            owasp_category="A05:2021-Security Misconfiguration",
            nist_control="SC-8",
            description="The Referrer-Policy header is missing or configured with a permissive value that leaks sensitive URLs, tokens, or parameters in the Referer header to external destinations.",
            impact="Query parameters containing session IDs, reset tokens, or private paths may leak to external analytics or CDNs.",
            remediation="Set Referrer-Policy to 'strict-origin-when-cross-origin' or 'no-referrer'.",
            remediation_code_snippet="add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;",
            references=["https://owasp.org/www-project-secure-headers/#referrer-policy"],
            evidence=Evidence(
                location=url,
                observed_value=str(referrer or "Header missing"),
                expected_value="Referrer-Policy: strict-origin-when-cross-origin",
            ),
            fingerprint=calculate_fingerprint("DAST-HDR-006", url, str(referrer or "missing")),
        ))

    # --- 6. Server & Technology Version Disclosure (DAST-HDR-007) ---
    server_hdr = headers.get("server")
    powered_by = headers.get("x-powered-by")
    disclosures = []
    if server_hdr and re.search(r"\d+\.\d+", server_hdr):
        disclosures.append(f"Server: {server_hdr}")
    if powered_by:
        disclosures.append(f"X-Powered-By: {powered_by}")

    if disclosures:
        findings.append(Finding(
            scan_id="auto",
            engine="web_dast",
            check_id="DAST-HDR-007",
            category="Information Disclosure",
            title="Server & Technology Version Disclosure",
            severity=Severity.LOW,
            cvss_score=3.1,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            cwe_id="CWE-200",
            owasp_category="A05:2021-Security Misconfiguration",
            nist_control="CM-6",
            description=f"HTTP response headers disclose granular backend software and version numbers: {', '.join(disclosures)}.",
            impact="Provides attackers with reconnaissance information to target known CVE vulnerabilities specific to the running version.",
            remediation="Suppress or obfuscate Server and X-Powered-By headers in web server and framework configs.",
            remediation_code_snippet="# Nginx:\nserver_tokens off;\n\n# Express.js:\napp.disable('x-powered-by');",
            references=["https://cwe.mitre.org/data/definitions/200.html"],
            evidence=Evidence(
                location=url,
                observed_value="; ".join(disclosures),
                expected_value="Generic or suppressed Server/X-Powered-By headers",
            ),
            fingerprint=calculate_fingerprint("DAST-HDR-007", url, "; ".join(disclosures)),
        ))

    # --- 7. Permissions-Policy (DAST-HDR-008) ---
    perm_policy = headers.get("permissions-policy") or headers.get("feature-policy")
    if not perm_policy:
        findings.append(Finding(
            scan_id="auto",
            engine="web_dast",
            check_id="DAST-HDR-008",
            category="Security Headers",
            title="Missing Permissions-Policy Header",
            severity=Severity.LOW,
            cvss_score=3.1,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            cwe_id="CWE-1021",
            owasp_category="A05:2021-Security Misconfiguration",
            nist_control="SC-18",
            description="The Permissions-Policy header is missing. It allows website owners to restrict browser features and APIs (camera, microphone, geolocation, payment) from being used by embedded iframes.",
            impact="Third-party scripts or frames can access hardware APIs without explicit restriction.",
            remediation="Configure a Permissions-Policy header restricting unneeded sensors and browser features.",
            remediation_code_snippet="add_header Permissions-Policy \"camera=(), microphone=(), geolocation=()\" always;",
            references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy"],
            evidence=Evidence(
                location=url,
                observed_value="Permissions-Policy header missing",
                expected_value="Permissions-Policy: camera=(), microphone=(), geolocation=()",
            ),
            fingerprint=calculate_fingerprint("DAST-HDR-008", url, "missing_perm_policy"),
        ))

    # --- 8. Cross-Origin Isolation COOP/COEP/CORP (DAST-HDR-009) ---
    coop = headers.get("cross-origin-opener-policy")
    coep = headers.get("cross-origin-embedder-policy")
    if not coop or not coep:
        findings.append(Finding(
            scan_id="auto",
            engine="web_dast",
            check_id="DAST-HDR-009",
            category="Security Headers",
            title="Missing Cross-Origin Isolation Headers (COOP / COEP)",
            severity=Severity.LOW,
            cvss_score=3.1,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            cwe_id="CWE-1021",
            owasp_category="A05:2021-Security Misconfiguration",
            nist_control="SC-18",
            description="The application does not enable Cross-Origin Opener Policy (COOP) or Cross-Origin Embedder Policy (COEP).",
            impact="Without cross-origin isolation, documents share browsing context groups and are susceptible to cross-origin side-channel leaks (Spectre).",
            remediation="Add COOP and COEP headers to isolate browsing contexts.",
            remediation_code_snippet="add_header Cross-Origin-Opener-Policy \"same-origin\" always;\nadd_header Cross-Origin-Embedder-Policy \"require-corp\" always;",
            references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy"],
            evidence=Evidence(
                location=url,
                observed_value=f"COOP: {coop or 'missing'}, COEP: {coep or 'missing'}",
                expected_value="COOP: same-origin, COEP: require-corp",
            ),
            fingerprint=calculate_fingerprint("DAST-HDR-009", url, "missing_coop_coep"),
        ))

    # --- 9. Cookie Security Flags (DAST-COOKIE-001 to 003) ---
    set_cookies = response.headers.get_list("set-cookie") if hasattr(response.headers, "get_list") else [headers.get("set-cookie")]
    set_cookies = [c for c in set_cookies if c]

    for cookie_header in set_cookies:
        cookie_parts = [p.strip() for p in cookie_header.split(";")]
        cookie_name = cookie_parts[0].split("=")[0] if cookie_parts else "cookie"
        lower_parts = [p.lower() for p in cookie_parts]

        # HttpOnly check
        if "httponly" not in lower_parts:
            findings.append(Finding(
                scan_id="auto",
                engine="web_dast",
                check_id="DAST-COOKIE-001",
                category="Cookie Security",
                title=f"Cookie Missing HttpOnly Flag: '{cookie_name}'",
                severity=Severity.MEDIUM,
                cvss_score=5.3,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
                cwe_id="CWE-1004",
                owasp_category="A05:2021-Security Misconfiguration",
                nist_control="SC-23",
                description=f"The cookie '{cookie_name}' was set without the 'HttpOnly' flag.",
                impact="Client-side JavaScript can read this cookie. In the event of an XSS vulnerability, session tokens can be stolen directly via document.cookie.",
                remediation="Ensure the 'HttpOnly' flag is enabled when setting session and authentication cookies.",
                remediation_code_snippet=f"Set-Cookie: {cookie_name}=...; HttpOnly; Secure; SameSite=Lax",
                references=["https://owasp.org/www-community/HttpOnly"],
                evidence=Evidence(
                    location=f"{url} [Cookie: {cookie_name}]",
                    observed_value=cookie_header,
                    expected_value="Cookie directive includes 'HttpOnly'",
                ),
                fingerprint=calculate_fingerprint("DAST-COOKIE-001", url, cookie_name),
            ))

        # Secure flag check
        if is_https and "secure" not in lower_parts:
            findings.append(Finding(
                scan_id="auto",
                engine="web_dast",
                check_id="DAST-COOKIE-002",
                category="Cookie Security",
                title=f"Cookie Missing Secure Flag: '{cookie_name}'",
                severity=Severity.MEDIUM,
                cvss_score=5.3,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                cwe_id="CWE-614",
                owasp_category="A05:2021-Security Misconfiguration",
                nist_control="SC-8, SC-13",
                description=f"The cookie '{cookie_name}' was transmitted over HTTPS without the 'Secure' flag.",
                impact="Browsers will transmit this cookie over unencrypted HTTP if the user clicks an http:// link, exposing session tokens to network eavesdropping.",
                remediation="Add the 'Secure' flag to all cookies set on HTTPS sites.",
                remediation_code_snippet=f"Set-Cookie: {cookie_name}=...; Secure; HttpOnly; SameSite=Lax",
                references=["https://cwe.mitre.org/data/definitions/614.html"],
                evidence=Evidence(
                    location=f"{url} [Cookie: {cookie_name}]",
                    observed_value=cookie_header,
                    expected_value="Cookie directive includes 'Secure'",
                ),
                fingerprint=calculate_fingerprint("DAST-COOKIE-002", url, cookie_name),
            ))

        # SameSite check
        samesite_present = any(p.startswith("samesite") for p in lower_parts)
        if not samesite_present:
            findings.append(Finding(
                scan_id="auto",
                engine="web_dast",
                check_id="DAST-COOKIE-003",
                category="Cookie Security",
                title=f"Cookie Missing SameSite Attribute: '{cookie_name}'",
                severity=Severity.LOW,
                cvss_score=3.7,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
                cwe_id="CWE-1275",
                owasp_category="A01:2021-Broken Access Control",
                nist_control="SC-23",
                description=f"The cookie '{cookie_name}' does not specify a 'SameSite' attribute (Strict, Lax, or None).",
                impact="Leaving SameSite undefined increases susceptibility to Cross-Site Request Forgery (CSRF) attacks.",
                remediation="Explicitly set SameSite=Lax or SameSite=Strict on all cookies.",
                remediation_code_snippet=f"Set-Cookie: {cookie_name}=...; SameSite=Lax; Secure; HttpOnly",
                references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite"],
                evidence=Evidence(
                    location=f"{url} [Cookie: {cookie_name}]",
                    observed_value=cookie_header,
                    expected_value="Cookie includes 'SameSite=Lax' or 'SameSite=Strict'",
                ),
                fingerprint=calculate_fingerprint("DAST-COOKIE-003", url, cookie_name),
            ))

    # --- 10. Cache-Control (DAST-CCH-001) ---
    cache_control = headers.get("cache-control")
    if not cache_control or not ("no-store" in cache_control.lower() or "no-cache" in cache_control.lower() or "private" in cache_control.lower()):
        findings.append(Finding(
            scan_id="auto",
            engine="web_dast",
            check_id="DAST-CCH-001",
            category="Information Disclosure",
            title="Missing Cache-Control Header on Response",
            severity=Severity.LOW,
            cvss_score=3.1,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            cwe_id="CWE-524",
            owasp_category="A05:2021-Security Misconfiguration",
            nist_control="SC-28",
            description="The HTTP response lacks anti-caching headers ('Cache-Control: no-store, no-cache').",
            impact="Shared intermediate caches and local browser history may cache sensitive response bodies or session state.",
            remediation="Set 'Cache-Control: no-store, no-cache' on authenticated or sensitive application endpoints.",
            remediation_code_snippet="add_header Cache-Control \"no-store, no-cache, must-revalidate\" always;",
            references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control"],
            evidence=Evidence(
                location=url,
                observed_value=f"Cache-Control: {cache_control or 'missing'}",
                expected_value="Cache-Control: no-store, no-cache",
            ),
            fingerprint=calculate_fingerprint("DAST-CCH-001", url, "missing_cache_control"),
        ))

    return findings
