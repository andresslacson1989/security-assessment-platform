"""
Contract 03, 06 & 08 CORS Misconfiguration Analyzer.
"""

from __future__ import annotations
import logging
from typing import List, Optional
import httpx

from app.core.models import Finding, Evidence, Severity, calculate_fingerprint, LogLevel
from app.engines.base import LogCallback

logger = logging.getLogger("cyberassess.engines.cors")


def normalize_target_url(target_value: str) -> str:
    if not target_value.startswith("http://") and not target_value.startswith("https://"):
        return f"https://{target_value}"
    return target_value


async def audit_cors_policies(
    target_value: str,
    client: httpx.AsyncClient,
    emit_log: Optional[LogCallback] = None,
) -> List[Finding]:
    """
    Sends non-destructive CORS probe requests with arbitrary and null origins.
    """
    findings: List[Finding] = []
    url = normalize_target_url(target_value)

    if emit_log:
        await emit_log(LogLevel.INFO, f"Probing CORS configuration on {url}...")

    probes_attempted = 0
    probes_failed = 0
    last_exc: Optional[Exception] = None

    # Test 1: Arbitrary Origin Reflection (https://attacker-origin.com)
    evil_origin = "https://attacker-origin.com"
    probes_attempted += 1
    try:
        resp = await client.get(url, headers={"Origin": evil_origin})
        allow_origin = resp.headers.get("access-control-allow-origin")
        allow_credentials = resp.headers.get("access-control-allow-credentials", "").lower() == "true"

        if allow_origin == evil_origin and allow_credentials:
            findings.append(Finding(
                scan_id="auto",
                engine="web_dast",
                check_id="DAST-CORS-001",
                category="CORS Misconfiguration",
                title="Insecure CORS Origin Reflection with Credentials",
                severity=Severity.HIGH,
                cvss_score=8.1,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
                cwe_id="CWE-942",
                owasp_category="A01:2021-Broken Access Control",
                nist_control="AC-3, SC-7",
                description=(
                    f"The server reflects arbitrary requested Origin headers ('{evil_origin}') in "
                    f"Access-Control-Allow-Origin while setting Access-Control-Allow-Credentials: true."
                ),
                impact=(
                    "An attacker hosting a malicious site can make authenticated cross-origin XMLHttpRequests "
                    "or fetch() calls to read sensitive user data and execute unauthorized actions."
                ),
                remediation="Whitelist trusted origins explicitly instead of reflecting the requested Origin.",
                remediation_code_snippet=(
                    "# Nginx Whitelist Example:\n"
                    "if ($http_origin ~* \"^(https://(app|staging)\\.example\\.com)$\") {\n"
                    "    add_header Access-Control-Allow-Origin \"$http_origin\" always;\n"
                    "    add_header Access-Control-Allow-Credentials \"true\" always;\n"
                    "}"
                ),
                references=["https://portswigger.net/web-security/cors"],
                evidence=Evidence(
                    location=url,
                    observed_value=f"Access-Control-Allow-Origin: {allow_origin}, Access-Control-Allow-Credentials: true",
                    expected_value="Strict origin whitelist; no dynamic reflection with credentials",
                    request_details={"method": "GET", "url": url, "headers": {"Origin": evil_origin}},
                    response_details={"status_code": resp.status_code, "headers": dict(resp.headers)},
                ),
                fingerprint=calculate_fingerprint("DAST-CORS-001", url, "origin_reflection"),
            ))
        elif allow_origin == "*" and allow_credentials:
            findings.append(Finding(
                scan_id="auto",
                engine="web_dast",
                check_id="DAST-CORS-002",
                category="CORS Misconfiguration",
                title="Insecure CORS Wildcard with Credentials Enabled",
                severity=Severity.HIGH,
                cvss_score=7.5,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
                cwe_id="CWE-942",
                owasp_category="A01:2021-Broken Access Control",
                nist_control="AC-3",
                description="The server returns Access-Control-Allow-Origin: * alongside Access-Control-Allow-Credentials: true.",
                impact="Allows any external domain to read cross-origin responses.",
                remediation="Do not combine wildcard '*' with credential sharing.",
                references=["https://portswigger.net/web-security/cors"],
                evidence=Evidence(
                    location=url,
                    observed_value="Access-Control-Allow-Origin: * with credentials",
                    expected_value="Specific trusted origin or credentials disabled",
                ),
                fingerprint=calculate_fingerprint("DAST-CORS-002", url, "wildcard_credentials"),
            ))
    except Exception as exc:
        logger.debug("CORS wildcard probe failed: error_type=%s", type(exc).__name__)
        probes_failed += 1
        last_exc = exc

    # Test 2: Trust of 'null' Origin
    probes_attempted += 1
    try:
        resp_null = await client.get(url, headers={"Origin": "null"})
        allow_origin_null = resp_null.headers.get("access-control-allow-origin")
        allow_credentials_null = resp_null.headers.get("access-control-allow-credentials", "").lower() == "true"

        if allow_origin_null == "null" and allow_credentials_null:
            findings.append(Finding(
                scan_id="auto",
                engine="web_dast",
                check_id="DAST-CORS-003",
                category="CORS Misconfiguration",
                title="CORS Trust of 'null' Origin with Credentials",
                severity=Severity.HIGH,
                cvss_score=7.5,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
                cwe_id="CWE-942",
                owasp_category="A01:2021-Broken Access Control",
                nist_control="AC-3",
                description="The server accepts and trusts the 'null' Origin with credentials allowed.",
                impact="Attackers can exploit sandboxed iframes (<iframe sandbox=\"allow-scripts allow-top-navigation\">) to send requests with Origin: null and steal user data.",
                remediation="Never whitelist or allow the 'null' origin in CORS configuration.",
                references=["https://portswigger.net/web-security/cors"],
                evidence=Evidence(
                    location=url,
                    observed_value="Access-Control-Allow-Origin: null with credentials",
                    expected_value="Reject 'null' origin",
                ),
                fingerprint=calculate_fingerprint("DAST-CORS-003", url, "null_origin"),
            ))
    except Exception as exc:
        logger.debug("CORS null-origin probe failed: error_type=%s", type(exc).__name__)
        probes_failed += 1
        last_exc = exc

    if probes_attempted > 0 and probes_failed == probes_attempted and last_exc is not None:
        raise RuntimeError(f"CORS audit failed: all probes failed with error: {last_exc}") from last_exc

    return findings
