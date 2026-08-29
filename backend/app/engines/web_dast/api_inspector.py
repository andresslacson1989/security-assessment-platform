"""
Contract 03, 06 & 08 Sensitive File Exposure & Dangerous HTTP Methods Inspector.
"""

from __future__ import annotations
import re
from typing import List, Optional
import urllib.parse
import httpx

from app.core.models import Finding, Evidence, Severity, calculate_fingerprint, LogLevel
from app.engines.base import LogCallback


def normalize_target_url(target_value: str) -> str:
    if not target_value.startswith("http://") and not target_value.startswith("https://"):
        return f"https://{target_value}"
    return target_value


async def audit_sensitive_exposure_and_methods(
    target_value: str,
    client: httpx.AsyncClient,
    emit_log: Optional[LogCallback] = None,
) -> List[Finding]:
    """
    Safely probes for exposed environment files, git metadata, actuator endpoints, and dangerous HTTP verbs.
    """
    findings: List[Finding] = []
    base_url = normalize_target_url(target_value).rstrip("/")

    if emit_log:
        await emit_log(LogLevel.INFO, f"Checking for exposed sensitive paths on {base_url}...")

    # --- 1. Exposed .env File (DAST-EXP-001) ---
    try:
        env_url = f"{base_url}/.env"
        resp = await client.get(env_url, follow_redirects=False)
        if resp.status_code == 200:
            text = resp.text
            # Verify signature of environment file
            if re.search(r"(?m)^[A-Z0-9_]+=[^\r\n]+", text) and any(
                k in text.upper() for k in ("KEY", "SECRET", "DB_", "PASSWORD", "APP_")
            ):
                findings.append(Finding(
                    scan_id="auto",
                    engine="web_dast",
                    check_id="DAST-EXP-001",
                    category="Information Exposure",
                    title="Publicly Exposed Environment Configuration File (.env)",
                    severity=Severity.CRITICAL,
                    cvss_score=9.8,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    cwe_id="CWE-552",
                    owasp_category="A01:2021-Broken Access Control",
                    nist_control="AC-3, SC-28",
                    description=f"The environment configuration file '{env_url}' is publicly accessible over HTTP.",
                    impact="Full system compromise. Attackers can read database credentials, API secrets, encryption keys, and application tokens.",
                    remediation="Block access to all dotfiles (.env, .git, etc.) in your web server configuration immediately.",
                    remediation_code_snippet="# Nginx Block Rule:\nlocation ~ /\\.(?!well-known).* {\n    deny all;\n    return 404;\n}",
                    references=["https://cwe.mitre.org/data/definitions/552.html"],
                    evidence=Evidence(
                        location=env_url,
                        observed_value=f"HTTP 200 OK containing environment variables: {text[:100]}...",
                        expected_value="HTTP 404 Not Found or HTTP 403 Forbidden",
                        request_details={"method": "GET", "url": env_url},
                        response_details={"status_code": resp.status_code},
                    ),
                    fingerprint=calculate_fingerprint("DAST-EXP-001", env_url, "env_exposed"),
                ))
    except Exception:
        pass

    # --- 2. Exposed Git Metadata (DAST-EXP-002) ---
    try:
        git_url = f"{base_url}/.git/HEAD"
        resp = await client.get(git_url, follow_redirects=False)
        if resp.status_code == 200 and resp.text.strip().startswith("ref: refs/"):
            findings.append(Finding(
                scan_id="auto",
                engine="web_dast",
                check_id="DAST-EXP-002",
                category="Information Exposure",
                title="Exposed Git Version Control Repository (/.git/HEAD)",
                severity=Severity.CRITICAL,
                cvss_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cwe_id="CWE-552",
                owasp_category="A01:2021-Broken Access Control",
                nist_control="AC-3, SC-28",
                description=f"The Git repository metadata '{git_url}' is publicly accessible over HTTP.",
                impact="Attackers can reconstruct and download the entire application source code, commit history, and historical secrets.",
                remediation="Configure web server to deny access to the '.git' directory.",
                remediation_code_snippet="# Nginx Rule:\nlocation ~ /\\.git {\n    deny all;\n    return 404;\n}",
                references=["https://cwe.mitre.org/data/definitions/552.html"],
                evidence=Evidence(
                    location=git_url,
                    observed_value=f"HTTP 200 OK: '{resp.text.strip()}'",
                    expected_value="HTTP 404 Not Found or HTTP 403 Forbidden",
                ),
                fingerprint=calculate_fingerprint("DAST-EXP-002", git_url, "git_head_exposed"),
            ))
    except Exception:
        pass

    # --- 3. Spring Boot Actuator Exposure (DAST-EXP-003) ---
    for act_path in ("/actuator/env", "/actuator/health", "/actuator"):
        try:
            act_url = f"{base_url}{act_path}"
            resp = await client.get(act_url, follow_redirects=False)
            if resp.status_code == 200 and "application/json" in resp.headers.get("content-type", ""):
                if "status" in resp.text or "propertySources" in resp.text or "_links" in resp.text:
                    findings.append(Finding(
                        scan_id="auto",
                        engine="web_dast",
                        check_id="DAST-EXP-003",
                        category="Information Exposure",
                        title=f"Publicly Exposed Spring Boot Actuator Endpoint ({act_path})",
                        severity=Severity.HIGH,
                        cvss_score=7.5,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        cwe_id="CWE-200",
                        owasp_category="A05:2021-Security Misconfiguration",
                        nist_control="AC-3",
                        description=f"Spring Boot Actuator management endpoint '{act_url}' is accessible without authentication.",
                        impact="Exposes internal JVM health metrics, loaded environment variables, thread dumps, and configuration properties.",
                        remediation="Restrict Actuator endpoints to internal management networks or disable exposure in application.yml.",
                        remediation_code_snippet="management.endpoints.web.exposure.exclude=*",
                        references=["https://docs.spring.io/spring-boot/docs/current/reference/html/actuator.html"],
                        evidence=Evidence(
                            location=act_url,
                            observed_value=f"HTTP 200 with Actuator JSON: {resp.text[:120]}...",
                            expected_value="HTTP 401 Unauthorized or HTTP 403 Forbidden",
                        ),
                        fingerprint=calculate_fingerprint("DAST-EXP-003", act_url, "actuator_open"),
                    ))
                    break
        except Exception:
            pass

    # --- 4. OpenAPI / Swagger Raw Spec Exposure (DAST-EXP-004) ---
    for spec_path in ("/swagger.json", "/openapi.json", "/v2/api-docs"):
        try:
            spec_url = f"{base_url}{spec_path}"
            resp = await client.get(spec_url, follow_redirects=False)
            if resp.status_code == 200 and any(k in resp.text for k in ('"openapi":', '"swagger":', '"paths":')):
                findings.append(Finding(
                    scan_id="auto",
                    engine="web_dast",
                    check_id="DAST-EXP-004",
                    category="Information Exposure",
                    title="Publicly Exposed OpenAPI / Swagger Specification",
                    severity=Severity.LOW,
                    cvss_score=3.7,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    cwe_id="CWE-200",
                    owasp_category="A05:2021-Security Misconfiguration",
                    nist_control="AC-3",
                    description=f"Raw OpenAPI/Swagger documentation schema is accessible at '{spec_url}'.",
                    impact="Reveals the entire API surface, unpublished endpoints, parameter types, and internal routes.",
                    remediation="Require authentication to access API schema specifications in production environments.",
                    references=["https://swagger.io/docs/specification/about/"],
                    evidence=Evidence(
                        location=spec_url,
                        observed_value="HTTP 200 containing OpenAPI schema definition",
                        expected_value="Authentication required or schema disabled in production",
                    ),
                    fingerprint=calculate_fingerprint("DAST-EXP-004", spec_url, "swagger_exposed"),
                ))
                break
        except Exception:
            pass

    # --- 5. Dangerous HTTP TRACE Method (DAST-METH-001) ---
    try:
        trace_resp = await client.request("TRACE", base_url)
        if trace_resp.status_code == 200 and "message/http" in trace_resp.headers.get("content-type", ""):
            findings.append(Finding(
                scan_id="auto",
                engine="web_dast",
                check_id="DAST-METH-001",
                category="Security Misconfiguration",
                title="Dangerous HTTP TRACE Method Enabled (Cross-Site Tracing XST)",
                severity=Severity.MEDIUM,
                cvss_score=4.3,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
                cwe_id="CWE-489",
                owasp_category="A05:2021-Security Misconfiguration",
                nist_control="CM-6",
                description="The server responded to an HTTP TRACE request by echoing back the request headers.",
                impact="Attackers can bypass HttpOnly cookie protections via Cross-Site Tracing (XST) in browsers.",
                remediation="Disable TRACE and TRACK methods in your web server configuration.",
                remediation_code_snippet="# Apache:\nTraceEnable off\n\n# Nginx:\nif ($request_method = TRACE) {\n    return 405;\n}",
                references=["https://owasp.org/www-community/attacks/Cross_Site_Tracing"],
                evidence=Evidence(
                    location=base_url,
                    observed_value="HTTP 200 response echoing TRACE headers",
                    expected_value="HTTP 405 Method Not Allowed",
                ),
                fingerprint=calculate_fingerprint("DAST-METH-001", base_url, "trace_enabled"),
            ))
    except Exception:
        pass

    return findings
