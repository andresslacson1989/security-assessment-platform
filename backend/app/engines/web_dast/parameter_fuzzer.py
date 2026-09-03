"""
Contract 03 §3.2 & Contract 08 §3.4: Active Parameter Fuzzing & Benign Injection Engine.
Performs non-destructive time-based SQLi, boolean differential SQLi, canary XSS,
LFI path traversal, SSTI expression evaluation, and open redirect detection with reproduction cURL synthesis.
"""

from __future__ import annotations
import logging
import asyncio
import re
import secrets
import time
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
from typing import List, Dict, Any, Optional, Tuple
import httpx

from app.core.models import (
    Finding,
    Evidence,
    Severity,
    ScanConfig,
    DiscoveredEndpoint,
    calculate_fingerprint,
    sanitize_reproduction_curl,
)
from app.engines.base import LogCallback, FindingCallback

logger = logging.getLogger("cyberassess.engines.parameter_fuzzer")


def format_curl_poc(method: str, url: str, headers: Optional[Dict[str, str]] = None, body: Optional[str] = None) -> str:
    """
    Synthesizes a standalone copy-pasteable cURL reproduction command.
    """
    cmd = f'curl -i -s -k -X {method.upper()} "{url}"'
    if headers:
        for k, v in headers.items():
            if k.lower() not in ("content-length", "host"):
                cmd += f' -H "{k}: {v}"'
    if body:
        # Escape double quotes
        escaped_body = body.replace('"', '\\"')
        cmd += f' -d "{escaped_body}"'
    return sanitize_reproduction_curl(cmd) or cmd


class ParameterFuzzExecution:
    """
    Authoritative per-URL parameter fuzzing execution record.
    Tracks parameters tested, requested probes, completed probes, and failed probes.
    """
    def __init__(
        self,
        url: str,
        parameters_tested: Optional[List[str]] = None,
        probes_requested: int = 0,
        probes_completed: int = 0,
        probes_failed: int = 0,
        failed_probe_details: Optional[List[str]] = None,
    ):
        self.url = url
        self.parameters_tested = parameters_tested or []
        self.probes_requested = probes_requested
        self.probes_completed = probes_completed
        self.probes_failed = probes_failed
        self.failed_probe_details = failed_probe_details or []

    @property
    def is_fully_completed(self) -> bool:
        return self.probes_requested > 0 and self.probes_failed == 0 and self.probes_completed == self.probes_requested

    @property
    def is_partial(self) -> bool:
        return self.probes_failed > 0 and self.probes_completed > 0

    @property
    def is_failed(self) -> bool:
        return self.probes_requested > 0 and self.probes_completed == 0


class ParameterFuzzAuditResult(list):
    """
    Subclass of list holding parameter fuzzing findings, while preserving
    authoritative per-endpoint probe execution records.
    """
    def __init__(
        self,
        findings: List[Finding],
        executions: Optional[Dict[str, ParameterFuzzExecution]] = None,
    ):
        super().__init__(findings)
        self.findings = findings
        self.executions = executions or {}


async def audit_parameter_fuzzing(
    target_url: str,
    discovered_endpoints: List[DiscoveredEndpoint],
    client: httpx.AsyncClient,
    config: ScanConfig,
    scan_id: str,
    emit_finding: Optional[FindingCallback] = None,
    emit_log: Optional[LogCallback] = None,
) -> ParameterFuzzAuditResult:
    """
    Performs safe, bounded parameter fuzzing across all discovered URL query parameters and forms.
    """
    findings: List[Finding] = []
    executions: Dict[str, ParameterFuzzExecution] = {}
    fuzz_cfg = config.fuzzing
    if not fuzz_cfg.enabled:
        return ParameterFuzzAuditResult(findings=findings, executions=executions)

    # Collect URLs with query parameters or forms to test
    test_urls = set()
    if "?" in target_url:
        test_urls.add(target_url)
    for ep in discovered_endpoints:
        if "?" in ep.url:
            test_urls.add(ep.url)

    # If no parameterized URLs found, test baseline endpoint with sample query params
    if not test_urls:
        test_urls.add(f"{target_url.rstrip('/')}/?id=1&search=test&redirect=home")

    delay_target = fuzz_cfg.delay_seconds or 2.0

    for url_str in test_urls:
        parsed = urlparse(url_str)
        params = dict(parse_qsl(parsed.query))
        if not params:
            continue

        exec_rec = ParameterFuzzExecution(url=url_str, parameters_tested=list(params.keys()))
        executions[url_str] = exec_rec

        for param_name, orig_val in params.items():
            # --- 1. Time-Based SQL Injection (DAST-INJ-001) ---
            if fuzz_cfg.fuzz_sqli:
                exec_rec.probes_requested += 1
                try:
                    # Baseline measurement
                    t0_start = time.perf_counter()
                    await client.get(url_str, timeout=config.timeout_seconds)
                    t0 = time.perf_counter() - t0_start

                    # Injection probe
                    sqli_payload = f"{orig_val}' AND (SELECT 1 FROM (SELECT(SLEEP({int(delay_target)})))a)-- "
                    fuzzed_params = dict(params)
                    fuzzed_params[param_name] = sqli_payload
                    fuzzed_query = urlencode(fuzzed_params)
                    fuzzed_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, fuzzed_query, parsed.fragment))

                    t1_start = time.perf_counter()
                    resp = await client.get(fuzzed_url, timeout=config.timeout_seconds + delay_target + 2.0)
                    t1 = time.perf_counter() - t1_start
                    exec_rec.probes_completed += 1

                    if t1 >= t0 + (delay_target - 0.3):
                        loc = f"{url_str} [{param_name}]"
                        obs = f"Parameter '{param_name}' provoked {t1:.2f}s response latency (Baseline: {t0:.2f}s with SLEEP({int(delay_target)}) probe)"
                        curl_cmd = format_curl_poc("GET", fuzzed_url)
                        f = Finding(
                            scan_id=scan_id,
                            engine="web_dast",
                            check_id="DAST-INJ-001",
                            category="Injection",
                            title=f"Time-Based Blind SQL Injection in Parameter '{param_name}'",
                            severity=Severity.CRITICAL,
                            cvss_score=9.8,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            cwe_id="CWE-89",
                            owasp_category="A03:2021-Injection",
                            nist_control="SI-10",
                            description=(
                                f"Parameter '{param_name}' at endpoint '{parsed.path}' is vulnerable to time-based blind SQL injection. "
                                f"The application executed a database sleep probe causing a measured delay of {t1:.2f} seconds."
                            ),
                            impact="Full database exfiltration, authentication bypass, data manipulation, and potential host compromise.",
                            remediation="Use parameterized SQL queries (Prepared Statements) or an Object-Relational Mapper (ORM). Never concatenate user input into SQL.",
                            remediation_code_snippet="# Parameterized query in Python:\ncursor.execute('SELECT * FROM items WHERE id = %s', (item_id,))",
                            references=[
                                "https://owasp.org/www-community/attacks/SQL_Injection",
                                "https://cwe.mitre.org/data/definitions/89.html"
                            ],
                            evidence=Evidence(
                                location=loc,
                                observed_value=obs,
                                expected_value="Consistent response latency without database timing execution",
                                request_details={"url": fuzzed_url, "parameter": param_name, "payload": sqli_payload},
                                response_details={"status_code": resp.status_code, "latency_seconds": round(t1, 2)},
                            ),
                            reproduction_curl=curl_cmd,
                            fingerprint=calculate_fingerprint("DAST-INJ-001", loc, "time_based_sqli"),
                            source_tool="native",
                        )
                        findings.append(f)
                        if emit_finding:
                            await emit_finding(f)
                except Exception as exc:
                    exec_rec.probes_failed += 1
                    exec_rec.failed_probe_details.append(f"SQLi on {param_name}: {type(exc).__name__} ({exc})")
                    logger.debug("SQL injection probe failed: error_type=%s", type(exc).__name__)

            # --- 2. Canary Reflected XSS (DAST-XSS-001) ---
            if fuzz_cfg.fuzz_xss:
                exec_rec.probes_requested += 1
                try:
                    canary_hex = secrets.token_hex(6)
                    canary_token = f"_CYBERASSESS_XSS_{canary_hex}_"
                    xss_payload = f'"{canary_token}<script>{canary_token}</script>'
                    fuzzed_params = dict(params)
                    fuzzed_params[param_name] = xss_payload
                    fuzzed_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(fuzzed_params), parsed.fragment))

                    resp = await client.get(fuzzed_url, timeout=config.timeout_seconds)
                    exec_rec.probes_completed += 1
                    if canary_token in resp.text and (f"<script>{canary_token}</script>" in resp.text or f'"{canary_token}' in resp.text):
                        loc = f"{url_str} [{param_name}]"
                        obs = f"Canary token '{canary_token}' and unescaped HTML tags reflected directly in response body."
                        curl_cmd = format_curl_poc("GET", fuzzed_url)
                        f = Finding(
                            scan_id=scan_id,
                            engine="web_dast",
                            check_id="DAST-XSS-001",
                            category="Injection",
                            title=f"Reflected Cross-Site Scripting (XSS) in Parameter '{param_name}'",
                            severity=Severity.HIGH,
                            cvss_score=7.5,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
                            cwe_id="CWE-79",
                            owasp_category="A03:2021-Injection",
                            nist_control="SI-10",
                            description=(
                                f"Parameter '{param_name}' at '{parsed.path}' is echoed back in the HTML response without contextual output encoding. "
                                "An attacker can craft a link executing arbitrary client-side JavaScript in victims' browsers."
                            ),
                            impact="Account takeover, session cookie theft, UI defacement, and credential harvesting.",
                            remediation="Implement contextual output encoding (HTML Entity / Attribute encoding) and deploy a strict Content-Security-Policy.",
                            remediation_code_snippet="# Contextual HTML encoding in Python:\nimport html\nsafe_output = html.escape(user_input)",
                            references=[
                                "https://owasp.org/www-community/attacks/xss/",
                                "https://cwe.mitre.org/data/definitions/79.html"
                            ],
                            evidence=Evidence(
                                location=loc,
                                observed_value=obs,
                                expected_value="Contextually encoded output without unescaped tags",
                                request_details={"url": fuzzed_url, "parameter": param_name, "payload": xss_payload},
                                response_details={"status_code": resp.status_code},
                                raw_response_snippet=resp.text[:300],
                            ),
                            reproduction_curl=curl_cmd,
                            fingerprint=calculate_fingerprint("DAST-XSS-001", loc, canary_token),
                            source_tool="native",
                        )
                        findings.append(f)
                        if emit_finding:
                            await emit_finding(f)
                except Exception as exc:
                    exec_rec.probes_failed += 1
                    exec_rec.failed_probe_details.append(f"XSS on {param_name}: {type(exc).__name__} ({exc})")
                    logger.debug("XSS probe failed: error_type=%s", type(exc).__name__)

            # --- 3. Local File Inclusion / Path Traversal (DAST-LFI-001) ---
            if fuzz_cfg.fuzz_lfi:
                exec_rec.probes_requested += 1
                try:
                    lfi_payload = "../../../../etc/passwd"
                    fuzzed_params = dict(params)
                    fuzzed_params[param_name] = lfi_payload
                    fuzzed_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(fuzzed_params), parsed.fragment))

                    resp = await client.get(fuzzed_url, timeout=config.timeout_seconds)
                    exec_rec.probes_completed += 1
                    if re.search(r"root:.*:0:0:", resp.text) or "[fonts]" in resp.text.lower() or "[extensions]" in resp.text.lower():
                        loc = f"{url_str} [{param_name}]"
                        obs = f"Parameter '{param_name}' path traversal returned system file contents (/etc/passwd)."
                        curl_cmd = format_curl_poc("GET", fuzzed_url)
                        f = Finding(
                            scan_id=scan_id,
                            engine="web_dast",
                            check_id="DAST-LFI-001",
                            category="Broken Access Control",
                            title=f"Local File Inclusion (LFI) / Path Traversal in Parameter '{param_name}'",
                            severity=Severity.HIGH,
                            cvss_score=8.6,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                            cwe_id="CWE-22",
                            owasp_category="A01:2021-Broken Access Control",
                            nist_control="AC-3, SI-10",
                            description=(
                                f"Parameter '{param_name}' at '{parsed.path}' accepts directory traversal sequences (`../../`) "
                                "and reads arbitrary files from the server filesystem."
                            ),
                            impact="Arbitrary local file reading, exposing source code, credentials, and system configuration.",
                            remediation="Validate user-supplied filenames against a strict whitelist or use an index mapping. Never pass input directly to filesystem APIs.",
                            remediation_code_snippet="# Path normalization check:\nimport os\nsafe_path = os.path.abspath(os.path.join(BASE_DIR, filename))\nif not safe_path.startswith(BASE_DIR):\n    raise ValueError('Access Denied')",
                            references=[
                                "https://owasp.org/www-community/attacks/Path_Traversal",
                                "https://cwe.mitre.org/data/definitions/22.html"
                            ],
                            evidence=Evidence(
                                location=loc,
                                observed_value=obs,
                                expected_value="File access restricted to authorized root directory with path resolution verification",
                                request_details={"url": fuzzed_url, "parameter": param_name, "payload": lfi_payload},
                                response_details={"status_code": resp.status_code},
                                raw_response_snippet=resp.text[:200],
                            ),
                            reproduction_curl=curl_cmd,
                            fingerprint=calculate_fingerprint("DAST-LFI-001", loc, "lfi_passwd"),
                            source_tool="native",
                        )
                        findings.append(f)
                        if emit_finding:
                            await emit_finding(f)
                except Exception as exc:
                    exec_rec.probes_failed += 1
                    exec_rec.failed_probe_details.append(f"LFI on {param_name}: {type(exc).__name__} ({exc})")
                    logger.debug("LFI probe failed: error_type=%s", type(exc).__name__)

            # --- 4. Server-Side Template Injection (DAST-SSTI-001) ---
            if fuzz_cfg.fuzz_ssti:
                exec_rec.probes_requested += 1
                try:
                    ssti_payload = "{{7*7}}"
                    fuzzed_params = dict(params)
                    fuzzed_params[param_name] = ssti_payload
                    fuzzed_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(fuzzed_params), parsed.fragment))

                    resp = await client.get(fuzzed_url, timeout=config.timeout_seconds)
                    exec_rec.probes_completed += 1
                    # Check if '49' is in response but not the literal '{{7*7}}'
                    if "49" in resp.text and "{{7*7}}" not in resp.text:
                        loc = f"{url_str} [{param_name}]"
                        obs = f"Template mathematical expression '{ssti_payload}' evaluated to '49' in rendered output."
                        curl_cmd = format_curl_poc("GET", fuzzed_url)
                        f = Finding(
                            scan_id=scan_id,
                            engine="web_dast",
                            check_id="DAST-SSTI-001",
                            category="Injection",
                            title=f"Server-Side Template Injection (SSTI) in Parameter '{param_name}'",
                            severity=Severity.CRITICAL,
                            cvss_score=9.8,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            cwe_id="CWE-1336",
                            owasp_category="A03:2021-Injection",
                            nist_control="SI-10",
                            description=(
                                f"Parameter '{param_name}' is evaluated dynamically by a server-side template engine (Jinja2, Twig, Freemarker, etc.). "
                                "Mathematical expressions were executed on the server, opening a direct vector to Remote Code Execution (RCE)."
                            ),
                            impact="Remote Code Execution (RCE), full server takeover, and arbitrary command execution.",
                            remediation="Do not pass user input directly into template string rendering. Pass user variables as data parameters to pre-compiled templates.",
                            remediation_code_snippet="# Secure Jinja2 rendering:\n# INSECURE: jinja2.Template(user_str).render()\n# SECURE: template.render(user_data=user_input)",
                            references=[
                                "https://portswigger.net/web-security/server-side-template-injection",
                                "https://cwe.mitre.org/data/definitions/1336.html"
                            ],
                            evidence=Evidence(
                                location=loc,
                                observed_value=obs,
                                expected_value="Template expressions rendered literally as text without mathematical execution",
                                request_details={"url": fuzzed_url, "parameter": param_name, "payload": ssti_payload},
                                response_details={"status_code": resp.status_code},
                                raw_response_snippet=resp.text[:200],
                            ),
                            reproduction_curl=curl_cmd,
                            fingerprint=calculate_fingerprint("DAST-SSTI-001", loc, "ssti_49"),
                            source_tool="native",
                        )
                        findings.append(f)
                        if emit_finding:
                            await emit_finding(f)
                except Exception as exc:
                    exec_rec.probes_failed += 1
                    exec_rec.failed_probe_details.append(f"SSTI on {param_name}: {type(exc).__name__} ({exc})")
                    logger.debug("SSTI probe failed: error_type=%s", type(exc).__name__)

            # --- 5. Open Redirection (DAST-REDIR-001) ---
            if fuzz_cfg.fuzz_redirect:
                exec_rec.probes_requested += 1
                try:
                    redir_payload = "https://attacker.invalid"
                    fuzzed_params = dict(params)
                    fuzzed_params[param_name] = redir_payload
                    fuzzed_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(fuzzed_params), parsed.fragment))

                    # Reuse the engine's validated, connection-pinned client;
                    # disabling redirect following here must not create a
                    # second unvalidated socket path.
                    resp = await client.get(fuzzed_url, follow_redirects=False)
                    exec_rec.probes_completed += 1
                    if resp.status_code in (301, 302, 303, 307, 308):
                        location_hdr = resp.headers.get("location", "")
                        if "attacker.invalid" in location_hdr:
                            loc = f"{url_str} [{param_name}]"
                            obs = f"HTTP {resp.status_code} Redirect Location: '{location_hdr}' reflects untrusted external target."
                            curl_cmd = format_curl_poc("GET", fuzzed_url)
                            f = Finding(
                                    scan_id=scan_id,
                                    engine="web_dast",
                                    check_id="DAST-REDIR-001",
                                    category="Broken Access Control",
                                    title=f"Open Redirection via Parameter '{param_name}'",
                                    severity=Severity.MEDIUM,
                                    cvss_score=6.1,
                                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                                    cwe_id="CWE-601",
                                    owasp_category="A01:2021-Broken Access Control",
                                    nist_control="AC-3",
                                    description=(
                                        f"Parameter '{param_name}' allows arbitrary external redirect targets. "
                                        "Attackers can leverage this to conduct convincing phishing attacks using the trusted domain name."
                                    ),
                                    impact="Phishing attacks, credential harvesting, and OAuth token redirection leaks.",
                                    remediation="Validate redirect destinations against a strict whitelist of relative paths or authorized hostnames.",
                                    remediation_code_snippet="# Redirect URL whitelist check:\nALLOWED_HOSTS = {'example.com', 'app.example.com'}\ntarget_host = urllib.parse.urlparse(target_url).hostname\nif target_host and target_host not in ALLOWED_HOSTS:\n    target_url = '/dashboard'",
                                    references=[
                                        "https://cwe.mitre.org/data/definitions/601.html",
                                        "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"
                                    ],
                                    evidence=Evidence(
                                        location=loc,
                                        observed_value=obs,
                                        expected_value="Redirect restricted to same-origin paths or whitelisted domains",
                                        request_details={"url": fuzzed_url, "parameter": param_name, "payload": redir_payload},
                                        response_details={"status_code": resp.status_code, "headers": dict(resp.headers)},
                                    ),
                                    reproduction_curl=curl_cmd,
                                    fingerprint=calculate_fingerprint("DAST-REDIR-001", loc, "open_redir"),
                                    source_tool="native",
                                )
                            findings.append(f)
                            if emit_finding:
                                await emit_finding(f)
                except Exception as exc:
                    exec_rec.probes_failed += 1
                    exec_rec.failed_probe_details.append(f"Open Redirect on {param_name}: {type(exc).__name__} ({exc})")
                    logger.debug("Open redirect probe failed: error_type=%s", type(exc).__name__)

    return ParameterFuzzAuditResult(findings=findings, executions=executions)
