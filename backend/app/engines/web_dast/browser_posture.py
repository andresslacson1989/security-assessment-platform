"""
Contract 03, 06 & 08 Subresource Integrity (SRI) and Mixed Content Auditor.
"""

from __future__ import annotations
import urllib.parse
from typing import List, Optional
from bs4 import BeautifulSoup
import httpx

from app.core.models import Finding, Evidence, Severity, calculate_fingerprint, LogLevel
from app.engines.base import LogCallback


def normalize_target_url(target_value: str) -> str:
    if not target_value.startswith("http://") and not target_value.startswith("https://"):
        return f"https://{target_value}"
    return target_value


async def audit_browser_posture(
    target_value: str,
    client: httpx.AsyncClient,
    emit_log: Optional[LogCallback] = None,
) -> List[Finding]:
    """
    Parses HTML DOM to detect external scripts lacking SRI and passive mixed content.
    """
    findings: List[Finding] = []
    url = normalize_target_url(target_value)
    is_https = url.startswith("https://")
    parsed_target = urllib.parse.urlparse(url)
    target_host = parsed_target.hostname or ""

    if emit_log:
        await emit_log(LogLevel.INFO, f"Parsing HTML DOM for SRI and Mixed Content on {url}...")

    try:
        resp = await client.get(url, follow_redirects=True)
        if resp.status_code != 200 or "text/html" not in resp.headers.get("content-type", ""):
            return findings
        html = resp.text
    except Exception:
        return findings

    soup = BeautifulSoup(html, "html.parser")

    # --- 1. Subresource Integrity (SRI) Check (DAST-SRI-001) ---
    scripts = soup.find_all("script", src=True)
    links = soup.find_all("link", rel="stylesheet", href=True)
    missing_sri_assets: List[str] = []

    for tag in scripts:
        src = tag.get("src", "")
        if src.startswith("//") or src.startswith("http://") or src.startswith("https://"):
            asset_parsed = urllib.parse.urlparse(src)
            asset_host = asset_parsed.hostname or ""
            if asset_host and asset_host != target_host and not tag.get("integrity"):
                missing_sri_assets.append(src)

    for tag in links:
        href = tag.get("href", "")
        if href.startswith("//") or href.startswith("http://") or href.startswith("https://"):
            asset_parsed = urllib.parse.urlparse(href)
            asset_host = asset_parsed.hostname or ""
            if asset_host and asset_host != target_host and not tag.get("integrity"):
                missing_sri_assets.append(href)

    if missing_sri_assets:
        sample = missing_sri_assets[0]
        findings.append(Finding(
            scan_id="auto",
            engine="web_dast",
            check_id="DAST-SRI-001",
            category="Third-Party Supply Chain",
            title="Missing Subresource Integrity (SRI) on External CDN Asset",
            severity=Severity.LOW,
            cvss_score=3.7,
            cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
            cwe_id="CWE-353",
            owasp_category="A06:2021-Vulnerable and Outdated Components",
            nist_control="SI-7",
            description=(
                f"Found {len(missing_sri_assets)} third-party script/stylesheet assets loaded from external CDNs "
                f"without 'integrity' hashes (e.g. '{sample}')."
            ),
            impact="If the external CDN is compromised, malicious code could be injected into users' browsers without detection.",
            remediation="Add cryptographic 'integrity' (sha384/sha512) and 'crossorigin=\"anonymous\"' attributes to all CDN assets.",
            remediation_code_snippet="<script src=\"https://cdn.example.com/lib.js\"\n        integrity=\"sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC\"\n        crossorigin=\"anonymous\"></script>",
            references=["https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity"],
            evidence=Evidence(
                location=url,
                observed_value=f"Missing integrity on: {', '.join(missing_sri_assets[:3])}",
                expected_value="<script src=\"...\" integrity=\"sha384-...\" crossorigin=\"anonymous\">",
            ),
            fingerprint=calculate_fingerprint("DAST-SRI-001", url, sample),
        ))

    # --- 2. Mixed Content Detection (DAST-MIX-001) ---
    if is_https:
        mixed_assets: List[str] = []
        for tag in soup.find_all(["img", "script", "link", "iframe", "audio", "video"]):
            asset_url = tag.get("src") or tag.get("href")
            if asset_url and asset_url.startswith("http://"):
                mixed_assets.append(asset_url)

        if mixed_assets:
            findings.append(Finding(
                scan_id="auto",
                engine="web_dast",
                check_id="DAST-MIX-001",
                category="Cryptographic Failures",
                title="Passive Mixed Content Detected on HTTPS Page",
                severity=Severity.MEDIUM,
                cvss_score=4.3,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
                cwe_id="CWE-319",
                owasp_category="A02:2021-Cryptographic Failures",
                nist_control="SC-8",
                description=f"HTTPS page includes {len(mixed_assets)} assets loaded over unencrypted HTTP (e.g. '{mixed_assets[0]}').",
                impact="Unencrypted HTTP requests on an HTTPS site can be intercepted, tampered with, or blocked by modern browsers.",
                remediation="Update asset URLs to use 'https://' or protocol-relative '//'.",
                references=["https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content"],
                evidence=Evidence(
                    location=url,
                    observed_value=f"Insecure assets: {', '.join(mixed_assets[:3])}",
                    expected_value="All embedded resources loaded strictly over HTTPS",
                ),
                fingerprint=calculate_fingerprint("DAST-MIX-001", url, mixed_assets[0]),
            ))

    return findings
