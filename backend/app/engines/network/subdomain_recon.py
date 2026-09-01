"""
Contract 03 §3.1 & Contract 08 §2.4: Passive OSINT Subdomain Reconnaissance & Takeover Auditor.
Queries Certificate Transparency logs (crt.sh), resolves subdomains, detects dangling CNAME takeovers.
"""

from __future__ import annotations
import asyncio
import re
import socket
from typing import List, Optional, Callable, Awaitable, Set
import httpx
import dns.asyncresolver
import dns.resolver

from app.core.models import (
    Target,
    Finding,
    ScanConfig,
    Evidence,
    Severity,
    DiscoveredSubdomain,
    calculate_fingerprint,
)
from app.engines.base import LogCallback, FindingCallback, SubdomainDiscoveredCallback

# Authoritative CNAME signatures of third-party cloud services prone to dangling takeover
TAKEOVER_CNAME_SIGNATURES = {
    "s3.amazonaws.com": "AWS S3 Bucket",
    "github.io": "GitHub Pages",
    "herokuapp.com": "Heroku App",
    "herokudns.com": "Heroku DNS",
    "azurewebsites.net": "Azure App Service",
    "cloudapp.net": "Azure Cloud App",
    "trafficmanager.net": "Azure Traffic Manager",
    "fastly.net": "Fastly CDN",
    "myshopify.com": "Shopify Store",
    "zendesk.com": "Zendesk Help Center",
    "ghost.io": "Ghost Blog",
    "surge.sh": "Surge.sh",
    "bitbucket.io": "Bitbucket Cloud",
    "pantheonsite.io": "Pantheon CMS",
    "wordpress.com": "WordPress.com",
    "unbouncepages.com": "Unbounce Landing Page",
}

SENSITIVE_SUBDOMAIN_PREFIXES = {
    "admin", "dev", "devel", "development", "staging", "stage",
    "internal", "corp", "private", "vpn", "portal", "test", "testing",
    "uat", "qa", "api-dev", "auth-dev", "intranet", "db", "database",
}


async def resolve_subdomain_details(
    subdomain: str,
    resolver: Optional[dns.asyncresolver.Resolver] = None
) -> DiscoveredSubdomain:
    """
    Asynchronously resolves IP addresses and CNAME records for a subdomain.
    """
    if resolver is None:
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = 3.0

    ip_addresses: List[str] = []
    cname_targets: List[str] = []
    is_takeover_vulnerable = False
    service_fingerprint: Optional[str] = None

    # 1. Query CNAME
    try:
        cname_answers = await resolver.resolve(subdomain, "CNAME")
        for rdata in cname_answers:
            target_cname = str(rdata.target).rstrip(".").lower()
            cname_targets.append(target_cname)

            for sig, svc_name in TAKEOVER_CNAME_SIGNATURES.items():
                if target_cname.endswith(sig):
                    service_fingerprint = svc_name
                    # Check if the CNAME target itself resolves to NXDOMAIN or is dangling
                    try:
                        await resolver.resolve(target_cname, "A")
                    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                        is_takeover_vulnerable = True
                    except Exception:
                        pass
                    break
    except Exception:
        pass

    # 2. Query A / AAAA records
    try:
        a_answers = await resolver.resolve(subdomain, "A")
        for rdata in a_answers:
            ip_addresses.append(str(rdata))
    except Exception:
        pass

    try:
        aaaa_answers = await resolver.resolve(subdomain, "AAAA")
        for rdata in aaaa_answers:
            ip_addresses.append(str(rdata))
    except Exception:
        pass

    return DiscoveredSubdomain(
        domain=subdomain,
        ip_addresses=ip_addresses,
        cname_targets=cname_targets,
        is_takeover_vulnerable=is_takeover_vulnerable,
        service_fingerprint=service_fingerprint,
        discovered_via="crt.sh",
        dns_status="ACTIVE" if ip_addresses else "NXDOMAIN",
    )


async def audit_subdomain_osint(
    domain: str,
    config: ScanConfig,
    scan_id: str,
    emit_subdomain: Optional[SubdomainDiscoveredCallback] = None,
    emit_finding: Optional[FindingCallback] = None,
    emit_log: Optional[LogCallback] = None,
) -> List[Finding]:
    """
    Queries crt.sh Certificate Transparency logs, discovers subdomains, and evaluates takeover risks.
    """
    findings: List[Finding] = []
    if not config.osint.subdomain_enumeration:
        return findings

    val = domain.lower().strip()
    if "://" in val:
        import urllib.parse
        parsed = urllib.parse.urlparse(val)
        val = (parsed.hostname or val).lower().strip()
    if ":" in val:
        val = val.split(":")[0]
    if "/" in val:
        val = val.split("/")[0]
    if val.startswith("www."):
        val = val[4:]

    parts = val.split(".")
    if len(parts) >= 2 and not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", val):
        apex_domain = ".".join(parts[-2:])
    else:
        apex_domain = val

    # Don't query crt.sh for IP addresses or local domains
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", apex_domain) or apex_domain in ("localhost", "127.0.0.1"):
        return findings

    discovered_names: Set[str] = set()
    timeout_sec = config.osint.crtsh_timeout_seconds or 10.0

    try:
        url = f"https://crt.sh/?q=%25.{apex_domain}&output=json"
        # crt.sh is a fixed external dependency; provider redirects must not
        # expand the scan's external egress destinations.
        async with httpx.AsyncClient(timeout=timeout_sec, follow_redirects=False, verify=True) as client:
            resp = await client.get(url, headers={"User-Agent": "CyberAssess-OSINT/4.1.0"})
            if resp.status_code == 200:
                entries = resp.json()
                if isinstance(entries, list):
                    for entry in entries:
                        name_val = entry.get("name_value", "")
                        for line in name_val.split("\n"):
                            cand = line.strip().lower()
                            if cand.startswith("*."):
                                cand = cand[2:]
                            if cand and cand.endswith(apex_domain) and cand != apex_domain:
                                discovered_names.add(cand)
    except Exception as exc:
        if emit_log:
            from app.core.models import LogLevel
            await emit_log(LogLevel.WARNING, f"crt.sh query exception: {str(exc)}")

    # Process and resolve discovered subdomains
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = 3.0

    for sub in sorted(discovered_names):
        sub_info = await resolve_subdomain_details(sub, resolver)
        
        if emit_subdomain:
            await emit_subdomain(sub_info)

        # Evaluate Dangling CNAME Takeover (NET-OSINT-001)
        if sub_info.is_takeover_vulnerable and config.osint.subdomain_takeover_check:
            loc = f"dns://{sub}"
            obs = f"CNAME -> {', '.join(sub_info.cname_targets)} ({sub_info.service_fingerprint or 'Unclaimed Cloud Target'})"
            findings.append(
                Finding(
                    scan_id=scan_id,
                    engine="network",
                    check_id="NET-OSINT-001",
                    category="OSINT & Attack Surface",
                    title=f"Dangling DNS CNAME / Subdomain Takeover Vulnerability on '{sub}'",
                    severity=Severity.CRITICAL,
                    cvss_score=9.1,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                    cwe_id="CWE-284",
                    owasp_category="A01:2021-Broken Access Control",
                    nist_control="AC-3, SC-7",
                    description=(
                        f"Subdomain '{sub}' contains a DNS CNAME record pointing to an unclaimed third-party "
                        f"service ({sub_info.service_fingerprint or 'cloud provider'}). An external attacker can register "
                        "the missing resource name and hijack the subdomain to serve malicious content or steal session cookies."
                    ),
                    impact="Complete subdomain takeover, cross-domain cookie stealing, and brand reputation loss.",
                    remediation=f"Delete the dangling DNS CNAME record for '{sub}' or register the missing resource in the cloud console.",
                    remediation_code_snippet=f"# Delete or update DNS record:\n# {sub}. IN CNAME {', '.join(sub_info.cname_targets)} (REMOVE)",
                    references=[
                        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover",
                        "https://cwe.mitre.org/data/definitions/284.html"
                    ],
                    evidence=Evidence(
                        location=loc,
                        observed_value=obs,
                        expected_value="CNAME target active and claimed, or record removed.",
                    ),
                    fingerprint=calculate_fingerprint("NET-OSINT-001", loc, obs),
                    source_tool="native",
                )
            )

        # Evaluate Sensitive Subdomain Disclosure (NET-OSINT-002)
        prefix = sub.replace(f".{apex_domain}", "").split(".")[0]
        if prefix in SENSITIVE_SUBDOMAIN_PREFIXES:
            loc = f"dns://{sub}"
            obs = f"Discovered subdomain: {sub} (Resolved IPs: {', '.join(sub_info.ip_addresses) or 'Unresolved'})"
            findings.append(
                Finding(
                    scan_id=scan_id,
                    engine="network",
                    check_id="NET-OSINT-002",
                    category="OSINT & Reconnaissance",
                    title=f"Sensitive Subdomain Discovered via Public Certificate Transparency: '{sub}'",
                    severity=Severity.MEDIUM,
                    cvss_score=5.3,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    cwe_id="CWE-200",
                    owasp_category="A05:2021-Security Misconfiguration",
                    nist_control="CM-6",
                    description=(
                        f"The subdomain '{sub}' matches a sensitive environment pattern ('{prefix}') and is publicly "
                        "indexed in Certificate Transparency logs. Non-production environments exposed to the internet "
                        "expand the attack surface."
                    ),
                    impact="Reconnaissance discovery of pre-production or administrative environments.",
                    remediation=f"Restrict access to '{sub}' using internal VPNs, IP whitelisting, or firewall rules.",
                    remediation_code_snippet=f"# Protect {sub} behind VPN / IP Whitelist in Nginx:\nallow 10.0.0.0/8;\ndeny all;",
                    references=[
                        "https://certificate.transparency.dev/",
                        "https://cwe.mitre.org/data/definitions/200.html"
                    ],
                    evidence=Evidence(
                        location=loc,
                        observed_value=obs,
                        expected_value="Sensitive staging/admin environments restricted from public internet.",
                    ),
                    fingerprint=calculate_fingerprint("NET-OSINT-002", loc, obs),
                    source_tool="native",
                )
            )

    return findings
