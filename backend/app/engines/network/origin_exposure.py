"""
Contract 06 §1.1 & Contract 08 §2.5: Certificate Transparency (CT) Log IP Discovery & Direct Origin Exposure Auditor.
Identifies backend origin server IP addresses and unproxied subdomains bypassing Cloudflare / CDN reverse-proxy defenses.
"""

from __future__ import annotations
import asyncio
import ipaddress
import re
from typing import List, Optional, Set, Dict, Any, Tuple
import httpx
import dns.asyncresolver
import dns.resolver

from app.core.models import (
    Finding,
    ScanConfig,
    Evidence,
    Severity,
    DiscoveredSubdomain,
    calculate_fingerprint,
    LogLevel,
)
from app.engines.base import LogCallback, FindingCallback, SubdomainDiscoveredCallback

# ==============================================================================
# Official Cloudflare IP CIDR Ranges (IPv4 & IPv6)
# Reference: https://www.cloudflare.com/ips/
# ==============================================================================
CLOUDFLARE_IPV4_CIDRS = [
    "1.0.0.0/24",
    "1.1.1.0/24",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "108.162.192.0/18",
    "131.0.72.0/22",
    "141.101.64.0/18",
    "162.158.0.0/15",
    "172.64.0.0/13",
    "173.245.48.0/20",
    "188.114.96.0/20",
    "190.93.240.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
]

CLOUDFLARE_IPV6_CIDRS = [
    "2400:cb00::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2405:b500::/32",
    "2405:8100::/32",
    "2a06:98c0::/29",
    "2c0f:f248::/32",
]

CLOUDFLARE_NETWORKS = [
    ipaddress.ip_network(cidr) for cidr in (CLOUDFLARE_IPV4_CIDRS + CLOUDFLARE_IPV6_CIDRS)
]


def is_cloudflare_ip(ip_str: str) -> bool:
    """
    Returns True if the given IP address string belongs to Cloudflare's public Anycast network.
    """
    if not ip_str:
        return False
    try:
        ip_obj = ipaddress.ip_address(ip_str.strip())
        return any(ip_obj in net for net in CLOUDFLARE_NETWORKS)
    except ValueError:
        return False


def is_private_or_loopback_ip(ip_str: str) -> bool:
    """
    Returns True if IP is RFC 1918 private, loopback, or link-local.
    """
    if not ip_str:
        return False
    try:
        ip_obj = ipaddress.ip_address(ip_str.strip())
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
    except ValueError:
        return False


async def fetch_ct_logs(
    domain: str,
    timeout_sec: float = 8.0,
    emit_log: Optional[LogCallback] = None,
) -> Tuple[Set[str], List[Dict[str, Any]], List[str]]:
    """
    Dual-source Certificate Transparency log mining querying Certspotter and crt.sh.
    Returns: (discovered_subdomains, cert_records, wildcard_domains)
    """
    discovered_subdomains: Set[str] = set()
    cert_records: List[Dict[str, Any]] = []
    wildcard_domains: List[str] = []
    apex_domain = domain.lower().strip()

    if apex_domain.startswith("www."):
        apex_domain = apex_domain[4:]
    if ":" in apex_domain:
        apex_domain = apex_domain.split(":")[0]

    # Skip IP addresses and local hostnames
    if is_private_or_loopback_ip(apex_domain) or re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", apex_domain):
        return discovered_subdomains, cert_records, wildcard_domains

    async with httpx.AsyncClient(timeout=timeout_sec, follow_redirects=True) as client:
        # 1. Primary Source: Certspotter API
        try:
            certspotter_url = (
                f"https://api.certspotter.com/v1/issuances?domain={apex_domain}"
                "&include_subdomains=true&expand=dns_names&expand=issuer"
            )
            resp = await client.get(certspotter_url, headers={"User-Agent": "CyberAssess-CT/8.0.0"})
            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data, list):
                    for item in data:
                        dns_names = item.get("dns_names", [])
                        issuer_info = item.get("issuer", {}).get("name", "Unknown CA")
                        not_before = item.get("not_before", "")
                        cert_records.append({
                            "source": "certspotter",
                            "dns_names": dns_names,
                            "issuer": issuer_info,
                            "not_before": not_before,
                        })
                        for name in dns_names:
                            cand = name.strip().lower()
                            if cand.startswith("*."):
                                wildcard_domains.append(cand)
                                cand = cand[2:]
                            if cand and (cand == apex_domain or cand.endswith(f".{apex_domain}")):
                                discovered_subdomains.add(cand)
        except Exception as exc:
            if emit_log:
                await emit_log(LogLevel.DEBUG, f"Certspotter query notice: {exc}")

        # 2. Secondary Source: crt.sh API (Redundancy & Fallback)
        try:
            crtsh_url = f"https://crt.sh/?q=%25.{apex_domain}&output=json"
            resp = await client.get(crtsh_url, headers={"User-Agent": "CyberAssess-CT/8.0.0"})
            if resp.status_code == 200:
                entries = resp.json()
                if isinstance(entries, list):
                    for entry in entries:
                        name_val = entry.get("name_value", "")
                        issuer_name = entry.get("issuer_name", "Unknown CA")
                        entry_time = entry.get("entry_timestamp", "")
                        for line in name_val.split("\n"):
                            cand = line.strip().lower()
                            if cand.startswith("*."):
                                if cand not in wildcard_domains:
                                    wildcard_domains.append(cand)
                                cand = cand[2:]
                            if cand and (cand == apex_domain or cand.endswith(f".{apex_domain}")):
                                discovered_subdomains.add(cand)
        except Exception as exc:
            if emit_log:
                await emit_log(LogLevel.DEBUG, f"crt.sh query notice: {exc}")

    return discovered_subdomains, cert_records, wildcard_domains


async def resolve_host_ips(
    hostname: str,
    resolver: Optional[dns.asyncresolver.Resolver] = None,
) -> List[str]:
    """
    Resolves IPv4 (A) and IPv6 (AAAA) records for a hostname asynchronously.
    """
    if resolver is None:
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = 3.0

    resolved_ips: List[str] = []
    # 1. A records
    try:
        a_records = await resolver.resolve(hostname, "A")
        for rdata in a_records:
            resolved_ips.append(str(rdata))
    except Exception:
        pass

    # 2. AAAA records
    try:
        aaaa_records = await resolver.resolve(hostname, "AAAA")
        for rdata in aaaa_records:
            resolved_ips.append(str(rdata))
    except Exception:
        pass

    return resolved_ips


async def safe_probe_exposed_ip(
    ip_str: str,
    timeout_sec: float = 3.0,
) -> Dict[str, str]:
    """
    Non-destructive passive HTTP/HTTPS probe on an exposed IP to capture headers.
    """
    probe_details = {"server": "", "x_powered_by": "", "status_code": ""}
    if is_private_or_loopback_ip(ip_str):
        return probe_details

    for scheme, port in [("http", 80), ("https", 443)]:
        try:
            url = f"{scheme}://{ip_str}:{port}/"
            async with httpx.AsyncClient(timeout=timeout_sec, verify=False) as client:
                resp = await client.head(url)
                probe_details["status_code"] = str(resp.status_code)
                probe_details["server"] = resp.headers.get("Server", "")
                probe_details["x_powered_by"] = resp.headers.get("X-Powered-By", "")
                if probe_details["server"] or probe_details["status_code"]:
                    break
        except Exception:
            continue

    return probe_details


async def audit_origin_exposure(
    domain: str,
    config: ScanConfig,
    scan_id: str = "active",
    emit_subdomain: Optional[SubdomainDiscoveredCallback] = None,
    emit_finding: Optional[FindingCallback] = None,
    emit_log: Optional[LogCallback] = None,
    mock_ct_results: Optional[List[Dict[str, Any]]] = None,
) -> List[Finding]:
    """
    Performs full Certificate Transparency Log discovery & Direct Origin Exposure auditing.
    Identifies real server IPs exposed via DNS records outside Cloudflare's protected Anycast CIDRs.
    """
    findings: List[Finding] = []
    apex_domain = domain.lower().strip()
    if apex_domain.startswith("www."):
        apex_domain = apex_domain[4:]
    if ":" in apex_domain:
        apex_domain = apex_domain.split(":")[0]

    # Skip IP targets
    if is_private_or_loopback_ip(apex_domain) or re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", apex_domain):
        return findings

    # Step 1: Query CT Logs or use mock test data
    wildcard_list: List[str] = []
    subdomain_entries: List[Dict[str, Any]] = []

    if mock_ct_results is not None:
        # Unit testing mock injection
        subdomain_entries = mock_ct_results
        # Check if mock has wildcard
        if any("*" in item.get("subdomain", "") for item in mock_ct_results):
            wildcard_list.append(f"*.{apex_domain}")
    else:
        discovered_subs, cert_records, wildcard_list = await fetch_ct_logs(
            apex_domain,
            timeout_sec=config.osint.crtsh_timeout_seconds or 8.0,
            emit_log=emit_log,
        )
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = 3.0

        # Also ensure apex and www are checked
        all_hosts = sorted(discovered_subs | {apex_domain, f"www.{apex_domain}"})
        for host in all_hosts:
            ips = await resolve_host_ips(host, resolver)
            if ips:
                for ip in ips:
                    cf_status = is_cloudflare_ip(ip)
                    subdomain_entries.append({
                        "subdomain": host,
                        "ip": ip,
                        "cloudflare": cf_status,
                    })

    # Step 2: Evaluate Wildcard Certificate Findings (NET-CERT-004)
    for wildcard in sorted(set(wildcard_list)):
        loc = f"dns://{wildcard}"
        obs = f"Wildcard certificate found in CT logs covering all subdomains for '{apex_domain}'"
        finding = Finding(
            scan_id=scan_id,
            engine="network",
            check_id="NET-CERT-004",
            category="Cryptographic & Infrastructure",
            title=f"Wildcard Certificate SAN Detected in CT Logs: '{wildcard}'",
            severity=Severity.INFO,
            cvss_score=0.0,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
            cwe_id="CWE-200",
            owasp_category="A05:2021-Security Misconfiguration",
            nist_control="SC-8",
            description=(
                f"A wildcard certificate ('{wildcard}') was discovered in public Certificate Transparency logs. "
                "While wildcard certificates simplify SSL management, any compromised private key covers all subdomains."
            ),
            impact="Broad blast radius if private keys for wildcard certificates are compromised.",
            remediation="Use distinct single-host or automated ACME certificates per environment where practical.",
            references=[
                "https://certificate.transparency.dev/",
                "https://cwe.mitre.org/data/definitions/200.html",
            ],
            evidence=Evidence(
                location=loc,
                observed_value=obs,
                expected_value="Specific host certificates used where strict environment isolation is required.",
            ),
            fingerprint=calculate_fingerprint("NET-CERT-004", loc, obs),
            source_tool="native",
        )
        findings.append(finding)
        if emit_finding:
            await emit_finding(finding)

    # Step 3: Determine if the apex domain is utilizing Cloudflare
    apex_on_cloudflare = any(
        entry["cloudflare"] for entry in subdomain_entries
        if entry.get("subdomain") in (apex_domain, f"www.{apex_domain}")
    )

    # Step 4: Audit Discovered Subdomains for Origin IP Exposure (NET-ORIGIN-001 & NET-CT-001)
    seen_exposed_pairs = set()

    for entry in subdomain_entries:
        sub = entry.get("subdomain", "")
        ip = entry.get("ip", "")
        is_cf = entry.get("cloudflare", is_cloudflare_ip(ip))

        # Emit discovered subdomain event if callback present
        if emit_subdomain and sub:
            await emit_subdomain(
                DiscoveredSubdomain(
                    domain=sub,
                    ip_addresses=[ip] if ip else [],
                    is_takeover_vulnerable=False,
                    service_fingerprint="Cloudflare Anycast" if is_cf else "Exposed Origin Host",
                    discovered_via="Certificate Transparency Logs",
                )
            )

        # Flag exposed non-Cloudflare real IPs (NET-ORIGIN-001)
        if not is_cf and ip and not is_private_or_loopback_ip(ip):
            pair_key = (sub, ip)
            if pair_key in seen_exposed_pairs:
                continue
            seen_exposed_pairs.add(pair_key)

            loc = f"dns://{sub} -> {ip}"
            obs = f"Subdomain '{sub}' resolves to non-Cloudflare IP {ip} (Direct Origin Server Exposed)"
            
            # Non-destructive HTTP banner probe if live scanning
            probe_info = ""
            if mock_ct_results is None:
                probe_res = await safe_probe_exposed_ip(ip)
                if probe_res.get("server"):
                    probe_info = f" [Banner: Server={probe_res['server']}]"

            finding = Finding(
                scan_id=scan_id,
                engine="network",
                check_id="NET-ORIGIN-001",
                category="OSINT & Attack Surface Exposure",
                title=f"Direct Origin Server IP Exposed via CT Log Subdomain: '{sub}' ({ip})",
                severity=Severity.HIGH,
                cvss_score=7.5,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                cwe_id="CWE-200",
                owasp_category="A05:2021-Security Misconfiguration",
                nist_control="AC-3, SC-7",
                description=(
                    f"The subdomain '{sub}' discovered in Certificate Transparency logs resolves directly to "
                    f"public IP address {ip}, which is NOT protected behind Cloudflare's Anycast proxy network.{probe_info} "
                    "Attackers can bypass WAF rules, DDoS mitigations, and rate limits by sending requests directly to this origin IP."
                ),
                impact=(
                    "Complete WAF bypass, unmitigated direct DDoS attacks against backend infrastructure, "
                    "and potential exploitation of unpatched backend management services."
                ),
                remediation=(
                    f"1. Enable Cloudflare proxy (Orange Cloud) for '{sub}'.\n"
                    f"2. Configure firewall rules on {ip} to only accept ingress traffic from Cloudflare IP ranges.\n"
                    f"3. Remove unused DNS A/AAAA records if the subdomain is decommissioned."
                ),
                remediation_code_snippet=(
                    f"# Configure UFW / Iptables on {ip} to allow only Cloudflare IPs:\n"
                    "ufw default deny incoming\n"
                    "for ip in $(curl -s https://www.cloudflare.com/ips-v4); do ufw allow from $ip to any port 443 proto tcp; done\n"
                    "for ip in $(curl -s https://www.cloudflare.com/ips-v6); do ufw allow from $ip to any port 443 proto tcp; done"
                ),
                references=[
                    "https://www.cloudflare.com/ips/",
                    "https://cwe.mitre.org/data/definitions/200.html",
                    "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
                ],
                evidence=Evidence(
                    location=loc,
                    observed_value=obs + probe_info,
                    expected_value="All public web assets routed through Cloudflare Anycast proxy CIDRs.",
                ),
                fingerprint=calculate_fingerprint("NET-ORIGIN-001", loc, obs),
                source_tool="native",
            )
            findings.append(finding)
            if emit_finding:
                await emit_finding(finding)

    return findings
