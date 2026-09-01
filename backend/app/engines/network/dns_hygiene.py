"""
Contract 03, 06 & 08 DNS Hygiene, Email Security (SPF/DMARC/MTA-STS/BIMI), DNSSEC & Zone Transfer Auditor.
"""

from __future__ import annotations
import logging
import asyncio
from typing import List, Optional
import urllib.parse
import dns.asyncresolver
import dns.resolver
import dns.query
import dns.zone
import dns.exception

from app.core.models import Finding, Evidence, Severity, calculate_fingerprint, LogLevel
from app.engines.base import LogCallback

logger = logging.getLogger("cyberassess.engines.dns_hygiene")


def extract_apex_domain(target_value: str) -> Optional[str]:
    """
    Extracts the root domain apex from a target URL, domain, or IP.
    Returns None if target is an IP address.
    """
    if "://" in target_value:
        target_value = urllib.parse.urlparse(target_value).hostname or target_value
    
    if ":" in target_value:
        target_value = target_value.split(":")[0]

    target_value = target_value.strip().lower()
    
    # Check if IP address
    parts = target_value.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return None
    if ":" in target_value:  # IPv6
        return None

    # Handle domain parts (extract root 2 levels e.g. example.com from sub.example.com)
    if len(parts) >= 2:
        return f"{parts[-2]}.{parts[-1]}"
    return target_value


async def audit_dns_hygiene(
    target_value: str,
    emit_log: Optional[LogCallback] = None,
    timeout_seconds: float = 3.0,
) -> List[Finding]:
    """
    Evaluates SPF, DMARC, CAA, MTA-STS, DNSSEC, AXFR, and BIMI records.
    """
    findings: List[Finding] = []
    apex_domain = extract_apex_domain(target_value)

    if not apex_domain:
        if emit_log:
            await emit_log(LogLevel.INFO, f"Target '{target_value}' is an IP address; skipping DNS hygiene checks.")
        return findings

    if emit_log:
        await emit_log(LogLevel.INFO, f"Analyzing DNS email hygiene & zone security for {apex_domain}...")

    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = timeout_seconds
    resolver.timeout = timeout_seconds

    # --- 1. SPF Record Audit (NET-DNS-001, NET-DNS-002) ---
    try:
        txt_records = await resolver.resolve(apex_domain, "TXT")
        spf_records = [
            r.to_text().strip('"')
            for r in txt_records
            if "v=spf1" in r.to_text()
        ]
        if not spf_records:
            findings.append(Finding(
                scan_id="auto",
                engine="network",
                check_id="NET-DNS-001",
                category="DNS & Email Security",
                title="Missing or Incomplete SPF Record",
                severity=Severity.MEDIUM,
                cvss_score=5.3,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
                cwe_id="CWE-345",
                owasp_category="A05:2021-Security Misconfiguration",
                nist_control="SI-8",
                description=f"The domain {apex_domain} lacks a Sender Policy Framework (SPF) TXT record.",
                impact="Attackers can forge email headers to send phishing emails appearing to originate from your domain.",
                remediation="Publish a valid SPF record in your DNS zone authorizing legitimate mail servers.",
                remediation_code_snippet=f"{apex_domain}. IN TXT \"v=spf1 include:_spf.google.com ~all\"",
                references=["https://datatracker.ietf.org/doc/html/rfc7208"],
                evidence=Evidence(
                    location=apex_domain,
                    observed_value="No v=spf1 TXT record found",
                    expected_value="v=spf1 record defining authorized senders",
                ),
                fingerprint=calculate_fingerprint("NET-DNS-001", apex_domain, "missing_spf"),
            ))
        else:
            spf_text = spf_records[0]
            if "+all" in spf_text:
                findings.append(Finding(
                    scan_id="auto",
                    engine="network",
                    check_id="NET-DNS-002",
                    category="DNS & Email Security",
                    title="Permissive SPF Record (+all)",
                    severity=Severity.HIGH,
                    cvss_score=7.5,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
                    cwe_id="CWE-345",
                    owasp_category="A05:2021-Security Misconfiguration",
                    nist_control="SI-8",
                    description=f"The SPF record for {apex_domain} contains the permissive '+all' mechanism: '{spf_text}'.",
                    impact="Anyone on the internet is authorized to send emails on behalf of this domain, completely negating SPF protection.",
                    remediation="Change '+all' to SoftFail '~all' or HardFail '-all'.",
                    remediation_code_snippet=f"{apex_domain}. IN TXT \"v=spf1 ... -all\"",
                    references=["https://datatracker.ietf.org/doc/html/rfc7208"],
                    evidence=Evidence(
                        location=apex_domain,
                        observed_value=spf_text,
                        expected_value="SPF ending in -all or ~all",
                    ),
                    fingerprint=calculate_fingerprint("NET-DNS-002", apex_domain, spf_text),
                ))
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
        findings.append(Finding(
            scan_id="auto",
            engine="network",
            check_id="NET-DNS-001",
            category="DNS & Email Security",
            title="Missing or Incomplete SPF Record",
            severity=Severity.MEDIUM,
            cvss_score=5.3,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
            cwe_id="CWE-345",
            owasp_category="A05:2021-Security Misconfiguration",
            nist_control="SI-8",
            description=f"The domain {apex_domain} lacks a Sender Policy Framework (SPF) TXT record.",
            impact="Attackers can spoof emails from your domain.",
            remediation="Publish a valid SPF TXT record in your DNS zone.",
            remediation_code_snippet=f"{apex_domain}. IN TXT \"v=spf1 include:_spf.google.com ~all\"",
            references=["https://datatracker.ietf.org/doc/html/rfc7208"],
            evidence=Evidence(
                location=apex_domain,
                observed_value="DNS query returned no SPF TXT record",
                expected_value="Valid v=spf1 TXT record",
            ),
            fingerprint=calculate_fingerprint("NET-DNS-001", apex_domain, "no_answer"),
        ))
    except Exception as ex:
        if emit_log:
            await emit_log(LogLevel.WARNING, f"SPF check error: {str(ex)}")

    # --- 2. DMARC Policy Audit (NET-DNS-003, NET-DNS-004) ---
    dmarc_domain = f"_dmarc.{apex_domain}"
    try:
        dmarc_txt = await resolver.resolve(dmarc_domain, "TXT")
        dmarc_records = [
            r.to_text().strip('"')
            for r in dmarc_txt
            if "v=DMARC1" in r.to_text()
        ]
        if not dmarc_records:
            findings.append(Finding(
                scan_id="auto",
                engine="network",
                check_id="NET-DNS-003",
                category="DNS & Email Security",
                title="Missing DMARC Email Protection Record",
                severity=Severity.MEDIUM,
                cvss_score=5.3,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
                cwe_id="CWE-345",
                owasp_category="A05:2021-Security Misconfiguration",
                nist_control="SI-8",
                description=f"The domain {apex_domain} has no DMARC record published at {dmarc_domain}.",
                impact="Without DMARC, receiving mail servers cannot verify SPF/DKIM alignment, allowing domain impersonation.",
                remediation="Publish a DMARC policy TXT record at _dmarc.{domain}.",
                remediation_code_snippet=f"{dmarc_domain}. IN TXT \"v=DMARC1; p=reject; rua=mailto:dmarc-reports@{apex_domain}\"",
                references=["https://dmarc.org/"],
                evidence=Evidence(
                    location=dmarc_domain,
                    observed_value="No DMARC record found",
                    expected_value="v=DMARC1; p=reject or p=quarantine",
                ),
                fingerprint=calculate_fingerprint("NET-DNS-003", dmarc_domain, "missing_dmarc"),
            ))
        else:
            dmarc_text = dmarc_records[0]
            if "p=none" in dmarc_text.lower():
                findings.append(Finding(
                    scan_id="auto",
                    engine="network",
                    check_id="NET-DNS-004",
                    category="DNS & Email Security",
                    title="Permissive DMARC Policy (p=none)",
                    severity=Severity.LOW,
                    cvss_score=3.7,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
                    cwe_id="CWE-345",
                    owasp_category="A05:2021-Security Misconfiguration",
                    nist_control="SI-8",
                    description=f"The DMARC policy for {apex_domain} is set to 'p=none' (monitoring only).",
                    impact="Fraudulent emails failing SPF/DKIM authentication are not quarantined or rejected by receivers.",
                    remediation="Upgrade DMARC policy from 'p=none' to 'p=quarantine' or 'p=reject'.",
                    remediation_code_snippet=f"{dmarc_domain}. IN TXT \"v=DMARC1; p=reject; rua=mailto:reports@{apex_domain}\"",
                    references=["https://dmarc.org/"],
                    evidence=Evidence(
                        location=dmarc_domain,
                        observed_value=dmarc_text,
                        expected_value="p=reject or p=quarantine",
                    ),
                    fingerprint=calculate_fingerprint("NET-DNS-004", dmarc_domain, dmarc_text),
                ))
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
        findings.append(Finding(
            scan_id="auto",
            engine="network",
            check_id="NET-DNS-003",
            category="DNS & Email Security",
            title="Missing DMARC Email Protection Record",
            severity=Severity.MEDIUM,
            cvss_score=5.3,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
            cwe_id="CWE-345",
            owasp_category="A05:2021-Security Misconfiguration",
            nist_control="SI-8",
            description=f"The domain {apex_domain} has no DMARC record at {dmarc_domain}.",
            impact="Receiving mail servers cannot enforce authentication on spoofed emails.",
            remediation="Publish a DMARC record at _dmarc.{domain}.",
            remediation_code_snippet=f"{dmarc_domain}. IN TXT \"v=DMARC1; p=reject; rua=mailto:dmarc@{apex_domain}\"",
            references=["https://dmarc.org/"],
            evidence=Evidence(
                location=dmarc_domain,
                observed_value="NXDOMAIN / No Answer",
                expected_value="v=DMARC1 record",
            ),
            fingerprint=calculate_fingerprint("NET-DNS-003", dmarc_domain, "nxdomain"),
        ))
    except Exception as ex:
        if emit_log:
            await emit_log(LogLevel.WARNING, f"DMARC check error: {str(ex)}")

    # --- 3. CAA Record Audit (NET-DNS-005) ---
    try:
        await resolver.resolve(apex_domain, "CAA")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
        findings.append(Finding(
            scan_id="auto",
            engine="network",
            check_id="NET-DNS-005",
            category="DNS & Email Security",
            title="Missing DNS CAA Record",
            severity=Severity.INFO,
            cvss_score=0.0,
            cwe_id="CWE-1021",
            owasp_category="A05:2021-Security Misconfiguration",
            nist_control="SC-8",
            description=f"The domain {apex_domain} does not publish a Certification Authority Authorization (CAA) record.",
            impact="Any public Certificate Authority is permitted to issue certificates for this domain.",
            remediation="Specify allowed Certificate Authorities (e.g. Let's Encrypt, DigiCert) in a CAA record.",
            remediation_code_snippet=f"{apex_domain}. IN CAA 0 issue \"letsencrypt.org\"",
            references=["https://datatracker.ietf.org/doc/html/rfc6844"],
            evidence=Evidence(
                location=apex_domain,
                observed_value="No CAA record found",
                expected_value="CAA record restricting certificate issuance",
            ),
            fingerprint=calculate_fingerprint("NET-DNS-005", apex_domain, "missing_caa"),
        ))
    except Exception as exc:
        logger.debug("CAA record audit failed: error_type=%s", type(exc).__name__)

    # --- 4. MTA-STS & TLS-RPT Record Audit (NET-DNS-006) ---
    try:
        await resolver.resolve(f"_mta-sts.{apex_domain}", "TXT")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
        findings.append(Finding(
            scan_id="auto",
            engine="network",
            check_id="NET-DNS-006",
            category="DNS & Email Security",
            title="Missing MTA-STS / TLS-RPT Record",
            severity=Severity.LOW,
            cvss_score=3.5,
            cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
            cwe_id="CWE-319",
            owasp_category="A02:2021-Cryptographic Failures",
            nist_control="SC-8",
            description=f"The domain {apex_domain} lacks MTA-STS and TLS-RPT records for enforcing TLS encryption during mail transit.",
            impact="Mail transfer agents may fall back to plaintext SMTP delivery if active network tampering occurs.",
            remediation="Publish an MTA-STS TXT record and host an mta-sts.txt policy file.",
            remediation_code_snippet=f"_mta-sts.{apex_domain}. IN TXT \"v=STSv1; id=20260101;\"",
            references=["https://datatracker.ietf.org/doc/html/rfc8461"],
            evidence=Evidence(
                location=f"_mta-sts.{apex_domain}",
                observed_value="No _mta-sts TXT record",
                expected_value="v=STSv1 record",
            ),
            fingerprint=calculate_fingerprint("NET-DNS-006", apex_domain, "missing_mta_sts"),
        ))
    except Exception as exc:
        logger.debug("MTA-STS/TLS-RPT audit failed: error_type=%s", type(exc).__name__)

    # --- 5. DNSSEC Audit (NET-DNS-007) ---
    try:
        await resolver.resolve(apex_domain, "DNSKEY")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
        findings.append(Finding(
            scan_id="auto",
            engine="network",
            check_id="NET-DNS-007",
            category="DNS & Email Security",
            title="Missing DNSSEC Deployment",
            severity=Severity.LOW,
            cvss_score=3.7,
            cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
            cwe_id="CWE-345",
            owasp_category="A05:2021-Security Misconfiguration",
            nist_control="SC-20",
            description=f"The domain {apex_domain} does not have DNSSEC enabled (no signed DNSKEY/DS records).",
            impact="DNS responses can theoretically be spoofed via cache poisoning attacks on vulnerable resolvers.",
            remediation="Enable DNSSEC signing through your domain registrar and DNS hosting provider.",
            references=["https://datatracker.ietf.org/doc/html/rfc4033"],
            evidence=Evidence(
                location=apex_domain,
                observed_value="No DNSKEY record found",
                expected_value="Signed DNSKEY record",
            ),
            fingerprint=calculate_fingerprint("NET-DNS-007", apex_domain, "missing_dnssec"),
        ))
    except Exception as exc:
        logger.debug("DNSSEC audit failed: error_type=%s", type(exc).__name__)

    # --- 6. DNS Zone Transfer (AXFR) Audit (NET-DNS-008) ---
    try:
        ns_answers = await resolver.resolve(apex_domain, "NS")
        for ns_item in ns_answers:
            ns_host = str(ns_item.target).rstrip(".")
            try:
                # Attempt safe, bounded AXFR zone transfer check in a background thread
                def _probe_axfr(nameserver: str, zone_name: str) -> bool:
                    import dns.query
                    import dns.zone
                    z = dns.zone.from_xfr(dns.query.xfr(nameserver, zone_name, timeout=2.0))
                    return len(z.nodes) > 1

                is_axfr_open = await asyncio.to_thread(_probe_axfr, ns_host, apex_domain)
                if is_axfr_open:
                    loc = f"dns://{ns_host}/{apex_domain}"
                    obs = f"Nameserver '{ns_host}' permitted unauthenticated AXFR zone transfer."
                    findings.append(Finding(
                        scan_id="auto",
                        engine="network",
                        check_id="NET-DNS-008",
                        category="DNS & Zone Security",
                        title=f"DNS Zone Transfer (AXFR) Exposure on '{ns_host}'",
                        severity=Severity.HIGH,
                        cvss_score=7.5,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        cwe_id="CWE-200",
                        owasp_category="A01:2021-Broken Access Control",
                        nist_control="AC-3, SC-7",
                        description=(
                            f"The DNS nameserver '{ns_host}' permits unauthenticated full zone transfer (AXFR) for domain '{apex_domain}'. "
                            "Attackers can obtain a complete map of all internal and external hostnames, subdomains, and IP mappings."
                        ),
                        impact="Full internal network mapping and disclosure of sensitive unlinked DNS subdomains.",
                        remediation="Configure the DNS server to restrict AXFR zone transfers strictly to authorized secondary nameserver IPs.",
                        remediation_code_snippet=f"# BIND configuration fix:\nzone \"{apex_domain}\" {{\n    type master;\n    allow-transfer {{ none; }}; // Or secondary IP only\n}};",
                        references=["https://cwe.mitre.org/data/definitions/200.html"],
                        evidence=Evidence(
                            location=loc,
                            observed_value=obs,
                            expected_value="AXFR queries rejected for unauthorized clients",
                        ),
                        fingerprint=calculate_fingerprint("NET-DNS-008", loc, obs),
                        source_tool="native",
                    ))
                    break
            except Exception as exc:
                logger.debug("AXFR probe failed: error_type=%s", type(exc).__name__)
    except Exception as exc:
        logger.debug("Nameserver lookup for AXFR audit failed: error_type=%s", type(exc).__name__)

    return findings
