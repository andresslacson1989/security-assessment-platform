"""
Subfinder Tool Adapter for Multi-Source Passive Subdomain Discovery.
Authoritative Reference: contracts/03_ENGINE_PLUGIN_INTERFACE_CONTRACT.md (Section 4.2)
"""

from __future__ import annotations
import json
import re
from typing import Optional, List, Callable, Awaitable, Dict, Any
from urllib.parse import urlparse

from app.core.models import (
    Target, Finding, Evidence, ScanConfig, LogLevel, Severity,
    calculate_fingerprint, DiscoveredSubdomain
)
from app.adapters.base_adapter import BaseToolAdapter


class SubfinderAdapter(BaseToolAdapter):
    """
    Adapter for ProjectDiscovery's Subfinder fast passive subdomain enumeration tool.
    """

    @property
    def tool_name(self) -> str:
        return "subfinder"

    async def get_version(self, custom_path: Optional[str] = None) -> Optional[str]:
        binary = self.resolve_binary_path(custom_path)
        if not binary:
            return None
        code, stdout, stderr = await self.execute_command([binary, "-version"], timeout=10.0)
        output = stdout + " " + stderr
        match = re.search(r"v\d+\.\d+\.\d+", output, re.IGNORECASE)
        if match:
            return f"subfinder {match.group(0)}"
        return "subfinder" if code == 0 else None

    async def _resolve_host_dns(self, hostname: str) -> tuple[List[str], List[str], str]:
        import dns.asyncresolver
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = 2.0
        ips: List[str] = []
        cnames: List[str] = []
        status = "NXDOMAIN"
        try:
            try:
                a_ans = await resolver.resolve(hostname, "A")
                for r in a_ans:
                    ips.append(str(r))
                status = "ACTIVE"
            except Exception:
                pass
            try:
                aaaa_ans = await resolver.resolve(hostname, "AAAA")
                for r in aaaa_ans:
                    ips.append(str(r))
                status = "ACTIVE"
            except Exception:
                pass
            try:
                c_ans = await resolver.resolve(hostname, "CNAME")
                for r in c_ans:
                    cnames.append(str(r.target).rstrip(".").lower())
            except Exception:
                pass
        except Exception:
            pass
        return ips, cnames, status

    async def run(
        self,
        target: Target,
        config: ScanConfig,
        emit_log: Callable[[LogLevel, str], Awaitable[None]],
        emit_finding: Callable[[Finding], Awaitable[None]],
        **kwargs,
    ) -> List[Finding]:
        findings: List[Finding] = []
        scan_id = kwargs.get("scan_id", "local-scan")
        emit_subdomain: Optional[Callable[[DiscoveredSubdomain], Awaitable[None]]] = kwargs.get("emit_subdomain")

        binary = self.resolve_binary_path(config.adapters.subfinder_path or config.adapters.custom_subfinder_path)
        if not binary:
            await emit_log(LogLevel.WARNING, "Subfinder binary not found. Skipping Subfinder EASM recon.")
            return findings

        # Extract apex domain
        domain = target.value
        if "://" in domain:
            domain = urlparse(domain).hostname or domain
        if ":" in domain:
            domain = domain.split(":")[0]
        if "/" in domain:
            domain = domain.split("/")[0]
        if domain.startswith("www."):
            domain = domain[4:]

        parts = domain.split(".")
        if len(parts) >= 2 and not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain):
            apex_domain = ".".join(parts[-2:])
        else:
            apex_domain = domain

        await emit_log(LogLevel.INFO, f"Executing Subfinder passive subdomain reconnaissance on: {apex_domain}")
        cmd = [binary, "-d", apex_domain, "-silent", "-oJ", "-timeout", "10", "-max-time", "1"]

        code, stdout, stderr = await self.execute_command(cmd, timeout=30.0, emit_log=emit_log)
        if code != 0 and not stdout:
            await emit_log(LogLevel.WARNING, f"Subfinder exited with code {code}: {stderr.strip()[:200]}")
            return findings

        discovered_hosts = set()
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                host = data.get("host", "").strip().lower()
                sources = data.get("sources", [])
                if host and host not in discovered_hosts:
                    discovered_hosts.add(host)
                    ips, cnames, dns_status = await self._resolve_host_dns(host)
                    sub_model = DiscoveredSubdomain(
                        domain=host,
                        ip_addresses=ips,
                        cname_targets=cnames,
                        dns_status=dns_status,
                        service_fingerprint=f"Sources: {', '.join(sources)}" if sources else "Subfinder",
                        discovered_via="Subfinder",
                    )
                    if emit_subdomain:
                        await emit_subdomain(sub_model)
            except Exception:
                # If plain text line
                host = line.strip().lower()
                if "." in host and host not in discovered_hosts:
                    discovered_hosts.add(host)
                    ips, cnames, dns_status = await self._resolve_host_dns(host)
                    sub_model = DiscoveredSubdomain(
                        domain=host,
                        ip_addresses=ips,
                        cname_targets=cnames,
                        dns_status=dns_status,
                        service_fingerprint="Subfinder",
                        discovered_via="Subfinder",
                    )
                    if emit_subdomain:
                        await emit_subdomain(sub_model)

        if discovered_hosts:
            desc = f"Subfinder discovered {len(discovered_hosts)} subdomains in the external attack surface: {', '.join(list(discovered_hosts)[:10])}"
            if len(discovered_hosts) > 10:
                desc += f" ...and {len(discovered_hosts) - 10} more."

            evidence = Evidence(
                location=domain,
                observed_value=f"{len(discovered_hosts)} passive subdomains enumerated",
                expected_value="Subdomain attack surface cataloged and monitored",
                raw_response_snippet=json.dumps(list(discovered_hosts)[:20], indent=2),
            )
            finding = Finding(
                scan_id=scan_id,
                engine="network",
                source_tool="subfinder",
                check_id="EASM-SUB-001",
                category="Attack Surface Recon",
                title=f"Discovered {len(discovered_hosts)} Subdomains on Perimeter",
                severity=Severity.INFO,
                cvss_score=0.0,
                cwe_id="CWE-200",
                description=desc,
                impact="Unmonitored external subdomains can expose staging environments, forgotten APIs, or vulnerable third-party services.",
                remediation="Regularly audit DNS zones, decommission obsolete subdomains, and place perimeter assets behind Web Application Firewalls.",
                references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/01-Conduct_Search_Engine_Discovery_Reconnaissance_for_Information_Leakage"],
                evidence=evidence,
                fingerprint=calculate_fingerprint("EASM-SUB-001", domain, f"{len(discovered_hosts)} subdomains"),
            )
            findings.append(finding)
            await emit_finding(finding)
            await emit_log(LogLevel.INFO, f"Subfinder identified {len(discovered_hosts)} subdomains.")

        return findings
