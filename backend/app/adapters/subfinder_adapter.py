"""
Subfinder Tool Adapter for Multi-Source Passive Subdomain Discovery.
Authoritative Reference: contracts/03_ENGINE_PLUGIN_INTERFACE_CONTRACT.md (Section 4.2)
"""

from __future__ import annotations
import json
import re
import ipaddress
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

    APPROVED_VERSION = "v2.6.5"
    MAX_DOMAINS = 10_000
    ALLOWED_PROFILES = {"FULL_STACK", "NETWORK_ONLY", "PASSIVE_OSINT", "DAST_ONLY"}

    @staticmethod
    def normalize_domain(value: str) -> Optional[str]:
        if not isinstance(value, str):
            return None
        value = value.strip().rstrip(".").lower()
        if value.startswith("*.") or "://" in value or "/" in value:
            return None
        try:
            ipaddress.ip_address(value)
            return None
        except ValueError:
            pass
        try:
            value = value.encode("idna").decode("ascii")
        except UnicodeError:
            return None
        if len(value) > 253 or not value or any(
            len(label) > 63 or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
            for label in value.split(".")
        ):
            return None
        return value

    @classmethod
    def classify_scope(cls, domain: str, authorized_root: str) -> str:
        root = cls.normalize_domain(authorized_root)
        candidate = cls.normalize_domain(domain)
        if not root or not candidate:
            return "INVALID"
        return "IN_SCOPE" if candidate == root or candidate.endswith("." + root) else "OUT_OF_SCOPE"

    @classmethod
    def build_command(cls, binary: str, authorized_root: str) -> List[str]:
        root = cls.normalize_domain(authorized_root)
        if not root:
            raise ValueError("Invalid authorized discovery domain")
        return [binary, "-d", root, "-silent", "-json", "-timeout", "10", "-max-time", "1"]

    async def get_version(self, custom_path: Optional[str] = None) -> Optional[str]:
        binary = self.resolve_binary_path(custom_path)
        if not binary:
            return None
        code, stdout, stderr = await self.execute_command([binary, "-version"], timeout=10.0)
        output = stdout + " " + stderr
        match = re.search(r"(?<![0-9A-Za-z])v?(\d+\.\d+\.\d+)(?![0-9A-Za-z])", output, re.IGNORECASE)
        if match:
            return f"subfinder v{match.group(1)}"
        return "subfinder" if code == 0 else None

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

        profile = getattr(config, "profile", None)
        if getattr(profile, "value", profile) not in self.ALLOWED_PROFILES:
            await emit_log(LogLevel.WARNING, "Subfinder discovery blocked for unsupported assessment profile.")
            return findings
        version = await self.get_version(binary)
        if version != f"subfinder {self.APPROVED_VERSION}":
            state = "VERSION_UNAVAILABLE" if version is None else "INVALID_VERSION"
            await emit_log(LogLevel.ERROR, f"Subfinder execution blocked: {state} (approved {self.APPROVED_VERSION}).")
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

        apex_domain = self.normalize_domain(domain)
        if not apex_domain or "." not in apex_domain:
            await emit_log(LogLevel.WARNING, "Subfinder discovery blocked: target is not a valid domain.")
            return findings

        await emit_log(LogLevel.INFO, f"Executing Subfinder passive subdomain reconnaissance on: {apex_domain}")
        cmd = self.build_command(binary, apex_domain)

        code, stdout, stderr = await self.execute_command(cmd, timeout=30.0, emit_log=emit_log)
        if code != 0 and not stdout:
            await emit_log(LogLevel.WARNING, f"Subfinder exited with code {code}: {stderr.strip()[:200]}")
            return findings

        discovered_hosts = set()
        source_map: Dict[str, set[str]] = {}
        parser_warnings = 0
        out_of_scope = 0
        limit_reached = False
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                if not isinstance(data, dict):
                    raise ValueError("record is not an object")
                host = self.normalize_domain(data.get("host", ""))
                sources = data.get("sources", ["unknown"])
                if not isinstance(sources, list) or not all(isinstance(s, str) for s in sources):
                    sources = ["unknown"]
            except (ValueError, TypeError, json.JSONDecodeError):
                parser_warnings += 1
                continue
            if not host:
                parser_warnings += 1
                continue
            if self.classify_scope(host, apex_domain) != "IN_SCOPE":
                out_of_scope += 1
                continue
            if host in discovered_hosts:
                source_map[host].update(sources)
                continue
            if len(discovered_hosts) >= self.MAX_DOMAINS:
                limit_reached = True
                continue
            discovered_hosts.add(host)
            source_map[host] = set(sources)
            # Discovery is not authorization and remains passive; DNS probing is a separate stage.
            if emit_subdomain:
                await emit_subdomain(DiscoveredSubdomain(
                    domain=host,
                    service_fingerprint=f"Sources: {', '.join(sorted(source_map[host]))}",
                    discovered_via="Subfinder",
                    dns_status="UNRESOLVED",
                ))

        if parser_warnings:
            await emit_log(LogLevel.WARNING, f"Subfinder parser rejected {parser_warnings} malformed JSONL records.")
        if out_of_scope:
            await emit_log(LogLevel.WARNING, f"Subfinder classified {out_of_scope} discoveries as OUT_OF_SCOPE; none were admitted.")
        if limit_reached:
            await emit_log(LogLevel.WARNING, "Subfinder discovery reached the per-run result limit; results are partial.")

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
