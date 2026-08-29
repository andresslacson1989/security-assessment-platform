"""
Contract 03 (Section 4.2), Contract 06 (Section 2) & Contract 08 (Section 8.1) Nmap Tool Adapter.
Authoritative Reference: contracts/03_ENGINE_PLUGIN_INTERFACE_CONTRACT.md
"""

from __future__ import annotations
import re
import urllib.parse
import xml.etree.ElementTree as ET
from typing import Optional, List, Callable, Awaitable

from app.core.models import (
    Target,
    Finding,
    Evidence,
    Severity,
    ScanConfig,
    LogLevel,
    calculate_fingerprint,
)
from app.adapters.base_adapter import BaseToolAdapter


def extract_host(target_value: str) -> str:
    """
    Extracts the hostname or IP address from target value.
    """
    if "://" in target_value:
        parsed = urllib.parse.urlparse(target_value)
        return parsed.hostname or target_value
    if ":" in target_value and not target_value.count(":") > 1:
        return target_value.split(":")[0]
    return target_value.strip()


class NmapAdapter(BaseToolAdapter):
    """
    Hybrid tool adapter for Nmap network port scanner and service detection.
    Normalizes XML output into canonical NET-PORT-xxx and NET-SVC-001 findings.
    """

    @property
    def tool_name(self) -> str:
        return "nmap"

    async def get_version(self, custom_path: Optional[str] = None) -> Optional[str]:
        """
        Retrieves Nmap version string via `nmap --version`.
        """
        path = self.resolve_binary_path(custom_path)
        if not path:
            return None

        returncode, stdout, _ = await self.execute_command([path, "--version"], timeout=5.0)
        if returncode == 0 and stdout:
            first_line = stdout.splitlines()[0].strip()
            match = re.search(r"Nmap version\s+([0-9\.]+[a-zA-Z0-9]*)", first_line, re.IGNORECASE)
            if match:
                return f"Nmap {match.group(1)}"
            return first_line
        return None

    async def run(
        self,
        target: Target,
        config: ScanConfig,
        emit_log: Callable[[LogLevel, str], Awaitable[None]],
        emit_finding: Callable[[Finding], Awaitable[None]],
        **kwargs,
    ) -> List[Finding]:
        """
        Executes Nmap scan: nmap -sV -sC --version-light -T4 -oX - <target_host>
        Parses XML results and produces normalized Finding objects.
        """
        findings: List[Finding] = []
        custom_path = getattr(config.adapters, "nmap_path", None) or getattr(config.adapters, "custom_nmap_path", None)
        nmap_path = self.resolve_binary_path(custom_path)

        if not nmap_path:
            await emit_log(LogLevel.WARNING, "Nmap binary not found on host. Skipping Nmap execution.")
            return findings

        target_host = extract_host(target.value)
        if not target_host:
            await emit_log(LogLevel.WARNING, "Invalid target host for Nmap scan.")
            return findings

        cmd = [nmap_path, "-sV", "-sC", "--version-light", "-T4", "-oX", "-"]
        if config.port_list:
            cmd.extend(["-p", ",".join(str(p) for p in config.port_list)])
        cmd.append(target_host)

        await emit_log(LogLevel.INFO, f"Starting Nmap port and service scan on target '{target_host}'...")
        returncode, stdout, stderr = await self.execute_command(
            cmd,
            timeout=float(min(60.0, config.timeout_seconds * 6)),
            emit_log=emit_log,
        )

        if not stdout.strip():
            await emit_log(
                LogLevel.WARNING,
                f"Nmap produced no stdout (exit code {returncode}). {stderr.strip() if stderr else ''}",
            )
            return findings

        try:
            root = ET.fromstring(stdout)
        except ET.ParseError as e:
            await emit_log(LogLevel.ERROR, f"Failed to parse Nmap XML output: {e}")
            return findings

        scan_id = kwargs.get("scan_id", "adapter-nmap")

        for port_elem in root.findall(".//ports/port"):
            portid_str = port_elem.get("portid", "0")
            try:
                portid = int(portid_str)
            except ValueError:
                continue

            protocol = port_elem.get("protocol", "tcp")
            state_elem = port_elem.find("state")
            state = state_elem.get("state") if state_elem is not None else "unknown"

            if state != "open":
                continue

            service_elem = port_elem.find("service")
            service_name = service_elem.get("name", "unknown") if service_elem is not None else "unknown"
            product = service_elem.get("product", "") if service_elem is not None else ""
            version = service_elem.get("version", "") if service_elem is not None else ""
            extrainfo = service_elem.get("extrainfo", "") if service_elem is not None else ""

            version_desc = f"{product} {version} {extrainfo}".strip() or service_name

            script_outputs = []
            for script in port_elem.findall("script"):
                s_id = script.get("id", "")
                s_out = script.get("output", "").strip()
                if s_id and s_out:
                    script_outputs.append(f"[{s_id}]\n{s_out}")
            script_text = "\n\n".join(script_outputs) if script_outputs else None

            # Categorize check IDs per Contract 06 & Contract 03
            if portid in (3306, 5432) or service_name in ("mysql", "postgresql", "postgres"):
                check_id = "NET-PORT-001"
                title = f"Exposed Database Port (Port {portid} - {service_name.capitalize()})"
                category = "Network Perimeter Exposure"
                cwe_id = "CWE-284"
                owasp = "A01:2021-Broken Access Control"
                nist = "AC-3, SC-7"
                description = f"Database port {portid} ({service_name}) is publicly reachable on {target_host}."
                remediation = "Bind database daemon to 127.0.0.1 or internal VPC subnet; block public access via firewall."
            elif portid in (6379, 27017, 9200) or service_name in ("redis", "mongodb", "mongod", "elasticsearch"):
                check_id = "NET-PORT-002"
                title = f"Exposed In-Memory Cache / NoSQL Datastore (Port {portid} - {service_name.capitalize()})"
                category = "Network Perimeter Exposure"
                cwe_id = "CWE-284"
                owasp = "A01:2021-Broken Access Control"
                nist = "AC-3, SC-7"
                description = f"In-memory datastore/cache port {portid} ({service_name}) is exposed to public networks."
                remediation = "Bind service to localhost, enforce strict authentication, and restrict firewall access."
            elif portid in (21, 23) or service_name in ("ftp", "telnet"):
                check_id = "NET-PORT-003"
                title = f"Exposed Insecure Remote Management Service (Port {portid} - {service_name.upper()})"
                category = "Network Perimeter Exposure"
                cwe_id = "CWE-319"
                owasp = "A02:2021-Cryptographic Failures"
                nist = "AC-17, IA-2"
                description = f"Insecure plaintext remote management service {service_name.upper()} is active on port {portid}."
                remediation = "Disable plaintext management service and migrate exclusively to SSH or SFTP with TLS."
            else:
                check_id = "NET-SVC-001"
                title = f"Service Daemon Detected on Port {portid} ({version_desc})"
                category = "Service Posture"
                cwe_id = "CWE-200"
                owasp = "A05:2021-Security Misconfiguration"
                nist = "CM-6"
                description = f"Service '{service_name}' ({version_desc}) detected on port {portid} on {target_host}."
                remediation = "Verify whether this port must be publicly accessible and ensure the service daemon is updated."

            evidence = Evidence(
                location=f"{target_host}:{portid}",
                observed_value=f"Port {portid}/{protocol} is open - Service: {version_desc}",
                expected_value="Port closed or blocked by perimeter firewall",
                raw_response_snippet=script_text or f"Service: {service_name}\nProduct: {product}\nVersion: {version}",
            )

            finding = Finding(
                scan_id=scan_id,
                engine="network",
                source_tool="nmap",
                check_id=check_id,
                category=category,
                title=title,
                severity=Severity.HIGH,
                cvss_score=7.5,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                cwe_id=cwe_id,
                owasp_category=owasp,
                nist_control=nist,
                description=description,
                impact="Unauthenticated or weakly authenticated actors can probe or exploit exposed network daemons.",
                remediation=remediation,
                remediation_code_snippet=f"# UFW Firewall Deny:\nsudo ufw deny {portid}/tcp",
                references=["https://nmap.org/book/man-version-detection.html"],
                evidence=evidence,
                fingerprint=calculate_fingerprint(check_id, f"{target_host}:{portid}", f"nmap_{portid}_{service_name}"),
            )

            findings.append(finding)
            await emit_finding(finding)

        await emit_log(LogLevel.INFO, f"Nmap completed successfully. Generated {len(findings)} findings.")
        return findings
