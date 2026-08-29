"""
Contract 03, 06 & 08 Docker Compose Security & Misconfiguration Auditor.
"""

from __future__ import annotations
import os
from pathlib import Path
from typing import List, Optional
import yaml

from app.core.models import Finding, Evidence, Severity, calculate_fingerprint, LogLevel
from app.engines.base import LogCallback

IGNORED_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build"}
SENSITIVE_SERVICE_PORTS = {"3306", "5432", "6379", "27017", "9200", "23", "21"}


def audit_compose_yaml(content: str, file_path_str: str) -> List[Finding]:
    """
    Parses docker-compose data structure and evaluates security misconfigurations.
    """
    findings: List[Finding] = []
    try:
        data = yaml.safe_load(content)
        if not isinstance(data, dict):
            return findings
    except Exception:
        return findings

    services = data.get("services", {})
    if not isinstance(services, dict):
        return findings

    for service_name, svc_conf in services.items():
        if not isinstance(svc_conf, dict):
            continue

        loc_str = f"{file_path_str} [service: {service_name}]"

        # 1. Privileged Container (IAC-CMP-001)
        if svc_conf.get("privileged") is True:
            findings.append(Finding(
                scan_id="auto",
                engine="infra_iac",
                check_id="IAC-CMP-001",
                category="Privilege Management",
                title=f"Docker Compose Service '{service_name}' Configured with 'privileged: true'",
                severity=Severity.HIGH,
                cvss_score=8.5,
                cvss_vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-250",
                owasp_category="A05:2021-Security Misconfiguration",
                nist_control="AC-6",
                description=f"Service '{service_name}' has privileged mode enabled in '{file_path_str}'.",
                impact="Container has full root access to all host devices, making container breakout trivial.",
                remediation="Remove 'privileged: true' and grant granular Linux capabilities (cap_add) only where strictly necessary.",
                remediation_code_snippet=f"# Instead of privileged: true, use:\ncap_add:\n  - NET_BIND_SERVICE\ncap_drop:\n  - ALL",
                references=["https://docs.docker.com/compose/compose-file/05-services/#privileged"],
                evidence=Evidence(
                    location=loc_str,
                    observed_value="privileged: true",
                    expected_value="privileged: false with minimal cap_add capabilities",
                ),
                fingerprint=calculate_fingerprint("IAC-CMP-001", loc_str, "privileged_true"),
            ))

        # 2. Docker Socket Mount (IAC-CMP-002)
        volumes = svc_conf.get("volumes", [])
        if isinstance(volumes, list):
            for vol in volumes:
                vol_str = str(vol)
                if "/var/run/docker.sock" in vol_str:
                    findings.append(Finding(
                        scan_id="auto",
                        engine="infra_iac",
                        check_id="IAC-CMP-002",
                        category="Container Breakout Risk",
                        title=f"Host Docker Socket Mounted into Service '{service_name}'",
                        severity=Severity.CRITICAL,
                        cvss_score=9.0,
                        cvss_vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
                        cwe_id="CWE-250",
                        owasp_category="A05:2021-Security Misconfiguration",
                        nist_control="AC-6, SC-7",
                        description=f"The host Docker UNIX daemon socket (/var/run/docker.sock) is mounted into container '{service_name}'.",
                        impact="Any process inside the container can command the host Docker daemon to create root containers and compromise the host node.",
                        remediation="Do not mount the Docker socket into untrusted containers. Use rootless Docker or socket proxies.",
                        references=["https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html"],
                        evidence=Evidence(
                            location=loc_str,
                            observed_value=f"volumes: - {vol_str}",
                            expected_value="No host docker.sock volume mounts",
                        ),
                        fingerprint=calculate_fingerprint("IAC-CMP-002", loc_str, "docker_sock_mount"),
                    ))

        # 3. Sensitive Port Exposed Publicly (IAC-CMP-003)
        ports = svc_conf.get("ports", [])
        if isinstance(ports, list):
            for p in ports:
                p_str = str(p)
                # Check if format is "3306:3306" or "0.0.0.0:3306:3306"
                parts = p_str.split(":")
                host_port = ""
                bind_ip = "0.0.0.0"

                if len(parts) == 2:
                    host_port = parts[0]
                elif len(parts) == 3:
                    bind_ip = parts[0]
                    host_port = parts[1]

                if host_port in SENSITIVE_SERVICE_PORTS and bind_ip in ("0.0.0.0", ""):
                    findings.append(Finding(
                        scan_id="auto",
                        engine="infra_iac",
                        check_id="IAC-CMP-003",
                        category="Network Perimeter Exposure",
                        title=f"Database/Datastore Port {host_port} Exposed on 0.0.0.0 in Service '{service_name}'",
                        severity=Severity.HIGH,
                        cvss_score=7.5,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        cwe_id="CWE-284",
                        owasp_category="A01:2021-Broken Access Control",
                        nist_control="SC-7",
                        description=f"Port {host_port} on service '{service_name}' is published on all public network interfaces (0.0.0.0).",
                        impact="Exposes internal database or cache instances directly to the public network without firewall isolation.",
                        remediation=f"Bind published port explicitly to localhost (127.0.0.1:{host_port}:{host_port}) or use internal Docker network.",
                        remediation_code_snippet=f"ports:\n  - \"127.0.0.1:{host_port}:{host_port}\"",
                        references=["https://docs.docker.com/compose/compose-file/05-services/#ports"],
                        evidence=Evidence(
                            location=loc_str,
                            observed_value=f"ports: - \"{p_str}\"",
                            expected_value=f"\"127.0.0.1:{host_port}:{host_port}\"",
                        ),
                        fingerprint=calculate_fingerprint("IAC-CMP-003", loc_str, p_str),
                    ))

    return findings


async def audit_compose_files(
    target_path: str,
    emit_log: Optional[LogCallback] = None,
) -> List[Finding]:
    """
    Finds and audits docker-compose.yml / compose.yaml files.
    """
    findings: List[Finding] = []
    root = Path(target_path)
    if not root.exists():
        return findings

    files_to_check = []
    if root.is_file() and any(k in root.name.lower() for k in ("compose", "docker-compose")):
        files_to_check.append(root)
    elif root.is_dir():
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in IGNORED_DIRS]
            for fn in filenames:
                fn_lower = fn.lower()
                if fn_lower.startswith("docker-compose") or fn_lower.startswith("compose"):
                    if fn_lower.endswith((".yml", ".yaml")):
                        files_to_check.append(Path(dirpath) / fn)

    for fpath in files_to_check:
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            rel_str = str(fpath.relative_to(root) if root.is_dir() else fpath.name)
            findings.extend(audit_compose_yaml(content, rel_str))
        except Exception:
            continue

    if emit_log:
        await emit_log(LogLevel.INFO, f"Docker Compose auditor inspected {len(files_to_check)} compose file(s).")

    return findings
