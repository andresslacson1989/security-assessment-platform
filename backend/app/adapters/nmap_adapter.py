"""
Contract 09 (TOOL-NMAP v14.3.0), Contract 03 (Section 4.2), Contract 06 (Section 2) & Contract 08 (Section 8.1)
Enterprise Nmap Tool Adapter Implementation & Execution Specification.

Authoritative References:
- contracts/09_TOOL_IMPLEMENTATION_CONTRACT.md (TOOL-NMAP Specification)
- contracts/03_ENGINE_PLUGIN_INTERFACE_CONTRACT.md
- contracts/01_PROJECT_SCOPE_AND_SAFETY_CONTRACT.md
- contracts/08_TECHNICAL_IMPLEMENTATION_AND_TEST_VECTORS_CONTRACT.md
"""

from __future__ import annotations
from datetime import datetime, timezone
from enum import Enum
import hashlib
import ipaddress
import logging
import os
import re
from typing import Optional, List, Dict, Any, Tuple, Set, Callable, Awaitable
import urllib.parse
import xml.etree.ElementTree as ET
from pydantic import BaseModel, Field

from app.core.models import (
    Target,
    ValidatedTarget,
    Finding,
    Evidence,
    Severity,
    ScanConfig,
    ScanProfile,
    TargetType,
    LogLevel,
    NormalizedExecutionState,
    calculate_fingerprint,
    calculate_evidence_hash,
    mask_secret,
    utc_now,
)
from app.adapters.base_adapter import BaseToolAdapter
from app.core.ssrf_protector import create_validated_target, is_ip_allowed

logger = logging.getLogger("cyberassess.adapters.nmap")


class ToolOperationClass(str, Enum):
    """
    Contract 09 §1.1 Invariant 2 & §2: Authoritative Operation Classifications.
    """
    PASSIVE = "PASSIVE"
    ACTIVE_READ_ONLY = "ACTIVE_READ_ONLY"
    ACTIVE_INTRUSIVE = "ACTIVE_INTRUSIVE"
    STATE_CHANGING = "STATE_CHANGING"
    CREDENTIAL_AWARE = "CREDENTIAL_AWARE"
    PRIVILEGED = "PRIVILEGED"


# ============================================================================
# 1. Authoritative Constants & Policy Invariants (Contract 09 v14.3.0)
# ============================================================================

TOOL_ID = "TOOL-NMAP"
TOOL_NAME = "nmap"
APPROVED_VERSION = "7.95"
APPROVED_VERSION_FULL = "Nmap 7.95"
TRUST_MODE = "PACKAGE_MANAGER_MODE"
ROLE = "PRIMARY"
SECURITY_DOMAIN = "NETWORK / PERIMETER / EASM"
DEFAULT_OPERATION_CLASS = ToolOperationClass.ACTIVE_READ_ONLY

# Approved NSE Script Allowlist (Contract 09 TOOL-NMAP §14 & §15)
APPROVED_NSE_SCRIPTS: Set[str] = {
    "banner",
    "ssl-cert",
    "http-title",
    "ssh2-enum-algos",
    "dns-nsec-enum",
}

# Forbidden Intrusive Script Categories (Contract 09 TOOL-NMAP §14)
FORBIDDEN_SCRIPT_CATEGORIES: Set[str] = {
    "exploit",
    "dos",
    "fuzzer",
    "intrusive",
    "brute",
    "vuln",
    "auth",
    "broadcast",
}

DEFAULT_TIMING_PROFILE = "-T4"
DEFAULT_PLATFORM_RATE_LIMIT_RPS = 5


# ============================================================================
# 2. Reproducibility & Execution Metadata Record
# ============================================================================

class NmapExecutionRecord(BaseModel):
    """
    Contract 09 TOOL-NMAP §38 & §44: Authoritative Execution Reproducibility Record.
    Captures complete immutable metadata of an Nmap execution.
    """
    model_config = dict(frozen=True, extra="ignore")

    tool_id: str = Field(default=TOOL_ID)
    exact_version: str = Field(default=APPROVED_VERSION)
    trust_mode: str = Field(default=TRUST_MODE)
    validated_target_id: str = Field(..., description="Cryptographic Target ID")
    authorization_decision_id: str = Field(..., description="Cryptographic Authorization Decision ID")
    policy_version: str = Field(default="14.3.0")
    command_args: List[str] = Field(default_factory=list)
    ports_scanned: List[int] = Field(default_factory=list)
    scripts_executed: List[str] = Field(default_factory=list)
    timing_profile: str = Field(default=DEFAULT_TIMING_PROFILE)
    upstream_exit_code: int = Field(default=0)
    normalized_state: NormalizedExecutionState = Field(default=NormalizedExecutionState.COMPLETED_NO_FINDINGS)
    evidence_hashes: List[str] = Field(default_factory=list)
    execution_timestamp: datetime = Field(default_factory=utc_now)


# ============================================================================
# 3. Port & Script Validation Helpers
# ============================================================================

def validate_port_specification(port_input: Any) -> Tuple[bool, List[int], Optional[str]]:
    """
    Contract 09 TOOL-NMAP §26: Strictly validates port list.
    Prevents shell injection and rejects invalid port ranges.
    Returns (is_valid, validated_port_integers, error_message).
    """
    if not port_input:
        return True, [], None

    valid_ports: List[int] = []
    if isinstance(port_input, (list, tuple, set)):
        for item in port_input:
            try:
                p_int = int(str(item).strip())
                if 1 <= p_int <= 65535:
                    valid_ports.append(p_int)
                else:
                    return False, [], f"Port number out of valid range 1..65535: {p_int}"
            except (ValueError, TypeError):
                return False, [], f"Invalid port value: '{item}'"
    elif isinstance(port_input, str):
        # Support comma-separated port numbers: "80,443,8080"
        for part in port_input.split(","):
            part_clean = part.strip()
            if not part_clean:
                continue
            if "-" in part_clean:
                # Port range: "1-1024"
                try:
                    start_str, end_str = part_clean.split("-", 1)
                    start_p, end_p = int(start_str.strip()), int(end_str.strip())
                    if 1 <= start_p <= end_p <= 65535:
                        valid_ports.extend(range(start_p, end_p + 1))
                    else:
                        return False, [], f"Invalid port range: '{part_clean}'"
                except ValueError:
                    return False, [], f"Invalid port range format: '{part_clean}'"
            else:
                try:
                    p_int = int(part_clean)
                    if 1 <= p_int <= 65535:
                        valid_ports.append(p_int)
                    else:
                        return False, [], f"Port number out of range 1..65535: {p_int}"
                except ValueError:
                    return False, [], f"Invalid port string token: '{part_clean}'"
    else:
        return False, [], f"Unsupported port input type: {type(port_input)}"

    # Deduplicate and sort
    deduped = sorted(list(dict.fromkeys(valid_ports)))
    return True, deduped, None


def extract_host(target_value: str) -> str:
    """
    Extracts the clean hostname or IP from target string.
    """
    if "://" in target_value:
        parsed = urllib.parse.urlparse(target_value)
        return parsed.hostname or target_value
    if ":" in target_value and not target_value.count(":") > 1:
        return target_value.split(":")[0]
    return target_value.strip().strip("[]")


def sanitize_banner_or_script(text: str) -> str:
    """
    Sanitizes potential credential leaks in banners or NSE script outputs.
    Masks high-entropy tokens and password values matching key patterns.
    """
    if not text:
        return ""
    # Mask key patterns like password=..., api_key=..., secret=...
    sanitized = re.sub(
        r"(?i)(password|passwd|pwd|secret|api_key|token|auth_token|bearer)\s*[:=]\s*([^\s,;]+)",
        r"\1: [MASKED]",
        text,
    )
    return sanitized


def classify_nmap_operation(
    scripts: Optional[List[str]] = None,
    dns_zone_authorized: bool = False,
    is_domain: bool = False,
) -> ToolOperationClass:
    """
    Contract 09 §1.1 Invariant 2 & TOOL-NMAP §2:
    Deterministically classifies the requested Nmap operation based on target, scripts, and arguments.
    - If dns-nsec-enum or explicit intrusive scripts are requested: ToolOperationClass.ACTIVE_INTRUSIVE
    - Otherwise (port discovery, service version probing -sV, standard discovery scripts): ToolOperationClass.ACTIVE_READ_ONLY
    """
    if scripts:
        for s in scripts:
            if s.lower() in ("dns-nsec-enum",):
                return ToolOperationClass.ACTIVE_INTRUSIVE
    elif is_domain and dns_zone_authorized:
        return ToolOperationClass.ACTIVE_INTRUSIVE
    return ToolOperationClass.ACTIVE_READ_ONLY


# ============================================================================
# 4. Dedicated Nmap Command Builder (Contract 09 §11, §19, §20, §21)
# ============================================================================

class NmapCommandBuilder:
    """
    Dedicated deterministic Nmap command builder.
    Rejects raw user command strings and constructs bounded argument vectors.
    Enforces intrusive authorization directly at the command construction boundary.
    """

    @staticmethod
    def build_command(
        nmap_path: str,
        target: ValidatedTarget,
        config: ScanConfig,
        intrusive_authorized: bool = False,
        dns_zone_authorized: bool = False,
        custom_scripts: Optional[List[str]] = None,
    ) -> Tuple[List[str], List[int], List[str], Optional[str]]:
        """
        Builds the exact argument vector for Nmap execution:
        nmap -sV --version-light -T4 -oX - [--script <approved_scripts>] [-p <ports>] <selected_destination>
        
        Returns: (cmd_list, ports_list, scripts_list, error_message)
        """
        if not nmap_path or not isinstance(nmap_path, str) or not nmap_path.strip():
            return [], [], [], "Nmap executable path must be a non-empty string."

        # Validate destination IP
        destination_ip = target.selected_destination.strip().strip("[]")
        if not destination_ip:
            return [], [], [], "ValidatedTarget missing selected_destination IP address."

        # Validate port specification
        ports_to_scan = config.port_list or []
        is_ports_valid, valid_ports, port_err = validate_port_specification(ports_to_scan)
        if not is_ports_valid:
            return [], [], [], f"Port validation error: {port_err}"

        # Resolve approved scripts
        resolved_scripts: List[str] = []
        if custom_scripts:
            for s in custom_scripts:
                s_clean = s.strip().lower()
                if s_clean in APPROVED_NSE_SCRIPTS:
                    if s_clean == "dns-nsec-enum":
                        if target.target_type == TargetType.DOMAIN and dns_zone_authorized:
                            resolved_scripts.append(s_clean)
                    else:
                        resolved_scripts.append(s_clean)
                else:
                    return [], [], [], f"NSE Script '{s}' is not on the approved allowlist."
        else:
            # Default discovery scripts
            resolved_scripts = ["banner", "ssl-cert", "http-title", "ssh2-enum-algos"]
            if target.target_type == TargetType.DOMAIN and dns_zone_authorized:
                resolved_scripts.append("dns-nsec-enum")

        # Classify operation and enforce intrusive authorization at builder boundary
        op_class = classify_nmap_operation(resolved_scripts)
        if op_class == ToolOperationClass.ACTIVE_INTRUSIVE and not intrusive_authorized:
            return (
                [],
                [],
                [],
                "INTRUSIVE_OPERATION_REJECTED: Active intrusive operation (e.g. dns-nsec-enum) requested but intrusive_authorized is False at execution boundary.",
            )

        # Base Command Vector (Contract 09 TOOL-NMAP §19)
        cmd: List[str] = [
            nmap_path,
            "-sV",
            "--version-light",
            DEFAULT_TIMING_PROFILE,
            "-oX",
            "-",
        ]

        # Port argument
        if valid_ports:
            cmd.extend(["-p", ",".join(str(p) for p in valid_ports)])

        # Script argument
        if resolved_scripts:
            cmd.extend(["--script", ",".join(resolved_scripts)])
            # Inject Host header context for HTTP scripts (Contract 09 TOOL-NMAP §13)
            canonical_host = target.canonical_value
            if "://" in canonical_host:
                parsed = urllib.parse.urlparse(canonical_host)
                canonical_host = parsed.hostname or canonical_host
            cmd.extend(["--script-args", f"http.host={canonical_host}"])

        # Destination IP (Connection-Level Destination Binding Invariant)
        cmd.append(destination_ip)

        return cmd, valid_ports, resolved_scripts, None


# ============================================================================
# 5. Nmap Adapter Class (Contract 09 TOOL-NMAP v14.3.0)
# ============================================================================

class NmapAdapter(BaseToolAdapter):
    """
    Authoritative Enterprise Nmap Tool Adapter.
    Enforces exact version (7.95), approved NSE allowlist, 3-tier authorization,
    connection-level destination binding, hardened XML parsing, and coverage preservation.
    """

    @property
    def tool_id(self) -> str:
        return TOOL_ID

    @property
    def tool_name(self) -> str:
        return TOOL_NAME

    @property
    def approved_version(self) -> str:
        return APPROVED_VERSION

    @property
    def trust_mode(self) -> str:
        return TRUST_MODE

    @property
    def operation_class(self) -> ToolOperationClass:
        return DEFAULT_OPERATION_CLASS

    async def get_version(self, custom_path: Optional[str] = None) -> Optional[str]:
        """
        Contract 09 TOOL-NMAP §7: Retrieves Nmap version via `nmap --version`.
        Strict regex extraction; rejects malformed output.
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

    def verify_version(self, version_str: Optional[str]) -> Tuple[bool, Optional[str]]:
        """
        Contract 09 TOOL-NMAP §7: Exact version enforcement.
        Requires actual_version == APPROVED_VERSION (7.95).
        Discrepancies fail closed.
        """
        if not version_str:
            return False, "Nmap version probe returned empty or unavailable version."

        clean_v = version_str.replace("Nmap", "").strip()
        if clean_v != self.approved_version:
            return (
                False,
                f"INVALID_VERSION: Approved Nmap version is '{self.approved_version}', but found '{clean_v}'."
            )
        return True, None

    def evaluate_three_tier_authorization(
        self,
        target: ValidatedTarget,
        config: ScanConfig,
        operation_class: ToolOperationClass = ToolOperationClass.ACTIVE_READ_ONLY,
        custom_scripts: Optional[List[str]] = None,
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Contract 09 §1.1 Invariant 7 & TOOL-NMAP §4: Three-Tier Authorization Gate.
        Evaluates:
          Gate 1: TOOL_CAPABILITY (Supported scan type & approved NSE allowlist)
          Gate 2: PROFILE_AUTHORIZATION (Profile allows network sweep / port probing)
          Gate 3: TENANT_SCOPE_AUTHORIZATION (Target scope authorized; ACTIVE_INTRUSIVE requires active_probing_granted)
        Returns (is_authorized, reason, failed_gate_name).
        """
        # Gate 1: Tool Capability
        if custom_scripts:
            for s in custom_scripts:
                if s.lower() not in APPROVED_NSE_SCRIPTS:
                    return False, f"NSE script '{s}' is not supported by TOOL-NMAP capability allowlist (Gate 1).", "TOOL_CAPABILITY"

        # Gate 2: Profile Authorization
        allowed_profiles = {
            ScanProfile.FULL_STACK,
            ScanProfile.NETWORK_ONLY,
            ScanProfile.NETWORK_TLS,
            ScanProfile.QUICK,
            ScanProfile.QUICK_AUDIT,
            ScanProfile.EASM_EXPANDED,
            ScanProfile.CUSTOM,
        }
        active_profile = getattr(config, "profile", ScanProfile.FULL_STACK)
        if active_profile not in allowed_profiles:
            return False, f"Scan profile '{active_profile.value}' does not authorize network port scanning (Gate 2).", "PROFILE_AUTHORIZATION"

        # Gate 3: Tenant Scope Authorization
        auth_ctx = getattr(target, "authorization_context", {}) or {}
        
        # Verify base scope authorization
        if auth_ctx.get("out_of_scope", False):
            return False, "Target is outside tenant authorized scope (Gate 3).", "TENANT_SCOPE_AUTHORIZATION"
        authorized_scope_list = getattr(target, "authorized_scope", None)
        if authorized_scope_list and target.canonical_value not in authorized_scope_list and target.selected_destination not in authorized_scope_list:
            return False, "Target is outside tenant authorized scope list (Gate 3).", "TENANT_SCOPE_AUTHORIZATION"

        # For ACTIVE_INTRUSIVE operations (e.g. dns-nsec-enum zone walking), require explicit active_probing_granted
        if operation_class == ToolOperationClass.ACTIVE_INTRUSIVE:
            if not auth_ctx.get("active_probing_granted", False):
                return False, "Active intrusive probing requested but tenant authorization lacks active_probing_granted (Gate 3).", "TENANT_SCOPE_AUTHORIZATION"

        return True, None, None

    def parse_nmap_xml(
        self,
        xml_content: str,
        target: ValidatedTarget,
        scan_id: str,
        emit_log: Optional[Callable[[LogLevel, str], Awaitable[None]]] = None,
    ) -> Tuple[List[Finding], NormalizedExecutionState, List[str]]:
        """
        Contract 09 TOOL-NMAP §24, §30, §31, §33, §34, §35: Hardened XML Parser.
        Treats XML as untrusted input. Extracts ports, services, banners, and NSE script output.
        Normalizes into canonical Finding models with cryptographic evidence digests.
        """
        findings: List[Finding] = []
        evidence_hashes: List[str] = []

        if not xml_content or not xml_content.strip():
            return findings, NormalizedExecutionState.TOOL_EXECUTION_FAILED, evidence_hashes

        try:
            root = ET.fromstring(xml_content)
        except ET.ParseError as e:
            if emit_log:
                logger.warning(f"PARSER_ERROR: Failed to parse Nmap XML output: {e}")
            return findings, NormalizedExecutionState.PARTIAL_RESULTS_WITH_WARNING, evidence_hashes

        # Validate root structure
        if root.tag != "nmaprun":
            if emit_log:
                logger.warning("PARSER_ERROR: Root XML element is not <nmaprun>.")
            return findings, NormalizedExecutionState.PARTIAL_RESULTS_WITH_WARNING, evidence_hashes

        target_host = target.canonical_value
        target_ip = target.selected_destination

        seen_ports: Set[Tuple[int, str]] = set()

        for port_elem in root.findall(".//ports/port"):
            portid_str = port_elem.get("portid", "0")
            try:
                portid = int(portid_str)
            except ValueError:
                continue

            protocol = (port_elem.get("protocol") or "tcp").lower()
            if (portid, protocol) in seen_ports:
                continue
            seen_ports.add((portid, protocol))

            state_elem = port_elem.find("state")
            state = (state_elem.get("state") if state_elem is not None else "unknown").lower()
            if state != "open":
                continue

            service_elem = port_elem.find("service")
            service_name = service_elem.get("name", "unknown") if service_elem is not None else "unknown"
            product = service_elem.get("product", "") if service_elem is not None else ""
            version = service_elem.get("version", "") if service_elem is not None else ""
            extrainfo = service_elem.get("extrainfo", "") if service_elem is not None else ""

            # Sanitize raw strings for secret masking
            clean_product = sanitize_banner_or_script(product) if product else ""
            clean_version = sanitize_banner_or_script(version) if version else ""
            clean_extrainfo = sanitize_banner_or_script(extrainfo) if extrainfo else ""

            version_desc = f"{clean_product} {clean_version} {clean_extrainfo}".strip() or service_name

            script_outputs: List[str] = []
            for script in port_elem.findall("script"):
                s_id = script.get("id", "")
                s_out = script.get("output", "").strip()
                if s_id and s_out:
                    masked_out = sanitize_banner_or_script(s_out)
                    script_outputs.append(f"[{s_id}]\n{masked_out}")
            script_text = "\n\n".join(script_outputs) if script_outputs else None

            # Finding Normalization & Service Observation vs Misconfiguration Distinction (Contract 09 §38 & §39)
            if portid in (21, 23) or service_name in ("ftp", "telnet"):
                # Cleartext insecure remote management misconfiguration
                check_id = "NET-PORT-003"
                title = f"Insecure Cleartext Remote Management Service (Port {portid} - {service_name.upper()})"
                category = "Network Perimeter Exposure"
                severity = Severity.MEDIUM
                cvss_score = 5.3
                cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
                cwe_id = "CWE-319"
                owasp = "A02:2021-Cryptographic Failures"
                nist = "AC-17, IA-2"
                description = f"Insecure cleartext remote management service {service_name.upper()} is active on port {portid} on {target_host} ({target_ip}). Cleartext protocols transmit credentials unencrypted across the network."
                remediation = "Disable plaintext management service and migrate exclusively to SSH or SFTP with TLS."
            else:
                # Service discovery & asset observation posture (Contract 09 TOOL-NMAP §39)
                check_id = "NET-SVC-001"
                title = f"Service Daemon Detected on Port {portid} ({version_desc})"
                category = "Service Posture / Asset Observation"
                severity = Severity.INFO
                cvss_score = 0.0
                cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
                cwe_id = "CWE-200"
                owasp = "A05:2021-Security Misconfiguration"
                nist = "CM-6"
                description = f"Service daemon '{service_name}' ({version_desc}) is open and listening on port {portid} on {target_host} ({target_ip})."
                remediation = "Verify whether this port must be publicly accessible and ensure the service daemon is updated and firewall-restricted if non-public."

            location = f"{target_host}:{portid}"
            observed_val = f"Port {portid}/{protocol} is open - Service: {version_desc}"
            raw_snippet = script_text or f"Service: {service_name}\nProduct: {clean_product}\nVersion: {clean_version}"
            
            ev_hash = calculate_evidence_hash(location, observed_val)
            evidence_hashes.append(ev_hash)

            evidence = Evidence(
                location=location,
                observed_value=observed_val,
                expected_value="Port closed or blocked by perimeter firewall",
                raw_response_snippet=raw_snippet,
            )

            finding = Finding(
                scan_id=scan_id,
                engine="network",
                source_tool="nmap",
                check_id=check_id,
                category=category,
                title=title,
                severity=severity,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                cwe_id=cwe_id,
                owasp_category=owasp,
                nist_control=nist,
                description=description,
                impact="Unauthenticated or weakly authenticated actors can probe or exploit exposed network daemons.",
                remediation=remediation,
                remediation_code_snippet=f"# UFW Firewall Deny:\nsudo ufw deny {portid}/{protocol}",
                references=["https://nmap.org/book/man-version-detection.html"],
                evidence=evidence,
                fingerprint=calculate_fingerprint(check_id, location, f"nmap_{portid}_{service_name}"),
            )

            findings.append(finding)

        exec_state = (
            NormalizedExecutionState.COMPLETED_WITH_FINDINGS
            if findings
            else NormalizedExecutionState.COMPLETED_NO_FINDINGS
        )
        return findings, exec_state, evidence_hashes

    async def run(
        self,
        target: Target | ValidatedTarget,
        config: ScanConfig,
        emit_log: Callable[[LogLevel, str], Awaitable[None]],
        emit_finding: Callable[[Finding], Awaitable[None]],
        **kwargs,
    ) -> List[Finding]:
        """
        Executes Nmap adapter lifecycle:
        1. Validates Target -> ValidatedTarget
        2. Resolves Binary & Enforces Version 7.95
        3. Evaluates 3-Tier Intrusive Authorization
        4. Builds Deterministic Command
        5. Executes via ProcessSupervisor
        6. Parses XML & Emits Findings
        7. Returns Findings & Preserves Reproducibility Metadata
        """
        findings: List[Finding] = []
        scan_id = kwargs.get("scan_id", "adapter-nmap")

        # 1. Target Validation & Normalization
        if isinstance(target, ValidatedTarget):
            val_target = target
        else:
            try:
                val_target = create_validated_target(
                    target,
                    organization_id=kwargs.get("organization_id", "org-default"),
                    project_id=kwargs.get("project_id"),
                    asset_id=kwargs.get("asset_id"),
                )
            except Exception as e:
                await emit_log(LogLevel.ERROR, f"Target validation failed for Nmap: {e}")
                return findings

        # 2. Binary Resolution
        custom_path = getattr(config.adapters, "nmap_path", None) or getattr(config.adapters, "custom_nmap_path", None)
        nmap_path = self.resolve_binary_path(custom_path)
        if not nmap_path:
            await emit_log(LogLevel.WARNING, "Nmap binary not found on host. Skipping Nmap execution.")
            return findings

        # 3. Exact Version Enforcement (Contract 09 TOOL-NMAP §7)
        version_str = await self.get_version(nmap_path)
        is_v_valid, v_err = self.verify_version(version_str)
        if not is_v_valid:
            await emit_log(LogLevel.ERROR, f"Nmap version rejected: {v_err}. Execution blocked.")
            return findings

        # 4. Classify Operation & Evaluate Three-Tier Authorization Check
        custom_scripts = kwargs.get("custom_scripts")
        auth_ctx = getattr(val_target, "authorization_context", {}) or {}
        dns_zone_auth = (
            auth_ctx.get("dns_zone_assessment_authorized", False)
            or auth_ctx.get("dns_zone_authorized", False)
            or kwargs.get("dns_zone_authorized", False)
        )
        is_domain = val_target.target_type == TargetType.DOMAIN
        intrusive_granted = bool(auth_ctx.get("active_probing_granted", False))

        op_class = classify_nmap_operation(
            scripts=custom_scripts,
            dns_zone_authorized=dns_zone_auth,
            is_domain=is_domain,
        )

        is_auth, auth_err, failed_gate = self.evaluate_three_tier_authorization(
            val_target,
            config,
            operation_class=op_class,
            custom_scripts=custom_scripts,
        )
        if not is_auth:
            await emit_log(LogLevel.WARNING, f"Nmap execution blocked by policy ({failed_gate}): {auth_err}")
            return findings

        # 5. Build Command via Command Builder (Enforces intrusive authorization at builder boundary)
        cmd, ports_scanned, scripts_executed, cmd_err = NmapCommandBuilder.build_command(
            nmap_path=nmap_path,
            target=val_target,
            config=config,
            intrusive_authorized=intrusive_granted,
            dns_zone_authorized=dns_zone_auth,
            custom_scripts=custom_scripts,
        )
        if cmd_err:
            await emit_log(LogLevel.ERROR, f"Failed to build Nmap command: {cmd_err}")
            return findings

        timeout_sec = float(min(60.0, config.timeout_seconds * 6))
        await emit_log(
            LogLevel.INFO,
            f"Executing Nmap port and service scan on destination IP '{val_target.selected_destination}' (Canonical: '{val_target.canonical_value}')...",
        )

        # 6. Execute via ProcessSupervisor
        returncode, stdout, stderr = await self.execute_command(
            cmd,
            timeout=timeout_sec,
            emit_log=emit_log,
        )

        # Handle Timeout & Cancellation
        if returncode != 0 and "timed out" in stderr.lower():
            await emit_log(LogLevel.WARNING, f"Nmap execution timed out after {timeout_sec}s.")
            return findings

        if not stdout.strip():
            await emit_log(
                LogLevel.WARNING,
                f"Nmap produced no output (Exit code {returncode}): {stderr.strip()}",
            )
            return findings

        # 7. Parse XML Output & Generate Findings
        parsed_findings, exec_state, ev_hashes = self.parse_nmap_xml(
            stdout,
            target=val_target,
            scan_id=scan_id,
            emit_log=emit_log,
        )

        # Emit findings
        for f in parsed_findings:
            findings.append(f)
            await emit_finding(f)

        await emit_log(
            LogLevel.INFO,
            f"Nmap scan completed successfully with state '{exec_state.value}'. Generated {len(findings)} observations.",
        )
        return findings
