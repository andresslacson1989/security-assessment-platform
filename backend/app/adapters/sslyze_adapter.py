"""
Contract 09 §TOOL-SSLYZE (TOOL 02: SSLyze v14.3.0), Contract 03 §4.2, Contract 06 §2 & Contract 08 §8.2.
Authoritative Reference: contracts/09_TOOL_IMPLEMENTATION_CONTRACT.md

SSLyze Enterprise-Grade Tool Adapter Specification:
- Tool ID: TOOL-SSLYZE
- Pinned Version: SSLyze 5.2.0 (Exact PyPI Release)
- Supply Chain Trust: PACKAGE_MANAGER_MODE (pip wheel in locked environment)
- Role: PRIMARY TLS & Cryptographic Configuration Authority
- Operation Class: ACTIVE_READ_ONLY
- Destination Binding: Positional <selected_destination>:<port> with separate SNI --server_name=<canonical_hostname>
"""

from __future__ import annotations
import hashlib
import json
import re
import urllib.parse
from datetime import datetime
from typing import Optional, List, Dict, Set, Tuple, Any, Callable, Awaitable
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
    utc_now,
)
from app.core.ssrf_protector import create_validated_target
from app.core.process_supervisor import ProcessSupervisor
from app.adapters.base_adapter import BaseToolAdapter


class ToolOperationClass:
    """
    Contract 09 §1.1 Invariant 2: Operational Safety Classifications.
    """
    PASSIVE = "PASSIVE"
    ACTIVE_READ_ONLY = "ACTIVE_READ_ONLY"
    ACTIVE_INTRUSIVE = "ACTIVE_INTRUSIVE"
    STATE_CHANGING = "STATE_CHANGING"
    CREDENTIAL_AWARE = "CREDENTIAL_AWARE"
    PRIVILEGED = "PRIVILEGED"


# ============================================================================
# 1. Authoritative Constants, Capability Taxonomy & Policies (Contract 09 v14.3.0)
# ============================================================================

TOOL_ID = "TOOL-SSLYZE"
TOOL_NAME = "sslyze"
APPROVED_VERSION = "5.2.0"
APPROVED_VERSION_FULL = "SSLyze 5.2.0"
TRUST_MODE = "PACKAGE_MANAGER_MODE"
ROLE = "PRIMARY"
SECURITY_DOMAIN = "NETWORK / PERIMETER / TLS"
DEFAULT_OPERATION_CLASS = ToolOperationClass.ACTIVE_READ_ONLY

# Capability & Classification Taxonomy for SSLyze Scan Modules (Contract 09 TOOL-SSLYZE §41)
SSLYZE_CAPABILITIES: Dict[str, Dict[str, Any]] = {
    "certinfo": {
        "operation_class": ToolOperationClass.ACTIVE_READ_ONLY,
        "description": "Certificate deployment, chain trust, and signature validation",
        "intrusive": False,
        "category": "certificate",
    },
    "sslv2": {
        "operation_class": ToolOperationClass.ACTIVE_READ_ONLY,
        "description": "SSL 2.0 deprecated protocol and cipher suite negotiation",
        "intrusive": False,
        "category": "protocol_cipher",
    },
    "sslv3": {
        "operation_class": ToolOperationClass.ACTIVE_READ_ONLY,
        "description": "SSL 3.0 deprecated protocol and cipher suite negotiation",
        "intrusive": False,
        "category": "protocol_cipher",
    },
    "tlsv1": {
        "operation_class": ToolOperationClass.ACTIVE_READ_ONLY,
        "description": "TLS 1.0 deprecated protocol and cipher suite negotiation",
        "intrusive": False,
        "category": "protocol_cipher",
    },
    "tlsv1_1": {
        "operation_class": ToolOperationClass.ACTIVE_READ_ONLY,
        "description": "TLS 1.1 deprecated protocol and cipher suite negotiation",
        "intrusive": False,
        "category": "protocol_cipher",
    },
    "tlsv1_2": {
        "operation_class": ToolOperationClass.ACTIVE_READ_ONLY,
        "description": "TLS 1.2 protocol and cipher suite negotiation",
        "intrusive": False,
        "category": "protocol_cipher",
    },
    "tlsv1_3": {
        "operation_class": ToolOperationClass.ACTIVE_READ_ONLY,
        "description": "TLS 1.3 modern protocol and cipher suite negotiation",
        "intrusive": False,
        "category": "protocol_cipher",
    },
    "heartbleed": {
        "operation_class": ToolOperationClass.ACTIVE_READ_ONLY,
        "description": "OpenSSL Heartbleed TLS extension probe (CVE-2014-0160)",
        "intrusive": False,
        "category": "vulnerability",
    },
    "robot": {
        "operation_class": ToolOperationClass.ACTIVE_READ_ONLY,
        "description": "Bleichenbacher RSA padding oracle vulnerability test",
        "intrusive": False,
        "category": "vulnerability",
    },
    "openssl_ccs": {
        "operation_class": ToolOperationClass.ACTIVE_READ_ONLY,
        "description": "OpenSSL ChangeCipherSpec injection probe (CVE-2014-0224)",
        "intrusive": False,
        "category": "vulnerability",
    },
}

# Approved CLI Flags & Scan Commands (Contract 09 TOOL-SSLYZE §20)
APPROVED_SSLYZE_FLAGS: Set[str] = {
    "--json_out=-",
    "--certinfo",
    "--sslv2",
    "--sslv3",
    "--tlsv1",
    "--tlsv1_1",
    "--tlsv1_2",
    "--tlsv1_3",
    "--heartbleed",
    "--robot",
    "--openssl_ccs",
    "--reneg",
    "--resum",
    "--early_data",
}

# Default Scan Flags (Contract 09 TOOL-SSLYZE §19)
DEFAULT_SCAN_FLAGS: List[str] = [
    "--certinfo",
    "--sslv2",
    "--sslv3",
    "--tlsv1",
    "--tlsv1_1",
    "--tlsv1_2",
    "--tlsv1_3",
    "--heartbleed",
    "--robot",
    "--openssl_ccs",
]

# Weak Cipher Suite Patterns (Contract 09 TOOL-SSLYZE §31 & CWE-327)
WEAK_CIPHER_PATTERNS: List[re.Pattern] = [
    re.compile(r"RC4", re.IGNORECASE),
    re.compile(r"3DES|DES_CBC", re.IGNORECASE),
    re.compile(r"_NULL_", re.IGNORECASE),
    re.compile(r"_EXPORT_", re.IGNORECASE),
    re.compile(r"_ANON_", re.IGNORECASE),
    re.compile(r"_MD5$", re.IGNORECASE),
]


# ============================================================================
# 2. Reproducibility & Execution Metadata Record
# ============================================================================

class SslyzeExecutionRecord(BaseModel):
    """
    Contract 09 TOOL-SSLYZE §38 & §44: Authoritative Execution Reproducibility Record.
    Captures complete immutable metadata of an SSLyze execution.
    """
    model_config = dict(frozen=True, extra="ignore")

    tool_id: str = Field(default=TOOL_ID)
    exact_version: str = Field(default=APPROVED_VERSION)
    trust_mode: str = Field(default=TRUST_MODE)
    validated_target_id: str = Field(..., description="Cryptographic Target ID")
    authorization_decision_id: str = Field(..., description="Cryptographic Authorization Decision ID")
    policy_version: str = Field(default="14.3.0")
    target_destination: str = Field(..., description="Pre-resolved IP address")
    target_port: int = Field(default=443)
    server_name_sni: str = Field(..., description="Host header / SNI passed to --server_name")
    command_args: List[str] = Field(default_factory=list)
    upstream_exit_code: int = Field(default=0)
    normalized_state: NormalizedExecutionState = Field(default=NormalizedExecutionState.COMPLETED_NO_FINDINGS)
    evidence_hashes: List[str] = Field(default_factory=list)
    execution_timestamp: datetime = Field(default_factory=utc_now)


# ============================================================================
# 3. Target, Sanitization & Operation Classification Helpers
# ============================================================================

def extract_host_port(target_value: str) -> Tuple[str, int]:
    """
    Extracts canonical hostname and port from target value.
    Defaults to port 443 for TLS scanning.
    """
    if "://" in target_value:
        parsed = urllib.parse.urlparse(target_value)
        host = parsed.hostname or target_value
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        return host.strip().strip("[]"), port
    if ":" in target_value and not target_value.count(":") > 1:
        parts = target_value.split(":")
        try:
            return parts[0].strip().strip("[]"), int(parts[1].strip())
        except ValueError:
            return parts[0].strip().strip("[]"), 443
    return target_value.strip().strip("[]"), 443


def sanitize_tls_evidence_text(text: str) -> str:
    """
    Contract 09 TOOL-SSLYZE §35:
    Sanitizes potential private keys or sensitive cryptographic material from evidence strings.
    Masks private key blocks and sensitive credential tokens.
    """
    if not text:
        return ""
    # Mask private key blocks
    text = re.sub(
        r"-----BEGIN (?:[A-Z0-9_-]+ )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9_-]+ )?PRIVATE KEY-----",
        "[REDACTED_PRIVATE_KEY]",
        text,
    )
    # Mask key patterns like password=..., api_key=..., secret=...
    text = re.sub(
        r"(?i)(password|passwd|pwd|secret|api_key|token|auth_token|bearer)\s*[:=]\s*([^\s,;]+)",
        r"\1: [MASKED]",
        text,
    )
    return text


def classify_sslyze_operation(
    scan_flags: Optional[List[str]] = None,
) -> ToolOperationClass:
    """
    Contract 09 §1.1 Invariant 2 & TOOL-SSLYZE §4:
    SSLyze performs non-destructive, non-state-changing cryptographic handshakes.
    All approved modules are classified as ACTIVE_READ_ONLY.
    """
    return ToolOperationClass.ACTIVE_READ_ONLY


# ============================================================================
# 4. Dedicated SSLyze Command Builder (Contract 09 TOOL-SSLYZE §13, §19, §20)
# ============================================================================

class SslyzeCommandBuilder:
    """
    Dedicated deterministic SSLyze command builder.
    Enforces connection-level destination binding (selected_destination IP)
    and separate SNI host header (--server_name) argument separation.
    Rejects arbitrary file outputs and unvalidated flags.
    """

    @staticmethod
    def build_command(
        sslyze_path: str,
        target: ValidatedTarget,
        port: Optional[int] = None,
        custom_flags: Optional[List[str]] = None,
    ) -> Tuple[List[str], str, int, Optional[str]]:
        """
        Constructs:
        <sslyze_path> --json_out=- <selected_destination>:<port> --server_name=<canonical_hostname> [<flags>]
        
        Returns: (cmd_list, destination_ip, target_port, error_message)
        """
        if not sslyze_path or not isinstance(sslyze_path, str) or not sslyze_path.strip():
            return [], "", 0, "SSLyze executable path must be a non-empty string."

        # Validate destination IP (Destination Binding Invariant)
        destination_ip = target.selected_destination.strip().strip("[]")
        if not destination_ip:
            return [], "", 0, "ValidatedTarget missing selected_destination IP address."

        # Resolve port
        target_port = port or target.port or 443
        if not (1 <= target_port <= 65535):
            return [], "", 0, f"Target port out of valid range 1..65535: {target_port}"

        # Resolve SNI Hostname (SNI / Virtual Host Header Context)
        canonical_host = target.canonical_value.strip()
        if "://" in canonical_host:
            parsed = urllib.parse.urlparse(canonical_host)
            canonical_host = parsed.hostname or canonical_host
        if ":" in canonical_host and not canonical_host.count(":") > 1:
            canonical_host = canonical_host.split(":")[0]
        canonical_host = canonical_host.strip().strip("[]")

        # Validate custom flags if provided
        resolved_flags: List[str] = []
        if custom_flags:
            for flag in custom_flags:
                clean_f = flag.strip()
                if clean_f.startswith("--json_out=") and clean_f != "--json_out=-":
                    return [], "", 0, "Arbitrary file output via --json_out is forbidden."
                if clean_f not in APPROVED_SSLYZE_FLAGS and not clean_f.startswith("--server_name="):
                    return [], "", 0, f"SSLyze flag '{clean_f}' is not on the approved allowlist."
                if clean_f != "--json_out=-" and not clean_f.startswith("--server_name="):
                    resolved_flags.append(clean_f)
        else:
            resolved_flags = list(DEFAULT_SCAN_FLAGS)

        # Base Command Vector
        cmd: List[str] = [
            sslyze_path,
            "--json_out=-",
            f"{destination_ip}:{target_port}",
            f"--server_name={canonical_host}",
        ]
        cmd.extend(resolved_flags)

        return cmd, destination_ip, target_port, None


# ============================================================================
# 5. SSLyze Adapter Class (Contract 09 TOOL-SSLYZE v14.3.0)
# ============================================================================

class SslyzeAdapter(BaseToolAdapter):
    """
    Contract 09 TOOL-SSLYZE: Authoritative SSLyze Tool Adapter.
    Executes SSLyze in a supervised process, parses JSON results, and normalizes
    findings into canonical NET-TLS-xxx security records with zero CVSS inflation.
    """

    def __init__(self):
        super().__init__()
        self.approved_version = APPROVED_VERSION
        self.trust_mode = TRUST_MODE
        self.role = ROLE
        self.security_domain = SECURITY_DOMAIN
        self.default_operation_class = DEFAULT_OPERATION_CLASS

    @property
    def tool_name(self) -> str:
        return TOOL_NAME

    async def get_version(self, custom_path: Optional[str] = None) -> Optional[str]:
        """
        Contract 09 TOOL-SSLYZE §7: Retrieves SSLyze version via `sslyze --version`.
        Strict regex extraction; rejects malformed output.
        """
        path = self.resolve_binary_path(custom_path)
        if not path:
            return None

        returncode, stdout, _ = await self.execute_command([path, "--version"], timeout=5.0)
        if returncode == 0 and stdout:
            first_line = stdout.splitlines()[0].strip()
            match = re.search(r"(\d+\.\d+(\.\d+)?)", first_line)
            if match:
                return f"SSLyze {match.group(1)}"
            return first_line
        return None

    def verify_version(self, version_str: Optional[str]) -> Tuple[bool, Optional[str]]:
        """
        Contract 09 TOOL-SSLYZE §7: Exact version enforcement.
        Requires actual_version == APPROVED_VERSION (5.2.0).
        Discrepancies fail closed.
        """
        if not version_str:
            return False, "SSLyze version probe returned empty or unavailable version."

        clean_v = version_str.replace("SSLyze", "").replace("sslyze", "").replace("v", "").strip()
        if clean_v != self.approved_version:
            return (
                False,
                f"INVALID_VERSION: Approved SSLyze version is '{self.approved_version}', but found '{clean_v}'."
            )
        return True, None

    def evaluate_three_tier_authorization(
        self,
        target: ValidatedTarget,
        config: ScanConfig,
        operation_class: ToolOperationClass = ToolOperationClass.ACTIVE_READ_ONLY,
        custom_flags: Optional[List[str]] = None,
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Contract 09 §1.1 Invariant 7 & TOOL-SSLYZE §4: Three-Tier Authorization Gate.
        Evaluates:
          Gate 1: TOOL_CAPABILITY (Supported scan type & approved flags)
          Gate 2: PROFILE_AUTHORIZATION (Profile allows network sweep / TLS probing)
          Gate 3: TENANT_SCOPE_AUTHORIZATION (Target scope authorized)
        Returns (is_authorized, reason, failed_gate_name).
        """
        # Gate 1: Tool Capability
        allowed_target_types = {TargetType.URL, TargetType.DOMAIN, TargetType.IP}
        if target.target_type not in allowed_target_types:
            return (
                False,
                f"SSLyze does not support target type '{target.target_type.value}' (Gate 1).",
                "TOOL_CAPABILITY",
            )

        if custom_flags:
            for flag in custom_flags:
                clean_f = flag.strip()
                if clean_f.startswith("--json_out=") and clean_f != "--json_out=-":
                    return False, "Arbitrary file output via --json_out is forbidden (Gate 1).", "TOOL_CAPABILITY"
                if clean_f not in APPROVED_SSLYZE_FLAGS and not clean_f.startswith("--server_name="):
                    return False, f"Flag '{clean_f}' is not supported by TOOL-SSLYZE allowlist (Gate 1).", "TOOL_CAPABILITY"

        # Gate 2: Profile Authorization
        allowed_profiles = {
            ScanProfile.FULL_STACK,
            ScanProfile.NETWORK_ONLY,
            ScanProfile.NETWORK_TLS,
            ScanProfile.DAST_ONLY,
            ScanProfile.QUICK,
            ScanProfile.QUICK_AUDIT,
            ScanProfile.EASM_EXPANDED,
            ScanProfile.CUSTOM,
        }
        active_profile = getattr(config, "profile", ScanProfile.FULL_STACK)
        if active_profile not in allowed_profiles:
            return (
                False,
                f"Scan profile '{active_profile.value}' does not authorize network/TLS assessment (Gate 2).",
                "PROFILE_AUTHORIZATION",
            )

        # Gate 3: Tenant Scope Authorization
        auth_ctx = getattr(target, "authorization_context", {}) or {}
        if auth_ctx.get("out_of_scope", False):
            return False, "Target is marked outside tenant authorized scope (Gate 3).", "TENANT_SCOPE_AUTHORIZATION"

        authorized_scope_list = getattr(target, "authorized_scope", None)
        if authorized_scope_list and target.canonical_value not in authorized_scope_list and target.selected_destination not in authorized_scope_list:
            return False, "Target is outside tenant authorized scope list (Gate 3).", "TENANT_SCOPE_AUTHORIZATION"

        return True, None, None

    def parse_sslyze_json(
        self,
        json_str: str,
        target_host: str,
        target_port: int,
        scan_id: str = "adapter-sslyze",
    ) -> Tuple[List[Finding], NormalizedExecutionState, List[str]]:
        """
        Contract 09 TOOL-SSLYZE §24, §30, §31, §34: Hardened JSON Output Parser.
        Extracts:
        - NET-TLS-001: Deprecated SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1 Protocols (HIGH / 7.5)
        - NET-TLS-002: Insecure / Weak Ciphers (RC4, 3DES, EXPORT, NULL) (MEDIUM / 5.9)
        - NET-TLS-003: Untrusted, Expired, or Weak Signature Certificates (HIGH / 7.4)
        - NET-TLS-006: OpenSSL Heartbleed Vulnerability (CVE-2014-0160) (CRITICAL / 9.8)
        - NET-TLS-007: ROBOT Bleichenbacher Padding Oracle (HIGH / 7.4)
        - NET-TLS-008: OpenSSL CCS Injection (CVE-2014-0224) (HIGH / 7.4)
        """
        findings: List[Finding] = []
        evidence_hashes: List[str] = []

        if not json_str or not json_str.strip():
            return findings, NormalizedExecutionState.TOOL_EXECUTION_FAILED, evidence_hashes

        try:
            data = json.loads(json_str)
        except json.JSONDecodeError:
            return findings, NormalizedExecutionState.PARTIAL_RESULTS_WITH_WARNING, evidence_hashes

        server_results = data.get("server_scan_results", [])
        if not server_results:
            return findings, NormalizedExecutionState.COMPLETED_NO_FINDINGS, evidence_hashes

        for res in server_results:
            scan_commands = res.get("scan_result") or res.get("scan_commands_results") or res
            if not isinstance(scan_commands, dict):
                continue

            # 1. Check for deprecated SSL 2.0/3.0 & TLS 1.0/1.1 (NET-TLS-001)
            for proto_key, proto_name in [
                ("ssl_2_0_cipher_suites", "SSL 2.0"),
                ("ssl_3_0_cipher_suites", "SSL 3.0"),
                ("tls_1_0_cipher_suites", "TLS 1.0"),
                ("tls_1_1_cipher_suites", "TLS 1.1"),
            ]:
                proto_res = scan_commands.get(proto_key, {})
                result_data = proto_res.get("result", proto_res) if isinstance(proto_res, dict) else {}
                if not isinstance(result_data, dict):
                    continue

                accepted = result_data.get("accepted_cipher_suites", [])
                is_supported = result_data.get("is_supported", bool(accepted))
                if is_supported or accepted:
                    ciphers_str = ", ".join(
                        c.get("cipher_suite", {}).get("name", "unknown") for c in accepted[:5]
                    ) if accepted else "Supported"
                    raw_snippet = json.dumps(accepted[:3]) if accepted else f"{proto_name} supported"
                    evidence_hash = hashlib.sha256(raw_snippet.encode("utf-8")).hexdigest()
                    evidence_hashes.append(evidence_hash)

                    evidence = Evidence(
                        location=f"{target_host}:{target_port}",
                        observed_value=f"Accepted deprecated protocol {proto_name}: {ciphers_str}",
                        expected_value="TLS 1.2 or TLS 1.3 only",
                        raw_response_snippet=raw_snippet,
                    )
                    f = Finding(
                        scan_id=scan_id,
                        engine="network",
                        source_tool=TOOL_NAME,
                        check_id="NET-TLS-001",
                        category="TLS/SSL Security",
                        title=f"Deprecated {proto_name} Protocol Supported",
                        severity=Severity.HIGH,
                        cvss_score=7.5,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        cwe_id="CWE-326",
                        owasp_category="A02:2021-Cryptographic Failures",
                        nist_control="SC-8, SC-13",
                        description=f"The server negotiated {proto_name} which contains known structural cryptographic weaknesses.",
                        impact="Man-in-the-middle attackers may decrypt or tamper with encrypted communication.",
                        remediation=f"Disable {proto_name} in server configuration and require TLS 1.2 or TLS 1.3 minimum.",
                        remediation_code_snippet="ssl_protocols TLSv1.2 TLSv1.3;",
                        references=["https://datatracker.ietf.org/doc/html/rfc8996"],
                        evidence=evidence,
                        fingerprint=calculate_fingerprint("NET-TLS-001", f"{target_host}:{target_port}", proto_name),
                    )
                    findings.append(f)

            # 2. Check for Weak Ciphers across all active protocols (NET-TLS-002)
            for proto_key, proto_name in [
                ("tls_1_2_cipher_suites", "TLS 1.2"),
                ("tls_1_1_cipher_suites", "TLS 1.1"),
                ("tls_1_0_cipher_suites", "TLS 1.0"),
            ]:
                proto_res = scan_commands.get(proto_key, {})
                result_data = proto_res.get("result", proto_res) if isinstance(proto_res, dict) else {}
                if not isinstance(result_data, dict):
                    continue

                accepted = result_data.get("accepted_cipher_suites", [])
                for cipher_item in accepted:
                    cipher_obj = cipher_item.get("cipher_suite", {})
                    cipher_name = cipher_obj.get("name", "")
                    if not cipher_name:
                        continue

                    # Evaluate weak cipher patterns
                    is_weak = any(p.search(cipher_name) for p in WEAK_CIPHER_PATTERNS)
                    if is_weak:
                        raw_snippet = json.dumps(cipher_item)
                        evidence_hash = hashlib.sha256(raw_snippet.encode("utf-8")).hexdigest()
                        evidence_hashes.append(evidence_hash)

                        evidence = Evidence(
                            location=f"{target_host}:{target_port}",
                            observed_value=f"Weak cipher suite accepted in {proto_name}: {cipher_name}",
                            expected_value="Strong AEAD cipher suites (AES-GCM, CHACHA20-POLY1305)",
                            raw_response_snippet=raw_snippet,
                        )
                        f = Finding(
                            scan_id=scan_id,
                            engine="network",
                            source_tool=TOOL_NAME,
                            check_id="NET-TLS-002",
                            category="TLS/SSL Security",
                            title=f"Weak or Insecure TLS Cipher Suite Supported ({cipher_name})",
                            severity=Severity.MEDIUM,
                            cvss_score=5.9,
                            cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
                            cwe_id="CWE-327",
                            owasp_category="A02:2021-Cryptographic Failures",
                            nist_control="SC-8, SC-13",
                            description=f"The server accepts weak cipher suite '{cipher_name}' in {proto_name}.",
                            impact="Attackers may perform cryptographic attacks (e.g. SWEET32, RC4 bias) to decrypt sensitive session data.",
                            remediation="Disable weak cipher suites and configure modern AEAD ciphers.",
                            remediation_code_snippet="ssl_ciphers HIGH:!aNULL:!MD5:!3DES:!RC4:!kEDH;",
                            references=["https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html"],
                            evidence=evidence,
                            fingerprint=calculate_fingerprint("NET-TLS-002", f"{target_host}:{target_port}", cipher_name),
                        )
                        findings.append(f)

            # 3. Check for Certificate Issues (NET-TLS-003)
            cert_res = scan_commands.get("certificate_info", {})
            cert_data = cert_res.get("result", cert_res) if isinstance(cert_res, dict) else {}
            if isinstance(cert_data, dict):
                deployments = cert_data.get("certificate_deployments", [])
                for dep in deployments:
                    # Path validation errors
                    for validation in dep.get("path_validation_results", []):
                        if not validation.get("is_valid_path", True):
                            error_msg = validation.get("validation_error", "Certificate validation failed")
                            raw_snippet = json.dumps(validation)
                            evidence_hash = hashlib.sha256(raw_snippet.encode("utf-8")).hexdigest()
                            evidence_hashes.append(evidence_hash)

                            evidence = Evidence(
                                location=f"{target_host}:{target_port}",
                                observed_value=f"Certificate validation error: {error_msg}",
                                expected_value="Valid trusted CA certificate path",
                                raw_response_snippet=raw_snippet,
                            )
                            f = Finding(
                                scan_id=scan_id,
                                engine="network",
                                source_tool=TOOL_NAME,
                                check_id="NET-TLS-003",
                                category="TLS/SSL Security",
                                title="Untrusted / Self-Signed SSL/TLS Certificate Path",
                                severity=Severity.HIGH,
                                cvss_score=7.4,
                                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                                cwe_id="CWE-295",
                                owasp_category="A02:2021-Cryptographic Failures",
                                nist_control="SC-8, SC-13",
                                description=f"The SSL/TLS certificate presented by {target_host}:{target_port} could not be validated against trusted root stores: {error_msg}",
                                impact="Users will encounter security warnings and are susceptible to man-in-the-middle interception.",
                                remediation="Install a valid SSL/TLS certificate issued by a recognized Certificate Authority (e.g., Let's Encrypt).",
                                references=["https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html"],
                                evidence=evidence,
                                fingerprint=calculate_fingerprint("NET-TLS-003", f"{target_host}:{target_port}", error_msg),
                            )
                            findings.append(f)

                    # Weak signature algorithm check
                    for cert in dep.get("received_certificate_chain", []):
                        sig_alg = cert.get("signature_hash_algorithm", {}).get("name", "").lower()
                        if "sha1" in sig_alg or "md5" in sig_alg:
                            raw_snippet = json.dumps(cert)
                            evidence_hash = hashlib.sha256(raw_snippet.encode("utf-8")).hexdigest()
                            evidence_hashes.append(evidence_hash)

                            evidence = Evidence(
                                location=f"{target_host}:{target_port}",
                                observed_value=f"Certificate signed with weak algorithm: {sig_alg}",
                                expected_value="SHA-256 or stronger signature algorithm",
                                raw_response_snippet=sanitize_tls_evidence_text(raw_snippet),
                            )
                            f = Finding(
                                scan_id=scan_id,
                                engine="network",
                                source_tool=TOOL_NAME,
                                check_id="NET-TLS-003",
                                category="TLS/SSL Security",
                                title=f"Weak Signature Algorithm in SSL/TLS Certificate ({sig_alg.upper()})",
                                severity=Severity.HIGH,
                                cvss_score=7.4,
                                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                                cwe_id="CWE-327",
                                owasp_category="A02:2021-Cryptographic Failures",
                                nist_control="SC-8, SC-13",
                                description=f"The SSL/TLS certificate uses obsolete weak signature algorithm '{sig_alg}'.",
                                impact="Attackers may forge certificates due to known cryptographic hash collision vulnerabilities.",
                                remediation="Reissue the certificate using SHA-256 or higher signature hashing.",
                                references=["https://datatracker.ietf.org/doc/html/rfc9155"],
                                evidence=evidence,
                                fingerprint=calculate_fingerprint("NET-TLS-003", f"{target_host}:{target_port}", sig_alg),
                            )
                            findings.append(f)

            # 4. Check for Heartbleed vulnerability (NET-TLS-006)
            hb_res = scan_commands.get("heartbleed", {})
            hb_data = hb_res.get("result", hb_res) if isinstance(hb_res, dict) else {}
            if isinstance(hb_data, dict) and (hb_data.get("is_vulnerable_to_heartbleed") or hb_data.get("is_vulnerable")):
                raw_snippet = json.dumps(hb_data)
                evidence_hash = hashlib.sha256(raw_snippet.encode("utf-8")).hexdigest()
                evidence_hashes.append(evidence_hash)

                evidence = Evidence(
                    location=f"{target_host}:{target_port}",
                    observed_value="Server is vulnerable to OpenSSL Heartbleed (CVE-2014-0160)",
                    expected_value="Patched OpenSSL version not vulnerable to Heartbleed",
                    raw_response_snippet=raw_snippet,
                )
                f = Finding(
                    scan_id=scan_id,
                    engine="network",
                    source_tool=TOOL_NAME,
                    check_id="NET-TLS-006",
                    category="TLS/SSL Security",
                    title="OpenSSL TLS Heartbleed Vulnerability (CVE-2014-0160)",
                    severity=Severity.CRITICAL,
                    cvss_score=9.8,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    cwe_id="CWE-119",
                    owasp_category="A06:2021-Vulnerable and Outdated Components",
                    nist_control="SI-2",
                    description=f"Server at {target_host}:{target_port} is vulnerable to OpenSSL Heartbleed, allowing remote unauthenticated memory disclosure.",
                    impact="Remote attackers can read private cryptographic keys, user session tokens, and credentials directly from memory.",
                    remediation="Upgrade OpenSSL to a patched version immediately and reissue all certificates and credentials.",
                    references=["https://nvd.nist.gov/vuln/detail/CVE-2014-0160"],
                    evidence=evidence,
                    fingerprint=calculate_fingerprint("NET-TLS-006", f"{target_host}:{target_port}", "Heartbleed"),
                )
                findings.append(f)

            # 5. Check for Bleichenbacher ROBOT Attack (NET-TLS-007)
            robot_res = scan_commands.get("robot", {})
            robot_data = robot_res.get("result", robot_res) if isinstance(robot_res, dict) else {}
            if isinstance(robot_data, dict):
                robot_res_val = str(robot_data.get("robot_result", "")).upper()
                if "VULNERABLE" in robot_res_val and "NOT_VULNERABLE" not in robot_res_val:
                    raw_snippet = json.dumps(robot_data)
                    evidence_hash = hashlib.sha256(raw_snippet.encode("utf-8")).hexdigest()
                    evidence_hashes.append(evidence_hash)

                    evidence = Evidence(
                        location=f"{target_host}:{target_port}",
                        observed_value=f"Server is vulnerable to ROBOT attack: {robot_res_val}",
                        expected_value="Server not vulnerable to Bleichenbacher RSA padding oracle",
                        raw_response_snippet=raw_snippet,
                    )
                    f = Finding(
                        scan_id=scan_id,
                        engine="network",
                        source_tool=TOOL_NAME,
                        check_id="NET-TLS-007",
                        category="TLS/SSL Security",
                        title="Bleichenbacher RSA Padding Oracle (ROBOT Attack)",
                        severity=Severity.HIGH,
                        cvss_score=7.4,
                        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
                        cwe_id="CWE-327",
                        owasp_category="A02:2021-Cryptographic Failures",
                        nist_control="SC-8, SC-13",
                        description=f"Server at {target_host}:{target_port} is vulnerable to the Return of Bleichenbacher's Oracle Threat (ROBOT).",
                        impact="Attackers can perform RSA decryption and sign messages with the server's private key.",
                        remediation="Disable RSA encryption key exchange cipher suites in favor of ECDHE key exchange.",
                        references=["https://robotattack.org/"],
                        evidence=evidence,
                        fingerprint=calculate_fingerprint("NET-TLS-007", f"{target_host}:{target_port}", "ROBOT"),
                    )
                    findings.append(f)

            # 6. Check for OpenSSL CCS Injection (NET-TLS-008)
            ccs_res = scan_commands.get("openssl_ccs_injection", {})
            ccs_data = ccs_res.get("result", ccs_res) if isinstance(ccs_res, dict) else {}
            if isinstance(ccs_data, dict) and ccs_data.get("is_vulnerable_to_ccs_injection"):
                raw_snippet = json.dumps(ccs_data)
                evidence_hash = hashlib.sha256(raw_snippet.encode("utf-8")).hexdigest()
                evidence_hashes.append(evidence_hash)

                evidence = Evidence(
                    location=f"{target_host}:{target_port}",
                    observed_value="Server is vulnerable to OpenSSL ChangeCipherSpec Injection (CVE-2014-0224)",
                    expected_value="Patched OpenSSL version not vulnerable to CCS injection",
                    raw_response_snippet=raw_snippet,
                )
                f = Finding(
                    scan_id=scan_id,
                    engine="network",
                    source_tool=TOOL_NAME,
                    check_id="NET-TLS-008",
                    category="TLS/SSL Security",
                    title="OpenSSL ChangeCipherSpec Injection (CVE-2014-0224)",
                    severity=Severity.HIGH,
                    cvss_score=7.4,
                    cvss_vector="CVSS:3.1/AV:N/AC:M/PR:N/UI:N/S:U/C:H/I:H/A:N",
                    cwe_id="CWE-310",
                    owasp_category="A06:2021-Vulnerable and Outdated Components",
                    nist_control="SI-2",
                    description=f"Server at {target_host}:{target_port} allows unauthenticated man-in-the-middle attackers to inject CCS messages.",
                    impact="Attackers can force downgrade of cryptographic keys and decrypt communication in transit.",
                    remediation="Upgrade OpenSSL to a patched version.",
                    references=["https://nvd.nist.gov/vuln/detail/CVE-2014-0224"],
                    evidence=evidence,
                    fingerprint=calculate_fingerprint("NET-TLS-008", f"{target_host}:{target_port}", "CCS_Injection"),
                )
                findings.append(f)

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
        Executes SSLyze adapter lifecycle:
        1. Validates Target -> ValidatedTarget
        2. Resolves Binary & Enforces Version 5.2.0
        3. Evaluates 3-Tier Authorization Gate
        4. Builds Deterministic Command with Destination Binding & SNI Separation
        5. Executes via ProcessSupervisor
        6. Parses JSON & Emits Findings
        7. Preserves Reproducibility Metadata
        """
        findings: List[Finding] = []
        scan_id = kwargs.get("scan_id", "adapter-sslyze")

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
                await emit_log(LogLevel.ERROR, f"Target validation failed for SSLyze: {e}")
                return findings

        # 2. Binary Resolution
        custom_path = getattr(config.adapters, "sslyze_path", None) or getattr(config.adapters, "custom_sslyze_path", None)
        sslyze_path = self.resolve_binary_path(custom_path)
        if not sslyze_path:
            await emit_log(LogLevel.WARNING, "SSLyze binary not found on host. Skipping SSLyze execution.")
            return findings

        # 3. Exact Version Enforcement (Contract 09 TOOL-SSLYZE §7)
        version_str = await self.get_version(sslyze_path)
        is_v_valid, v_err = self.verify_version(version_str)
        if not is_v_valid:
            await emit_log(LogLevel.ERROR, f"SSLyze version rejected: {v_err}. Execution blocked.")
            return findings

        # 4. Three-Tier Authorization Check
        custom_flags = kwargs.get("custom_flags")
        op_class = classify_sslyze_operation(custom_flags)

        is_auth, auth_err, failed_gate = self.evaluate_three_tier_authorization(
            val_target,
            config,
            operation_class=op_class,
            custom_flags=custom_flags,
        )
        if not is_auth:
            await emit_log(LogLevel.WARNING, f"SSLyze execution blocked by policy ({failed_gate}): {auth_err}")
            return findings

        # 5. Build Command via Command Builder
        cmd, target_dest, target_port, cmd_err = SslyzeCommandBuilder.build_command(
            sslyze_path=sslyze_path,
            target=val_target,
            port=kwargs.get("port"),
            custom_flags=custom_flags,
        )
        if cmd_err:
            await emit_log(LogLevel.ERROR, f"Failed to build SSLyze command: {cmd_err}")
            return findings

        timeout_sec = float(min(60.0, config.timeout_seconds * 6))
        await emit_log(
            LogLevel.INFO,
            f"Executing SSLyze deep TLS audit on destination '{target_dest}:{target_port}' (SNI: '{val_target.canonical_value}')...",
        )

        # 6. Execute Subprocess via ProcessSupervisor
        returncode, stdout, stderr = await self.execute_command(
            cmd,
            timeout=timeout_sec,
            emit_log=emit_log,
        )

        # Handle Timeout & Execution Errors
        if returncode != 0 and "timed out" in stderr.lower():
            await emit_log(LogLevel.WARNING, f"SSLyze execution timed out after {timeout_sec}s.")
            return findings

        if not stdout.strip():
            await emit_log(
                LogLevel.WARNING,
                f"SSLyze produced no output (Exit code {returncode}): {stderr.strip()}",
            )
            return findings

        # 7. Output Parsing & Finding Emission
        parsed_findings, exec_state, evidence_hashes = self.parse_sslyze_json(
            stdout,
            target_host=val_target.canonical_value,
            target_port=target_port,
            scan_id=scan_id,
        )

        for f in parsed_findings:
            findings.append(f)
            await emit_finding(f)

        # 8. Record Reproducibility Metadata
        record = SslyzeExecutionRecord(
            validated_target_id=val_target.target_id,
            authorization_decision_id=val_target.authorization_decision_id,
            policy_version="14.3.0",
            target_destination=target_dest,
            target_port=target_port,
            server_name_sni=val_target.canonical_value,
            command_args=cmd,
            upstream_exit_code=returncode,
            normalized_state=exec_state,
            evidence_hashes=evidence_hashes,
        )
        await emit_log(LogLevel.DEBUG, f"SSLyze execution recorded: state={exec_state.value}, findings={len(findings)}")

        return findings
