"""
Contract 02 & 08 Data Models, Pydantic v2 Schemas, and State Machine Enums (v4.1.0).
Authoritative Reference: contracts/02_DATA_SCHEMA_AND_MODELS_CONTRACT.md
"""

from __future__ import annotations
from datetime import datetime, timezone
from enum import Enum
import hashlib
import re
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, model_validator
import uuid
from app.core.version import (
    APP_VERSION,
    API_VERSION,
    SCHEMA_VERSION,
    CONTRACT_VERSION,
    RULESET_VERSION,
    RISK_MODEL_VERSION,
)


def utc_now() -> datetime:
    """Helper to return current timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


# ============================================================================
# Centralized Version Authority & Hierarchy (Contract 01 §1 & Contract 02 §1)
# ============================================================================
# ============================================================================
# 1. Enums & Classifications
# ============================================================================

class Severity(str, Enum):
    """
    Vulnerability severity rating aligned with CVSS v3.1 base score bands.
    """
    CRITICAL = "CRITICAL"  # CVSS 9.0 - 10.0
    HIGH = "HIGH"          # CVSS 7.0 - 8.9
    MEDIUM = "MEDIUM"      # CVSS 4.0 - 6.9
    LOW = "LOW"            # CVSS 0.1 - 3.9
    INFO = "INFO"          # CVSS 0.0


class TargetType(str, Enum):
    """
    Supported assessment target types.
    """
    URL = "URL"                    # Web Application or REST/GraphQL Endpoint
    DOMAIN = "DOMAIN"              # Domain Name / FQDN (Perimeter, DNS, OSINT)
    IP = "IP"                      # Single IPv4 or IPv6 Address
    LOCAL_PATH = "LOCAL_PATH"      # Local Source Code Repository
    DOCKERFILE = "DOCKERFILE"      # Dockerfile Specification
    IAC_MANIFEST = "IAC_MANIFEST"  # Kubernetes, Compose, or Terraform Manifest
    CLOUD_ACCOUNT = "CLOUD_ACCOUNT"  # Cloud provider account/subscription/project
    KUBERNETES_CLUSTER = "KUBERNETES_CLUSTER"  # Kubernetes API/control-plane target


class ScanProfile(str, Enum):
    """
    Scan profile configurations determining which engine subsets run.
    """
    FULL_STACK = "FULL_STACK"                    # All 5 engines active + all 26 available modern adapters
    QUICK = "QUICK"                              # Fast audit alias
    QUICK_AUDIT = "QUICK_AUDIT"                  # Network + Web DAST Header Check only
    DAST_ONLY = "DAST_ONLY"                      # Web DAST + Crawler + Auth + Active Fuzzing + Nuclei + FFuF + Katana + Schemathesis
    SAST_ONLY = "SAST_ONLY"                      # Static Code + Taint AST + Secrets + Semgrep + Gitleaks + Bandit + TruffleHog + RetireJS
    NETWORK_ONLY = "NETWORK_ONLY"                # Network Ports + TLS Ciphers + DNS + OSINT + Nmap + SSLyze + Subfinder + Httpx
    NETWORK_TLS = "NETWORK_TLS"                  # Network Ports + TLS Ciphers + DNS + OSINT alias
    INFRA_ONLY = "INFRA_ONLY"                    # Dockerfile + Compose + K8s + Terraform + Trivy + Checkov + Dockle + KubeBench + Prowler
    INFRA_CONTAINER = "INFRA_CONTAINER"          # Container and IaC focus
    API_FOCUSED = "API_FOCUSED"                  # API & GraphQL inspection focus
    PASSIVE_OSINT = "PASSIVE_OSINT"              # OSINT and DNS reconnaissance
    EASM_EXPANDED = "EASM_EXPANDED"              # External Attack Surface: Subfinder + Httpx + Nmap + Katana + crt.sh
    SUPPLY_CHAIN_SBOM = "SUPPLY_CHAIN_SBOM"      # Syft + Grype + OSV-Scanner + Trivy + Retire.js + SBOM Export
    CLOUD_K8S_COMPLIANCE = "CLOUD_K8S_COMPLIANCE" # Prowler + Kube-bench + Checkov + Dockle (CIS Benchmarks)
    API_CONTRACT_AUDIT = "API_CONTRACT_AUDIT"    # Schemathesis + Nuclei API + FFuF (OpenAPI/GraphQL Contract Fuzzing)
    CUSTOM = "CUSTOM"                            # User-defined engine selection


class ScanStatus(str, Enum):
    """
    State machine enumeration for scan job lifecycle.
    """
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class EngineExecutionStatus(str, Enum):
    """
    Contract 03 §3 & Contract 05: Explicit execution status for individual security engines/scanners.
    Guarantees failed/skipped tools are not silently reported as 'No issues'.
    """
    PASS = "PASS"                  # Engine executed completely with zero findings
    FINDINGS = "FINDINGS"          # Engine executed completely with valid findings detected
    PARTIAL = "PARTIAL"            # Engine partially executed with non-fatal warnings
    FAILED = "FAILED"              # Engine encountered an unrecoverable failure
    BLOCKED = "BLOCKED"            # Engine was blocked by safety policy or missing authorization
    CANCELLED = "CANCELLED"        # Engine was terminated due to scan cancellation
    TIMED_OUT = "TIMED_OUT"        # Engine was terminated due to execution timeout


class FindingVerificationStatus(str, Enum):
    """
    Contract 02 §4 & Contract 05: Four-stage vulnerability verification lifecycle.
    """
    DETECTED = "DETECTED"          # Initial automated scanner detection
    VALIDATED = "VALIDATED"        # Cross-engine or multi-check confirmation
    REMEDIATED = "REMEDIATED"      # Marked as fixed by engineering
    VERIFIED = "VERIFIED"          # Confirmed fixed by authoritative retest


class AssessmentCoverage(BaseModel):
    """
    Contract 01 §5 & Contract 04: Explicit assessment coverage tracking.
    Distinguishes 'No issue detected' from 'Not assessed'.
    """
    engines_requested: List[str] = Field(default_factory=list, description="Engines requested by scan profile")
    engines_executed: List[str] = Field(default_factory=list, description="Engines successfully executed")
    engines_failed: List[str] = Field(default_factory=list, description="Engines that failed execution")
    engines_skipped: List[str] = Field(default_factory=list, description="Engines skipped due to scope/policy")
    tools_unavailable: List[str] = Field(default_factory=list, description="Tools missing from system")
    targets_inaccessible: List[str] = Field(default_factory=list, description="Target endpoints that were unreachable")
    coverage_limitations: List[str] = Field(default_factory=list, description="Explicit notes on assessment coverage gaps")
    coverage_status: str = Field(
        default="COVERAGE_DEGRADED",
        description="Authoritative coverage state: COVERAGE_COMPLETE or COVERAGE_DEGRADED",
    )
    is_fully_assessed: bool = Field(default=False, description="Whether all requested engines completed successfully")

    @model_validator(mode="after")
    def enforce_coverage_state(self) -> "AssessmentCoverage":
        """Keep the explicit coverage state consistent with recorded gaps."""
        allowed = {"COVERAGE_COMPLETE", "COVERAGE_DEGRADED"}
        if self.coverage_status not in allowed:
            raise ValueError(f"Unknown coverage status: {self.coverage_status!r}")
        has_gaps = (
            not self.is_fully_assessed
            or not self.engines_executed
            or (bool(self.engines_requested) and set(self.engines_executed) != set(self.engines_requested))
            or bool(self.engines_failed)
            or bool(self.engines_skipped)
            or bool(self.tools_unavailable)
            or bool(self.targets_inaccessible)
            or bool(self.coverage_limitations)
        )
        if has_gaps:
            self.coverage_status = "COVERAGE_DEGRADED"
            self.is_fully_assessed = False
        elif self.coverage_status == "COVERAGE_DEGRADED":
            self.is_fully_assessed = False
        return self


class SecurityGrade(str, Enum):
    """
    Deterministic letter grade classification based on scoring deductions.
    """
    A_PLUS = "A+"
    A = "A"
    B = "B"
    C = "C"
    D = "D"
    F = "F"


class LogLevel(str, Enum):
    """
    Telemetry log level.
    """
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    DEBUG = "DEBUG"


class AuthType(str, Enum):
    """
    Supported authentication mechanisms for authenticated scans.
    """
    NO_AUTH = "NO_AUTH"        # Alias for unauthenticated scan
    NONE = "NONE"              # Unauthenticated public scan
    HEADER = "HEADER"          # Static Bearer token or custom header
    COOKIE = "COOKIE"          # Direct session cookie injection
    FORM_LOGIN = "FORM_LOGIN"  # Automated form login with credential submission & CSRF handling


class ToolExecutionMode(str, Enum):
    """
    Operating execution mode for hybrid external security tool adapters.
    """
    ADAPTER_ACTIVE = "ADAPTER_ACTIVE"    # Host CLI tool found, verified, and active
    NATIVE_ENGINE_READY = "NATIVE_ENGINE_READY"  # Built-in rule engine ready; no external executable
    NATIVE_FALLBACK = "NATIVE_FALLBACK"  # Pure Python native fallback engine
    MANUAL_ONLY = "MANUAL_ONLY"          # Explicitly authorized manual-only adapter
    DISABLED = "DISABLED"                # Adapter explicitly disabled by user/config


class ToolAssuranceStatus(str, Enum):
    """Validated supply-chain and execution assurance classification."""

    ASSURED = "ASSURED"
    DELEGATED = "DELEGATED"
    INCOMPLETE = "INCOMPLETE"
    INVALID = "INVALID"
    UNASSURED = "UNASSURED"
    UNREGISTERED = "UNREGISTERED"
    DISABLED = "DISABLED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class ToolInstallMethod(str, Enum):
    """
    Installation method used to provision the tool.
    """
    PIP = "PIP"                                        # Pure Python package installed via sys.executable -m pip
    STANDALONE_BINARY = "STANDALONE_BINARY"            # Standalone Go/compiled binary downloaded from GitHub Releases into backend/bin/
    SYSTEM_PACKAGE_MANAGER = "SYSTEM_PACKAGE_MANAGER"  # System tool requiring OS package manager (winget/brew/apt) or elevated setup
    SCRIPT_DOWNLOAD = "SCRIPT_DOWNLOAD"                # Script-based tool downloaded via direct script
    MANUAL = "MANUAL"                                  # Manual binary placement


class ToolInstallStatus(str, Enum):
    """
    Installation lifecycle status for tools.
    """
    NOT_INSTALLED = "NOT_INSTALLED"
    INSTALLING = "INSTALLING"
    INSTALLED = "INSTALLED"
    FAILED = "FAILED"
    UPDATE_AVAILABLE = "UPDATE_AVAILABLE"


# ============================================================================
# 2. Configuration Models
# ============================================================================

class CrawlerConfig(BaseModel):
    """
    Configuration for automated web application crawler.
    """
    enabled: bool = Field(default=True, description="Enable multi-page link discovery crawler")
    max_depth: int = Field(default=3, ge=1, le=5, description="Maximum crawl tree traversal depth")
    max_pages: int = Field(default=50, ge=1, le=200, description="Maximum pages to crawl")
    exclude_patterns: List[str] = Field(
        default_factory=lambda: ["*logout*", "*signout*", "*delete*", "*destroy*", "*purge*"],
        description="Path patterns excluded from crawling to prevent destructive actions or logout"
    )
    follow_redirects: bool = Field(default=True, description="Follow same-origin HTTP redirects")
    parse_sitemap: bool = Field(default=True, description="Parse robots.txt and sitemap.xml for seeds")
    respect_robots: bool = Field(default=True, description="Respect robots.txt crawling restrictions")

CrawlConfig = CrawlerConfig


class AuthConfig(BaseModel):
    """
    Authentication configuration for authenticated vulnerability scanning.
    """
    auth_type: AuthType = Field(default=AuthType.NONE, description="Authentication mechanism")
    headers: Dict[str, str] = Field(default_factory=dict, description="Custom auth headers (e.g. Authorization: Bearer <token>)")
    cookies: Dict[str, str] = Field(default_factory=dict, description="Session cookies (e.g. sessionid=xyz)")
    login_url: Optional[str] = Field(default=None, description="Form login URL endpoint")
    username_field: str = Field(default="username", description="HTML input name for username/email")
    username: Optional[str] = Field(default=None, description="Login username or email")
    password_field: str = Field(default="password", description="HTML input name for password")
    password: Optional[str] = Field(default=None, description="Login password")
    csrf_token_field: Optional[str] = Field(default=None, description="Optional custom CSRF form field name")
    logged_in_indicator: Optional[str] = Field(default=None, description="Regex/string in response confirming active session")
    logout_url_patterns: List[str] = Field(
        default_factory=lambda: ["logout", "signout", "sign_out", "log_out", "exit", "destroy"],
        description="Path patterns excluded from crawling to prevent session termination"
    )


class FuzzingConfig(BaseModel):
    """
    Configuration for active parameter fuzzing & benign injection testing.
    """
    enabled: bool = Field(default=False, description="Enable active parameter fuzzing & benign injection testing")
    fuzz_query_params: bool = Field(default=True, description="Fuzz URL GET query parameters")
    fuzz_body_params: bool = Field(default=True, description="Fuzz POST/PUT form and JSON parameters")
    fuzz_sqli: bool = Field(default=True, description="Test for Time-based and Boolean-differential SQLi")
    fuzz_xss: bool = Field(default=True, description="Test for Reflected XSS using benign canary tokens")
    fuzz_lfi: bool = Field(default=True, description="Test for Local File Inclusion and Path Traversal")
    fuzz_ssti: bool = Field(default=True, description="Test for Server-Side Template Injection mathematical evaluation")
    fuzz_redirect: bool = Field(default=True, description="Test for Open Redirect via parameter tampering")
    delay_seconds: float = Field(default=2.0, ge=1.0, le=5.0, description="Expected delay for timing-based probes")


class OSINTConfig(BaseModel):
    """
    Configuration for OSINT perimeter and reconnaissance checks.
    """
    subdomain_enumeration: bool = Field(default=True, description="Query public Certificate Transparency logs (crt.sh)")
    subdomain_takeover_check: bool = Field(default=True, description="Detect dangling CNAME records pointing to unclaimed services")
    crtsh_timeout_seconds: float = Field(default=10.0, ge=3.0, le=30.0, description="Timeout for crt.sh API queries")

OsintConfig = OSINTConfig


class ToolAdapterConfig(BaseModel):
    """
    Configuration for hybrid external binary tool adapters across the complete 26-tool fleet:
    - Network / EASM: Nmap, SSLyze, Subfinder, Httpx, Amass, Metasploit
    - Web DAST: Nuclei, FFuF, Katana, Schemathesis, sqlmap
    - SAST / Secrets: Semgrep, Gitleaks, Bandit, TruffleHog, RetireJS
    - SCA / Supply Chain: Trivy, Syft, Grype, OSV-Scanner
    - Cloud / IaC / CIS: Checkov, Prowler, Kube-bench, Dockle, GTFOBins
    - Authentication Resilience: Hydra (manual-only)
    """
    # Core 9 Adapters
    enable_nmap: bool = Field(default=True, description="Enable Nmap port and service scanner adapter")
    enable_sslyze: bool = Field(default=True, description="Enable SSLyze deep TLS/SSL configuration adapter")
    enable_nuclei: bool = Field(default=True, description="Enable Nuclei CVE template scanner adapter")
    enable_ffuf: bool = Field(default=True, description="Enable FFuF high-speed content discovery adapter")
    enable_semgrep: bool = Field(default=True, description="Enable Semgrep multi-language AST SAST adapter")
    enable_gitleaks: bool = Field(default=True, description="Enable Gitleaks git history secret scanner adapter")
    enable_bandit: bool = Field(default=True, description="Enable Bandit Python AST security linter adapter")
    enable_trivy: bool = Field(default=True, description="Enable Trivy SCA and container vulnerability adapter")
    enable_checkov: bool = Field(default=True, description="Enable Checkov Infrastructure-as-Code policy adapter")

    # Expanded 12 Enterprise Adapters (v8.0.0)
    enable_subfinder: bool = Field(default=True, description="Enable Subfinder multi-source passive subdomain discovery adapter")
    enable_httpx: bool = Field(default=True, description="Enable Httpx high-speed HTTP probing and tech fingerprint adapter")
    enable_katana: bool = Field(default=True, description="Enable Katana headless Chromium SPA crawler adapter")
    enable_syft: bool = Field(default=True, description="Enable Syft SBOM (CycloneDX / SPDX) generation adapter")
    enable_grype: bool = Field(default=True, description="Enable Grype SBOM & container vulnerability adapter")
    enable_osv_scanner: bool = Field(default=True, description="Enable Google OSV-Scanner dependency vulnerability adapter")
    enable_retirejs: bool = Field(default=True, description="Enable Retire.js client-side JavaScript CVE adapter")
    enable_trufflehog: bool = Field(default=True, description="Enable TruffleHog verified live secret detection adapter")
    enable_prowler: bool = Field(default=True, description="Enable Prowler multi-cloud CIS benchmark posture adapter")
    enable_kube_bench: bool = Field(default=True, description="Enable Kube-bench CIS Kubernetes benchmark adapter")
    enable_dockle: bool = Field(default=True, description="Enable Dockle CIS Docker container hardening linter adapter")
    enable_schemathesis: bool = Field(default=True, description="Enable Schemathesis property-based API contract fuzzer adapter")

    # Offensive Verification & Extended Pentest Suite (v14.0.0)
    enable_metasploit: bool = Field(default=True, description="Enable Metasploit Framework auxiliary scanner & non-destructive CVE verification adapter")
    enable_sqlmap: bool = Field(default=True, description="Enable sqlmap automated SQL injection safe verification adapter")
    enable_amass: bool = Field(default=True, description="Enable OWASP Amass deep graph-based EASM attack surface discovery adapter")
    enable_hydra: bool = Field(default=True, description="Enable THC-Hydra authentication resilience & brute-force audit adapter")
    enable_gtfobins: bool = Field(default=True, description="Enable GTFOBins & LOLBAS host/container privilege escalation auditor")

    # Paths
    nmap_path: Optional[str] = Field(default=None)
    sslyze_path: Optional[str] = Field(default=None)
    nuclei_path: Optional[str] = Field(default=None)
    ffuf_path: Optional[str] = Field(default=None)
    semgrep_path: Optional[str] = Field(default=None)
    gitleaks_path: Optional[str] = Field(default=None)
    bandit_path: Optional[str] = Field(default=None)
    trivy_path: Optional[str] = Field(default=None)
    checkov_path: Optional[str] = Field(default=None)
    subfinder_path: Optional[str] = Field(default=None)
    httpx_path: Optional[str] = Field(default=None)
    katana_path: Optional[str] = Field(default=None)
    syft_path: Optional[str] = Field(default=None)
    grype_path: Optional[str] = Field(default=None)
    osv_scanner_path: Optional[str] = Field(default=None)
    retirejs_path: Optional[str] = Field(default=None)
    trufflehog_path: Optional[str] = Field(default=None)
    prowler_path: Optional[str] = Field(default=None)
    kube_bench_path: Optional[str] = Field(default=None)
    dockle_path: Optional[str] = Field(default=None)
    schemathesis_path: Optional[str] = Field(default=None)
    metasploit_path: Optional[str] = Field(default=None)
    sqlmap_path: Optional[str] = Field(default=None)
    amass_path: Optional[str] = Field(default=None)
    hydra_path: Optional[str] = Field(default=None)

    custom_nmap_path: Optional[str] = Field(default=None)
    custom_sslyze_path: Optional[str] = Field(default=None)
    custom_nuclei_path: Optional[str] = Field(default=None)
    custom_ffuf_path: Optional[str] = Field(default=None)
    custom_semgrep_path: Optional[str] = Field(default=None)
    custom_gitleaks_path: Optional[str] = Field(default=None)
    custom_bandit_path: Optional[str] = Field(default=None)
    custom_trivy_path: Optional[str] = Field(default=None)
    custom_checkov_path: Optional[str] = Field(default=None)
    custom_subfinder_path: Optional[str] = Field(default=None)
    custom_httpx_path: Optional[str] = Field(default=None)
    custom_katana_path: Optional[str] = Field(default=None)
    custom_syft_path: Optional[str] = Field(default=None)
    custom_grype_path: Optional[str] = Field(default=None)
    custom_osv_scanner_path: Optional[str] = Field(default=None)
    custom_retirejs_path: Optional[str] = Field(default=None)
    custom_trufflehog_path: Optional[str] = Field(default=None)
    custom_prowler_path: Optional[str] = Field(default=None)
    custom_kube_bench_path: Optional[str] = Field(default=None)
    custom_dockle_path: Optional[str] = Field(default=None)
    custom_schemathesis_path: Optional[str] = Field(default=None)
    custom_metasploit_path: Optional[str] = Field(default=None)
    custom_sqlmap_path: Optional[str] = Field(default=None)
    custom_amass_path: Optional[str] = Field(default=None)
    custom_hydra_path: Optional[str] = Field(default=None)

    @model_validator(mode="after")
    def sync_paths(self) -> "ToolAdapterConfig":
        tools = [
            "nmap", "sslyze", "nuclei", "ffuf", "semgrep", "gitleaks", "bandit", "trivy", "checkov",
            "subfinder", "httpx", "katana", "syft", "grype", "osv_scanner", "retirejs", "trufflehog", "prowler", "kube_bench", "dockle", "schemathesis",
            "metasploit", "sqlmap", "amass", "hydra"
        ]
        for tool in tools:
            path_attr = f"{tool}_path"
            custom_path_attr = f"custom_{tool}_path"
            p = getattr(self, path_attr, None)
            cp = getattr(self, custom_path_attr, None)
            if cp and not p:
                setattr(self, path_attr, cp)
            elif p and not cp:
                setattr(self, custom_path_attr, p)
        return self


class ScanConfig(BaseModel):
    """
    Execution configuration options for a scan.
    """
    profile: ScanProfile = Field(default=ScanProfile.FULL_STACK, description="Assessment scan profile")
    rate_limit_rps: int = Field(default=5, ge=1, le=20, description="Max requests per second")
    timeout_seconds: int = Field(default=10, ge=2, le=60, description="Network timeout in seconds")
    custom_headers: Dict[str, str] = Field(default_factory=dict, description="Custom request headers")
    port_list: List[int] = Field(default_factory=list, description="Custom target ports for network probing")
    include_subdomains: bool = Field(default=False, description="Scan discovered subdomains")
    crawler: CrawlerConfig = Field(default_factory=CrawlerConfig, description="Crawler configuration")
    auth: AuthConfig = Field(default_factory=AuthConfig, description="Authentication configuration")
    fuzzing: FuzzingConfig = Field(default_factory=FuzzingConfig, description="Active fuzzing configuration")
    osint: OSINTConfig = Field(default_factory=OSINTConfig, description="OSINT reconnaissance configuration")
    adapters: ToolAdapterConfig = Field(default_factory=ToolAdapterConfig, description="External tool adapters configuration")


# ============================================================================
# 3. Reconnaissance & Surface Models
# ============================================================================

class EndpointTestStatus(str, Enum):
    SAFE = "SAFE"
    VULNERABLE = "VULNERABLE"
    INFO = "INFO"
    PARTIAL = "PARTIAL"
    SKIPPED = "SKIPPED"
    NOT_EXECUTED = "NOT_EXECUTED"
    NOT_ASSESSED = "NOT_ASSESSED"


class EndpointTestRecord(BaseModel):
    """
    Detailed record of a specific security check/test evaluated on an endpoint.
    """
    test_name: str = Field(..., description="Name of the evaluated check (e.g., SQLi, XSS, CSRF, Security Headers)")
    category: str = Field(default="Web Application Security", description="Category of the test")
    tool: str = Field(default="native_dast", description="Tool or engine that evaluated the test")
    status: EndpointTestStatus = Field(default=EndpointTestStatus.NOT_EXECUTED, description="Outcome of the evaluation")
    details: str = Field(default="", description="Detailed observation or probe result")
    execution_time_ms: float = Field(default=0.0, description="Duration of test execution in milliseconds")
    findings_count: int = Field(default=0, description="Number of findings generated by this check")


class DiscoveredEndpoint(BaseModel):
    """
    URL endpoint discovered during crawling or API discovery with comprehensive per-link assessment dossier.
    """
    url: str = Field(..., description="Normalized discovered URL")
    method: str = Field(default="GET", description="HTTP method")
    depth: int = Field(default=0, ge=0, description="Crawl depth level at which endpoint was discovered")
    status_code: Optional[int] = Field(default=None, description="Observed HTTP response status code")
    content_type: Optional[str] = Field(default=None, description="Observed Content-Type header")
    is_authenticated: bool = Field(default=False, description="Whether endpoint requires/received active authentication")
    has_forms: bool = Field(default=False, description="Whether HTML forms were discovered on this page")
    discovered_forms: int = Field(default=0, ge=0, description="Number of HTML forms discovered on this page")
    response_time_ms: Optional[float] = Field(default=None, description="Server response latency in milliseconds")
    tools_executed: List[str] = Field(default_factory=list, description="List of tools executed on this endpoint")
    tests_performed: List[EndpointTestRecord] = Field(default_factory=list, description="List of security tests evaluated on this endpoint")
    finding_ids: List[str] = Field(default_factory=list, description="List of finding IDs detected on this endpoint")


class DiscoveredSubdomain(BaseModel):
    """
    Subdomain discovered via passive OSINT or DNS reconnaissance.
    """
    domain: str = Field(..., description="Fully-qualified discovered subdomain name")
    ip_addresses: List[str] = Field(default_factory=list, description="Resolved IPv4/IPv6 addresses")
    cname_targets: List[str] = Field(default_factory=list, description="Resolved CNAME aliases")
    is_takeover_vulnerable: bool = Field(default=False, description="Whether CNAME points to unclaimed cloud resource")
    service_fingerprint: Optional[str] = Field(default=None, description="Identified hosting provider or technology")
    discovered_via: str = Field(default="crt.sh", description="Reconnaissance source (crt.sh, Certspotter, Subfinder)")
    dns_status: str = Field(default="ACTIVE", description="DNS resolution status (ACTIVE or NXDOMAIN)")
    organization_id: Optional[str] = Field(default=None, description="Authoritative owning tenant organization ID")
    assessment_id: Optional[str] = Field(default=None, description="Parent assessment execution identity")
    authorized_root: Optional[str] = Field(default=None, description="Root scope used to classify the discovery")
    sources: List[str] = Field(default_factory=list, description="Provider/source attribution for the discovery")


class RejectedDiscovery(BaseModel):
    """Auditable discovery rejected before inventory admission."""
    domain: str
    reason: str
    source: str = "Subfinder"
    sources: List[str] = Field(default_factory=list)
    authorized_root: str
    assessment_id: str
    organization_id: str
    observed_at: datetime = Field(default_factory=utc_now)


class ToolStatus(BaseModel):
    """
    Status of an external binary tool adapter.
    """
    name: str = Field(..., description="Tool identifier (nmap, nuclei, semgrep, trivy)")
    available: bool = Field(default=False, description="Whether a binary was detected on the host; this is not trust or execution evidence")
    version: Optional[str] = Field(default=None, description="Detected executable version string")
    path: Optional[str] = Field(default=None, description="Resolved absolute executable path")
    execution_mode: ToolExecutionMode = Field(default=ToolExecutionMode.NATIVE_FALLBACK, description="'ADAPTER_ACTIVE', 'NATIVE_ENGINE_READY', 'NATIVE_FALLBACK', 'MANUAL_ONLY', or 'DISABLED'")
    install_method: ToolInstallMethod = Field(default=ToolInstallMethod.MANUAL, description="Installation method for this tool")
    is_installed: bool = Field(default=False, description="Whether tool binary is present and executable")
    installable: bool = Field(default=True, description="Whether tool can be installed in-app")
    assurance_status: ToolAssuranceStatus = Field(
        default=ToolAssuranceStatus.UNASSURED,
        description="Execution trust state: ASSURED, DELEGATED, INCOMPLETE, INVALID, UNASSURED, UNREGISTERED, DISABLED, or NOT_APPLICABLE",
    )


class ToolInstallationInfo(BaseModel):
    """
    Detailed installation status and metadata for a tool adapter.
    """
    name: str = Field(..., description="Machine name of tool (e.g. 'nuclei', 'bandit', 'sslyze')")
    display_name: str = Field(..., description="Human-readable tool title")
    category: str = Field(..., description="Security domain (Network, Web DAST, Code SAST, Infra IaC)")
    install_method: ToolInstallMethod = Field(..., description="Installation mechanism")
    status: ToolInstallStatus = Field(default=ToolInstallStatus.NOT_INSTALLED)
    version: Optional[str] = Field(default=None, description="Discovered version string")
    path: Optional[str] = Field(default=None, description="Resolved binary executable path")
    is_elevated_required: bool = Field(default=False, description="Whether root / UAC admin elevation is required")
    install_command_hint: str = Field(..., description="CLI command snippet for manual or system package manager installation")
    download_url: Optional[str] = Field(default=None, description="Direct download URL or repo reference")
    error_message: Optional[str] = Field(default=None, description="Last installation error message if failed")
    progress_percent: int = Field(default=0, ge=0, le=100, description="Real-time installation progress percentage")
    assurance_status: ToolAssuranceStatus = Field(
        default=ToolAssuranceStatus.UNASSURED,
        description="Supply-chain assurance: ASSURED, UNASSURED, DELEGATED, INCOMPLETE, INVALID, or UNREGISTERED",
    )


class ToolInstallRequest(BaseModel):
    """
    Request body for initiating tool installation.
    """
    tool_name: Optional[str] = Field(default=None, description="Tool machine name to install")
    force: bool = Field(default=False, description="Reinstall or overwrite existing binary if present")


class ToolInstallResponse(BaseModel):
    """
    Response returned when tool installation is initiated.
    """
    task_id: str = Field(..., description="Async installation job task UUID")
    tool_name: str = Field(..., description="Target tool name")
    status: ToolInstallStatus = Field(..., description="Initial installation task status")
    message: str = Field(..., description="Informational progress or queue message")


class ToolBatchInstallRequest(BaseModel):
    """
    Request body for batch tool installation.
    """
    tool_names: List[str] = Field(default_factory=list, description="List of tools to install (empty installs all missing user-space tools)")
    force: bool = Field(default=False, description="Force reinstallation")


class SystemCapabilities(BaseModel):
    """
    System-wide tool availability and engine readiness snapshot.
    """
    tools: List[ToolStatus] = Field(default_factory=list, description="Tool availability and capability status")
    native_engines_ready: bool = True
    os_platform: str = Field(default="Unknown", description="Operating system platform details")
    capabilities_source: str = Field(default="LIVE", description="Whether this snapshot was produced LIVE or served from CACHE")
    capabilities_checked_at: Optional[datetime] = Field(default=None, description="UTC time of the live capability check")
    capabilities_cache_age_seconds: float = Field(default=0.0, ge=0, description="Age of the capability snapshot when returned")
    capabilities_cache_ttl_seconds: int = Field(default=60, ge=1, description="Maximum cache age for API capability snapshots")


# ============================================================================
# 3.1 Software Bill of Materials (SBOM) & CIS Benchmark Models (v8.0.0)
# ============================================================================

class SBOMExportFormat(str, Enum):
    CYCLONEDX_JSON = "CYCLONEDX_JSON"
    CYCLONEDX_XML = "CYCLONEDX_XML"
    SPDX_JSON = "SPDX_JSON"
    SPDX_TAG_VALUE = "SPDX_TAG_VALUE"


class SBOMComponent(BaseModel):
    name: str = Field(..., description="Package or component name")
    version: str = Field(..., description="Installed package version string")
    type: str = Field(default="library", description="Component type: library, application, container, operating-system")
    purl: Optional[str] = Field(default=None, description="Package URL specification (e.g. pkg:npm/lodash@4.17.21)")
    license: Optional[str] = Field(default=None, description="Declared SPDX license identifier")
    cpe: Optional[str] = Field(default=None, description="Common Platform Enumeration string")
    vulnerabilities_count: int = Field(default=0, description="Associated CVE/vulnerability count")


class SBOMReport(BaseModel):
    format: SBOMExportFormat = Field(default=SBOMExportFormat.CYCLONEDX_JSON)
    spec_version: str = Field(default="1.5", description="Specification version string")
    serial_number: str = Field(default_factory=lambda: f"urn:uuid:{uuid.uuid4()}")
    timestamp: datetime = Field(default_factory=utc_now)
    components: List[SBOMComponent] = Field(default_factory=list)
    raw_document: Optional[str] = Field(default=None, description="Full serialized CycloneDX or SPDX document string")


class CISBenchmarkResult(BaseModel):
    benchmark_name: str = Field(..., description="CIS Benchmark (e.g. 'CIS Kubernetes Benchmark v1.8', 'CIS Docker Benchmark v1.5')")
    section_id: str = Field(..., description="Section identifier (e.g. '1.1.1', '4.1')")
    title: str = Field(..., description="Benchmark control recommendation title")
    status: str = Field(..., description="'PASS', 'FAIL', 'WARN', 'INFO'")
    remediation: str = Field(..., description="Prescriptive remediation steps")
    scored: bool = Field(default=True, description="Whether control is scored in CIS certification")


class VerifiedSecretEvidence(BaseModel):
    secret_type: str = Field(..., description="Type of secret (e.g. 'AWS Access Key', 'Stripe API Key', 'GitHub PAT')")
    is_live: bool = Field(..., description="Whether real-time non-destructive probe confirmed credential is active")
    account_id: Optional[str] = Field(default=None, description="Masked account or identity returned by authorization probe")
    permissions_summary: Optional[str] = Field(default=None, description="Observed permission scope")


# ============================================================================
# 4. Target, Evidence & Finding Models
# ============================================================================

class Target(BaseModel):
    """
    Target specification model.
    """
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Unique target UUID")
    name: str = Field(..., min_length=1, max_length=120, description="User-friendly target label")
    type: TargetType = Field(..., description="Target classification type")
    value: str = Field(..., min_length=1, max_length=1024, description="Raw target URI, domain, IP, or path")
    resolved_ip: Optional[str] = Field(default=None, description="DNS-resolved IP address if applicable")
    created_at: datetime = Field(default_factory=utc_now)


class NormalizedExecutionState(str, Enum):
    """
    Contract 09 §1.1 & §25: Dual Execution State Architecture.
    Normalized platform execution state distinct from raw upstream process exit code.
    """
    COMPLETED_WITH_FINDINGS = "COMPLETED_WITH_FINDINGS"
    COMPLETED_NO_FINDINGS = "COMPLETED_NO_FINDINGS"
    PARTIAL_RESULTS_WITH_WARNING = "PARTIAL_RESULTS_WITH_WARNING"
    TOOL_EXECUTION_FAILED = "TOOL_EXECUTION_FAILED"
    EXECUTION_TIMED_OUT = "EXECUTION_TIMED_OUT"
    EXECUTION_CANCELLED = "EXECUTION_CANCELLED"
    EXECUTION_BLOCKED = "EXECUTION_BLOCKED"
    INVALID_VERSION = "INVALID_VERSION"
    FAILED_NON_ZERO_EXIT = "FAILED_NON_ZERO_EXIT"
    FAILED_TIMEOUT = "FAILED_TIMEOUT"
    FAILED_OUTPUT_LIMIT = "FAILED_OUTPUT_LIMIT"
    NOT_EXECUTED_PREREQUISITE_MISSING = "NOT_EXECUTED_PREREQUISITE_MISSING"
    NOT_EXECUTED_UNSUPPORTED_TARGET = "NOT_EXECUTED_UNSUPPORTED_TARGET"


class ValidatedTarget(BaseModel):
    """
    Contract 01 §5.1, Contract 02 §3, Contract 08 §12.1 & Contract 09 §1.1:
    Authoritative Validated Target Object.
    Frozen and immutable data model. Only validated target representations
    are authorized to reach the execution plane.
    """
    model_config = dict(frozen=True, extra="forbid")

    target_id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Cryptographic resource identity: sha256(canonical_value + ':' + selected_destination)")
    authorization_decision_id: str = Field(default="", description="Cryptographic authorization decision ID")
    integrity_seal: str = Field(default="", description="Cryptographic gateway integrity seal")
    organization_id: str = Field(default="org-default", description="Authoritative owning organization ID")
    project_id: Optional[str] = Field(default=None, description="Optional project context ID")
    asset_id: Optional[str] = Field(default=None, description="Optional linked asset ID")
    workspace_id: Optional[str] = Field(default=None, description="Optional authorized workspace ID")
    target_type: TargetType = Field(..., description="Target classification type")
    raw_value: str = Field(default="", description="Original raw user input string")
    canonical_value: str = Field(..., description="Canonical normalized target URI, FQDN, IP, or path")
    authorized_scope: List[str] = Field(default_factory=list, description="Authorized CIDRs or root domain wildcards")
    resolved_addresses: List[str] = Field(default_factory=list, description="All pre-resolved IPv4/IPv6 addresses")
    selected_destination: str = Field(..., description="Connection-bound IPv4/IPv6 destination or canonical filesystem root")
    port: Optional[int] = Field(default=None, description="Target port if applicable")
    scheme: Optional[str] = Field(default=None, description="Protocol scheme if applicable")
    authorization_context: Dict[str, Any] = Field(default_factory=dict, description="Audit authorization metadata")
    validation_timestamp: datetime = Field(default_factory=utc_now, description="Timestamp of validation gate passage")
    policy_version: str = Field(default=APP_VERSION, description="SSRF and boundary policy version applied")

    @property
    def id(self) -> str:
        return self.target_id

    @property
    def normalized_value(self) -> str:
        return self.canonical_value

    @property
    def resolved_destination(self) -> str:
        return self.selected_destination


class Evidence(BaseModel):
    """
    Evidence and proof collected during an assessment check.
    """
    location: str = Field(..., description="URL endpoint, file path + line number, or port number")
    observed_value: str = Field(..., description="What was actually observed (e.g. 'Server: Apache/2.4.41' or 'AKIA****')")
    expected_value: str = Field(..., description="What should have been configured according to security standard")
    raw_response_snippet: Optional[str] = Field(default=None, description="Safe excerpt of HTTP header, banner, or code snippet")
    request_details: Optional[Dict[str, Any]] = Field(default=None, description="HTTP method, URL, parameter name, and test headers used")
    response_details: Optional[Dict[str, Any]] = Field(default=None, description="HTTP status code and response headers")
    line_number: Optional[int] = Field(default=None, description="Line number if finding relates to a file")
    column_number: Optional[int] = Field(default=None, description="Column number if applicable")


def calculate_evidence_hash(location: str, observed_value: str) -> str:
    """
    Computes an immutable cryptographic SHA-256 hash of the evidence for non-repudiation.
    """
    raw = f"{location.strip()}:{observed_value.strip()}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def calculate_fingerprint(check_id: str, location: str, observed_value: str) -> str:
    """
    Generates a deterministic SHA256 fingerprint for finding deduplication.
    """
    raw = f"{check_id}|{location.strip().lower()}|{observed_value.strip().lower()}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def mask_secret(secret: str) -> str:
    """
    Masks sensitive secret tokens to guarantee no plaintext leaks.
    """
    secret = secret.strip()
    if len(secret) <= 8:
        return "*" * len(secret)
    return secret[:4] + "*" * (len(secret) - 7) + secret[-3:]


def sanitize_sensitive_text(value: Optional[str], max_length: int = 4096) -> Optional[str]:
    """Remove credential material from scanner output before telemetry or storage."""
    if value is None:
        return None
    text = str(value)[:max_length]
    patterns = (
        (r"\bAKIA[0-9A-Z]{16}\b", "[REDACTED_AWS_KEY]"),
        (r"\b(?:ghp|github_pat)_[A-Za-z0-9_]+\b", "[REDACTED_GITHUB_TOKEN]"),
        (r"\b(?:sk|pk)_(?:test|live)_[A-Za-z0-9]+\b", "[REDACTED_STRIPE_KEY]"),
        (r"(?i)([\"']?\b(password|passwd|pwd|secret|api[_-]?key|token|auth[_-]?token)\b[\"']?\s*[:=]\s*)([\"']?)([^\s,;}\"']+)\3", r"\1\3[REDACTED]\3"),
        (r"(?i)(Bearer\s+)[A-Za-z0-9._~+/=-]+", r"\1[REDACTED]"),
        (r"(?i)(https?://[^\s/:]+):[^@\s]+@", r"\1:[REDACTED]@"),
        (r"-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?-----END [^-]*PRIVATE KEY-----", "[REDACTED_PRIVATE_KEY]"),
    )
    for pattern, replacement in patterns:
        text = re.sub(pattern, replacement, text)
    return text


_SENSITIVE_DATA_KEY = re.compile(
    r"(?:^|[_-])(authorization|proxy-authorization|cookie|set-cookie|password|passwd|pwd|"
    r"token|api[_-]?key|access[_-]?token|client[_-]?secret|private[_-]?key|"
    r"raw[_-]?secret|secret[_-]?(?:value|data)|credential)(?:$|[_-])",
    re.IGNORECASE,
)


def sanitize_sensitive_data(value: Any, key: Optional[str] = None) -> Any:
    """Recursively sanitize data before persistence or external output."""
    if key and _SENSITIVE_DATA_KEY.search(str(key)):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(k): sanitize_sensitive_data(v, str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [sanitize_sensitive_data(item) for item in value]
    if isinstance(value, tuple):
        return [sanitize_sensitive_data(item) for item in value]
    if isinstance(value, str):
        return sanitize_sensitive_text(value)
    return value


_SENSITIVE_REPRODUCTION_NAME = r"(?:authorization|proxy-authorization|cookie|set-cookie|token|password|passwd|secret|api[_-]?key|access[_-]?token|client[_-]?secret|jwt)"


def sanitize_reproduction_curl(command: Optional[str]) -> Optional[str]:
    """Redact credentials from tool-generated reproduction commands before storage."""
    if not command:
        return None
    sanitized = str(command)[:4096]
    sanitized = re.sub(
        rf"((?:-H|--header)\s+['\"]?\s*[A-Za-z0-9_-]*{_SENSITIVE_REPRODUCTION_NAME}[A-Za-z0-9_-]*\s*:\s*)[^'\"]+",
        r"\1[REDACTED]",
        sanitized,
        flags=re.IGNORECASE,
    )
    sanitized = re.sub(
        rf"((?:['\"]{_SENSITIVE_REPRODUCTION_NAME}['\"]|['\"][A-Za-z0-9_-]*{_SENSITIVE_REPRODUCTION_NAME}[A-Za-z0-9_-]*['\"])\s*[:=]\s*['\"])[^'\"]+",
        r"\1[REDACTED]",
        sanitized,
        flags=re.IGNORECASE,
    )
    sanitized = re.sub(
        rf"([?&]{_SENSITIVE_REPRODUCTION_NAME}=)[^&\s'\"]+",
        r"\1[REDACTED]",
        sanitized,
        flags=re.IGNORECASE,
    )
    sanitized = re.sub(
        rf"(\b{_SENSITIVE_REPRODUCTION_NAME}\s*=\s*)[^\s&'\"]+",
        r"\1[REDACTED]",
        sanitized,
        flags=re.IGNORECASE,
    )
    return sanitized


class Finding(BaseModel):
    """
    Normalized vulnerability finding model conforming to Contract 02 v4.1.0.
    """
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Unique finding UUID")
    scan_id: str = Field(..., description="Parent scan execution UUID")
    organization_id: str = Field(default="org-default", description="Owning tenant organization ID; never null")
    workspace_id: Optional[str] = Field(default=None, description="Authorized workspace identity")
    engine: str = Field(..., description="Originating engine identifier (network, web_dast, code_sast, infra_iac, cicd_audit)")
    source_tool: str = Field(default="native", description="Originating tool/adapter: 'native', 'nmap', 'sslyze', 'nuclei', 'ffuf', 'semgrep', 'gitleaks', 'bandit', 'trivy', 'checkov'")
    is_fallback: bool = Field(default=False, description="Whether this finding came from a reduced-coverage fallback after a primary tool failure")
    primary_tool_failed: Optional[str] = Field(default=None, description="Primary tool whose failure caused fallback coverage")
    check_id: str = Field(..., description="Canonical check identifier (e.g. DAST-INJ-001, DAST-XSS-001, NET-OSINT-001)")
    category: str = Field(..., description="Taxonomy category (e.g. Injection, OSINT, SSL/TLS, Security Headers, Hardcoded Secrets)")
    title: str = Field(..., min_length=5, max_length=200, description="Concise summary title")
    severity: Severity = Field(..., description="Finding severity rating")
    cvss_score: float = Field(..., ge=0.0, le=10.0, description="CVSS v3.1 Base Score")
    cvss_vector: Optional[str] = Field(default=None, description="e.g. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    cwe_id: Optional[str] = Field(default=None, description="Common Weakness Enumeration ID (e.g. CWE-89, CWE-79)")
    owasp_category: Optional[str] = Field(default=None, description="OWASP Top 10 (2021) mapping (e.g. A03:2021-Injection)")
    nist_control: Optional[str] = Field(default=None, description="NIST SP 800-53 control mapping (e.g. SC-8, IA-5, SI-10)")
    description: str = Field(..., description="Detailed explanation of the flaw and why it occurred")
    impact: str = Field(..., description="Potential business or technical damage if exploited")
    remediation: str = Field(..., description="Step-by-step guidance to fix the issue")
    remediation_code_snippet: Optional[str] = Field(default=None, description="Example configuration or patch code")
    references: List[str] = Field(default_factory=list, description="Authoritative links (OWASP, NIST, RFC, vendor advisory)")
    evidence: Evidence = Field(..., description="Concrete proof and observed data")
    verified_secret: Optional[VerifiedSecretEvidence] = Field(default=None, description="Verified live credential evidence if validated by TruffleHog")
    reproduction_curl: Optional[str] = Field(default=None, description="Exact copy-pasteable curl PoC command to reproduce the finding")
    taint_trace: Optional[List[str]] = Field(default=None, description="AST dataflow taint trace steps from source to sink")
    created_at: datetime = Field(default_factory=utc_now)
    fingerprint: str = Field(default="", description="Deterministic SHA256 hash of (check_id + location + evidence.observed_value)")

    @model_validator(mode="after")
    def compute_default_fingerprint(self) -> "Finding":
        if not self.fingerprint and self.evidence:
            self.fingerprint = calculate_fingerprint(
                self.check_id,
                self.evidence.location,
                self.evidence.observed_value,
            )
        return self


# ============================================================================
# 5. Scan Job, Logs & Lifecycle Models
# ============================================================================

class ScanJobSummary(BaseModel):
    """
    Summary score and aggregated metrics for a scan job.
    """
    critical_count: int = Field(default=0, ge=0)
    high_count: int = Field(default=0, ge=0)
    medium_count: int = Field(default=0, ge=0)
    low_count: int = Field(default=0, ge=0)
    info_count: int = Field(default=0, ge=0)
    total_findings: int = Field(default=0, ge=0)
    passed_checks: int = Field(default=0, ge=0)
    total_checks_evaluated: int = Field(default=0, ge=0)
    pages_crawled: int = Field(default=1, ge=0, description="Total unique internal pages crawled")
    subdomains_discovered: int = Field(default=0, ge=0, description="Total unique subdomains discovered via OSINT")
    active_adapters: List[str] = Field(default_factory=list, description="List of external tools successfully executed")
    authenticated_session_active: bool = Field(default=False, description="Whether authentication was verified active")
    weighted_score: float = Field(default=100.0, ge=0.0, le=100.0, description="Calculated 0-100 security score")
    overall_security_grade: str = Field(default="A+", description="Letter grade: A+, A, B, C, D, or F")
    duration_seconds: float = Field(default=0.0, ge=0.0)
    engine_breakdown: Dict[str, int] = Field(default_factory=dict, description="Finding counts per engine")
    coverage: AssessmentCoverage = Field(default_factory=AssessmentCoverage, description="Assessment engine execution coverage")


class LogEntry(BaseModel):
    """
    Real-time log message emitted during scan execution.
    """
    timestamp: datetime = Field(default_factory=utc_now)
    correlation_id: Optional[str] = Field(default=None, description="Request/scan correlation identifier")
    level: LogLevel = Field(default=LogLevel.INFO)
    engine: Optional[str] = Field(default=None, description="Origin engine name")
    tool: Optional[str] = Field(default=None, description="Origin tool/adapter name (e.g. nmap, nuclei, katana, ffuf)")
    message: str = Field(..., description="Log message text")


class ToolExecutionTelemetry(BaseModel):
    """
    Contract 04 §1.3: Per-tool execution telemetry summary.
    """
    tool_name: str = Field(..., description="Name of external tool or native component")
    correlation_id: Optional[str] = Field(default=None, description="Request/scan correlation identifier")
    engine: str = Field(..., description="Parent assessment engine domain")
    status: EngineExecutionStatus = Field(
        default=EngineExecutionStatus.FAILED,
        description="Execution status; callers must explicitly establish a successful completion",
    )
    duration_seconds: float = Field(default=0.0, description="Total execution runtime in seconds")
    command_executed: Optional[str] = Field(default=None, description="Command snippet or invocation profile")
    findings_count: int = Field(default=0, ge=0, description="Findings generated by this tool")
    log_count: int = Field(default=0, ge=0, description="Telemetry log events produced by this tool")
    endpoints_tested: List[str] = Field(default_factory=list, description="Target links or paths evaluated")
    normalized_state: Optional[str] = Field(default=None, description="Tool-specific normalized execution state")
    output_bytes: int = Field(default=0, ge=0, description="Bytes produced in tool output")
    success_count: int = Field(default=0, ge=0, description="Successful executions of this tool")
    failure_count: int = Field(default=0, ge=0, description="Failed executions of this tool")


class ToolFailureEvent(BaseModel):
    """Durable record of a tool failure or degraded execution outcome."""

    tool_name: str = Field(..., description="Tool that failed or produced degraded coverage")
    engine: str = Field(default="unknown", description="Assessment engine that reported the outcome")
    state: str = Field(..., description="Canonical normalized execution state")
    correlation_id: Optional[str] = Field(default=None, description="Request/scan correlation identifier")
    occurred_at: datetime = Field(default_factory=utc_now)


class ScanTelemetryReport(BaseModel):
    """
    Contract 04 §1.3: Consolidated Assessment Telemetry & Tool Intelligence Hub Report.
    """
    scan_id: str = Field(..., description="Scan UUID")
    correlation_id: Optional[str] = Field(default=None, description="Request/scan correlation identifier")
    target_value: str = Field(..., description="Assessed target URL, IP, or path")
    target_type: TargetType = Field(default=TargetType.URL, description="Target classification")
    profile: ScanProfile = Field(..., description="Assessment profile")
    status: ScanStatus = Field(..., description="Overall scan status")
    total_logs: int = Field(default=0, description="Total log count")
    logs: List[LogEntry] = Field(default_factory=list, description="All structured execution logs")
    tools_executed: List[ToolExecutionTelemetry] = Field(default_factory=list, description="Per-tool execution breakdowns")
    tool_failure_events: List[ToolFailureEvent] = Field(default_factory=list, description="Durable tool failure/degradation events")
    discovered_endpoints: List[DiscoveredEndpoint] = Field(default_factory=list, description="All discovered/crawled endpoints")
    discovered_subdomains: List[DiscoveredSubdomain] = Field(default_factory=list, description="Discovered subdomains via OSINT")
    rejected_discoveries: List[RejectedDiscovery] = Field(default_factory=list)
    coverage: AssessmentCoverage = Field(default_factory=AssessmentCoverage, description="Engine coverage assessment")
    generated_at: datetime = Field(default_factory=utc_now)


class CloudCredentialEnvelope(BaseModel):
    """Worker-only, tenant-bound credentials for an authorized cloud run."""

    model_config = {"extra": "forbid"}

    organization_id: str
    asset_id: str
    provider: str
    credentials: Dict[str, str] = Field(..., repr=False)
    expires_at: datetime


class ScanJob(BaseModel):
    """
    Complete state representation of a scan job.
    """
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    correlation_id: Optional[str] = Field(default=None, description="Request correlation identifier that created the scan")
    organization_id: str = Field(default="org-default")
    project_id: Optional[str] = Field(default=None)
    asset_id: Optional[str] = Field(default=None)
    # Worker-side credential material is never accepted in public request
    # models and is excluded from persistence/serialization.
    cloud_credentials: Optional["CloudCredentialEnvelope"] = Field(default=None, exclude=True, repr=False)
    # Optional worker-side observations support the observation-only native
    # cloud fallback; public scan requests cannot populate this field.
    cloud_posture_observations: Optional[Dict[str, Any]] = Field(default=None, exclude=True, repr=False)
    active_probing_granted: bool = Field(default=False, description="Explicit tenant asset authorization for intrusive probing")
    state_changing_granted: bool = Field(default=False, description="Explicit authorization for state-changing checks")
    live_secret_verification_granted: bool = Field(default=False, description="Explicit tenant authorization for live secret verification")
    target: Target = Field(...)
    profile: ScanProfile = Field(default=ScanProfile.FULL_STACK)
    enabled_engines: List[str] = Field(
        default_factory=lambda: ["network", "web_dast", "code_sast", "infra_iac", "cicd_audit"]
    )
    config: ScanConfig = Field(default_factory=ScanConfig)
    status: ScanStatus = Field(default=ScanStatus.PENDING)
    progress_percent: int = Field(default=0, ge=0, le=100)
    current_stage: str = Field(default="Initializing assessment engine...")
    summary: ScanJobSummary = Field(default_factory=ScanJobSummary)
    active_adapters: List[str] = Field(default_factory=list, description="Active external adapters for this scan")
    discovered_endpoints: List[DiscoveredEndpoint] = Field(default_factory=list)
    discovered_subdomains: List[DiscoveredSubdomain] = Field(default_factory=list)
    rejected_discoveries: List[RejectedDiscovery] = Field(default_factory=list)
    tool_execution_states: Dict[str, str] = Field(default_factory=dict)
    tool_execution_engines: Dict[str, str] = Field(
        default_factory=dict,
        description="Authoritative assessment engine that reported each tool execution state",
    )
    tool_failure_events: List[ToolFailureEvent] = Field(default_factory=list)
    findings: List[Finding] = Field(default_factory=list)
    sbom_report: Optional[SBOMReport] = Field(default=None, description="Software Bill of Materials generated during scan")
    cis_results: List[CISBenchmarkResult] = Field(default_factory=list, description="CIS Benchmark compliance audit results")
    logs: List[LogEntry] = Field(default_factory=list)
    started_at: Optional[datetime] = Field(default=None)
    completed_at: Optional[datetime] = Field(default=None)


# ============================================================================
# 6. API Request / Response & Pentester Tool Schemas
# ============================================================================

class ScanCreateRequest(BaseModel):
    """
    Request payload schema for creating and initiating a new security scan.
    """
    target_type: TargetType = Field(..., description="Classification of target asset")
    target_value: str = Field(..., min_length=1, max_length=1024, description="Target URI, domain, IP, or filesystem path")
    target_name: Optional[str] = Field(default=None, max_length=120, description="Friendly display label for the target")
    profile: ScanProfile = Field(default=ScanProfile.FULL_STACK, description="Scanning depth and profile")
    enabled_engines: Optional[List[str]] = Field(default=None, description="Explicit list of engine names to run")
    config: Optional[ScanConfig] = Field(default=None, description="Execution parameters")

StartScanRequest = ScanCreateRequest


class ScanStartResponse(BaseModel):
    """
    Response returned upon successful initiation of a scan job.
    """
    scan_id: str = Field(..., description="Unique identifier of the initiated scan")
    status: ScanStatus = Field(default=ScanStatus.PENDING, description="Initial status of the scan")
    message: str = Field(default="Security assessment scan launched successfully.", description="Status message")


class RepeaterRequest(BaseModel):
    """
    Payload for manual HTTP request replay / repeater tool.
    """
    url: str = Field(..., description="Target URL for repeater request")
    method: str = Field(default="GET", description="HTTP method (GET, POST, PUT, DELETE, etc.)")
    headers: Dict[str, str] = Field(default_factory=dict, description="HTTP request headers")
    body: Optional[str] = Field(default=None, description="HTTP request body payload")
    follow_redirects: bool = Field(default=False, description="Whether to follow HTTP redirects")
    timeout_seconds: float = Field(default=10.0, ge=1.0, le=60.0, description="Request timeout in seconds")
    verify_tls: bool = Field(default=True, description="Whether to verify TLS certificates")


class RepeaterResponse(BaseModel):
    """
    Response returned from manual HTTP request replay / repeater tool.
    """
    status_code: int = Field(..., description="Observed HTTP response status code")
    headers: Dict[str, str] = Field(..., description="Observed HTTP response headers")
    body: str = Field(..., description="Observed HTTP response body text")
    duration_ms: float = Field(..., ge=0.0, description="Request duration in milliseconds")
    content_length: int = Field(..., ge=0, description="Response payload content length in bytes")
    tls_version: Optional[str] = Field(default=None, description="Observed TLS version (e.g. TLSv1.3)")
    cipher: Optional[str] = Field(default=None, description="Observed TLS cipher suite")
    tls_verified: Optional[bool] = Field(default=None, description="Whether TLS certificate verification succeeded")
    truncated: bool = Field(default=False, description="Whether the response body was truncated due to size limits")
    is_binary: bool = Field(default=False, description="Whether the response payload was binary data")


# ============================================================================
# 7. Enterprise ASPM, Multi-Tenancy, Asset Inventory, Canonical Findings & Audit
# ============================================================================

class OperatingMode(str, Enum):
    PRODUCTION = "PRODUCTION"
    DEVELOPMENT = "DEVELOPMENT"
    TEST = "TEST"


class PrincipalType(str, Enum):
    SYSTEM_PRINCIPAL = "SYSTEM_PRINCIPAL"
    TENANT_PRINCIPAL = "TENANT_PRINCIPAL"


class UserRole(str, Enum):
    ADMIN = "ADMIN"
    SECURITY_ANALYST = "SECURITY_ANALYST"
    DEVELOPER = "DEVELOPER"
    VIEWER = "VIEWER"


class Organization(BaseModel):
    id: str = Field(default_factory=lambda: f"org-{uuid.uuid4().hex[:8]}")
    name: str = Field(..., min_length=2, max_length=120)
    slug: str = Field(..., min_length=2, max_length=120)
    created_at: datetime = Field(default_factory=utc_now)
    is_active: bool = True


class Project(BaseModel):
    id: str = Field(default_factory=lambda: f"prj-{uuid.uuid4().hex[:8]}")
    organization_id: str
    name: str = Field(..., min_length=2, max_length=120)
    description: Optional[str] = None
    created_at: datetime = Field(default_factory=utc_now)


class Workspace(BaseModel):
    id: str = Field(default_factory=lambda: f"ws-{uuid.uuid4().hex[:8]}")
    organization_id: str
    project_id: Optional[str] = None
    name: str = Field(..., min_length=2, max_length=120)
    filesystem_root: str
    is_sandboxed: bool = True
    created_at: datetime = Field(default_factory=utc_now)


class UserProfile(BaseModel):
    id: str = Field(default_factory=lambda: f"usr-{uuid.uuid4().hex[:8]}")
    username: str = Field(..., min_length=3, max_length=50)
    email: str
    role: UserRole = Field(default=UserRole.VIEWER)
    principal_type: PrincipalType = Field(default=PrincipalType.TENANT_PRINCIPAL)
    organization_id: str = Field(default="org-default")
    scopes: List[str] = Field(default_factory=list)
    is_active: bool = True
    created_at: datetime = Field(default_factory=utc_now)
    last_login_at: Optional[datetime] = None

    @model_validator(mode="after")
    def validate_wildcard_scope(self) -> "UserProfile":
        if "*" in self.scopes:
            if self.principal_type != PrincipalType.SYSTEM_PRINCIPAL or self.role != UserRole.ADMIN:
                raise ValueError("Wildcard scope '*' is restricted exclusively to SYSTEM_PRINCIPAL with ADMIN role.")
        return self


class APIKeyRecord(BaseModel):
    key_id: str = Field(default_factory=lambda: f"ca_key_{uuid.uuid4().hex[:12]}")
    key_hash: str
    organization_id: str = Field(default="org-default")
    user_id: Optional[str] = None
    name: str
    scopes: List[str] = Field(default_factory=list)
    status: str = Field(default="ACTIVE")
    created_at: datetime = Field(default_factory=utc_now)
    expires_at: Optional[datetime] = None
    revoked_at: Optional[datetime] = None
    last_used_at: Optional[datetime] = None


class AssetType(str, Enum):
    WEB_APPLICATION = "WEB_APPLICATION"
    API_ENDPOINT = "API_ENDPOINT"
    DOMAIN = "DOMAIN"
    IP_ADDRESS = "IP_ADDRESS"
    GIT_REPOSITORY = "GIT_REPOSITORY"
    CONTAINER_IMAGE = "CONTAINER_IMAGE"
    KUBERNETES_CLUSTER = "KUBERNETES_CLUSTER"
    CLOUD_ACCOUNT = "CLOUD_ACCOUNT"
    IAC_TEMPLATE = "IAC_TEMPLATE"


class AssetCriticality(str, Enum):
    CRITICAL = "CRITICAL"    # Factor: 1.5x
    HIGH = "HIGH"            # Factor: 1.2x
    MEDIUM = "MEDIUM"        # Factor: 1.0x
    LOW = "LOW"              # Factor: 0.7x


class AssetLifecycleStatus(str, Enum):
    DISCOVERED = "DISCOVERED"
    MONITORED = "MONITORED"
    DECOMMISSIONED = "DECOMMISSIONED"
    ARCHIVED = "ARCHIVED"


class Asset(BaseModel):
    id: str = Field(default_factory=lambda: f"ast-{uuid.uuid4().hex[:12]}")
    organization_id: str = Field(default="org-default")
    project_id: Optional[str] = Field(default=None)
    name: str = Field(..., min_length=2, max_length=120)
    type: AssetType = Field(...)
    target_value: str = Field(...)
    criticality: AssetCriticality = Field(default=AssetCriticality.MEDIUM)
    internet_exposed: bool = Field(default=True)
    active_probing_granted: bool = Field(default=False, description="Explicit tenant authorization for intrusive probing")
    live_secret_verification_granted: bool = Field(default=False, description="Explicit tenant authorization for live secret verification")
    tags: List[str] = Field(default_factory=list)
    owner: Optional[str] = Field(default=None)
    lifecycle_status: AssetLifecycleStatus = Field(default=AssetLifecycleStatus.MONITORED)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    last_scanned_at: Optional[datetime] = None
    last_verified_at: Optional[datetime] = None
    active_findings_count: int = Field(default=0)


class FindingLifecycleStatus(str, Enum):
    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    IN_PROGRESS = "IN_PROGRESS"
    FIXED = "FIXED"
    VERIFIED = "VERIFIED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    RISK_ACCEPTED = "RISK_ACCEPTED"
    REOPENED = "REOPENED"


class FindingComment(BaseModel):
    id: str = Field(default_factory=lambda: f"cmt-{uuid.uuid4().hex[:12]}")
    user_id: str = Field(...)
    username: str = Field(...)
    comment: str = Field(...)
    created_at: datetime = Field(default_factory=utc_now)


class SLAInfo(BaseModel):
    severity: Severity = Field(...)
    sla_days: int = Field(..., description="Allowed remediation window (Crit: 7d, High: 14d, Med: 30d, Low: 90d)")
    sla_started_at: datetime = Field(default_factory=utc_now)
    sla_due_at: datetime = Field(...)
    due_date: Optional[datetime] = Field(default=None)  # Alias for backward compatibility
    sla_breached_at: Optional[datetime] = Field(default=None)
    is_breached: bool = Field(default=False)

    @model_validator(mode="after")
    def populate_due_date_alias(self) -> "SLAInfo":
        if self.sla_due_at and not self.due_date:
            self.due_date = self.sla_due_at
        elif self.due_date and not self.sla_due_at:
            self.sla_due_at = self.due_date
        return self


class CorrelationType(str, Enum):
    SAST_DAST_VERIFIED = "SAST_DAST_VERIFIED"
    MULTI_TOOL_CONFIRMED = "MULTI_TOOL_CONFIRMED"
    ENDPOINT_CLUSTERED = "ENDPOINT_CLUSTERED"
    TAINT_CONFIRMED = "TAINT_CONFIRMED"


class FindingOccurrence(BaseModel):
    id: str = Field(default_factory=lambda: f"occ-{uuid.uuid4().hex[:12]}")
    organization_id: str = Field(default="org-default")
    canonical_finding_id: str
    scan_id: str
    asset_id: Optional[str] = None
    source_tool: str
    check_id: str
    raw_evidence: Evidence
    reproduction_curl: Optional[str] = None
    taint_trace: Optional[List[str]] = None
    detected_at: datetime = Field(default_factory=utc_now)


class CanonicalFinding(BaseModel):
    id: str = Field(default_factory=lambda: f"cfind-{uuid.uuid4().hex[:12]}")
    organization_id: str = Field(default="org-default")
    project_id: Optional[str] = Field(default=None)
    asset_id: Optional[str] = Field(default=None)
    title: str = Field(...)
    category: str = Field(...)
    severity: Severity = Field(...)
    cvss_score: float = Field(..., ge=0.0, le=10.0)
    cvss_vector: Optional[str] = Field(default="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")
    contextual_risk_score: float = Field(default=0.0, ge=0.0, le=10.0)
    cwe_id: Optional[str] = Field(default=None)
    owasp_category: Optional[str] = Field(default=None)
    nist_control: Optional[str] = Field(default=None)
    status: FindingLifecycleStatus = Field(default=FindingLifecycleStatus.OPEN)
    lifecycle_status: FindingLifecycleStatus = Field(default=FindingLifecycleStatus.OPEN)  # Alias
    first_seen: datetime = Field(default_factory=utc_now)
    last_seen: datetime = Field(default_factory=utc_now)
    times_observed: int = Field(default=1)
    sla: Optional[SLAInfo] = Field(default=None)
    assigned_to: Optional[str] = Field(default=None)
    contributing_tools: List[str] = Field(default_factory=list)
    correlation_type: Optional[CorrelationType] = Field(default=None)
    description: str = Field(default="")
    impact: str = Field(default="")
    remediation: str = Field(default="")
    evidence_hash: str = Field(default="")
    comments: List[FindingComment] = Field(default_factory=list)

    @model_validator(mode="after")
    def sync_lifecycle_aliases(self) -> "CanonicalFinding":
        if self.lifecycle_status != self.status:
            self.lifecycle_status = self.status
        return self


UnifiedFinding = CanonicalFinding


class FindingTriageUpdate(BaseModel):
    status: FindingLifecycleStatus = Field(...)
    assigned_to: Optional[str] = Field(default=None)
    comment: Optional[str] = Field(default=None)


class AuditAction(str, Enum):
    LOGIN_SUCCESS = "LOGIN_SUCCESS"
    LOGIN_FAILURE = "LOGIN_FAILURE"
    LOGOUT = "LOGOUT"
    BOOTSTRAP_COMPLETE = "BOOTSTRAP_COMPLETE"
    TOKEN_REVOKED = "TOKEN_REVOKED"
    API_KEY_CREATED = "API_KEY_CREATED"
    API_KEY_REVOKED = "API_KEY_REVOKED"
    USER_CREATED = "USER_CREATED"
    USER_ROLE_CHANGED = "USER_ROLE_CHANGED"
    ASSET_CREATED = "ASSET_CREATED"
    ASSET_UPDATED = "ASSET_UPDATED"
    ASSET_DELETED = "ASSET_DELETED"
    SCAN_CREATED = "SCAN_CREATED"
    SCAN_STARTED = "SCAN_STARTED"
    SCAN_CANCELLED = "SCAN_CANCELLED"
    SCAN_COMPLETED = "SCAN_COMPLETED"
    SCAN_FAILED = "SCAN_FAILED"
    INTERNAL_SCAN_AUTHORIZED = "INTERNAL_SCAN_AUTHORIZED"
    TOOL_INSTALL_STARTED = "TOOL_INSTALL_STARTED"
    TOOL_INSTALL_COMPLETED = "TOOL_INSTALL_COMPLETED"
    TOOL_INSTALL_FAILED = "TOOL_INSTALL_FAILED"
    FINDING_STATUS_CHANGED = "FINDING_STATUS_CHANGED"
    FINDING_ASSIGNED = "FINDING_ASSIGNED"
    FINDING_COMMENTED = "FINDING_COMMENTED"
    RISK_ACCEPTED = "RISK_ACCEPTED"
    REPORT_GENERATED = "REPORT_GENERATED"


class AuditEvent(BaseModel):
    id: str = Field(default_factory=lambda: f"aud-{uuid.uuid4().hex[:12]}")
    timestamp: datetime = Field(default_factory=utc_now)
    actor: str = Field(default="system")
    organization_id: str = Field(default="org-default")
    action: AuditAction = Field(...)
    object_type: str = Field(...)
    object_id: str = Field(...)
    result: str = Field(default="SUCCESS")  # "SUCCESS", "FAILURE", "DENIED"
    source_ip: Optional[str] = Field(default=None)
    correlation_id: Optional[str] = Field(default=None)
    details: Dict[str, Any] = Field(default_factory=dict)
    previous_event_hash: Optional[str] = Field(default=None)
    event_hash: Optional[str] = Field(default=None)
