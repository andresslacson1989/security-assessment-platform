"""
Contract 02 & 08 Data Models, Pydantic v2 Schemas, and State Machine Enums (v4.1.0).
Authoritative Reference: contracts/02_DATA_SCHEMA_AND_MODELS_CONTRACT.md
"""

from __future__ import annotations
from datetime import datetime, timezone
from enum import Enum
import hashlib
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, model_validator
import uuid


def utc_now() -> datetime:
    """Helper to return current timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


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


class ScanProfile(str, Enum):
    """
    Scan profile configurations determining which engine subsets run.
    """
    FULL_STACK = "FULL_STACK"                    # All 5 engines active + all 22 available adapters
    QUICK = "QUICK"                              # Fast audit alias
    QUICK_AUDIT = "QUICK_AUDIT"                  # Network + Web DAST Header Check only
    DAST_ONLY = "DAST_ONLY"                      # Web DAST + Crawler + Auth + Active Fuzzing + Nuclei + FFuF + Nikto + Katana + Schemathesis
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
    NATIVE_FALLBACK = "NATIVE_FALLBACK"  # Pure Python native fallback engine
    DISABLED = "DISABLED"                # Adapter explicitly disabled by user/config


class ToolInstallMethod(str, Enum):
    """
    Installation method used to provision the tool.
    """
    PIP = "PIP"                                        # Pure Python package installed via sys.executable -m pip
    STANDALONE_BINARY = "STANDALONE_BINARY"            # Standalone Go/compiled binary downloaded from GitHub Releases into backend/bin/
    SYSTEM_PACKAGE_MANAGER = "SYSTEM_PACKAGE_MANAGER"  # System tool requiring OS package manager (winget/brew/apt) or elevated setup
    SCRIPT_DOWNLOAD = "SCRIPT_DOWNLOAD"                # Script-based tool (e.g. Nikto Perl script)
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
    Configuration for hybrid external binary tool adapters across 22 enterprise tools:
    - Network / EASM: Nmap, SSLyze, Subfinder, Httpx
    - Web DAST: Nuclei, FFuF, Nikto, Katana, Schemathesis
    - SAST / Secrets: Semgrep, Gitleaks, Bandit, TruffleHog, RetireJS
    - SCA / Supply Chain: Trivy, Syft, Grype, OSV-Scanner
    - Cloud / IaC / CIS: Checkov, Prowler, Kube-bench, Dockle
    """
    # Core 10 Adapters
    enable_nmap: bool = Field(default=True, description="Enable Nmap port and service scanner adapter")
    enable_sslyze: bool = Field(default=True, description="Enable SSLyze deep TLS/SSL configuration adapter")
    enable_nuclei: bool = Field(default=True, description="Enable Nuclei CVE template scanner adapter")
    enable_ffuf: bool = Field(default=True, description="Enable FFuF high-speed content discovery adapter")
    enable_nikto: bool = Field(default=True, description="Enable Nikto web server misconfiguration adapter")
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

    # Paths
    nmap_path: Optional[str] = Field(default=None)
    sslyze_path: Optional[str] = Field(default=None)
    nuclei_path: Optional[str] = Field(default=None)
    ffuf_path: Optional[str] = Field(default=None)
    nikto_path: Optional[str] = Field(default=None)
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

    custom_nmap_path: Optional[str] = Field(default=None)
    custom_sslyze_path: Optional[str] = Field(default=None)
    custom_nuclei_path: Optional[str] = Field(default=None)
    custom_ffuf_path: Optional[str] = Field(default=None)
    custom_nikto_path: Optional[str] = Field(default=None)
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

    @model_validator(mode="after")
    def sync_paths(self) -> "ToolAdapterConfig":
        tools = [
            "nmap", "sslyze", "nuclei", "ffuf", "nikto", "semgrep", "gitleaks", "bandit", "trivy", "checkov",
            "subfinder", "httpx", "katana", "syft", "grype", "osv_scanner", "retirejs", "trufflehog", "prowler", "kube_bench", "dockle", "schemathesis"
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

class DiscoveredEndpoint(BaseModel):
    """
    URL endpoint discovered during crawling or API discovery.
    """
    url: str = Field(..., description="Normalized discovered URL")
    method: str = Field(default="GET", description="HTTP method")
    depth: int = Field(default=0, ge=0, description="Crawl depth level at which endpoint was discovered")
    status_code: Optional[int] = Field(default=None, description="Observed HTTP response status code")
    content_type: Optional[str] = Field(default=None, description="Observed Content-Type header")
    is_authenticated: bool = Field(default=False, description="Whether endpoint requires/received active authentication")
    has_forms: bool = Field(default=False, description="Whether HTML forms were discovered on this page")
    discovered_forms: int = Field(default=0, ge=0, description="Number of HTML forms discovered on this page")


class DiscoveredSubdomain(BaseModel):
    """
    Subdomain discovered via passive OSINT or DNS reconnaissance.
    """
    domain: str = Field(..., description="Fully-qualified discovered subdomain name")
    ip_addresses: List[str] = Field(default_factory=list, description="Resolved IPv4/IPv6 addresses")
    cname_targets: List[str] = Field(default_factory=list, description="Resolved CNAME aliases")
    is_takeover_vulnerable: bool = Field(default=False, description="Whether CNAME points to unclaimed cloud resource")
    service_fingerprint: Optional[str] = Field(default=None, description="Identified hosting provider or technology")
    discovered_via: str = Field(default="crt.sh", description="Reconnaissance source (crt.sh, DNS enumeration, TLS SAN)")


class ToolStatus(BaseModel):
    """
    Status of an external binary tool adapter.
    """
    name: str = Field(..., description="Tool identifier (nmap, nuclei, semgrep, trivy)")
    available: bool = Field(default=False, description="Whether binary was detected and verified on PATH/filesystem")
    version: Optional[str] = Field(default=None, description="Detected executable version string")
    path: Optional[str] = Field(default=None, description="Resolved absolute executable path")
    execution_mode: ToolExecutionMode = Field(default=ToolExecutionMode.NATIVE_FALLBACK, description="'ADAPTER_ACTIVE', 'NATIVE_FALLBACK', or 'DISABLED'")
    install_method: ToolInstallMethod = Field(default=ToolInstallMethod.MANUAL, description="Installation method for this tool")
    is_installed: bool = Field(default=False, description="Whether tool binary is present and executable")
    installable: bool = Field(default=True, description="Whether tool can be installed in-app")


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


class Finding(BaseModel):
    """
    Normalized vulnerability finding model conforming to Contract 02 v4.1.0.
    """
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Unique finding UUID")
    scan_id: str = Field(..., description="Parent scan execution UUID")
    engine: str = Field(..., description="Originating engine identifier (network, web_dast, code_sast, infra_iac, cicd_audit)")
    source_tool: str = Field(default="native", description="Originating tool/adapter: 'native', 'nmap', 'sslyze', 'nuclei', 'ffuf', 'nikto', 'semgrep', 'gitleaks', 'bandit', 'trivy', 'checkov'")
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
    fingerprint: str = Field(..., description="Deterministic SHA256 hash of (check_id + location + evidence.observed_value)")


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


class LogEntry(BaseModel):
    """
    Real-time log message emitted during scan execution.
    """
    timestamp: datetime = Field(default_factory=utc_now)
    level: LogLevel = Field(default=LogLevel.INFO)
    engine: Optional[str] = Field(default=None, description="Origin engine name")
    message: str = Field(..., description="Log message text")


class ScanJob(BaseModel):
    """
    Complete state representation of a scan job.
    """
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
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
