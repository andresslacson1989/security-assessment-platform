# Contract 02: Core Data Schema, Pydantic Models & Scoring Algorithm

**Project Name:** Full-Stack Automated Security Assessment & Vulnerability Management Platform  
**Document Version:** 5.0.0 (Enterprise Adapters First-in-Line & Penetration Testing Architecture Specification)  
**Status:** APPROVED / AUTHORITATIVE SPECIFICATION  
**Scope Authority:** Data Models, State Machines, Serialization & Mathematical Scoring  

---

## 1. Schema Design Philosophy

All models in this platform are strictly defined using **Pydantic v2** with type validation, immutability guarantees where appropriate, and deterministic serialization to JSON, OASIS SARIF v2.1.0, and HTML formats.

---

## 2. Enums & Classifications

### 2.1 Target Classification (`TargetType`)
```python
from enum import Enum

class TargetType(str, Enum):
    URL = "URL"                    # Web Application or REST/GraphQL Endpoint
    DOMAIN = "DOMAIN"              # Domain Name / FQDN (Perimeter, DNS, OSINT)
    IP = "IP"                      # Single IPv4 or IPv6 Address
    LOCAL_PATH = "LOCAL_PATH"      # Local Source Code Repository
    DOCKERFILE = "DOCKERFILE"      # Dockerfile Specification
    IAC_MANIFEST = "IAC_MANIFEST"  # Kubernetes, Compose, or Terraform Manifest
```

### 2.2 Finding Severity Rating (`Severity`)
```python
class Severity(str, Enum):
    CRITICAL = "CRITICAL"  # CVSS 9.0 - 10.0: Immediate compromise / RCE / Root Secret / SQLi / Subdomain Takeover
    HIGH = "HIGH"          # CVSS 7.0 - 8.9: Significant vulnerability / XSS / LFI / Insecure Auth / Sudo / Privileged Pod
    MEDIUM = "MEDIUM"      # CVSS 4.0 - 6.9: Security misconfiguration / Missing CSP / SWEET32 / Weak CORS / OSINT Subdomain
    LOW = "LOW"            # CVSS 0.1 - 3.9: Informational hygiene / Missing CAA / Unpinned dep / Server banner
    INFO = "INFO"          # CVSS 0.0: Educational observation or positive posture note
```

### 2.3 Scan Profiles (`ScanProfile`)
```python
class ScanProfile(str, Enum):
    FULL_STACK = "FULL_STACK"        # All 5 engines active + all 10 available adapters
    QUICK_AUDIT = "QUICK_AUDIT"      # Network + Web DAST Header Check only
    DAST_ONLY = "DAST_ONLY"          # Web DAST + Crawler + Auth + Active Fuzzing + Nuclei + FFuF + Nikto
    SAST_ONLY = "SAST_ONLY"          # Static Code + Taint AST + Secrets + Semgrep + Gitleaks + Bandit + Trivy
    NETWORK_TLS = "NETWORK_TLS"      # Network Ports + TLS Ciphers + DNS + OSINT + Nmap + SSLyze
    INFRA_ONLY = "INFRA_ONLY"        # Dockerfile + Compose + K8s + Terraform + Trivy + Checkov
    CUSTOM = "CUSTOM"                # User-defined engine selection
```

### 2.4 Scan Status & State Machine (`ScanStatus`)
```
  [ PENDING ]
       │ (Orchestrator picks job)
       ▼
  [ RUNNING ] ──────────(User Cancels)──────────► [ CANCELLED ]
       │                                                ▲
       ├────────────────(Fatal Crash / Timeout)──► [ FAILED ]
       │
       ▼ (All engines complete)
 [ COMPLETED ]
```

### 2.5 Authentication Classification (`AuthType`)
```python
class AuthType(str, Enum):
    NONE = "NONE"              # Unauthenticated public scan
    HEADER = "HEADER"          # Static Bearer token or custom header
    COOKIE = "COOKIE"          # Direct session cookie injection
    FORM_LOGIN = "FORM_LOGIN"  # Automated form login with credential submission & CSRF handling
```

### 2.6 Tool Execution Mode (`ToolExecutionMode`)
```python
class ToolExecutionMode(str, Enum):
    ADAPTER_ACTIVE = "ADAPTER_ACTIVE"      # External CLI adapter executed as primary front-line engine
    NATIVE_FALLBACK = "NATIVE_FALLBACK"    # External CLI binary absent; resilient native Python engine executed
    DISABLED = "DISABLED"                  # Explicitly disabled in scan configuration
```

---

## 3. Pydantic v2 Models & Schema Definitions

### 3.1 Target Model (`Target`)
```python
from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
import uuid

class Target(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Unique target UUID")
    name: str = Field(..., min_length=1, max_length=120, description="User-friendly target label")
    type: TargetType = Field(..., description="Target classification type")
    value: str = Field(..., min_length=1, max_length=1024, description="Raw target URI, domain, IP, or path")
    resolved_ip: Optional[str] = Field(default=None, description="DNS-resolved IP address if applicable")
    created_at: datetime = Field(default_factory=datetime.utcnow)
```

### 3.2 Finding Evidence Model (`Evidence`)
```python
class Evidence(BaseModel):
    location: str = Field(..., description="URL endpoint, file path + line number, or port number")
    observed_value: str = Field(..., description="What was actually observed (e.g. 'Server: Apache/2.4.41' or 'AKIA****')")
    expected_value: str = Field(..., description="What should have been configured according to security standard")
    raw_response_snippet: Optional[str] = Field(default=None, description="Safe excerpt of HTTP header, banner, or code snippet")
    request_details: Optional[Dict[str, Any]] = Field(default=None, description="HTTP method, URL, parameter name, and test headers used")
    response_details: Optional[Dict[str, Any]] = Field(default=None, description="HTTP status code and response headers")
    line_number: Optional[int] = Field(default=None, description="Line number if finding relates to a file")
    column_number: Optional[int] = Field(default=None, description="Column number if applicable")
```

### 3.3 Finding Model (`Finding`)
```python
class Finding(BaseModel):
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
    reproduction_curl: Optional[str] = Field(default=None, description="Exact copy-pasteable curl PoC command to reproduce the finding")
    taint_trace: Optional[List[str]] = Field(default=None, description="AST dataflow taint trace steps from source to sink")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    fingerprint: str = Field(..., description="Deterministic SHA256 hash of (check_id + location + evidence.observed_value)")
```

### 3.4 Discovered Subdomain & Endpoint Models
```python
class DiscoveredSubdomain(BaseModel):
    domain: str = Field(..., description="Fully-qualified discovered subdomain name")
    ip_addresses: List[str] = Field(default_factory=list, description="Resolved IPv4/IPv6 addresses")
    cname_targets: List[str] = Field(default_factory=list, description="Resolved CNAME aliases")
    is_takeover_vulnerable: bool = Field(default=False, description="Whether CNAME points to unclaimed cloud resource")
    service_fingerprint: Optional[str] = Field(default=None, description="Identified hosting provider or technology")
    discovered_via: str = Field(default="crt.sh", description="Reconnaissance source (crt.sh, DNS enumeration, TLS SAN)")

class DiscoveredEndpoint(BaseModel):
    url: str = Field(..., description="Normalized discovered URL")
    method: str = Field(default="GET", description="HTTP method")
    depth: int = Field(default=0, ge=0, description="Crawl depth level at which endpoint was discovered")
    status_code: Optional[int] = Field(default=None, description="Observed HTTP response status code")
    content_type: Optional[str] = Field(default=None, description="Observed Content-Type header")
    is_authenticated: bool = Field(default=False, description="Whether endpoint requires/received active authentication")
    has_forms: bool = Field(default=False, description="Whether HTML forms were discovered on this page")
```

### 3.5 Hybrid Tool Adapter Configurations & Status Models
```python
class ToolAdapterConfig(BaseModel):
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
    custom_nmap_path: Optional[str] = Field(default=None, description="Explicit path to nmap executable")
    custom_sslyze_path: Optional[str] = Field(default=None, description="Explicit path to sslyze executable")
    custom_nuclei_path: Optional[str] = Field(default=None, description="Explicit path to nuclei executable")
    custom_ffuf_path: Optional[str] = Field(default=None, description="Explicit path to ffuf executable")
    custom_nikto_path: Optional[str] = Field(default=None, description="Explicit path to nikto executable")
    custom_semgrep_path: Optional[str] = Field(default=None, description="Explicit path to semgrep executable")
    custom_gitleaks_path: Optional[str] = Field(default=None, description="Explicit path to gitleaks executable")
    custom_bandit_path: Optional[str] = Field(default=None, description="Explicit path to bandit executable")
    custom_trivy_path: Optional[str] = Field(default=None, description="Explicit path to trivy executable")
    custom_checkov_path: Optional[str] = Field(default=None, description="Explicit path to checkov executable")

class ToolStatus(BaseModel):
    name: str = Field(..., description="Tool identifier (nmap, sslyze, nuclei, ffuf, nikto, semgrep, gitleaks, bandit, trivy, checkov)")
    available: bool = Field(..., description="Whether binary was detected and verified on PATH/filesystem")
    version: Optional[str] = Field(default=None, description="Detected executable version string")
    path: Optional[str] = Field(default=None, description="Resolved absolute executable path")
    execution_mode: ToolExecutionMode = Field(default=ToolExecutionMode.NATIVE_FALLBACK, description="'ADAPTER_ACTIVE', 'NATIVE_FALLBACK', or 'DISABLED'")

class SystemCapabilities(BaseModel):
    tools: List[ToolStatus] = Field(default_factory=list, description="Tool availability and capability status")
    native_engines_ready: bool = Field(default=True, description="Native Python async engines ready")
    os_platform: str = Field(default="unknown", description="Operating system platform details")
```

### 3.6 Authentication, Crawler, Fuzzing & OSINT Configurations
```python
class FuzzingConfig(BaseModel):
    enabled: bool = Field(default=False, description="Enable active parameter fuzzing & benign injection testing")
    fuzz_query_params: bool = Field(default=True, description="Fuzz URL GET query parameters")
    fuzz_body_params: bool = Field(default=True, description="Fuzz POST/PUT form and JSON parameters")
    fuzz_sqli: bool = Field(default=True, description="Test for Time-based and Boolean-differential SQLi")
    fuzz_xss: bool = Field(default=True, description="Test for Reflected XSS using benign canary tokens")
    fuzz_lfi: bool = Field(default=True, description="Test for Local File Inclusion and Path Traversal")
    fuzz_ssti: bool = Field(default=True, description="Test for Server-Side Template Injection mathematical evaluation")
    fuzz_redirect: bool = Field(default=True, description="Test for Open Redirect via parameter tampering")
    delay_seconds: float = Field(default=2.0, ge=1.0, le=5.0, description="Expected delay for timing-based probes")

class OsintConfig(BaseModel):
    subdomain_enumeration: bool = Field(default=True, description="Query public Certificate Transparency logs (crt.sh)")
    subdomain_takeover_check: bool = Field(default=True, description="Detect dangling CNAME records pointing to unclaimed services")
    crtsh_timeout_seconds: float = Field(default=10.0, ge=3.0, le=30.0, description="Timeout for crt.sh API queries")

class AuthConfig(BaseModel):
    auth_type: AuthType = Field(default=AuthType.NONE, description="Authentication mechanism")
    headers: Dict[str, str] = Field(default_factory=dict, description="Custom headers (e.g. Authorization: Bearer <token>)")
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

class CrawlerConfig(BaseModel):
    enabled: bool = Field(default=True, description="Enable multi-page link discovery crawler")
    max_depth: int = Field(default=3, ge=1, le=5, description="Maximum crawl tree traversal depth")
    max_pages: int = Field(default=50, ge=1, le=200, description="Maximum pages to crawl")
    exclude_patterns: List[str] = Field(
        default_factory=lambda: ["*logout*", "*signout*", "*delete*", "*destroy*", "*purge*"],
        description="Path patterns excluded from crawling"
    )
    follow_redirects: bool = Field(default=True, description="Follow same-origin redirects")
    parse_sitemap: bool = Field(default=True, description="Parse robots.txt and sitemap.xml for seeds")
```

### 3.7 Scan Job Summary Model (`ScanJobSummary`)
```python
class ScanJobSummary(BaseModel):
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
```

### 3.8 Log Entry Model (`LogEntry`)
```python
class LogLevel(str, Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    DEBUG = "DEBUG"

class LogEntry(BaseModel):
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    level: LogLevel = Field(default=LogLevel.INFO)
    engine: Optional[str] = Field(default=None, description="Origin engine name")
    message: str = Field(..., description="Log message text")
```

### 3.9 Complete Scan Job Model (`ScanJob`)
```python
class ScanConfig(BaseModel):
    rate_limit_rps: int = Field(default=5, ge=1, le=20)
    timeout_seconds: int = Field(default=10, ge=2, le=60)
    custom_headers: Dict[str, str] = Field(default_factory=dict)
    port_list: List[int] = Field(default_factory=list)
    include_subdomains: bool = Field(default=False)
    crawler: CrawlerConfig = Field(default_factory=CrawlerConfig)
    auth: AuthConfig = Field(default_factory=AuthConfig)
    fuzzing: FuzzingConfig = Field(default_factory=FuzzingConfig)
    osint: OsintConfig = Field(default_factory=OsintConfig)
    adapters: ToolAdapterConfig = Field(default_factory=ToolAdapterConfig)

class ScanJob(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    target: Target = Field(...)
    profile: ScanProfile = Field(default=ScanProfile.FULL_STACK)
    enabled_engines: List[str] = Field(default_factory=lambda: ["network", "web_dast", "code_sast", "infra_iac", "cicd_audit"])
    config: ScanConfig = Field(default_factory=ScanConfig)
    status: ScanStatus = Field(default=ScanStatus.PENDING)
    progress_percent: int = Field(default=0, ge=0, le=100)
    current_stage: str = Field(default="Initializing assessment engine...")
    summary: ScanJobSummary = Field(default_factory=ScanJobSummary)
    discovered_endpoints: List[DiscoveredEndpoint] = Field(default_factory=list)
    discovered_subdomains: List[DiscoveredSubdomain] = Field(default_factory=list)
    findings: List[Finding] = Field(default_factory=list)
    logs: List[LogEntry] = Field(default_factory=list)
    started_at: Optional[datetime] = Field(default=None)
    completed_at: Optional[datetime] = Field(default=None)
```

---

## 4. Deterministic Grading Algorithm Contract

The platform calculates overall security posture through a transparent, mathematical formula.

### 4.1 Base Score Deduction Formula
Starting with a base score of $S_0 = 100.0$:

$$S_{\text{raw}} = 100.0 - \left( N_{\text{crit}} \times 35.0 + N_{\text{high}} \times 15.0 + N_{\text{med}} \times 5.0 + N_{\text{low}} \times 1.0 \right)$$

$$\text{Final Score } S = \max(0.0, \min(100.0, S_{\text{raw}}))$$

### 4.2 Letter Grade Assignment Table

| Letter Grade | Score Range | Mandatory Hard Constraints | Security Posture Description |
| :---: | :---: | :--- | :--- |
| **`A+`** | $96.0 - 100.0$ | `critical == 0`, `high == 0`, `medium == 0`, `low == 0` | Exemplary posture. Zero vulnerabilities. Strict CSP, modern TLS 1.3, strict SPF/DMARC/MTA-STS, zero hardcoded secrets. |
| **`A`** | $90.0 - 95.9$ | `critical == 0`, `high == 0`, `medium == 0`, `low <= 2` | Strong posture. No significant vulnerabilities. Only minor hygiene recommendations (e.g. server banner, missing CAA). |
| **`B`** | $80.0 - 89.9$ | `critical == 0`, `high == 0`, `medium <= 2` | Good posture with minor gaps (e.g. missing Referrer-Policy, 1 non-sensitive cookie flag, weak DMARC policy `p=none`). |
| **`C`** | $65.0 - 79.9$ | `critical == 0`, `high == 0` | Moderate risk. Multiple medium vulnerabilities present (missing CSP, missing HSTS, or weak CORS). |
| **`D`** | $50.0 - 64.9$ | `critical == 0`, `high >= 1` OR $S \in [50, 64.9]$ | Poor posture. High-severity exposure detected (exposed database port, deprecated TLS 1.0, container running as root). |
| **`F`** | $< 50.0$ | **`critical >= 1` ALWAYS FORCES AN `F` GRADE**, regardless of raw score | Critical failure. Severe vulnerability detected (hardcoded AWS root key, public `.env` leak, expired SSL cert). |

---

## 5. Finding Fingerprinting & Deduplication

```python
import hashlib

def calculate_fingerprint(check_id: str, location: str, observed_value: str) -> str:
    raw = f"{check_id}|{location.strip().lower()}|{observed_value.strip().lower()}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()
```
If a newly generated finding has an identical `fingerprint` to an existing finding in the `ScanJob`, the new finding MUST be discarded and its occurrence logged as a duplicate observation.

