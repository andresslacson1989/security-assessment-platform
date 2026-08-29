# Contract 02: Data Schema & Data Models Specification

**Project Name:** Full-Stack Automated Security Assessment & Vulnerability Management Platform  
**Document Version:** 3.0.0 (Comprehensive Production Specification)  
**Status:** APPROVED / AUTHORITATIVE SPECIFICATION  
**Scope Authority:** Core Data Models, Pydantic v2 Schemas, Interchange Formats & Scoring  

---

## 1. Overview & Architecture Standards

This contract defines the authoritative data contracts, JSON schemas, Pydantic v2 models, enumeration states, and deterministic grading algorithms for all platform entities. Every API request, engine check output, streaming event, database record, and export artifact MUST conform to these schemas without deviation.

---

## 2. Core Enumerations & State Machines

### 2.1 Severity Level (`Severity`)
Aliged with CVSS v3.1 base scoring:

| Enum Value | CVSS v3.1 Range | Color Token | Definition & SLA Guidance |
| :--- | :--- | :--- | :--- |
| **`CRITICAL`** | 9.0 – 10.0 | `#ef4444` (Crimson) | Severe vulnerability allowing remote unauthorized access, exposed private keys, public `.env` leak, or root execution. Immediate 24h remediation. |
| **`HIGH`** | 7.0 – 8.9 | `#f97316` (Orange) | Significant vulnerability that directly degrades security controls, exposes internal database ports, CORS origin reflection with credentials, or leaks API keys. Fix within 7 days. |
| **`MEDIUM`** | 4.0 – 6.9 | `#eab308` (Yellow) | Flaw or misconfiguration weakening defense-in-depth (missing CSP, insecure cookie flags, deprecated TLS 1.0/1.1, GraphQL introspection enabled). Fix within 30 days. |
| **`LOW`** | 0.1 – 3.9 | `#3b82f6` (Blue) | Minor hygiene deficiency or non-standard configuration (server banner disclosure, missing Referrer-Policy, unpinned base image tag). Fix in regular release. |
| **`INFO`** | 0.0 | `#10b981` (Green) | Positive observation, architectural best practice, or safe reconnaissance metadata. No fix required. |

### 2.2 Target Type (`TargetType`)
```python
class TargetType(str, Enum):
    URL = "URL"                    # Full web URL (e.g. https://example.com/app)
    DOMAIN = "DOMAIN"              # Fully Qualified Domain Name (e.g. example.com)
    IP = "IP"                      # IPv4 or IPv6 host address (e.g. 192.168.1.100)
    LOCAL_PATH = "LOCAL_PATH"      # Local code repository or filesystem directory
    DOCKERFILE = "DOCKERFILE"      # Dockerfile or container specification
    IAC_MANIFEST = "IAC_MANIFEST"  # Kubernetes YAML, Terraform .tf, or Docker Compose
```

### 2.3 Scan Profile (`ScanProfile`)
```python
class ScanProfile(str, Enum):
    FULL_STACK = "FULL_STACK"     # Executes all applicable engines across the target
    QUICK = "QUICK"               # Rapid triage checks (TLS + Top Headers + Critical Ports)
    DAST_ONLY = "DAST_ONLY"       # Web application, modern browser & API security checks
    SAST_ONLY = "SAST_ONLY"       # Static code analysis, secrets, weak crypto & dependency audit
    NETWORK_ONLY = "NETWORK_ONLY" # TLS/SSL, DNS hygiene, MTA-STS, and port scanner
    INFRA_ONLY = "INFRA_ONLY"     # Container, Kubernetes, Dockerfile & IaC audit
    CUSTOM = "CUSTOM"             # User-selected engine and check subset
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
    request_details: Optional[Dict[str, Any]] = Field(default=None, description="HTTP method, URL, and test headers used")
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
    check_id: str = Field(..., description="Canonical check identifier (e.g. DAST-HDR-001, NET-TLS-001, SAST-SEC-001)")
    category: str = Field(..., description="Taxonomy category (e.g. SSL/TLS, Security Headers, Hardcoded Secrets, Container Posture)")
    title: str = Field(..., min_length=5, max_length=200, description="Concise summary title")
    severity: Severity = Field(..., description="Finding severity rating")
    cvss_score: float = Field(..., ge=0.0, le=10.0, description="CVSS v3.1 Base Score")
    cvss_vector: Optional[str] = Field(default=None, description="e.g. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    cwe_id: Optional[str] = Field(default=None, description="Common Weakness Enumeration ID (e.g. CWE-798)")
    owasp_category: Optional[str] = Field(default=None, description="OWASP Top 10 (2021) mapping (e.g. A05:2021-Security Misconfiguration)")
    nist_control: Optional[str] = Field(default=None, description="NIST SP 800-53 control mapping (e.g. SC-8, IA-5)")
    description: str = Field(..., description="Detailed explanation of the flaw and why it occurred")
    impact: str = Field(..., description="Potential business or technical damage if exploited")
    remediation: str = Field(..., description="Step-by-step guidance to fix the issue")
    remediation_code_snippet: Optional[str] = Field(default=None, description="Example configuration or patch code")
    references: List[str] = Field(default_factory=list, description="Authoritative links (OWASP, NIST, RFC, vendor advisory)")
    evidence: Evidence = Field(..., description="Concrete proof and observed data")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    fingerprint: str = Field(..., description="Deterministic SHA256 hash of (check_id + location + evidence.observed_value)")
```

### 3.4 Scan Job Summary Model (`ScanJobSummary`)
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
    weighted_score: float = Field(default=100.0, ge=0.0, le=100.0, description="Calculated 0-100 security score")
    overall_security_grade: str = Field(default="A+", description="Letter grade: A+, A, B, C, D, or F")
    duration_seconds: float = Field(default=0.0, ge=0.0)
    engine_breakdown: Dict[str, int] = Field(default_factory=dict, description="Finding counts per engine")
```

### 3.5 Log Entry Model (`LogEntry`)
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

### 3.6 Complete Scan Job Model (`ScanJob`)
```python
class ScanConfig(BaseModel):
    rate_limit_rps: int = Field(default=5, ge=1, le=20)
    timeout_seconds: int = Field(default=10, ge=2, le=60)
    custom_headers: Dict[str, str] = Field(default_factory=dict)
    port_list: List[int] = Field(default_factory=list)
    include_subdomains: bool = Field(default=False)

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
