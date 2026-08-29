"""
Contract 02 & 08 Data Models and Pydantic v2 Schemas.
"""

from __future__ import annotations
from datetime import datetime, timezone
from enum import Enum
import hashlib
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
import uuid


def utc_now() -> datetime:
    """Helper to return current timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


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
    URL = "URL"
    DOMAIN = "DOMAIN"
    IP = "IP"
    LOCAL_PATH = "LOCAL_PATH"
    DOCKERFILE = "DOCKERFILE"
    IAC_MANIFEST = "IAC_MANIFEST"


class ScanProfile(str, Enum):
    """
    Scan profile configurations determining which engine subsets run.
    """
    FULL_STACK = "FULL_STACK"
    QUICK = "QUICK"
    DAST_ONLY = "DAST_ONLY"
    SAST_ONLY = "SAST_ONLY"
    NETWORK_ONLY = "NETWORK_ONLY"
    INFRA_ONLY = "INFRA_ONLY"
    CUSTOM = "CUSTOM"


class ScanStatus(str, Enum):
    """
    State machine enumeration for scan job lifecycle.
    """
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class LogLevel(str, Enum):
    """
    Telemetry log level.
    """
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    DEBUG = "DEBUG"


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
    observed_value: str = Field(..., description="Observed value or sanitized token snippet")
    expected_value: str = Field(..., description="Expected value according to security baseline")
    raw_response_snippet: Optional[str] = Field(default=None, description="Safe excerpt of HTTP header, banner, or code snippet")
    request_details: Optional[Dict[str, Any]] = Field(default=None, description="HTTP method, URL, and test headers used")
    response_details: Optional[Dict[str, Any]] = Field(default=None, description="HTTP status code and response headers")
    line_number: Optional[int] = Field(default=None, description="Line number if finding relates to a file")
    column_number: Optional[int] = Field(default=None, description="Column number if applicable")


def calculate_fingerprint(check_id: str, location: str, observed_value: str) -> str:
    """
    Generates a deterministic SHA256 fingerprint for deduplication.
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
    Normalized vulnerability finding model.
    """
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
    created_at: datetime = Field(default_factory=utc_now)
    fingerprint: str = Field(..., description="Deterministic SHA256 hash of (check_id + location + evidence.observed_value)")


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


class ScanConfig(BaseModel):
    """
    Execution configuration options for a scan.
    """
    rate_limit_rps: int = Field(default=5, ge=1, le=20)
    timeout_seconds: int = Field(default=10, ge=2, le=60)
    custom_headers: Dict[str, str] = Field(default_factory=dict)
    port_list: List[int] = Field(default_factory=list)
    include_subdomains: bool = Field(default=False)


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
    findings: List[Finding] = Field(default_factory=list)
    logs: List[LogEntry] = Field(default_factory=list)
    started_at: Optional[datetime] = Field(default=None)
    completed_at: Optional[datetime] = Field(default=None)
