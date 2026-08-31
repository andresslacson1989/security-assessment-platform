# Contract 02: Enterprise Data Schemas, Entity Models & Multi-Tenant State Specifications

**Project Name:** CyberAssess Automated Security Assessment & Vulnerability Management Platform  
**Document Version:** 13.0.0 (Enterprise ASPM Schema, Canonical Findings & Occurrences, Tenant Isolation, Version Authority & Tamper-Evident Audit Models)  
**Status:** APPROVED / AUTHORITATIVE SPECIFICATION  
**Scope Authority:** Core Data Schemas, Relational Persistence Tables, Identity, Assets, Findings Lifecycle & Audit Records  

---

## 1. Single Version Authority

All platform components, API responses, exporters, UI banners, and database migrations MUST derive their version metadata exclusively from the centralized version authority:

```python
# backend/app/core/version.py
APP_VERSION = "13.0.0"
API_VERSION = "v1"
SCHEMA_VERSION = "13.0.0"
CONTRACT_VERSION = "13.0.0"
RULESET_VERSION = "2026.08.31"
RISK_MODEL_VERSION = "contextual_risk_model_v2"
```

Hardcoded independent version strings in READMEs, endpoints, or UI templates are strictly prohibited.

---

## 2. Identity, Authentication & Multi-Tenancy Models

### 2.1 Enums
- `OperatingMode`: `PRODUCTION`, `DEVELOPMENT`, `TEST`
- `PrincipalType`: `SYSTEM_PRINCIPAL`, `TENANT_PRINCIPAL`
- `UserRole`: `ADMIN`, `SECURITY_ANALYST`, `DEVELOPER`, `VIEWER`
- `APIKeyScope`:
  - `scan:create`, `scan:read`, `scan:cancel`, `scan:repeater`, `scan:internal`
  - `finding:read`, `finding:write`, `finding:triage`, `finding:risk_accept`
  - `asset:read`, `asset:write`, `asset:delete`
  - `report:read`
  - `tool:read`, `tool:install`
  - `system:admin`

### 2.2 Entity Schemas
```python
class Organization(BaseModel):
    id: str  # e.g., "org-7a8f9c"
    name: str
    slug: str
    created_at: datetime
    is_active: bool = True

class Project(BaseModel):
    id: str  # e.g., "prj-b1c2d3"
    organization_id: str
    name: str
    description: Optional[str] = None
    created_at: datetime

class Workspace(BaseModel):
    id: str  # e.g., "ws-e4f5a6"
    organization_id: str
    project_id: str
    name: str
    filesystem_root: str  # Canonical resolved absolute path
    is_sandboxed: bool = True
    created_at: datetime

class UserProfile(BaseModel):
    id: str  # e.g., "usr-1a2b3c"
    username: str
    email: str
    role: UserRole
    principal_type: PrincipalType = PrincipalType.TENANT_PRINCIPAL
    organization_id: str = "org-default"
    scopes: List[str] = Field(default_factory=lambda: ["*"])
    is_active: bool = True
    created_at: datetime
    last_login_at: Optional[datetime] = None

class APIKeyRecord(BaseModel):
    key_id: str  # e.g., "ca_key_9f8e7d" (public identifier prefix)
    key_hash: str  # SHA-256 hash of secret token
    organization_id: str
    user_id: Optional[str] = None
    name: str
    scopes: List[str]
    status: str = "ACTIVE"  # "ACTIVE" or "REVOKED"
    created_at: datetime
    expires_at: Optional[datetime] = None
    revoked_at: Optional[datetime] = None
    last_used_at: Optional[datetime] = None
```

---

## 3. Attack Surface & Asset Inventory Models

```python
class AssetType(str, Enum):
    WEB_APPLICATION = "WEB_APPLICATION"
    API_ENDPOINT = "API_ENDPOINT"
    DOMAIN = "DOMAIN"
    IP_ADDRESS = "IP_ADDRESS"
    GIT_REPOSITORY = "GIT_REPOSITORY"
    CONTAINER_IMAGE = "CONTAINER_IMAGE"
    CLOUD_ACCOUNT = "CLOUD_ACCOUNT"
    IAC_TEMPLATE = "IAC_TEMPLATE"

class AssetCriticality(str, Enum):
    CRITICAL = "CRITICAL"  # 1.5x risk multiplier
    HIGH = "HIGH"          # 1.2x risk multiplier
    MEDIUM = "MEDIUM"      # 1.0x risk multiplier
    LOW = "LOW"            # 0.7x risk multiplier

class AssetLifecycleStatus(str, Enum):
    DISCOVERED = "DISCOVERED"
    MONITORED = "MONITORED"
    DECOMMISSIONED = "DECOMMISSIONED"
    ARCHIVED = "ARCHIVED"

class Asset(BaseModel):
    id: str = Field(default_factory=lambda: f"ast-{uuid.uuid4().hex[:12]}")
    organization_id: str = "org-default"
    project_id: Optional[str] = None
    name: str
    type: AssetType
    target_value: str
    criticality: AssetCriticality = AssetCriticality.MEDIUM
    internet_exposed: bool = True
    owner: Optional[str] = None
    lifecycle_status: AssetLifecycleStatus = AssetLifecycleStatus.MONITORED
    tags: List[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_scanned_at: Optional[datetime] = None
    last_verified_at: Optional[datetime] = None
    active_findings_count: int = 0
```

---

## 4. Canonical Finding & Finding Occurrence Models

To prevent data loss and preserve temporal vulnerability lifecycles:

```python
class FindingLifecycleStatus(str, Enum):
    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    IN_PROGRESS = "IN_PROGRESS"
    FIXED = "FIXED"
    VERIFIED = "VERIFIED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    RISK_ACCEPTED = "RISK_ACCEPTED"
    REOPENED = "REOPENED"

class CorrelationType(str, Enum):
    SAST_DAST_VERIFIED = "SAST_DAST_VERIFIED"
    MULTI_TOOL_CONFIRMED = "MULTI_TOOL_CONFIRMED"
    ENDPOINT_CLUSTERED = "ENDPOINT_CLUSTERED"
    TAINT_CONFIRMED = "TAINT_CONFIRMED"

class SLAInfo(BaseModel):
    severity: Severity
    sla_days: int
    sla_started_at: datetime
    sla_due_at: datetime
    sla_breached_at: Optional[datetime] = None
    is_breached: bool = False

class FindingOccurrence(BaseModel):
    id: str = Field(default_factory=lambda: f"occ-{uuid.uuid4().hex[:12]}")
    organization_id: str = "org-default"
    canonical_finding_id: str
    scan_id: str
    asset_id: Optional[str] = None
    source_tool: str
    check_id: str
    raw_evidence: Evidence
    reproduction_curl: Optional[str] = None
    taint_trace: Optional[List[str]] = None
    detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class CanonicalFinding(BaseModel):
    id: str = Field(default_factory=lambda: f"cfind-{uuid.uuid4().hex[:12]}")
    organization_id: str = "org-default"
    project_id: Optional[str] = None
    asset_id: Optional[str] = None
    title: str
    category: str
    severity: Severity
    cvss_score: float
    cvss_vector: str
    contextual_risk_score: float
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    nist_control: Optional[str] = None
    status: FindingLifecycleStatus = FindingLifecycleStatus.OPEN
    first_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    times_observed: int = 1
    sla: SLAInfo
    assigned_to: Optional[str] = None
    contributing_tools: List[str] = Field(default_factory=list)
    correlation_type: Optional[CorrelationType] = None
    description: str
    impact: str
    remediation: str
    evidence_hash: str
```

---

## 5. Contextual Risk Model (`contextual_risk_model_v2`)

Contextual risk score calculation follows policy parameters:
$$\text{Risk} = \min\left(10.0, \text{CVSS} \times C_{\text{asset}} \times E_{\text{exposure}} \times F_{\text{confidence}}\right)$$

Where:
- $C_{\text{asset}} \in \{ \text{CRITICAL}: 1.5, \text{HIGH}: 1.2, \text{MEDIUM}: 1.0, \text{LOW}: 0.7 \}$
- $E_{\text{exposure}} \in \{ \text{Internet Exposed}: 1.0, \text{Internal/Protected}: 0.7 \}$
- $F_{\text{confidence}} \in \{ \text{SAST+DAST Verified}: 1.3, \text{Multi-Tool Confirmed}: 1.15, \text{Single Tool / Heuristic}: 1.0 \}$

---

## 6. Tamper-Evident Audit Event Model

```python
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
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    actor: str  # User ID, username, or API Key ID
    organization_id: str = "org-default"
    action: AuditAction
    object_type: str  # "scan", "asset", "finding", "user", "tool", "api_key"
    object_id: str
    result: str  # "SUCCESS", "FAILURE", "DENIED"
    source_ip: Optional[str] = None
    correlation_id: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)
    previous_event_hash: Optional[str] = None
    event_hash: Optional[str] = None  # SHA256(canonical_event_json + previous_event_hash)
```
