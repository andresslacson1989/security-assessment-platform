# Contract 02: Enterprise Data Schemas, Entity Models & Multi-Tenant State Specifications

**Project Name:** CyberAssess Automated Security Assessment & Vulnerability Management Platform  
**Document Version:** 14.3.0 (Enterprise ASPM Schema, 26-Tool Fleet, Per-Link Assessment Intelligence Dossier, Discovery Evidence & Audit Models)
**Status:** APPROVED / AUTHORITATIVE SPECIFICATION  
**Scope Authority:** Core Data Schemas, Relational Persistence Tables, Identity, Assets, Per-Link Dossiers, Findings Lifecycle & Audit Records  

---

## 1. Single Version Authority

All platform components, API responses, exporters, UI banners, and database migrations MUST derive their version metadata exclusively from the centralized version authority:

```python
# backend/app/core/version.py
APP_VERSION = "14.3.0"
API_VERSION = "v1"
SCHEMA_VERSION = "4.1.0"
CONTRACT_VERSION = "14.3.0"
RULESET_VERSION = "14.3.0"
RISK_MODEL_VERSION = "14.3.0"
```

Hardcoded independent version strings in READMEs, endpoints, or UI templates are strictly prohibited.
`backend/app/core/version.py` is the runtime source of truth. Contract, API, UI, export,
ruleset, and migration metadata MUST import or receive these values from that authority;
the values above are normative and MUST remain synchronized with it in CI.

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
    asvs_control: ASVSControl | ASVSNotApplicable  # Contract 06 typed union; never an unstructured nullable string
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

### 4.1 Finding taxonomy and persistence invariants

Execution requests and execution runs are tenant-owned durable records. One
authorized request maps to exactly one execution run; retries and recovery
attempts require a new request and approval. Request, decision, and run records
MUST preserve the same tenant and authority binding through relational
constraints and versioned migrations. Legacy upgrades MUST preflight duplicates
and orphaned or cross-tenant references and fail closed with an actionable
error rather than silently reconciling data.

`asvs_control` MUST use the exact Contract 06 typed union: `ASVSControl` carries
`kind="ASVS_CONTROL"` and a version-qualified value; `ASVSNotApplicable` carries
`kind="ASVS_NOT_APPLICABLE"`, `owner`, `rationale`, and `review_date`. A finding
or occurrence with an unknown, deprecated, unversioned, or absent control
identifier MUST be rejected or represented as an explicit normalization
failure; it MUST NOT be silently emitted as valid.

Tenant-owned `CanonicalFinding`, `FindingOccurrence`, `ScanJob`, and `Asset`
relationships MUST be enforced by database foreign keys and tenant-consistency
constraints in the same transaction as the write. Application-level checks are
defense in depth, not a substitute for relational integrity. Any retention or
purge operation MUST preserve the stated legal-hold and audit invariants.

`ValidatedTarget` is operationally immutable: nested addresses, scope entries,
authorization context, and metadata MUST use immutable representations or a
documented defensive-copy boundary at construction. Top-level model freezing is
not sufficient for nested containers. A caller MUST NOT be able to mutate a
previously sealed target by retaining a reference to a nested list or mapping;
mutation attempts MUST fail or be detected before execution. The canonical
serialized form MUST be specified separately from the in-memory immutable
representation.

### 4.2 Scan authorization manifest records

Each scan request MUST have a durable parent authorization record and a
normalized operation and fleet snapshot. The parent binds requester, tenant,
project, inventory asset, gateway-issued target ID, target integrity seal,
target policy version, profile, selected engines, engine revision, complete
26-tool fleet snapshot, canonical operation-policy revision, manifest hash,
expiry, budgets, credential-scope reference, and emergency-stop reference.

Each operation row MUST identify its canonical tool ID, owning engine,
operation family, exact typed options, classification, policy revision, target
and authorization decision IDs, budgets, capability/readiness state,
selection/exclusion reason, and child request/decision/run identifiers when
approved. A fleet snapshot MUST contain every canonical tool, including
manual-only, native-only, unselected, deferred, and policy-gap states; absence
is not a valid representation of non-selection.

The in-memory `ScanAuthorizationManifest` is deeply immutable. Top-level
model freezing alone is insufficient: nested operation options, resource and
account-impact budgets, credential-scope values, effective scan configuration,
target authorization context, resolved-address sequences, authorized-scope
sequences, operations, engine operations, and fleet entries MUST be recursively
frozen or defensively copied at construction. A retained caller reference MUST
NOT be able to mutate a sealed manifest after its hash is calculated. The
canonical serialized form is a separate JSON representation using deterministic
sorted keys and compact separators; `manifest_hash` is the SHA-256 digest of
that representation with the hash field excluded. Persisted `manifest_json`
MUST reconstruct to the same canonical representation, and approval MUST fail
closed if it does not.

When inventory metadata is available, the manifest MAY carry an asset-owner and
asset-lifecycle snapshot. If present, approval MUST revalidate both values
under the tenant/project/asset lock and MUST reject owner, delegation, or
decommissioning changes after request creation. The request creation
`Idempotency-Key` is mandatory, is validated without normalization against the
bounded ASCII grammar, and is scoped by organization. The same organization,
key, and canonical request fingerprint MAY replay the original request; a
different fingerprint MUST return a conflict; a missing key MUST never be
generated by the server; and the same key in another organization MUST remain
isolated.

Durable scan manifests MUST NOT contain plaintext passwords, bearer tokens,
cookies, authorization headers, custom credential headers, API keys, private
keys, or equivalent secret material. The current application has a worker-only
`CloudCredentialEnvelope` for governed cloud execution but does not yet have a
generic tenant-scoped web-credential reference and resolver. Until that
resolver exists, durable scan authorization MUST reject non-`NONE`/`NO_AUTH`
web authentication and inline credential-bearing configuration; it MUST NOT
silently replace it with a redacted or unusable hash. The cloud envelope MUST
not be reused as a web-authentication substitute.

On persistence and approval, normalized operation rows and all 26 fleet rows
MUST compare canonically to the parent manifest, including tool/engine
identity, operation family, options, policy revision, budgets, credential
scope, capability, selection, exclusion, and disabled/deferred reason. Approval
MUST acquire the parent authority lock before rehydrating and comparing this
material, then revalidate current policy, target seal/version, tenant/project/
asset ownership and lifecycle, requester/approver/session status, and expiry.
Any mismatch MUST fail closed before child authority creation. A failure after
child insertion begins MUST roll back every child request, decision, run,
dispatch, ownership, recovery, and parent-link mutation atomically. An exact
approval replay MUST validate the complete existing child graph and MUST NOT
create duplicates.

Parent manifest records and child execution records MUST be tenant-bound by
composite foreign keys and uniqueness constraints. Approval of a parent does
not authorize multiple process launches: every actual external operation has
one child request and one durable run. Any manifest mutation requires a new
request fingerprint and approval. Capability status and cached availability
are observational data and MUST NOT satisfy authorization.

Execution lifecycle evidence is a separate durable dimension on each child
run. `execution_process_ownership` MUST distinguish `UNKNOWN`,
`NO_EXTERNAL_PROCESS`, `EXTERNAL_PROCESS_GOVERNED`, `LAUNCH_UNCERTAIN`,
`RECOVERY_BLOCKED`, and `TERMINAL`; `execution_recovery_attempts` is append-only
and `execution_recovery_state` is the tenant-bound coordination projection.
`worker_generation` MUST be persisted on the execution run and recovery state,
and all ownership, settlement, and recovery updates MUST verify the worker
identity/generation and composite tenant key. `NO_EXTERNAL_PROCESS` MUST carry
a digest-bound proof record. Null process IDs, task completion, missing
in-memory mappings, and `NOT_FOUND` cancellation results are not proof of that
state. A post-creation ownership ambiguity remains non-terminal until a
supervisor-confirmed recovery settlement atomically updates ownership, run,
dispatch, and recovery records. Authorized operators MUST have a tenant-scoped
recovery-health view; ordinary users and cross-tenant identifiers MUST not
access it.

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

---

## 7. Reconnaissance, Attack Surface & Per-Link Security Dossier Models

### 7.1 Endpoint Test Record & Security Dossier
```python
class EndpointTestStatus(str, Enum):
    SAFE = "SAFE"          # Test executed cleanly, no vulnerability detected
    VULNERABLE = "VULNERABLE"  # Flaw or misconfiguration detected
    INFO = "INFO"          # Informational exposure or structural discovery
    SKIPPED = "SKIPPED"    # Skipped due to scope/rate-limit/inapplicability

class EndpointTestRecord(BaseModel):
    test_name: str         # e.g., "SQL Injection Probe", "Reflected XSS", "Security Headers", "CORS Origin Reflection", "Form CSRF Audit"
    category: str          # e.g., "Injection", "Authentication", "Configuration", "Client-Side"
    tool: str              # e.g., "ffuf", "nuclei", "katana", "native_dast", "schemathesis"
    status: EndpointTestStatus = EndpointTestStatus.SAFE
    details: str           # Concrete probe details and observations
    execution_time_ms: float = 0.0
    findings_count: int = 0

class DiscoveredEndpoint(BaseModel):
    url: str
    method: str = "GET"
    depth: int = 0
    status_code: Optional[int] = None
    content_type: Optional[str] = None
    is_authenticated: bool = False
    has_forms: bool = False
    discovered_forms: int = 0
    response_time_ms: Optional[float] = None
    tools_executed: List[str] = Field(default_factory=list)
    tests_performed: List[EndpointTestRecord] = Field(default_factory=list)
    finding_ids: List[str] = Field(default_factory=list)

class DiscoveredSubdomain(BaseModel):
    domain: str
    ip_addresses: List[str] = Field(default_factory=list)  # Must be actively resolved via DNS A/AAAA
    cname_targets: List[str] = Field(default_factory=list)
    is_takeover_vulnerable: bool = False
    service_fingerprint: Optional[str] = None
    discovered_via: str = "crt.sh"
    dns_status: str = "ACTIVE"  # "ACTIVE" or "NXDOMAIN"
```
