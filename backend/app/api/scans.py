"""
Contract 04 §1.3 & Contract 08 §1:
Scan Lifecycle, Execution, Cancellation & Real-Time SSE Streaming Endpoints.
Enforces multi-tenant organization authorization and IDOR protection.
"""

from __future__ import annotations
import asyncio
import hashlib
import json
import uuid
from datetime import timedelta
from pathlib import Path
from typing import Dict, Any, List, Optional
import urllib.parse
from fastapi import APIRouter, HTTPException, Query, status, Depends, Request, Header
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from app.core.models import (
    Target,
    TargetType,
    AssetType,
    ScanProfile,
    ScanStatus,
    ScanConfig,
    ScanJob,
    AuditEvent,
    AuditAction,
    utc_now,
    EngineExecutionStatus,
    AssessmentCoverage,
    ToolExecutionTelemetry,
    ScanTelemetryReport,
    DiscoveredEndpoint,
    EndpointTestRecord,
    EndpointTestStatus,
    PrincipalType,
    ScanAuthorizationRequestRecord,
    validate_idempotency_key,
)
from app.core.storage import get_scan, list_scans, save_scan, save_scan_with_authorization_request
from app.core.orchestrator import orchestrator
from app.core.ssrf_protector import assert_safe_url, SSRFProtectionError
from app.core.path_sandbox import assert_safe_path, PathSandboxViolation, get_default_workspace_dir
from app.core.auth import (
    get_current_user,
    decode_access_token,
    require_admin,
    require_dev_or_higher,
    require_permission,
    UserProfile,
    UserRole,
    authorize_scan_access,
    authorize_internal_target,
)
from app.core.db import db_manager, is_database_integrity_error
from app.core.scan_manifest import build_scan_manifest, validate_durable_scan_config
from app.core.ssrf_protector import create_validated_target
from app.core.execution_service import get_worker_generation, get_worker_identity

router = APIRouter()


def _organization_scope(user: UserProfile) -> Optional[str]:
    if user.principal_type == PrincipalType.SYSTEM_PRINCIPAL and user.role == UserRole.ADMIN:
        return None
    return user.organization_id


class StartScanRequest(BaseModel):
    target_type: TargetType = Field(..., description="Classification of target asset")
    target_value: str = Field(..., min_length=1, max_length=1024, description="Target URI, domain, IP, filesystem path, cloud account, or Kubernetes cluster")
    target_name: Optional[str] = Field(None, min_length=1, max_length=120, description="Friendly display label for the target")
    profile: ScanProfile = Field(default=ScanProfile.FULL_STACK, description="Scanning depth and profile")
    asset_id: Optional[str] = Field(None, description="Monitored asset UUID")
    project_id: Optional[str] = Field(None, description="Project boundary UUID")
    enabled_engines: Optional[List[str]] = Field(None, max_length=5, description="Explicit list of unique registered engine names to run")
    config: Optional[ScanConfig] = Field(default_factory=ScanConfig, description="Execution parameters")


class ScanApprovalRequest(BaseModel):
    """Explicit administrator acknowledgement for one immutable scan manifest."""

    manifest_hash: str = Field(..., min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")
    confirm_owned_target: bool = Field(
        ...,
        description="The administrator confirms the target is owned or explicitly authorized and no other property will be affected.",
    )


def _require_idempotency_key(value: Optional[str], *, operation: str) -> str:
    """Validate one exact visible-ASCII idempotency key without normalization."""
    if value is None or not isinstance(value, str):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"A unique Idempotency-Key header is required for {operation}.",
        )
    try:
        validate_idempotency_key(value)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Idempotency-Key must be 1-128 ASCII characters and contain only letters, numbers, '.', '_' , ':' or '-'.",
        )
    return value


def _scan_session_jti(authorization: Optional[str], current_user: UserProfile) -> str:
    if not authorization:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Bearer session is required.")
    parts = authorization.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Bearer session is required.")
    payload = decode_access_token(parts[1].strip())
    if str(payload.get("sub", "")) != current_user.id or str(payload.get("org_id", "")) != current_user.organization_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Approval session does not match the authenticated principal.")
    jti = payload.get("jti")
    if not isinstance(jti, str) or not jti:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authenticated session has no decision binding.")
    return jti


def validate_target_input(target_type: TargetType, target_value: str, allow_internal: bool = False) -> None:
    """
    Validates target value syntax and security constraints for ALL target types:
    URL, DOMAIN, IP, LOCAL_PATH, DOCKERFILE, IAC_MANIFEST.
    Ensures zero bypass routes around the security gateway.
    """
    val = target_value.strip()
    if not val:
        raise HTTPException(status_code=400, detail="Target value cannot be empty.")

    try:
        if target_type in (TargetType.LOCAL_PATH, TargetType.DOCKERFILE, TargetType.IAC_MANIFEST):
            assert_safe_path(val, allowed_roots=[get_default_workspace_dir()])
            return
        from app.core.ssrf_protector import assert_safe_target
        assert_safe_target(target_type.value, val, allow_internal=allow_internal)
    except SSRFProtectionError as err:
        raise HTTPException(
            status_code=400,
            detail=f"SSRF Protection Gate: {str(err)}"
        )
    except PathSandboxViolation as err:
        raise HTTPException(
            status_code=400,
            detail=f"Path Sandbox Violation: {str(err)}"
        )


@router.post("/start", status_code=status.HTTP_201_CREATED, summary="Start Automated Security Scan")
async def start_security_scan(
    payload: StartScanRequest,
    request: Request,
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
    current_user: UserProfile = Depends(require_permission(required_scope="scan:create", allowed_roles=[UserRole.ADMIN, UserRole.SECURITY_ANALYST, UserRole.DEVELOPER])),
) -> Dict[str, Any]:
    """
    Validates the target, creates a ScanJob, and launches asynchronous security assessment in the background.
    Protected by SSRF gateway, path sandboxing, and RBAC multi-tenant authentication.
    """
    request_key = _require_idempotency_key(idempotency_key, operation="scan creation")
    allow_internal = authorize_internal_target(current_user, payload.target_value)
    asset = None
    if payload.asset_id:
        asset = db_manager.get_asset(payload.asset_id, organization_id=_organization_scope(current_user))
        if not asset:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Authorized asset not found.")
        asset_target_type = {
            AssetType.WEB_APPLICATION: TargetType.URL,
            AssetType.API_ENDPOINT: TargetType.URL,
            AssetType.DOMAIN: TargetType.DOMAIN,
            AssetType.IP_ADDRESS: TargetType.IP,
            AssetType.IAC_TEMPLATE: TargetType.IAC_MANIFEST,
            AssetType.CLOUD_ACCOUNT: TargetType.CLOUD_ACCOUNT,
            AssetType.KUBERNETES_CLUSTER: TargetType.KUBERNETES_CLUSTER,
        }.get(asset.type)
        if asset_target_type != payload.target_type or asset.target_value.strip().lower() != payload.target_value.strip().lower():
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Scan target does not match the selected asset.")
        if payload.project_id and payload.project_id != asset.project_id:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Scan project does not match the selected asset.")
        allow_internal = authorize_internal_target(current_user, payload.target_value)
    else:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="A monitored inventory asset is required before a scan authorization request can be created.",
        )
    validate_target_input(payload.target_type, payload.target_value, allow_internal=allow_internal)

    target_name = payload.target_name or payload.target_value
    target = Target(
        name=target_name,
        type=payload.target_type,
        value=payload.target_value.strip(),
    )

    # Determine enabled engines
    if payload.enabled_engines:
        selected_engines = payload.enabled_engines
    else:
        selected_engines = [
            eng.name for eng in orchestrator.get_registered_engines()
            if eng.is_applicable(target)
        ]

    scan_config = payload.config or ScanConfig()
    try:
        durable_config = validate_durable_scan_config(scan_config)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Scan authorization configuration rejected: {exc}",
        ) from exc

    canonical_request = {
        "target_type": payload.target_type.value,
        "target_value": payload.target_value.strip(),
        "target_name": target_name,
        "profile": payload.profile.value,
        "asset_id": asset.id,
        "project_id": asset.project_id,
        "enabled_engines": sorted(selected_engines),
        "config": durable_config,
    }
    request_fingerprint = hashlib.sha256(
        json.dumps(canonical_request, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()
    existing_request = db_manager.find_scan_authorization_request_by_idempotency(
        current_user.organization_id, request_key,
    )
    if existing_request:
        if existing_request["creation_fingerprint"] != request_fingerprint:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Idempotency-Key is already bound to different scan input.")
        return {
            "scan_id": existing_request["scan_id"],
            "scan_request_id": existing_request["scan_request_id"],
            "authorization_state": existing_request["state"],
            "manifest_hash": existing_request["manifest_hash"],
            "status": "AUTHORIZATION_REQUIRED",
            "dispatch_state": "PENDING_APPROVAL",
            "execution_started": False,
            "idempotent_replay": True,
            "expires_at": existing_request["expires_at"],
        }

    try:
        validated_target = create_validated_target(
            target,
            organization_id=current_user.organization_id,
            project_id=asset.project_id if asset else payload.project_id,
            asset_id=asset.id if asset else None,
            active_probing_granted=False,
            allow_internal=allow_internal,
        )
        manifest = build_scan_manifest(
            organization_id=current_user.organization_id,
            project_id=asset.project_id if asset else payload.project_id,
            asset_id=asset.id if asset else "",
            asset_owner=asset.owner if asset else None,
            asset_lifecycle_status=asset.lifecycle_status.value if asset else None,
            validated_target=validated_target,
            profile=payload.profile.value,
            selected_engine_ids=selected_engines,
            engines=orchestrator.get_registered_engines(),
            requested_expiry=utc_now() + timedelta(minutes=15),
            scan_config=scan_config,
            emergency_stop_reference=f"stop:{uuid.uuid4().hex}",
        )
    except (ValueError, SSRFProtectionError) as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"Scan authorization manifest rejected: {exc}") from exc

    scan_job = ScanJob(
        correlation_id=getattr(request.state, "correlation_id", None),
        organization_id=asset.organization_id if asset else current_user.organization_id,
        project_id=asset.project_id if asset else payload.project_id,
        asset_id=asset.id if asset else None,
        active_probing_granted=bool(asset and asset.active_probing_granted),
        live_secret_verification_granted=bool(asset and asset.live_secret_verification_granted),
        target=target,
        profile=payload.profile,
        enabled_engines=selected_engines,
        config=scan_config,
        authorization_state="REQUESTED",
        authorization_request_id=f"scanreq-{uuid.uuid4().hex}",
        authorization_manifest_hash=manifest.manifest_hash,
    )

    # Persist the request before returning.  This endpoint is request-only:
    # no background task or process launch is permitted before approval.
    authorization_request = ScanAuthorizationRequestRecord(
            scan_request_id=scan_job.authorization_request_id,
            scan_id=scan_job.id,
            organization_id=scan_job.organization_id,
            requested_by_user_id=current_user.id,
            correlation_id=scan_job.correlation_id or f"corr-scan-{scan_job.id}",
            manifest_hash=manifest.manifest_hash,
            manifest=manifest,
            expires_at=manifest.requested_expiry,
            creation_idempotency_key=request_key,
            creation_fingerprint=request_fingerprint,
        )
    try:
        save_scan_with_authorization_request(scan_job, authorization_request)
    except Exception as exc:
        if not is_database_integrity_error(exc):
            raise
        existing_request = db_manager.find_scan_authorization_request_by_idempotency(
            current_user.organization_id, request_key,
        )
        if not existing_request:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Scan request could not be persisted safely.") from exc
        if existing_request["creation_fingerprint"] != request_fingerprint:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Idempotency-Key is already bound to different scan input.") from exc
        return {
            "scan_id": existing_request["scan_id"],
            "scan_request_id": existing_request["scan_request_id"],
            "authorization_state": existing_request["state"],
            "manifest_hash": existing_request["manifest_hash"],
            "status": "AUTHORIZATION_REQUIRED",
            "dispatch_state": "PENDING_APPROVAL",
            "execution_started": False,
            "idempotent_replay": True,
            "expires_at": existing_request["expires_at"],
        }

    return {
        "scan_id": scan_job.id,
        "scan_request_id": scan_job.authorization_request_id,
        "authorization_state": scan_job.authorization_state,
        "manifest_hash": manifest.manifest_hash,
        "status": "AUTHORIZATION_REQUIRED",
        "dispatch_state": "PENDING_APPROVAL",
        "execution_started": False,
        "target": {
            "name": target.name,
            "type": target.type.value,
            "value": target.value,
        },
        "profile": scan_job.profile.value,
        "enabled_engines": scan_job.enabled_engines,
        "active_adapters": scan_job.active_adapters,
        "created_at": None,
        "expires_at": manifest.requested_expiry.isoformat(),
        "selected_operations": [operation.operation_id for operation in manifest.operations if operation.selection_state == "SELECTED"],
        "excluded_operations": [
            {"operation_id": operation.operation_id, "reason": operation.exclusion_reason}
            for operation in manifest.operations if operation.selection_state != "SELECTED"
        ],
    }


@router.post("/{scan_id}/approve", status_code=status.HTTP_202_ACCEPTED, summary="Approve Exact Scan Manifest")
async def approve_scan_authorization(
    scan_id: str,
    payload: ScanApprovalRequest,
    authorization: Optional[str] = Header(default=None),
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
    current_user: UserProfile = Depends(require_permission(required_scope="execution:approve", allowed_roles=[UserRole.ADMIN])),
) -> Dict[str, Any]:
    """Approve one exact parent manifest and materialize tenant-bound child authorities."""
    approval_key = _require_idempotency_key(idempotency_key, operation="approval")
    if not payload.confirm_owned_target:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Approval requires confirmation that the target is owned or explicitly authorized and will not affect another person's property or website.",
        )
    session_jti = _scan_session_jti(authorization, current_user)
    scan_job = get_scan(scan_id, organization_id=current_user.organization_id)
    if not scan_job or not scan_job.authorization_request_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan authorization request not found.")
    try:
        result, child_links = db_manager.approve_scan_authorization_request(
            scan_job.authorization_request_id,
            current_user.organization_id,
            payload.manifest_hash,
            approval_key,
            current_user.id,
            session_jti,
            get_worker_identity(),
            get_worker_generation(),
        )
    except RuntimeError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Scan authorization integrity or current-policy validation failed; no execution authority was created.",
        ) from exc
    if result == "NOT_FOUND":
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan authorization request not found.")
    if result == "CONFLICT":
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Scan manifest or approval idempotency binding does not match.")
    if result == "EXPIRED":
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Scan authorization request has expired.")
    if result == "DENIED":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Scan authorization was denied by the tenant authority boundary.")
    if result not in {"AUTHORIZED", "REPLAY"}:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Scan authorization cannot be approved in its current state.")
    # Section A persists the administrator decision and immutable child
    # authorities only.  Dispatch, worker handoff, and process launch are
    # independently gated by Section B and must remain unreachable from this
    # approval route until that section is explicitly accepted.
    dispatch_state = "PENDING_IMPLEMENTATION"
    return {
        "scan_id": scan_id,
        "authorization_state": "DISPATCHABLE",
        "status": "AUTHORIZED",
        "dispatch_state": dispatch_state,
        "execution_started": False,
        "idempotent_replay": result == "REPLAY",
        "child_operations": child_links,
        "warning": "Approval permits only the exact immutable manifest against the owned or authorized target. It must not affect any other person's property or website.",
    }


@router.get("", summary="List Stored Scan Jobs for Tenant")
@router.get("/", summary="List Stored Scan Jobs for Tenant", include_in_schema=False)
@router.get("/history", summary="List Stored Scan Jobs (History Alias)")
async def get_all_scans(
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    current_user: UserProfile = Depends(require_permission(required_scope="scan:read")),
) -> Dict[str, Any]:
    """Returns paginated list of historical scan summaries for caller's organization."""
    scans, total = list_scans(
        limit=limit,
        offset=offset,
        organization_id=_organization_scope(current_user),
    )

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "items": [
            {
                "id": s.id,
                "target": {
                    "name": s.target.name,
                    "type": s.target.type.value,
                    "value": s.target.value,
                },
                "profile": s.profile.value,
                "status": s.status.value,
                "progress_percent": s.progress_percent,
                "overall_security_grade": s.summary.overall_security_grade if s.summary else "N/A",
                "weighted_score": s.summary.weighted_score if s.summary else 0.0,
                "total_findings": s.summary.total_findings if s.summary else len(s.findings),
                "started_at": s.started_at.isoformat() if s.started_at else None,
                "completed_at": s.completed_at.isoformat() if s.completed_at else None,
            }
            for s in scans
        ],
    }


@router.get("/{scan_id}", summary="Get Full Scan Job Details")
async def get_scan_details(
    scan_id: str,
    current_user: UserProfile = Depends(require_permission(required_scope="scan:read")),
) -> ScanJob:
    """Returns full ScanJob model. Enforces tenant ownership (IDOR denial)."""
    job = orchestrator.get_active_job(scan_id, organization_id=_organization_scope(current_user))
    if not job:
        raise HTTPException(status_code=404, detail=f"Scan job '{scan_id}' not found.")

    if not authorize_scan_access(current_user, job, action="read"):
        raise HTTPException(status_code=404, detail=f"Scan job '{scan_id}' not found.")

    return job


@router.get("/{scan_id}/telemetry", response_model=ScanTelemetryReport, summary="Get Structured Assessment Telemetry & Tool Logs")
async def get_scan_telemetry(
    scan_id: str,
    tool: Optional[str] = Query(default=None, description="Filter logs by tool name (e.g. nmap, nuclei, katana)"),
    engine: Optional[str] = Query(default=None, description="Filter logs by engine name (e.g. network, web_dast, code_sast)"),
    level: Optional[str] = Query(default=None, description="Filter logs by level (INFO, WARNING, ERROR, DEBUG)"),
    search: Optional[str] = Query(default=None, description="Search term in log messages or URLs"),
    current_user: UserProfile = Depends(require_permission(required_scope="scan:read")),
) -> ScanTelemetryReport:
    """
    Returns organized assessment telemetry, per-tool execution logs, tested links, and discovered attack surface.
    Enforces strict multi-tenant authorization and IDOR defense.
    """
    job = orchestrator.get_active_job(scan_id, organization_id=_organization_scope(current_user))
    if not job:
        raise HTTPException(status_code=404, detail=f"Scan job '{scan_id}' not found.")

    if not authorize_scan_access(current_user, job, action="read"):
        raise HTTPException(status_code=404, detail=f"Scan job '{scan_id}' not found.")

    all_logs = list(job.logs)
    filtered_logs = all_logs
    if tool:
        tool_lower = tool.strip().lower()
        filtered_logs = [
            l for l in filtered_logs
            if (l.tool and l.tool.lower() == tool_lower) or (tool_lower in l.message.lower())
        ]
    if engine:
        engine_lower = engine.strip().lower()
        filtered_logs = [
            l for l in filtered_logs
            if (l.engine and l.engine.lower() == engine_lower)
        ]
    if level:
        level_upper = level.strip().upper()
        filtered_logs = [
            l for l in filtered_logs
            if (l.level.value if hasattr(l.level, "value") else str(l.level)).upper() == level_upper
        ]
    if search:
        s_term = search.strip().lower()
        filtered_logs = [
            l for l in filtered_logs
            if s_term in l.message.lower() or (l.engine and s_term in l.engine.lower()) or (l.tool and s_term in l.tool.lower())
        ]

    # Build per-tool execution telemetry
    tool_telemetry_map: Dict[str, ToolExecutionTelemetry] = {}
    recorded_states = getattr(job, "tool_execution_states", {})
    # Availability is not execution. `active_adapters` is populated during
    # capability discovery and must never manufacture a successful telemetry
    # record for a tool that the selected engine did not actually run.
    telemetry_tools = list(dict.fromkeys([
        *recorded_states.keys(),
        *(f.source_tool or "native" for f in job.findings),
    ]))
    state_statuses = {
        "COMPLETED_NO_FINDINGS": EngineExecutionStatus.PASS,
        "COMPLETED_WITH_FINDINGS": EngineExecutionStatus.FINDINGS,
        "PARTIAL_RESULTS_WITH_WARNING": EngineExecutionStatus.PARTIAL,
        "TOOL_EXECUTION_FAILED": EngineExecutionStatus.FAILED,
        "BLOCKED": EngineExecutionStatus.BLOCKED,
        "TIMED_OUT": EngineExecutionStatus.TIMED_OUT,
        "CANCELLED": EngineExecutionStatus.CANCELLED,
        "INVALID_VERSION": EngineExecutionStatus.FAILED,
        "FAILED_NON_ZERO_EXIT": EngineExecutionStatus.FAILED,
        "FAILED_TIMEOUT": EngineExecutionStatus.TIMED_OUT,
        "FAILED_OUTPUT_LIMIT": EngineExecutionStatus.FAILED,
        "NOT_EXECUTED_PREREQUISITE_MISSING": EngineExecutionStatus.FAILED,
        "NOT_EXECUTED_UNSUPPORTED_TARGET": EngineExecutionStatus.FAILED,
    }
    for t_name in telemetry_tools:
        normalized_state = recorded_states.get(t_name)
        finding_engine = next(
            (f.engine for f in job.findings if (f.source_tool or "native").lower() == t_name.lower()),
            None,
        )
        exec_status = state_statuses.get(normalized_state, EngineExecutionStatus.FAILED)
        is_success = exec_status in {EngineExecutionStatus.PASS, EngineExecutionStatus.FINDINGS}
        tool_telemetry_map[t_name] = ToolExecutionTelemetry(
            tool_name=t_name,
            correlation_id=job.correlation_id,
            engine=getattr(job, "tool_execution_engines", {}).get(t_name) or finding_engine or "unknown",
            status=exec_status,
            duration_seconds=0.0,
            command_executed=None,
            findings_count=0,
            log_count=0,
            endpoints_tested=[],
            normalized_state=normalized_state,
            output_bytes=0,
            success_count=1 if is_success else 0,
            failure_count=0 if is_success else 1,
        )

    for f in job.findings:
        src = (f.source_tool or "native").lower()
        if src not in tool_telemetry_map:
            tool_telemetry_map[src] = ToolExecutionTelemetry(
                tool_name=src,
                correlation_id=job.correlation_id,
                engine=f.engine or "native",
                status=EngineExecutionStatus.FINDINGS,
                duration_seconds=0.0,
                command_executed=f"{src} active assessment",
                findings_count=0,
                log_count=0,
                endpoints_tested=[],
            )
        tool_telemetry_map[src].findings_count += 1
        # Findings do not erase a degraded execution state. A tool may emit
        # partial output before failing, timing out, or being blocked.
        if tool_telemetry_map[src].status in {
            EngineExecutionStatus.PASS,
            EngineExecutionStatus.FINDINGS,
        } or recorded_states.get(src) is None:
            tool_telemetry_map[src].status = EngineExecutionStatus.FINDINGS
        if f.evidence and f.evidence.location:
            if f.evidence.location not in tool_telemetry_map[src].endpoints_tested:
                tool_telemetry_map[src].endpoints_tested.append(f.evidence.location)

    for l in all_logs:
        msg = l.message.lower()
        for t_name in tool_telemetry_map.keys():
            if t_name in msg or (l.tool and l.tool.lower() == t_name):
                tool_telemetry_map[t_name].log_count += 1

    # Enrich discovered endpoints with per-link dossiers and finding correlations
    enriched_endpoints: List[DiscoveredEndpoint] = []
    for ep in job.discovered_endpoints:
        ep_copy = ep.model_copy(deep=True)
        # Correlate findings matching this endpoint URL
        matching_findings = [
            f for f in job.findings
            if f.evidence and f.evidence.location and (
                ep.url in f.evidence.location or f.evidence.location in ep.url
            )
        ]
        for f in matching_findings:
            if f.id not in ep_copy.finding_ids:
                ep_copy.finding_ids.append(f.id)

        # Do not manufacture tools_executed or tests_performed if none is recorded.
        # An empty execution/test list truthfully indicates no authoritative test execution on this endpoint.
        enriched_endpoints.append(ep_copy)

    tools_executed_list = list(tool_telemetry_map.values())
    coverage_data = getattr(job.summary, "coverage", None)
    if coverage_data is None:
        coverage_data = AssessmentCoverage(
            engines_requested=job.enabled_engines,
            engines_executed=[],
            is_fully_assessed=False,
            coverage_status="COVERAGE_DEGRADED",
            coverage_limitations=["Authoritative coverage data is absent or scan incomplete."],
        )

    return ScanTelemetryReport(
        scan_id=job.id,
        correlation_id=job.correlation_id,
        target_value=job.target.value,
        target_type=job.target.type,
        profile=job.profile,
        status=job.status,
        total_logs=len(all_logs),
        logs=filtered_logs,
        tools_executed=tools_executed_list,
        tool_failure_events=getattr(job, "tool_failure_events", []),
        discovered_endpoints=enriched_endpoints,
        discovered_subdomains=job.discovered_subdomains,
        rejected_discoveries=job.rejected_discoveries,
        coverage=coverage_data,
        generated_at=utc_now(),
    )


@router.post("/{scan_id}/cancel", summary="Cancel Running Scan Job")
async def cancel_running_scan(
    scan_id: str,
    current_user: UserProfile = Depends(require_permission(required_scope="scan:cancel", allowed_roles=[UserRole.ADMIN, UserRole.SECURITY_ANALYST, UserRole.DEVELOPER])),
) -> Dict[str, Any]:
    """Signals orchestrator to abort scan execution and forcefully terminate subprocesses."""
    job = orchestrator.get_active_job(scan_id, organization_id=_organization_scope(current_user))
    if not job:
        raise HTTPException(status_code=404, detail=f"Scan job '{scan_id}' not found.")

    if not authorize_scan_access(current_user, job, action="cancel"):
        raise HTTPException(status_code=403, detail=f"Unauthorized to cancel scan job '{scan_id}'.")

    cancelled = await orchestrator.cancel_scan(scan_id, organization_id=_organization_scope(current_user))

    db_manager.record_audit_event(
        AuditEvent(
            actor=current_user.username,
            organization_id=current_user.organization_id,
            action=AuditAction.SCAN_CANCELLED,
            object_type="scan",
            object_id=scan_id,
            result="SUCCESS",
        )
    )

    return {
        "scan_id": scan_id,
        "status": ScanStatus.CANCELLED.value,
        "cancelled": cancelled,
        "message": "Scan job cancellation processed.",
    }


@router.get("/{scan_id}/events", summary="Stream Real-Time Scan Telemetry via Server-Sent Events (SSE)")
async def stream_scan_events(
    scan_id: str,
    current_user: UserProfile = Depends(require_permission(required_scope="scan:read")),
) -> StreamingResponse:
    """Streams real-time logs, findings, and progress updates over SSE."""
    job = orchestrator.get_active_job(scan_id, organization_id=_organization_scope(current_user))
    if not job:
        raise HTTPException(status_code=404, detail=f"Scan job '{scan_id}' not found.")

    if not authorize_scan_access(current_user, job, action="read"):
        raise HTTPException(status_code=404, detail=f"Scan job '{scan_id}' not found.")

    async def event_generator():
        # Yield initial connected event
        yield f"event: connected\ndata: {json.dumps({'scan_id': scan_id, 'status': job.status.value})}\n\n"

        # If job already completed/failed/cancelled, stream historical events and close
        if job.status in (ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED):
            for log in job.logs:
                yield f"event: log\ndata: {log.model_dump_json()}\n\n"
            for finding in job.findings:
                yield f"event: finding\ndata: {finding.model_dump_json()}\n\n"
            for rejection in job.rejected_discoveries:
                yield f"event: discovery_rejected\ndata: {rejection.model_dump_json()}\n\n"
            if job.status == ScanStatus.COMPLETED:
                yield f"event: completed\ndata: {job.summary.model_dump_json() if job.summary else '{}'}\n\n"
            elif job.status == ScanStatus.FAILED:
                yield f"event: failed\ndata: {json.dumps({'reason': job.failure_reason or 'Scan failed'})}\n\n"
            elif job.status == ScanStatus.CANCELLED:
                yield f"event: cancelled\ndata: {json.dumps({'message': 'Scan cancelled by user'})}\n\n"
            return

        # Stream live events from orchestrator
        queue = orchestrator.subscribe_events(scan_id)
        try:
            # Yield initial snapshot of active scan progress & logs recorded before handshake
            if job.progress_percent > 0 or job.current_stage:
                yield f"event: progress\ndata: {json.dumps({'percent': job.progress_percent, 'stage': job.current_stage, 'status': job.status.value})}\n\n"
            for log in list(job.logs):
                yield f"event: log\ndata: {log.model_dump_json()}\n\n"
            for finding in list(job.findings):
                yield f"event: finding\ndata: {finding.model_dump_json()}\n\n"
            for ep in list(job.discovered_endpoints):
                yield f"event: crawl_discovered\ndata: {ep.model_dump_json()}\n\n"
            for sub in list(job.discovered_subdomains):
                yield f"event: subdomain_discovered\ndata: {sub.model_dump_json()}\n\n"
            for rejection in list(job.rejected_discoveries):
                yield f"event: discovery_rejected\ndata: {rejection.model_dump_json()}\n\n"

            while True:
                msg = await queue.get()
                if isinstance(msg, dict):
                    event_name = msg.get("event", "message")
                    data = msg.get("data", {})
                elif isinstance(msg, (tuple, list)) and len(msg) >= 2:
                    event_name, data = msg[0], msg[1]
                else:
                    event_name, data = "message", msg

                data_str = data if isinstance(data, str) else json.dumps(data)
                yield f"event: {event_name}\ndata: {data_str}\n\n"
                if event_name in ("completed", "failed", "cancelled"):
                    break
        finally:
            orchestrator.unsubscribe_events(scan_id, queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
