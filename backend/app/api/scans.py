"""
Contract 04 §1.3 & Contract 08 §1:
Scan Lifecycle, Execution, Cancellation & Real-Time SSE Streaming Endpoints.
Enforces multi-tenant organization authorization and IDOR protection.
"""

from __future__ import annotations
import json
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, HTTPException, Query, status, Depends, Request
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
    PrincipalType,
)
from app.core.storage import list_scans, delete_scan
from app.core.orchestrator import orchestrator
from app.core.ssrf_protector import SSRFProtectionError
from app.core.path_sandbox import assert_safe_path, PathSandboxViolation, get_default_workspace_dir
from app.core.auth import (
    require_permission,
    UserProfile,
    UserRole,
    authorize_scan_access,
    authorize_internal_target,
)
from app.core.db import db_manager

router = APIRouter()


def _organization_scope(user: UserProfile) -> Optional[str]:
    if user.principal_type == PrincipalType.SYSTEM_PRINCIPAL and user.role == UserRole.ADMIN:
        return None
    return user.organization_id


class StartScanRequest(BaseModel):
    target_type: TargetType = Field(..., description="Classification of target asset")
    target_value: str = Field(..., description="Target URI, domain, IP, filesystem path, cloud account, or Kubernetes cluster")
    target_name: Optional[str] = Field(None, description="Friendly display label for the target")
    profile: ScanProfile = Field(default=ScanProfile.FULL_STACK, description="Scanning depth and profile")
    asset_id: Optional[str] = Field(None, description="Monitored asset UUID")
    project_id: Optional[str] = Field(None, description="Project boundary UUID")
    enabled_engines: Optional[List[str]] = Field(None, description="Explicit list of engine names to run")
    config: Optional[ScanConfig] = Field(default_factory=ScanConfig, description="Execution parameters")


def validate_target_input(target_type: TargetType, target_value: str, allow_internal: bool = False) -> None:
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
        raise HTTPException(status_code=400, detail=f"SSRF Protection Gate: {str(err)}")
    except PathSandboxViolation as err:
        raise HTTPException(status_code=400, detail=f"Path Sandbox Violation: {str(err)}")


@router.post("/start", status_code=status.HTTP_201_CREATED, summary="Start Automated Security Scan")
async def start_security_scan(
    payload: StartScanRequest,
    request: Request,
    current_user: UserProfile = Depends(require_permission(required_scope="scan:create", allowed_roles=[UserRole.ADMIN, UserRole.SECURITY_ANALYST, UserRole.DEVELOPER])),
) -> Dict[str, Any]:
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

    validate_target_input(payload.target_type, payload.target_value, allow_internal=allow_internal)
    target = Target(name=payload.target_name or payload.target_value, type=payload.target_type, value=payload.target_value.strip())
    selected_engines = payload.enabled_engines or [
        eng.name for eng in orchestrator.get_registered_engines() if eng.is_applicable(target)
    ]
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
        config=payload.config or ScanConfig(),
    )

    db_manager.record_audit_event(AuditEvent(
        actor=current_user.username,
        organization_id=current_user.organization_id,
        action=AuditAction.SCAN_CREATED,
        object_type="scan",
        object_id=scan_job.id,
        result="SUCCESS",
        correlation_id=scan_job.correlation_id,
        details={"target_type": target.type.value, "target_value": target.value, "profile": scan_job.profile.value},
    ))
    await orchestrator.start_scan(scan_job)
    db_manager.record_audit_event(AuditEvent(
        actor=current_user.username,
        organization_id=current_user.organization_id,
        action=AuditAction.SCAN_STARTED,
        object_type="scan",
        object_id=scan_job.id,
        result="SUCCESS",
        correlation_id=scan_job.correlation_id,
    ))
    return {
        "scan_id": scan_job.id,
        "status": scan_job.status.value,
        "target": {"name": target.name, "type": target.type.value, "value": target.value},
        "profile": scan_job.profile.value,
        "enabled_engines": scan_job.enabled_engines,
        "active_adapters": scan_job.active_adapters,
        "created_at": scan_job.started_at.isoformat() if scan_job.started_at else None,
    }


@router.get("", summary="List Stored Scan Jobs for Tenant")
@router.get("/", summary="List Stored Scan Jobs for Tenant", include_in_schema=False)
@router.get("/history", summary="List Stored Scan Jobs (History Alias)")
async def get_all_scans(
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    current_user: UserProfile = Depends(require_permission(required_scope="scan:read")),
) -> Dict[str, Any]:
    scans, total = list_scans(limit=limit, offset=offset, organization_id=_organization_scope(current_user))
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "items": [
            {
                "id": s.id,
                "target": {"name": s.target.name, "type": s.target.type.value, "value": s.target.value},
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
    job = orchestrator.get_active_job(scan_id, organization_id=_organization_scope(current_user))
    if not job or not authorize_scan_access(current_user, job, action="read"):
        raise HTTPException(status_code=404, detail=f"Scan job '{scan_id}' not found.")
    return job


def _tool_telemetry_from_authoritative_evidence(job: ScanJob) -> Dict[str, ToolExecutionTelemetry]:
    """Build tool telemetry without manufacturing execution evidence."""
    recorded_states = dict(getattr(job, "tool_execution_states", {}) or {})
    state_statuses = {
        "COMPLETED_NO_FINDINGS": EngineExecutionStatus.PASS,
        "COMPLETED_WITH_FINDINGS": EngineExecutionStatus.FINDINGS,
        "PARTIAL_RESULTS_WITH_WARNING": EngineExecutionStatus.PARTIAL,
        "TOOL_EXECUTION_FAILED": EngineExecutionStatus.FAILED,
        "BLOCKED": EngineExecutionStatus.BLOCKED,
        "TIMED_OUT": EngineExecutionStatus.TIMED_OUT,
        "CANCELLED": EngineExecutionStatus.CANCELLED,
        "INVALID_VERSION": EngineExecutionStatus.FAILED,
    }
    tool_names = list(dict.fromkeys([
        *recorded_states.keys(),
        *((finding.source_tool or "native").lower() for finding in job.findings),
    ]))
    result: Dict[str, ToolExecutionTelemetry] = {}
    for tool_name in tool_names:
        normalized_state = recorded_states.get(tool_name)
        finding_engine = next(
            (finding.engine for finding in job.findings if (finding.source_tool or "native").lower() == tool_name),
            None,
        )
        # A finding is affirmative execution evidence. In its absence, only a
        # recorded state can establish that the tool ran.
        has_finding = any((finding.source_tool or "native").lower() == tool_name for finding in job.findings)
        status_value = state_statuses.get(normalized_state)
        if status_value is None:
            status_value = EngineExecutionStatus.FINDINGS if has_finding else EngineExecutionStatus.FAILED
        result[tool_name] = ToolExecutionTelemetry(
            tool_name=tool_name,
            correlation_id=job.correlation_id,
            engine=getattr(job, "tool_execution_engines", {}).get(tool_name) or finding_engine or "unknown",
            status=status_value,
            duration_seconds=0.0,
            command_executed=None,
            findings_count=0,
            log_count=0,
            endpoints_tested=[],
            normalized_state=normalized_state,
        )

    for finding in job.findings:
        source = (finding.source_tool or "native").lower()
        telemetry = result[source]
        telemetry.findings_count += 1
        if telemetry.status in {EngineExecutionStatus.PASS, EngineExecutionStatus.FINDINGS} and recorded_states.get(source) is None:
            telemetry.status = EngineExecutionStatus.FINDINGS
        if finding.evidence and finding.evidence.location and finding.evidence.location not in telemetry.endpoints_tested:
            telemetry.endpoints_tested.append(finding.evidence.location)

    for log in job.logs:
        message = log.message.lower()
        for tool_name, telemetry in result.items():
            if tool_name in message or (log.tool and log.tool.lower() == tool_name):
                telemetry.log_count += 1
    return result


@router.get("/{scan_id}/telemetry", response_model=ScanTelemetryReport, summary="Get Structured Assessment Telemetry & Tool Logs")
async def get_scan_telemetry(
    scan_id: str,
    tool: Optional[str] = Query(default=None, description="Filter logs by tool name (e.g. nmap, nuclei, katana)"),
    engine: Optional[str] = Query(default=None, description="Filter logs by engine name (e.g. network, web_dast, code_sast)"),
    level: Optional[str] = Query(default=None, description="Filter logs by level (INFO, WARNING, ERROR, DEBUG)"),
    search: Optional[str] = Query(default=None, description="Search term in log messages or URLs"),
    current_user: UserProfile = Depends(require_permission(required_scope="scan:read")),
) -> ScanTelemetryReport:
    job = orchestrator.get_active_job(scan_id, organization_id=_organization_scope(current_user))
    if not job or not authorize_scan_access(current_user, job, action="read"):
        raise HTTPException(status_code=404, detail=f"Scan job '{scan_id}' not found.")

    all_logs = list(job.logs)
    filtered_logs = all_logs
    if tool:
        tool_lower = tool.strip().lower()
        filtered_logs = [log for log in filtered_logs if (log.tool and log.tool.lower() == tool_lower) or tool_lower in log.message.lower()]
    if engine:
        engine_lower = engine.strip().lower()
        filtered_logs = [log for log in filtered_logs if log.engine and log.engine.lower() == engine_lower]
    if level:
        level_upper = level.strip().upper()
        filtered_logs = [log for log in filtered_logs if (log.level.value if hasattr(log.level, "value") else str(log.level)).upper() == level_upper]
    if search:
        search_term = search.strip().lower()
        filtered_logs = [
            log for log in filtered_logs
            if search_term in log.message.lower()
            or (log.engine and search_term in log.engine.lower())
            or (log.tool and search_term in log.tool.lower())
        ]

    tool_telemetry_map = _tool_telemetry_from_authoritative_evidence(job)

    # Endpoint presentation is allowed to correlate existing findings, but it
    # must not add tools or tests that the engine did not record as executed.
    enriched_endpoints: List[DiscoveredEndpoint] = []
    for endpoint in job.discovered_endpoints:
        endpoint_copy = endpoint.model_copy(deep=True)
        for finding in job.findings:
            if finding.evidence and finding.evidence.location and (
                endpoint.url in finding.evidence.location or finding.evidence.location in endpoint.url
            ) and finding.id not in endpoint_copy.finding_ids:
                endpoint_copy.finding_ids.append(finding.id)
        enriched_endpoints.append(endpoint_copy)

    coverage = getattr(job.summary, "coverage", None)
    if coverage is None:
        coverage = AssessmentCoverage(
            engines_requested=list(job.enabled_engines),
            engines_executed=[],
            coverage_limitations=["Authoritative coverage evidence is unavailable for this scan."],
            is_fully_assessed=False,
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
        tools_executed=list(tool_telemetry_map.values()),
        tool_failure_events=getattr(job, "tool_failure_events", []),
        discovered_endpoints=enriched_endpoints,
        discovered_subdomains=job.discovered_subdomains,
        rejected_discoveries=job.rejected_discoveries,
        coverage=coverage,
        generated_at=utc_now(),
    )


@router.post("/{scan_id}/cancel", summary="Cancel Running Scan Job")
async def cancel_running_scan(
    scan_id: str,
    current_user: UserProfile = Depends(require_permission(required_scope="scan:cancel", allowed_roles=[UserRole.ADMIN, UserRole.SECURITY_ANALYST, UserRole.DEVELOPER])),
) -> Dict[str, Any]:
    job = orchestrator.get_active_job(scan_id, organization_id=_organization_scope(current_user))
    if not job:
        raise HTTPException(status_code=404, detail=f"Scan job '{scan_id}' not found.")
    if not authorize_scan_access(current_user, job, action="cancel"):
        raise HTTPException(status_code=403, detail=f"Unauthorized to cancel scan job '{scan_id}'.")

    cancelled = await orchestrator.cancel_scan(scan_id)
    db_manager.record_audit_event(AuditEvent(
        actor=current_user.username,
        organization_id=current_user.organization_id,
        action=AuditAction.SCAN_CANCELLED,
        object_type="scan",
        object_id=scan_id,
        result="SUCCESS",
    ))
    return {
        "scan_id": scan_id,
        "status": ScanStatus.CANCELLED.value,
        "cancelled": cancelled,
        "message": "Scan job cancellation processed.",
    }


@router.delete("/{scan_id}", summary="Delete Scan Job Record")
async def delete_scan_job(
    scan_id: str,
    current_user: UserProfile = Depends(require_permission(required_scope="scan:delete")),
) -> Dict[str, Any]:
    job = orchestrator.get_active_job(scan_id, organization_id=_organization_scope(current_user))
    if not job:
        raise HTTPException(status_code=404, detail=f"Scan job '{scan_id}' not found.")
    if not authorize_scan_access(current_user, job, action="delete"):
        raise HTTPException(status_code=403, detail=f"Unauthorized to delete scan job '{scan_id}'.")
    deleted = delete_scan(scan_id, organization_id=_organization_scope(current_user))
    return {"scan_id": scan_id, "deleted": deleted, "message": "Scan record deleted."}


@router.get("/{scan_id}/events", summary="Stream Real-Time Scan Telemetry via Server-Sent Events (SSE)")
async def stream_scan_events(
    scan_id: str,
    current_user: UserProfile = Depends(require_permission(required_scope="scan:read")),
) -> StreamingResponse:
    job = orchestrator.get_active_job(scan_id, organization_id=_organization_scope(current_user))
    if not job or not authorize_scan_access(current_user, job, action="read"):
        raise HTTPException(status_code=404, detail=f"Scan job '{scan_id}' not found.")

    async def event_generator():
        yield f"event: connected\ndata: {json.dumps({'scan_id': scan_id, 'status': job.status.value})}\n\n"
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
            else:
                yield f"event: cancelled\ndata: {json.dumps({'message': 'Scan cancelled by user'})}\n\n"
            return

        queue = orchestrator.subscribe_events(scan_id)
        try:
            if job.progress_percent > 0 or job.current_stage:
                yield f"event: progress\ndata: {json.dumps({'percent': job.progress_percent, 'stage': job.current_stage, 'status': job.status.value})}\n\n"
            for log in list(job.logs):
                yield f"event: log\ndata: {log.model_dump_json()}\n\n"
            for finding in list(job.findings):
                yield f"event: finding\ndata: {finding.model_dump_json()}\n\n"
            for endpoint in list(job.discovered_endpoints):
                yield f"event: crawl_discovered\ndata: {endpoint.model_dump_json()}\n\n"
            for subdomain in list(job.discovered_subdomains):
                yield f"event: subdomain_discovered\ndata: {subdomain.model_dump_json()}\n\n"
            for rejection in list(job.rejected_discoveries):
                yield f"event: discovery_rejected\ndata: {rejection.model_dump_json()}\n\n"

            while True:
                message = await queue.get()
                if isinstance(message, dict):
                    event_name = message.get("event", "message")
                    data = message.get("data", {})
                elif isinstance(message, (tuple, list)) and len(message) >= 2:
                    event_name, data = message[0], message[1]
                else:
                    event_name, data = "message", message
                data_str = data if isinstance(data, str) else json.dumps(data)
                yield f"event: {event_name}\ndata: {data_str}\n\n"
                if event_name in ("completed", "failed", "cancelled"):
                    break
        finally:
            orchestrator.unsubscribe_events(scan_id, queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive", "X-Accel-Buffering": "no"},
    )
