"""
Contract 04 §1.3 & Contract 08 §1:
Scan Lifecycle, Execution, Cancellation & Real-Time SSE Streaming Endpoints.
Enforces multi-tenant organization authorization and IDOR protection.
"""

from __future__ import annotations
import asyncio
import json
from pathlib import Path
from typing import Dict, Any, List, Optional
import urllib.parse
from fastapi import APIRouter, HTTPException, Query, status, Depends
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from app.core.models import (
    Target,
    TargetType,
    ScanProfile,
    ScanStatus,
    ScanConfig,
    ScanJob,
    AuditEvent,
    AuditAction,
    utc_now,
)
from app.core.storage import get_scan, list_scans, delete_scan
from app.core.orchestrator import orchestrator
from app.core.ssrf_protector import assert_safe_url, SSRFProtectionError
from app.core.path_sandbox import assert_safe_path, PathSandboxViolation
from app.core.auth import (
    get_current_user,
    require_admin,
    require_dev_or_higher,
    require_permission,
    UserProfile,
    UserRole,
    authorize_scan_access,
)
from app.core.db import db_manager

router = APIRouter()


class StartScanRequest(BaseModel):
    target_type: TargetType = Field(..., description="Classification of target asset")
    target_value: str = Field(..., description="Target URI, domain, IP, or filesystem path")
    target_name: Optional[str] = Field(None, description="Friendly display label for the target")
    profile: ScanProfile = Field(default=ScanProfile.FULL_STACK, description="Scanning depth and profile")
    asset_id: Optional[str] = Field(None, description="Monitored asset UUID")
    project_id: Optional[str] = Field(None, description="Project boundary UUID")
    enabled_engines: Optional[List[str]] = Field(None, description="Explicit list of engine names to run")
    config: Optional[ScanConfig] = Field(default_factory=ScanConfig, description="Execution parameters")


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
    current_user: UserProfile = Depends(require_permission(required_scope="scan:create", allowed_roles=[UserRole.ADMIN, UserRole.SECURITY_ANALYST, UserRole.DEVELOPER])),
) -> Dict[str, Any]:
    """
    Validates the target, creates a ScanJob, and launches asynchronous security assessment in the background.
    Protected by SSRF gateway, path sandboxing, and RBAC multi-tenant authentication.
    """
    allow_internal = (current_user.role == UserRole.ADMIN)
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

    scan_job = ScanJob(
        organization_id=current_user.organization_id,
        target=target,
        profile=payload.profile,
        enabled_engines=selected_engines,
        config=scan_config,
    )

    # Record Audit Events
    db_manager.record_audit_event(
        AuditEvent(
            actor=current_user.username,
            organization_id=current_user.organization_id,
            action=AuditAction.SCAN_CREATED,
            object_type="scan",
            object_id=scan_job.id,
            result="SUCCESS",
            details={"target_type": target.type.value, "target_value": target.value, "profile": scan_job.profile.value},
        )
    )

    # Launch background task
    await orchestrator.start_scan(scan_job)

    db_manager.record_audit_event(
        AuditEvent(
            actor=current_user.username,
            organization_id=current_user.organization_id,
            action=AuditAction.SCAN_STARTED,
            object_type="scan",
            object_id=scan_job.id,
            result="SUCCESS",
        )
    )

    return {
        "scan_id": scan_job.id,
        "status": scan_job.status.value,
        "target": {
            "name": target.name,
            "type": target.type.value,
            "value": target.value,
        },
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
    current_user: UserProfile = Depends(get_current_user),
) -> Dict[str, Any]:
    """Returns paginated list of historical scan summaries for caller's organization."""
    scans, total = list_scans(limit=limit, offset=offset)
    # Filter by user's organization if not super admin
    if current_user.organization_id and current_user.role != UserRole.ADMIN:
        scans = [s for s in scans if getattr(s, "organization_id", None) == current_user.organization_id or getattr(s, "organization_id", None) is None]
        total = len(scans)

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
    current_user: UserProfile = Depends(get_current_user),
) -> ScanJob:
    """Returns full ScanJob model. Enforces tenant ownership (IDOR denial)."""
    job = orchestrator.get_active_job(scan_id) or get_scan(scan_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Scan job '{scan_id}' not found.")

    if not authorize_scan_access(current_user, job, action="read"):
        raise HTTPException(status_code=404, detail=f"Scan job '{scan_id}' not found.")

    return job


@router.post("/{scan_id}/cancel", summary="Cancel Running Scan Job")
async def cancel_running_scan(
    scan_id: str,
    current_user: UserProfile = Depends(require_dev_or_higher),
) -> Dict[str, Any]:
    """Signals orchestrator to abort scan execution and forcefully terminate subprocesses."""
    job = orchestrator.get_active_job(scan_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Scan job '{scan_id}' not found.")

    if not authorize_scan_access(current_user, job, action="cancel"):
        raise HTTPException(status_code=403, detail=f"Unauthorized to cancel scan job '{scan_id}'.")

    cancelled = await orchestrator.cancel_scan(scan_id)

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


@router.delete("/{scan_id}", summary="Delete Scan Job Record")
async def delete_scan_job(
    scan_id: str,
    current_user: UserProfile = Depends(get_current_user),
) -> Dict[str, Any]:
    """Deletes a scan job from storage. Enforces tenant ownership."""
    job = orchestrator.get_active_job(scan_id) or get_scan(scan_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Scan job '{scan_id}' not found.")

    if not authorize_scan_access(current_user, job, action="delete"):
        raise HTTPException(status_code=403, detail=f"Unauthorized to delete scan job '{scan_id}'.")

    deleted = delete_scan(scan_id)
    return {"scan_id": scan_id, "deleted": deleted, "message": "Scan record deleted."}


@router.get("/{scan_id}/events", summary="Stream Real-Time Scan Telemetry via Server-Sent Events (SSE)")
async def stream_scan_events(
    scan_id: str,
    current_user: UserProfile = Depends(get_current_user),
) -> StreamingResponse:
    """Streams real-time logs, findings, and progress updates over SSE."""
    job = orchestrator.get_active_job(scan_id) or get_scan(scan_id)
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
            if job.status == ScanStatus.COMPLETED:
                yield f"event: completed\ndata: {job.summary.model_dump_json() if job.summary else '{}'}\n\n"
            elif job.status == ScanStatus.FAILED:
                yield f"event: failed\ndata: {json.dumps({'reason': job.failure_reason or 'Scan failed'})}\n\n"
            elif job.status == ScanStatus.CANCELLED:
                yield f"event: cancelled\ndata: {json.dumps({'message': 'Scan cancelled by user'})}\n\n"
            return

        # Stream live events from orchestrator
        queue = await orchestrator.subscribe(scan_id)
        try:
            while True:
                event_name, data = await queue.get()
                yield f"event: {event_name}\ndata: {json.dumps(data)}\n\n"
                if event_name in ("completed", "failed", "cancelled"):
                    break
        finally:
            await orchestrator.unsubscribe(scan_id, queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
