"""
Contract 04 & 08 Scan Lifecycle, Management and Real-Time SSE Streaming Endpoints.
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
)
from app.core.storage import get_scan, list_scans, delete_scan
from app.core.orchestrator import orchestrator
from app.core.ssrf_protector import assert_safe_url, SSRFProtectionError
from app.core.path_sandbox import assert_safe_path, PathSandboxViolation
from app.core.auth import get_current_user, require_admin, require_dev_or_higher, UserProfile, UserRole

router = APIRouter()


class StartScanRequest(BaseModel):
    target_type: TargetType = Field(..., description="Classification of target asset")
    target_value: str = Field(..., description="Target URI, domain, IP, or filesystem path")
    target_name: Optional[str] = Field(None, description="Friendly display label for the target")
    profile: ScanProfile = Field(default=ScanProfile.FULL_STACK, description="Scanning depth and profile")
    enabled_engines: Optional[List[str]] = Field(None, description="Explicit list of engine names to run")
    config: Optional[ScanConfig] = Field(default_factory=ScanConfig, description="Execution parameters")


def validate_target_input(target_type: TargetType, target_value: str, allow_internal: bool = False) -> None:
    """
    Validates target value syntax and security constraints according to target type specifications.
    Enforces SSRF gateway validation on URLs and workspace containment sandboxing on filesystem paths.
    """
    val = target_value.strip()
    if not val:
        raise HTTPException(status_code=400, detail="Target value cannot be empty.")

    if target_type == TargetType.URL:
        try:
            assert_safe_url(val, allow_internal=allow_internal)
        except SSRFProtectionError as err:
            raise HTTPException(
                status_code=400,
                detail=f"SSRF Protection Gate: {str(err)}"
            )

    elif target_type in (TargetType.LOCAL_PATH, TargetType.DOCKERFILE, TargetType.IAC_MANIFEST):
        try:
            assert_safe_path(val)
        except PathSandboxViolation as err:
            raise HTTPException(
                status_code=400,
                detail=f"Path Sandbox Violation: {str(err)}"
            )


@router.post("/start", status_code=status.HTTP_201_CREATED, summary="Start Automated Security Scan")
async def start_security_scan(
    payload: StartScanRequest,
    current_user: UserProfile = Depends(require_dev_or_higher),
) -> Dict[str, Any]:
    """
    Validates the target, creates a ScanJob, and launches asynchronous security assessment in the background.
    Protected by SSRF gateway, path sandboxing, and RBAC authentication.
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
        # Default to all registered engines applicable to this target type
        selected_engines = [
            eng.name for eng in orchestrator.get_registered_engines()
            if eng.is_applicable(target)
        ]

    scan_config = payload.config or ScanConfig()

    scan_job = ScanJob(
        target=target,
        profile=payload.profile,
        enabled_engines=selected_engines,
        config=scan_config,
    )

    # Launch background task
    await orchestrator.start_scan(scan_job)

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


@router.get("", summary="List All Stored Scan Jobs")
@router.get("/", summary="List All Stored Scan Jobs", include_in_schema=False)
@router.get("/history", summary="List All Stored Scan Jobs (History Alias)")
async def get_all_scans(
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    current_user: UserProfile = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Returns paginated list of historical scan summaries.
    """
    scans, total = list_scans(limit=limit, offset=offset)
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
    """
    Returns full ScanJob model including findings, endpoints, and summary.
    """
    job = orchestrator.get_active_job(scan_id)
    if job:
        return job

    stored_job = get_scan(scan_id)
    if stored_job:
        return stored_job

    raise HTTPException(status_code=404, detail=f"Scan job '{scan_id}' not found.")


@router.post("/{scan_id}/cancel", summary="Cancel Running Scan Job")
async def cancel_running_scan(
    scan_id: str,
    current_user: UserProfile = Depends(require_dev_or_higher),
) -> Dict[str, Any]:
    """
    Signals orchestrator to abort scan execution and terminate subprocesses.
    """
    job = orchestrator.get_active_job(scan_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Scan job '{scan_id}' not found.")

    cancelled = await orchestrator.cancel_scan(scan_id)
    return {
        "scan_id": scan_id,
        "status": ScanStatus.CANCELLED.value,
        "cancelled": cancelled,
        "message": "Scan job cancellation processed.",
    }


@router.delete("/{scan_id}", summary="Delete Scan Record")
async def delete_scan_record(
    scan_id: str,
    current_user: UserProfile = Depends(require_admin),
) -> Dict[str, Any]:
    """
    Removes a scan record from persistence (Restricted to ADMIN).
    """
    success = delete_scan(scan_id)
    if not success:
        raise HTTPException(status_code=404, detail=f"Scan record '{scan_id}' not found.")
    return {
        "scan_id": scan_id,
        "deleted": True,
        "message": "Scan record deleted successfully.",
    }


@router.get("/{scan_id}/events", summary="Real-Time Server-Sent Events (SSE) Stream")
async def stream_scan_events(scan_id: str):
    """
    Establishes an HTTP Server-Sent Events (SSE) streaming connection to deliver live telemetry.
    """
    job = orchestrator.get_active_job(scan_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Scan job '{scan_id}' not found.")

    queue = orchestrator.subscribe_events(scan_id)

    async def event_generator():
        try:
            # Yield initial snapshot if job already exists
            current_job = orchestrator.get_active_job(scan_id)
            if current_job:
                initial_progress = {
                    "percent": current_job.progress_percent,
                    "stage": current_job.current_stage or "Initializing...",
                    "status": current_job.status.value,
                }
                yield f"event: progress\ndata: {json.dumps(initial_progress)}\n\n"

                # If job was already completed before SSE connection was opened
                if current_job.status in (ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED):
                    if current_job.summary:
                        yield f"event: completed\ndata: {json.dumps(current_job.summary.model_dump(mode='json'))}\n\n"
                    return

            while True:
                try:
                    msg = await asyncio.wait_for(queue.get(), timeout=15.0)
                    evt_type = msg.get("event", "message")
                    data_obj = msg.get("data", {})
                    data_str = json.dumps(data_obj) if isinstance(data_obj, (dict, list)) else str(data_obj)
                    yield f"event: {evt_type}\ndata: {data_str}\n\n"

                    # Close SSE stream upon terminal event
                    if evt_type in ("completed", "error") or (
                        evt_type == "progress" and data_obj.get("status") in ("COMPLETED", "FAILED", "CANCELLED")
                    ):
                        break

                except asyncio.TimeoutError:
                    # 15s Keepalive ping to prevent proxy/browser timeout
                    yield ": ping\n\n"

        except asyncio.CancelledError:
            pass
        finally:
            orchestrator.unsubscribe_events(scan_id, queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream; charset=utf-8",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
