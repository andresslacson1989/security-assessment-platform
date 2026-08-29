"""
Contract 04 & 08 Scan Lifecycle, Management and Real-Time SSE Streaming Endpoints.
"""

from __future__ import annotations
import asyncio
import json
from pathlib import Path
from typing import Dict, Any, List, Optional
import urllib.parse
from fastapi import APIRouter, HTTPException, Query, status
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

router = APIRouter()


class StartScanRequest(BaseModel):
    target_type: TargetType = Field(..., description="Classification of target asset")
    target_value: str = Field(..., description="Target URI, domain, IP, or filesystem path")
    target_name: Optional[str] = Field(None, description="Friendly display label for the target")
    profile: ScanProfile = Field(default=ScanProfile.FULL_STACK, description="Scanning depth and profile")
    enabled_engines: Optional[List[str]] = Field(None, description="Explicit list of engine names to run")
    config: Optional[ScanConfig] = Field(default_factory=ScanConfig, description="Execution parameters")


def validate_target_input(target_type: TargetType, target_value: str) -> None:
    """
    Validates target value syntax according to target type specifications.
    """
    val = target_value.strip()
    if not val:
        raise HTTPException(status_code=400, detail="Target value cannot be empty.")

    if target_type == TargetType.URL:
        if not (val.startswith("http://") or val.startswith("https://")):
            raise HTTPException(
                status_code=400,
                detail=f"Invalid URL format: '{val}'. Must start with 'http://' or 'https://'."
            )
        parsed = urllib.parse.urlparse(val)
        if not parsed.hostname:
            raise HTTPException(status_code=400, detail=f"Invalid URL hostname in '{val}'.")

    elif target_type in (TargetType.LOCAL_PATH, TargetType.DOCKERFILE, TargetType.IAC_MANIFEST):
        path = Path(val)
        if not path.exists():
            raise HTTPException(
                status_code=400,
                detail=f"Target path does not exist on filesystem: '{val}'."
            )


@router.post("/start", status_code=status.HTTP_201_CREATED, summary="Start Automated Security Scan")
async def start_security_scan(payload: StartScanRequest) -> Dict[str, Any]:
    """
    Validates the target, creates a ScanJob, and launches asynchronous security assessment in the background.
    """
    validate_target_input(payload.target_type, payload.target_value)

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
        "message": "Security assessment scan launched successfully.",
    }


@router.get("/history", summary="List Past Scans")
async def list_scan_history(
    limit: int = Query(default=20, ge=1, le=100, description="Max scans to return"),
    offset: int = Query(default=0, ge=0, description="Pagination offset"),
) -> Dict[str, Any]:
    """
    Returns a paginated list of all past security assessments sorted descending by timestamp.
    """
    scans, total = list_scans(limit=limit, offset=offset)
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "scans": [s.model_dump(mode="json") for s in scans],
    }


@router.get("/{scan_id}", summary="Get Scan Details Snapshot")
async def get_scan_details(scan_id: str) -> Dict[str, Any]:
    """
    Retrieves full details, progress, logs, findings, and score summary for a scan job.
    """
    job = orchestrator.get_active_job(scan_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Scan job '{scan_id}' not found.")
    return job.model_dump(mode="json")


@router.post("/{scan_id}/cancel", summary="Cancel Running Scan")
async def cancel_active_scan(scan_id: str) -> Dict[str, Any]:
    """
    Gracefully halts execution of an active background scan.
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
async def delete_scan_record(scan_id: str) -> Dict[str, Any]:
    """
    Removes a scan record from disk persistence.
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
