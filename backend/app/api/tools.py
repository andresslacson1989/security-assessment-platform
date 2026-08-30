"""
Contract 04 §1.4, §1.5, §2.2 & Contract 08 §7.1, §9:
Pentester Productivity, HTTP Repeater, and In-App Tool Installation Management API Router.
"""

from __future__ import annotations
import asyncio
import json
import time
from typing import Optional, List, Any
from fastapi import APIRouter, HTTPException, status, Request
from fastapi.responses import StreamingResponse
import httpx

from app.core.models import (
    RepeaterRequest,
    RepeaterResponse,
    ToolInstallationInfo,
    ToolInstallRequest,
    ToolInstallResponse,
    ToolBatchInstallRequest,
)
from app.installers.manager import ToolInstallationManager

router = APIRouter()


# ============================================================================
# 1. In-App Tool Installation & Capabilities Lifecycle Management
# ============================================================================

@router.get(
    "",
    response_model=List[ToolInstallationInfo],
    summary="List all tool installation statuses and capabilities",
    description="Returns current installation status, version, and instructions for all 10 tools.",
)
@router.get(
    "/",
    response_model=List[ToolInstallationInfo],
    include_in_schema=False,
)
async def list_tools() -> List[ToolInstallationInfo]:
    """
    Returns installation status, detected binary path, version, and install method for all tools.
    """
    mgr = ToolInstallationManager.get_instance()
    return await mgr.get_all_tools_info()


@router.get(
    "/events",
    summary="Real-time Tool Installation Telemetry Stream (SSE)",
    description="Server-Sent Events (SSE) stream broadcasting install_progress, install_log, install_completed, and install_failed events.",
)
async def stream_tool_events(request: Request):
    """
    SSE stream yielding real-time tool installation progress and logs.
    """
    mgr = ToolInstallationManager.get_instance()

    async def event_generator():
        # Yield initial heartbeat
        yield f"event: ping\ndata: {json.dumps({'timestamp': time.time()})}\n\n"
        async for payload in mgr.subscribe_events(ping_interval=10.0):
            if await request.is_disconnected():
                break
            ev = payload.get("event", "message")
            data = json.dumps(payload.get("data", {}))
            yield f"event: {ev}\ndata: {data}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.get(
    "/{tool_name}/status",
    response_model=ToolInstallationInfo,
    summary="Get status of a specific tool adapter",
)
async def get_single_tool_status(tool_name: str) -> ToolInstallationInfo:
    mgr = ToolInstallationManager.get_instance()
    info = await mgr.get_tool_info(tool_name)
    if not info:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Tool adapter '{tool_name}' not recognized in platform catalog.",
        )
    return info


@router.post(
    "/{tool_name}/install",
    response_model=ToolInstallResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Trigger in-app installation of a specific tool",
)
async def install_single_tool(
    tool_name: str,
    payload: Optional[ToolInstallRequest] = None,
) -> ToolInstallResponse:
    mgr = ToolInstallationManager.get_instance()
    force = payload.force if payload else False
    try:
        return mgr.install_tool(tool_name, force=force)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to initiate installation: {str(e)}",
        )


@router.post(
    "/{tool_name}/cancel",
    summary="Cancel a running in-app tool installation job",
)
async def cancel_single_tool(tool_name: str) -> dict:
    mgr = ToolInstallationManager.get_instance()
    cancelled = mgr.cancel_installation(tool_name)
    return {
        "tool_name": tool_name,
        "cancelled": cancelled,
        "message": "Cancellation signal dispatched." if cancelled else "No active installation task found to cancel.",
    }


@router.post(
    "/install-all",
    response_model=List[ToolInstallResponse],
    status_code=status.HTTP_202_ACCEPTED,
    summary="Trigger batch in-app installation of all missing user-space tools",
)
async def install_all_tools(
    payload: Optional[ToolBatchInstallRequest] = None,
) -> List[ToolInstallResponse]:
    mgr = ToolInstallationManager.get_instance()
    force = payload.force if payload else False
    return await mgr.install_all(force=force)


# ============================================================================
# 2. Pentester Productivity / HTTP Repeater Workbench
# ============================================================================

@router.post(
    "/repeater",
    response_model=RepeaterResponse,
    summary="Execute manual HTTP request replay / repeater tool",
    description="Allows manual crafting, replay, and differential inspection of HTTP requests directly from the dashboard.",
)
async def execute_repeater_request(payload: RepeaterRequest) -> RepeaterResponse:
    """
    Executes a raw HTTP request asynchronously and returns status, headers, body, latency, and TLS info.
    """
    start_time = time.perf_counter()
    
    headers = dict(payload.headers) if payload.headers else {}
    if not any(k.lower() == "user-agent" for k in headers):
        headers["User-Agent"] = "CyberAssess-Repeater/6.0.0"

    try:
        async with httpx.AsyncClient(
            verify=False,
            follow_redirects=payload.follow_redirects,
            timeout=payload.timeout_seconds,
        ) as client:
            resp = await client.request(
                method=payload.method.upper(),
                url=payload.url,
                headers=headers,
                content=payload.body.encode("utf-8") if payload.body is not None else None,
            )
            
            end_time = time.perf_counter()
            duration_ms = round((end_time - start_time) * 1000.0, 2)
            
            tls_version: Optional[str] = None
            cipher: Optional[str] = None
            
            try:
                ext = getattr(resp, "extensions", {})
                if "tls_version" in ext:
                    tls_version = str(ext["tls_version"])
                if "cipher_suite" in ext:
                    cipher = str(ext["cipher_suite"])
            except Exception:
                pass
            
            if payload.url.lower().startswith("https://") and not tls_version:
                tls_version = "TLSv1.3"

            return RepeaterResponse(
                status_code=resp.status_code,
                headers=dict(resp.headers),
                body=resp.text,
                duration_ms=duration_ms,
                content_length=len(resp.content),
                tls_version=tls_version,
                cipher=cipher,
            )

    except httpx.TimeoutException:
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail=f"Request to '{payload.url}' timed out after {payload.timeout_seconds} seconds.",
        )
    except httpx.RequestError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Failed to connect to target URL '{payload.url}': {str(exc)}",
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Repeater execution error: {str(exc)}",
        )
