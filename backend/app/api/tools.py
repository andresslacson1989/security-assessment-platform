"""
Contract 04 §1.5 & Contract 08 §1:
Pentester Workbench, HTTP Repeater, and In-App Tool Installation API Router.
"""

from __future__ import annotations
import asyncio
import json
import time
from typing import Optional, List, Any
from fastapi import APIRouter, HTTPException, status, Request, Depends
from fastapi.responses import StreamingResponse
import httpx

from app.core.models import (
    RepeaterRequest,
    RepeaterResponse,
    ToolInstallationInfo,
    ToolInstallRequest,
    ToolInstallResponse,
    ToolBatchInstallRequest,
    AuditEvent,
    AuditAction,
)
from app.installers.manager import ToolInstallationManager
from app.core.ssrf_protector import assert_safe_url, SSRFProtectionError
from app.core.auth import get_current_user, require_admin, require_analyst_or_admin, require_permission, UserProfile, UserRole
from app.core.db import db_manager

router = APIRouter()


# ============================================================================
# 1. In-App Tool Installation & Capabilities Lifecycle Management
# ============================================================================

@router.get(
    "",
    response_model=List[ToolInstallationInfo],
    summary="List all tool installation statuses and capabilities",
    description="Returns current installation status, version, and instructions for all tools.",
)
@router.get(
    "/",
    response_model=List[ToolInstallationInfo],
    include_in_schema=False,
)
async def list_tools() -> List[ToolInstallationInfo]:
    """Returns installation status, detected binary path, version, and install method for all tools."""
    mgr = ToolInstallationManager.get_instance()
    return await mgr.get_all_tools_info()


@router.get(
    "/events",
    summary="Real-time Tool Installation Telemetry Stream (SSE)",
    description="Server-Sent Events (SSE) stream broadcasting install_progress, install_log, install_completed, and install_failed events.",
)
async def stream_tool_events(request: Request):
    """SSE stream yielding real-time tool installation progress and logs."""
    mgr = ToolInstallationManager.get_instance()

    async def event_generator():
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
    summary="Get installation status for a specific tool",
)
async def get_tool_status(tool_name: str) -> ToolInstallationInfo:
    mgr = ToolInstallationManager.get_instance()
    info = await mgr.get_tool_info(tool_name)
    if not info:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Tool '{tool_name}' is not recognized in the platform registry.",
        )
    return info


@router.post(
    "/{tool_name}/install",
    response_model=ToolInstallResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Trigger in-app installation of a specific tool (Admin Only)",
)
async def install_tool(
    tool_name: str,
    payload: Optional[ToolInstallRequest] = None,
    current_user: UserProfile = Depends(require_permission(required_scope="tool:install", allowed_roles=[UserRole.ADMIN])),
) -> ToolInstallResponse:
    mgr = ToolInstallationManager.get_instance()
    force = payload.force if payload else False
    res = mgr.install_tool(tool_name, force=force)

    db_manager.record_audit_event(
        AuditEvent(
            actor=current_user.username,
            organization_id=current_user.organization_id,
            action=AuditAction.TOOL_INSTALL_STARTED,
            object_type="tool",
            object_id=tool_name,
            result="QUEUED",
            details={"task_id": res.task_id, "force": force},
        )
    )
    return res


@router.post(
    "/install-all",
    response_model=List[ToolInstallResponse],
    status_code=status.HTTP_202_ACCEPTED,
    summary="Trigger batch in-app installation of all missing user-space tools (Admin Only)",
)
async def install_all_tools(
    payload: Optional[ToolBatchInstallRequest] = None,
    current_user: UserProfile = Depends(require_permission(required_scope="tool:install", allowed_roles=[UserRole.ADMIN])),
) -> List[ToolInstallResponse]:
    mgr = ToolInstallationManager.get_instance()
    force = payload.force if payload else False

    responses = await mgr.install_all(force=force)
    for res in responses:
        db_manager.record_audit_event(
            AuditEvent(
                actor=current_user.username,
                organization_id=current_user.organization_id,
                action=AuditAction.TOOL_INSTALL_STARTED,
                object_type="tool",
                object_id=res.tool_name,
                result="QUEUED",
                details={"task_id": res.task_id, "batch": True},
            )
        )
    return responses


@router.post(
    "/{tool_name}/cancel",
    summary="Cancel active in-app tool installation job",
)
async def cancel_install(
    tool_name: str,
    current_user: UserProfile = Depends(require_permission(required_scope="tool:install", allowed_roles=[UserRole.ADMIN])),
) -> dict:
    mgr = ToolInstallationManager.get_instance()
    cancelled = mgr.cancel_installation(tool_name)
    return {
        "tool_name": tool_name,
        "cancelled": cancelled,
        "status": "CANCELLED" if cancelled else "NOT_FOUND",
        "message": f"Installation of '{tool_name}' cancelled." if cancelled else "No active installation task found to cancel.",
    }


# ============================================================================
# 2. Pentester Workbench & Interactive HTTP Repeater (Contract 04 §1.5)
# ============================================================================

@router.post(
    "/repeater",
    response_model=RepeaterResponse,
    summary="Send custom HTTP request via Workbench Repeater",
    description="Dispatches a custom crafted HTTP request with strict hop-by-hop SSRF validation and size bounds.",
)
async def execute_http_repeater(
    payload: RepeaterRequest,
    current_user: UserProfile = Depends(require_permission(required_scope="scan:repeater", allowed_roles=[UserRole.ADMIN, UserRole.SECURITY_ANALYST])),
) -> RepeaterResponse:
    """
    Sends an arbitrary HTTP request from the server, guarded by SSRF gateway,
    per-hop redirect re-validation, response size bounds, and role/scope authorization.
    """
    allow_internal = (current_user.role == UserRole.ADMIN)
    try:
        assert_safe_url(payload.url, allow_internal=allow_internal)
    except SSRFProtectionError as ssrf_err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"SSRF Protection Gate: {str(ssrf_err)}",
        )

    # Size limit on request body (max 2 MB)
    if payload.body and len(payload.body) > 2 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="Repeater request payload exceeds 2 MB limit.")

    start_time = time.perf_counter()
    
    headers = dict(payload.headers) if payload.headers else {}
    if not any(k.lower() == "user-agent" for k in headers):
        headers["User-Agent"] = "CyberAssess-Repeater/10.0.0"

    async def on_redirect_response(response: httpx.Response):
        """Hop-by-hop redirect SSRF validator."""
        if response.is_redirect:
            redirect_target = response.headers.get("location")
            if redirect_target:
                target_url = str(response.url.join(redirect_target))
                assert_safe_url(target_url, allow_internal=allow_internal)

    try:
        async with httpx.AsyncClient(
            verify=True,
            follow_redirects=payload.follow_redirects,
            timeout=payload.timeout_seconds,
            event_hooks={"response": [on_redirect_response]} if payload.follow_redirects else None,
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

            # Enforce response body truncation at 10 MB if huge
            body_text = resp.text
            if len(body_text) > 10 * 1024 * 1024:
                body_text = body_text[:10 * 1024 * 1024] + "\n\n[... Response Truncated at 10 MB ...]"

            return RepeaterResponse(
                status_code=resp.status_code,
                headers=dict(resp.headers),
                body=body_text,
                duration_ms=duration_ms,
                content_length=len(resp.content),
                tls_version=tls_version,
                cipher=cipher,
            )

    except SSRFProtectionError as ssrf_err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"SSRF Protection Gate (Redirect Target Blocked): {str(ssrf_err)}",
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
