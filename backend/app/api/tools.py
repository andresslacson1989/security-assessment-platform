"""
Contract 04 §1.5 & Contract 08 §1:
Pentester Workbench, HTTP Repeater, and In-App Tool Installation API Router.
"""

from __future__ import annotations
import json
import logging
import time
from typing import Optional, List, Tuple
from fastapi import APIRouter, HTTPException, status, Request, Depends
from fastapi.responses import StreamingResponse
import httpx

from app.core.models import (
    RepeaterRequest,
    RepeaterResponse,
    Target,
    TargetType,
    ToolInstallationInfo,
    ToolInstallRequest,
    ToolInstallResponse,
    ToolBatchInstallRequest,
    AuditEvent,
    AuditAction,
    sanitize_sensitive_text,
)
from app.core.version import APP_VERSION
from app.installers.manager import ToolInstallationManager
from app.core.ssrf_protector import (
    assert_safe_url,
    create_validated_target,
    SSRFProtectionError,
    ValidatedTargetTransport,
)
from app.core.auth import require_permission, authorize_internal_target, UserProfile, UserRole
from app.core.db import db_manager

router = APIRouter()
logger = logging.getLogger("cyberassess.api.tools")

REPEATER_MAX_REQUEST_BODY_BYTES = 2 * 1024 * 1024
REPEATER_MAX_RESPONSE_BODY_BYTES = 10 * 1024 * 1024
REPEATER_TRUNCATION_MARKER = b"\n\n[... Response Truncated at 10 MB ...]"


def _extract_tls_metadata(response: httpx.Response) -> Tuple[Optional[str], Optional[str]]:
    """Return observed TLS metadata only; never infer protocol/cipher values."""
    try:
        extensions = getattr(response, "extensions", {}) or {}
        tls_version = extensions.get("tls_version")
        cipher = extensions.get("cipher_suite")
        network_stream = extensions.get("network_stream")
        if network_stream is not None and hasattr(network_stream, "get_extra_info"):
            ssl_object = network_stream.get_extra_info("ssl_object")
            if ssl_object is not None:
                if tls_version is None and hasattr(ssl_object, "version"):
                    tls_version = ssl_object.version()
                if cipher is None and hasattr(ssl_object, "cipher"):
                    cipher_info = ssl_object.cipher()
                    if cipher_info:
                        cipher = cipher_info[0] if isinstance(cipher_info, (tuple, list)) else cipher_info
        return (
            str(tls_version) if tls_version else None,
            str(cipher) if cipher else None,
        )
    except Exception as exc:
        logger.debug("Repeater TLS metadata unavailable: error_type=%s", type(exc).__name__)
        return None, None


async def _read_response_body_bounded(
    response: httpx.Response,
    limit_bytes: int = REPEATER_MAX_RESPONSE_BODY_BYTES,
) -> Tuple[bytes, int, bool]:
    """Stream a response through a hard allocation ceiling.

    Returns captured bytes, bytes observed from the upstream before stopping,
    and whether the body was truncated. The full upstream response is never
    materialized by this helper.
    """
    if limit_bytes <= 0:
        raise ValueError("Response body limit must be positive.")
    captured = bytearray()
    observed = 0
    truncated = False
    async for chunk in response.aiter_bytes():
        if not chunk:
            continue
        observed += len(chunk)
        remaining = limit_bytes - len(captured)
        if remaining > 0:
            captured.extend(chunk[:remaining])
        if len(chunk) > max(remaining, 0) or len(captured) >= limit_bytes and observed > limit_bytes:
            truncated = True
            break
    return bytes(captured), observed, truncated


@router.get("", response_model=List[ToolInstallationInfo], summary="List all tool installation statuses and capabilities")
@router.get("/", response_model=List[ToolInstallationInfo], include_in_schema=False)
async def list_tools(current_user: UserProfile = Depends(require_permission(required_scope="tool:read"))) -> List[ToolInstallationInfo]:
    return await ToolInstallationManager.get_instance().get_all_tools_info()


@router.get("/events", summary="Real-time Tool Installation Telemetry Stream")
async def stream_tool_events(
    request: Request,
    current_user: UserProfile = Depends(require_permission(required_scope="tool:read")),
):
    manager = ToolInstallationManager.get_instance()

    async def event_generator():
        yield f"event: ping\ndata: {json.dumps({'timestamp': time.time()})}\n\n"
        async for payload in manager.subscribe_events(ping_interval=10.0):
            if await request.is_disconnected():
                break
            yield f"event: {payload.get('event', 'message')}\ndata: {json.dumps(payload.get('data', {}))}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive", "X-Accel-Buffering": "no"},
    )


@router.get("/{tool_name}/status", response_model=ToolInstallationInfo, summary="Get installation status for a specific tool")
async def get_tool_status(
    tool_name: str,
    current_user: UserProfile = Depends(require_permission(required_scope="tool:read")),
) -> ToolInstallationInfo:
    info = await ToolInstallationManager.get_instance().get_tool_info(tool_name)
    if not info:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Tool '{tool_name}' is not recognized in the platform registry.")
    return info


@router.post("/{tool_name}/install", response_model=ToolInstallResponse, status_code=status.HTTP_202_ACCEPTED, summary="Trigger in-app installation of a specific tool (Admin Only)")
async def install_tool(
    tool_name: str,
    payload: Optional[ToolInstallRequest] = None,
    current_user: UserProfile = Depends(require_permission(required_scope="tool:install", allowed_roles=[UserRole.ADMIN])),
) -> ToolInstallResponse:
    manager = ToolInstallationManager.get_instance()
    force = payload.force if payload else False
    result = manager.install_tool(tool_name, force=force)
    db_manager.record_audit_event(AuditEvent(
        actor=current_user.username,
        organization_id=current_user.organization_id,
        action=AuditAction.TOOL_INSTALL_STARTED,
        object_type="tool",
        object_id=tool_name,
        result="QUEUED",
        details={"task_id": result.task_id, "force": force},
    ))
    return result


@router.post("/install-all", response_model=List[ToolInstallResponse], status_code=status.HTTP_202_ACCEPTED, summary="Trigger batch in-app installation of all missing user-space tools (Admin Only)")
async def install_all_tools(
    payload: Optional[ToolBatchInstallRequest] = None,
    current_user: UserProfile = Depends(require_permission(required_scope="tool:install", allowed_roles=[UserRole.ADMIN])),
) -> List[ToolInstallResponse]:
    manager = ToolInstallationManager.get_instance()
    force = payload.force if payload else False
    responses = await manager.install_all(force=force)
    for result in responses:
        db_manager.record_audit_event(AuditEvent(
            actor=current_user.username,
            organization_id=current_user.organization_id,
            action=AuditAction.TOOL_INSTALL_STARTED,
            object_type="tool",
            object_id=result.tool_name,
            result="QUEUED",
            details={"task_id": result.task_id, "batch": True},
        ))
    return responses


@router.post("/{tool_name}/cancel", summary="Cancel active in-app tool installation job")
async def cancel_install(
    tool_name: str,
    current_user: UserProfile = Depends(require_permission(required_scope="tool:install", allowed_roles=[UserRole.ADMIN])),
) -> dict:
    cancelled = ToolInstallationManager.get_instance().cancel_installation(tool_name)
    return {
        "tool_name": tool_name,
        "cancelled": cancelled,
        "status": "CANCELLED" if cancelled else "NOT_FOUND",
        "message": f"Installation of '{tool_name}' cancelled." if cancelled else "No active installation task found to cancel.",
    }


@router.post(
    "/repeater",
    response_model=RepeaterResponse,
    summary="Send custom HTTP request via Workbench Repeater",
    description="Dispatches a custom crafted HTTP request with validated-target transport and hard streaming size bounds.",
)
async def execute_http_repeater(
    payload: RepeaterRequest,
    current_user: UserProfile = Depends(require_permission(required_scope="scan:repeater", allowed_roles=[UserRole.ADMIN, UserRole.SECURITY_ANALYST])),
) -> RepeaterResponse:
    allow_internal = authorize_internal_target(current_user, payload.url)
    try:
        assert_safe_url(payload.url, allow_internal=allow_internal)
        validated_target = create_validated_target(
            Target(name="repeater-target", type=TargetType.URL, value=payload.url),
            organization_id=current_user.organization_id,
            allow_internal=allow_internal,
        )
    except SSRFProtectionError as ssrf_err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"SSRF Protection Gate: {str(ssrf_err)}")

    request_body = payload.body.encode("utf-8") if payload.body is not None else None
    if request_body is not None and len(request_body) > REPEATER_MAX_REQUEST_BODY_BYTES:
        raise HTTPException(status_code=400, detail="Repeater request payload exceeds 2 MB limit.")

    headers = dict(payload.headers) if payload.headers else {}
    if "user-agent" not in {key.lower() for key in headers}:
        headers["User-Agent"] = f"CyberAssess-Repeater/{APP_VERSION}"

    async def on_redirect_response(response: httpx.Response):
        if response.is_redirect:
            redirect_target = response.headers.get("location")
            if redirect_target:
                assert_safe_url(str(response.url.join(redirect_target)), allow_internal=allow_internal)

    start_time = time.perf_counter()
    try:
        async with httpx.AsyncClient(
            verify=True,
            trust_env=False,
            transport=ValidatedTargetTransport(validated_target),
            follow_redirects=payload.follow_redirects,
            timeout=payload.timeout_seconds,
            event_hooks={"response": [on_redirect_response]} if payload.follow_redirects else None,
        ) as client:
            async with client.stream(
                method=payload.method.upper(),
                url=payload.url,
                headers=headers,
                content=request_body,
            ) as response:
                captured, observed_bytes, truncated = await _read_response_body_bounded(response)
                duration_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
                tls_version, cipher = _extract_tls_metadata(response)
                encoding = response.encoding or "utf-8"
                body_text = captured.decode(encoding, errors="replace")
                if truncated:
                    body_text += REPEATER_TRUNCATION_MARKER.decode("ascii")
                body_text = sanitize_sensitive_text(body_text)
                safe_headers = {
                    str(name): sanitize_sensitive_text(str(value))
                    for name, value in response.headers.items()
                }
                return RepeaterResponse(
                    status_code=response.status_code,
                    headers=safe_headers,
                    body=body_text,
                    duration_ms=duration_ms,
                    content_length=observed_bytes,
                    tls_version=tls_version,
                    cipher=cipher,
                )

    except SSRFProtectionError as ssrf_err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"SSRF Protection Gate (Redirect Target Blocked): {str(ssrf_err)}")
    except httpx.TimeoutException:
        raise HTTPException(status_code=status.HTTP_504_GATEWAY_TIMEOUT, detail="The repeater request exceeded its configured timeout.")
    except httpx.RequestError:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="The repeater could not complete the outbound request.")
    except Exception as exc:
        logger.exception("Repeater execution failed: %s", type(exc).__name__)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="The repeater request could not be completed.")
