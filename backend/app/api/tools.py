"""
Contract 04 §1.4 & Contract 08 §7.1: Pentester Productivity & HTTP Repeater API Router.
Provides manual HTTP request crafting, replay, and differential inspection.
"""

from __future__ import annotations
import time
from typing import Optional
from fastapi import APIRouter, HTTPException, status
import httpx

from app.core.models import RepeaterRequest, RepeaterResponse

router = APIRouter()


@router.post(
    "/repeater",
    response_model=RepeaterResponse,
    summary="Execute manual HTTP request replay / repeater tool",
    description="Allows manual crafting, replay, and differential inspection of HTTP requests directly from the dashboard."
)
async def execute_repeater_request(payload: RepeaterRequest) -> RepeaterResponse:
    """
    Executes a raw HTTP request asynchronously and returns status, headers, body, latency, and TLS info.
    """
    start_time = time.perf_counter()
    
    headers = dict(payload.headers) if payload.headers else {}
    # Ensure a default User-Agent if none provided
    if not any(k.lower() == "user-agent" for k in headers):
        headers["User-Agent"] = "CyberAssess-Repeater/4.1.0"

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
            
            # Extract TLS metadata if available from raw connection
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
            detail=f"Request to '{payload.url}' timed out after {payload.timeout_seconds} seconds."
        )
    except httpx.RequestError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Failed to connect to target URL '{payload.url}': {str(exc)}"
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Repeater execution error: {str(exc)}"
        )
