"""
Contract 04 §1, §3 & Contract 08 §1:
CyberAssess FastAPI Application Server Entrypoint.
Auto-registers all 5 assessment engines, mounts REST/SSE routers, adds request correlation IDs,
enforces security headers, and derives metadata exclusively from app.core.version.
"""

from __future__ import annotations
import os
import uuid
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlparse
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse

from app.core.version import (
    APP_NAME,
    APP_TITLE,
    APP_VERSION,
    API_VERSION,
    CONTRACT_VERSION,
    RULESET_VERSION,
)
from app.core.orchestrator import orchestrator
from app.core.correlation import set_correlation_id, reset_correlation_id
from app.engines.network.engine import NetworkAssessmentEngine
from app.engines.web_dast.engine import WebDastAssessmentEngine
from app.engines.code_sast.engine import CodeSastAssessmentEngine
from app.engines.infra_iac.engine import InfraIacAssessmentEngine
from app.engines.cicd_audit.engine import CicdAuditAssessmentEngine
from app.api import api_router

logger = logging.getLogger("cyberassess.api")


def register_default_engines() -> None:
    """Registers all 5 core security assessment engines into the global orchestrator."""
    orchestrator.register_engine(NetworkAssessmentEngine())
    orchestrator.register_engine(WebDastAssessmentEngine())
    orchestrator.register_engine(CodeSastAssessmentEngine())
    orchestrator.register_engine(InfraIacAssessmentEngine())
    orchestrator.register_engine(CicdAuditAssessmentEngine())


# Eager registration ensures engines are registered in testing and non-lifespan ASGI runners
register_default_engines()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup & shutdown lifespan hook."""
    register_default_engines()
    if os.getenv("EXECUTION_QUEUE_URL", "").strip() and os.getenv("ENVIRONMENT", "").strip().lower() == "production":
        from app.core.credential_handoff import require_credential_handoff_key

        require_credential_handoff_key()
    yield


def _load_allowed_origins(raw: str | None) -> list[str]:
    """Parse CORS origins and fail closed on wildcard or malformed values."""
    if not raw:
        return [
            "http://localhost:8000",
            "http://127.0.0.1:8000",
            "http://localhost:3000",
            "http://127.0.0.1:3000",
        ]

    origins = [origin.strip() for origin in raw.split(",") if origin.strip()]
    if not origins or "*" in origins:
        raise RuntimeError("ALLOWED_ORIGINS must contain explicit origins; wildcard CORS is forbidden")
    for origin in origins:
        parsed = urlparse(origin)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.path or parsed.params or parsed.query or parsed.fragment:
            raise RuntimeError(f"ALLOWED_ORIGINS contains a malformed origin: {origin!r}")
    return origins


ALLOWED_ORIGINS_ENV = os.getenv("ALLOWED_ORIGINS")
if ALLOWED_ORIGINS_ENV:
    ALLOWED_ORIGINS = _load_allowed_origins(ALLOWED_ORIGINS_ENV)
else:
    # Explicit trusted local frontend origins
    ALLOWED_ORIGINS = _load_allowed_origins(None)

app = FastAPI(
    title=APP_TITLE,
    version=APP_VERSION,
    description=f"Enterprise Automated Security Assessment Platform (Contract v{CONTRACT_VERSION}, Ruleset v{RULESET_VERSION}).",
    lifespan=lifespan,
)


@app.exception_handler(Exception)
async def handle_unexpected_exception(request: Request, exc: Exception) -> JSONResponse:
    """Return a generic production error while retaining correlation-safe logs."""
    correlation_id = getattr(request.state, "correlation_id", "unavailable")
    logger.exception(
        "Unhandled API exception correlation_id=%s method=%s path=%s",
        correlation_id,
        request.method,
        request.url.path,
    )
    return JSONResponse(
        status_code=500,
        content={
            "error_code": "INTERNAL_ERROR",
            "message": "An internal server error occurred.",
            "correlation_id": correlation_id,
        },
        headers={"X-Correlation-ID": correlation_id},
    )


@app.middleware("http")
async def security_headers_and_correlation_middleware(request: Request, call_next):
    """
    Injects unique X-Correlation-ID for end-to-end request tracing and adds strict enterprise security headers.
    """
    correlation_id = request.headers.get("X-Correlation-ID") or f"corr-{uuid.uuid4().hex[:12]}"
    request.state.correlation_id = correlation_id
    correlation_token = set_correlation_id(correlation_id)

    try:
        response: Response = await call_next(request)
    finally:
        reset_correlation_id(correlation_token)

    response.headers["X-Correlation-ID"] = correlation_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com data:; "
        "img-src 'self' data: https:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "object-src 'none'; "
        "base-uri 'self';"
    )

    return response


# CORS Middleware for modern browser SPAs and external API clients
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Accept", "Authorization", "Content-Type", "X-API-Key", "X-Correlation-ID"],
)

# Mount REST & SSE API Routers
app.include_router(api_router)

# Mount Frontend Static Directory (if exists)
frontend_dir = Path(__file__).resolve().parent.parent.parent / "frontend"
if frontend_dir.exists():
    app.mount("/static", StaticFiles(directory=str(frontend_dir)), name="static")

    @app.get("/", include_in_schema=False)
    async def serve_frontend_index():
        index_path = frontend_dir / "index.html"
        if index_path.exists():
            return FileResponse(str(index_path))
        return {"message": f"{APP_NAME} Platform Backend Online (v{APP_VERSION})."}
else:
    @app.get("/", include_in_schema=False)
    async def root():
        return {
            "platform": APP_NAME,
            "version": APP_VERSION,
            "docs": "/docs",
            "api_health": "/api/system/health",
        }
