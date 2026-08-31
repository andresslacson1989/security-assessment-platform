"""
Contract 04 & 08 FastAPI Application Server Entrypoint.
Auto-registers all 5 assessment engines and serves REST API, SSE streaming, and frontend static assets.
"""

from __future__ import annotations
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from app.core.orchestrator import orchestrator
from app.engines.network.engine import NetworkAssessmentEngine
from app.engines.web_dast.engine import WebDastAssessmentEngine
from app.engines.code_sast.engine import CodeSastAssessmentEngine
from app.engines.infra_iac.engine import InfraIacAssessmentEngine
from app.engines.cicd_audit.engine import CicdAuditAssessmentEngine
from app.api import api_router


def register_default_engines() -> None:
    """
    Registers all 5 core security assessment engines into the global orchestrator.
    """
    orchestrator.register_engine(NetworkAssessmentEngine())
    orchestrator.register_engine(WebDastAssessmentEngine())
    orchestrator.register_engine(CodeSastAssessmentEngine())
    orchestrator.register_engine(InfraIacAssessmentEngine())
    orchestrator.register_engine(CicdAuditAssessmentEngine())


# Eager registration ensures engines are registered even in testing and non-lifespan ASGI runners
register_default_engines()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application startup & shutdown lifespan hook.
    """
    register_default_engines()
    yield
    # Shutdown cleanup if required


import os

# Configurable CORS origins
ALLOWED_ORIGINS = [
    origin.strip()
    for origin in os.getenv("ALLOWED_ORIGINS", "*").split(",")
    if origin.strip()
]

app = FastAPI(
    title="CyberAssess Security Assessment & Vulnerability Platform",
    version="9.0.0",
    description="Enterprise Automated Security Assessment, Vulnerability Scoring and Vulnerability Management Platform.",
    lifespan=lifespan,
)

# CORS Middleware for modern browser SPAs and external API clients
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS if ALLOWED_ORIGINS else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
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
        return {"message": "CyberAssess Security Platform Backend Online."}
else:
    @app.get("/", include_in_schema=False)
    async def root():
        return {
            "platform": "CyberAssess Security Assessment Platform",
            "version": "3.0.0",
            "docs": "/docs",
            "api_health": "/api/system/health",
        }
