"""
FastAPI REST & SSE Routers Package.
"""

from fastapi import APIRouter
from app.api.system import router as system_router
from app.api.scans import router as scans_router
from app.api.export import router as export_router
from app.api.tools import router as tools_router
from app.api.auth import router as auth_router
from app.api.assets import router as assets_router
from app.api.findings import router as findings_router
from app.api.executions import router as executions_router

api_router = APIRouter(prefix="/api")
api_router.include_router(auth_router, prefix="/auth", tags=["Authentication & RBAC"])
api_router.include_router(assets_router, prefix="/assets", tags=["Attack Surface & Asset Inventory"])
api_router.include_router(findings_router, prefix="/findings", tags=["Vulnerability Lifecycle & Triage"])
api_router.include_router(executions_router, prefix="/system/executions", tags=["Execution Authorization"])
api_router.include_router(system_router, prefix="/system", tags=["System"])
api_router.include_router(tools_router, prefix="/system/tools", tags=["System Tools"])
api_router.include_router(scans_router, prefix="/scans", tags=["Scans"])
api_router.include_router(export_router, prefix="/scans", tags=["Export"])
api_router.include_router(tools_router, prefix="/tools", tags=["Pentester Tools"])

__all__ = ["api_router"]

