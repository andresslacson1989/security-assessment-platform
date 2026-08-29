"""
FastAPI REST & SSE Routers Package.
"""

from fastapi import APIRouter
from app.api.system import router as system_router
from app.api.scans import router as scans_router
from app.api.export import router as export_router
from app.api.tools import router as tools_router

api_router = APIRouter(prefix="/api")
api_router.include_router(system_router, prefix="/system", tags=["System"])
api_router.include_router(scans_router, prefix="/scans", tags=["Scans"])
api_router.include_router(export_router, prefix="/scans", tags=["Export"])
api_router.include_router(tools_router, prefix="/tools", tags=["Pentester Tools"])

__all__ = ["api_router"]
