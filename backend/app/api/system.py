"""
Contract 04 & 08 System Health and Engine Metadata Endpoints.
"""

from __future__ import annotations
from typing import Dict, Any, List
from fastapi import APIRouter
from app.core.models import utc_now, TargetType, Target
from app.core.storage import list_scans
from app.core.orchestrator import orchestrator

router = APIRouter()


@router.get("/health", summary="System Health & Status")
async def get_system_health() -> Dict[str, Any]:
    """
    Returns platform health status, API version, system clock, and total persistent scan count.
    """
    _, total_scans = list_scans(limit=1, offset=0)
    return {
        "status": "HEALTHY",
        "version": "3.0.0",
        "timestamp": utc_now().isoformat(),
        "total_scans_stored": total_scans,
        "registered_engines_count": len(orchestrator.get_registered_engines()),
    }


@router.get("/engines", summary="List Registered Assessment Engines")
async def get_registered_engines() -> Dict[str, Any]:
    """
    Returns metadata, supported target types, and descriptions for all registered security assessment engines.
    """
    engines_list: List[Dict[str, Any]] = []
    all_target_types = list(TargetType)

    for eng in orchestrator.get_registered_engines():
        supported = [
            tt.value for tt in all_target_types
            if eng.is_applicable(Target(name="test", type=tt, value="test"))
        ]
        engines_list.append({
            "name": eng.name,
            "display_name": eng.display_name,
            "description": eng.description,
            "supported_target_types": supported,
        })

    return {
        "count": len(engines_list),
        "engines": engines_list,
    }


@router.get("/capabilities", summary="System Tool & Engine Capabilities")
async def get_system_capabilities() -> Any:
    """
    Returns host tool discovery status, binary paths, versions, and execution modes.
    """
    from app.adapters import discover_system_capabilities
    return await discover_system_capabilities()

