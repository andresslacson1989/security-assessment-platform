"""
Contract 04 §3.2:
Continuous Attack Surface Asset Inventory & Posture Tracking Router.
"""

from __future__ import annotations
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, HTTPException, Depends, Query, status
from pydantic import BaseModel, Field

from app.core.models import Asset, AssetType, AssetCriticality
from app.core.auth import get_current_user, require_dev_or_higher, require_admin, UserProfile
from app.core.db import db_manager

router = APIRouter()


class CreateAssetRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=120)
    type: AssetType = Field(...)
    target_value: str = Field(..., min_length=1, max_length=1024)
    criticality: AssetCriticality = Field(default=AssetCriticality.MEDIUM)
    internet_exposed: bool = Field(default=True)
    tags: List[str] = Field(default_factory=list)
    owner: Optional[str] = Field(default=None)


@router.get("", summary="List Monitored Organization Assets")
@router.get("/", summary="List Monitored Organization Assets", include_in_schema=False)
async def list_assets(
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    current_user: UserProfile = Depends(get_current_user),
) -> Dict[str, Any]:
    assets, total = db_manager.list_assets(limit=limit, offset=offset)
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "items": [a.model_dump(mode="json") for a in assets],
    }


@router.post("", status_code=status.HTTP_201_CREATED, summary="Register New Monitored Asset")
@router.post("/", status_code=status.HTTP_201_CREATED, include_in_schema=False)
async def create_asset(
    payload: CreateAssetRequest,
    current_user: UserProfile = Depends(require_dev_or_higher),
) -> Asset:
    asset = Asset(
        organization_id=current_user.organization_id,
        name=payload.name,
        type=payload.type,
        target_value=payload.target_value.strip(),
        criticality=payload.criticality,
        internet_exposed=payload.internet_exposed,
        tags=payload.tags,
        owner=payload.owner or current_user.username,
    )
    return db_manager.create_asset(asset)


@router.get("/{asset_id}", summary="Get Asset Details & Posture Status")
async def get_asset(
    asset_id: str,
    current_user: UserProfile = Depends(get_current_user),
) -> Asset:
    asset = db_manager.get_asset(asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail=f"Asset '{asset_id}' not found.")
    return asset


@router.delete("/{asset_id}", summary="Delete Monitored Asset")
async def delete_asset(
    asset_id: str,
    current_user: UserProfile = Depends(require_admin),
) -> Dict[str, Any]:
    deleted = db_manager.delete_asset(asset_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Asset '{asset_id}' not found.")
    return {"asset_id": asset_id, "deleted": True, "message": "Asset deleted successfully."}
