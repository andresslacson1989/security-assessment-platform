"""
Contract 04 §1.2 & Contract 08 §1:
Continuous Attack Surface Asset Inventory & Posture Tracking Router.
Enforces multi-tenant organization scoping and prevents IDOR cross-tenant access.
"""

from __future__ import annotations
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, HTTPException, Depends, Query, status
from pydantic import BaseModel, Field

from app.core.models import Asset, AssetType, AssetCriticality, AssetLifecycleStatus, AuditEvent, AuditAction, utc_now
from app.core.auth import (
    get_current_user,
    require_dev_or_higher,
    require_admin,
    UserProfile,
    authorize_asset_access,
)
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


class UpdateAssetRequest(BaseModel):
    name: Optional[str] = Field(default=None, min_length=2, max_length=120)
    criticality: Optional[AssetCriticality] = Field(default=None)
    internet_exposed: Optional[bool] = Field(default=None)
    tags: Optional[List[str]] = Field(default=None)
    owner: Optional[str] = Field(default=None)
    lifecycle_status: Optional[AssetLifecycleStatus] = Field(default=None)


@router.get("", summary="List Monitored Organization Assets")
@router.get("/", summary="List Monitored Organization Assets", include_in_schema=False)
async def list_assets(
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    current_user: UserProfile = Depends(get_current_user),
) -> Dict[str, Any]:
    """Lists assets belonging strictly to the caller's organization."""
    org_id = current_user.organization_id if current_user.role != "ADMIN" or current_user.organization_id else None
    assets, total = db_manager.list_assets(organization_id=org_id, limit=limit, offset=offset)
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
    """Registers a new monitored asset within the caller's organization."""
    asset = Asset(
        organization_id=current_user.organization_id,
        name=payload.name.strip(),
        type=payload.type,
        target_value=payload.target_value.strip(),
        criticality=payload.criticality,
        internet_exposed=payload.internet_exposed,
        tags=payload.tags,
        owner=payload.owner or current_user.username,
        created_at=utc_now(),
        updated_at=utc_now(),
    )
    created = db_manager.create_asset(asset)

    db_manager.record_audit_event(
        AuditEvent(
            actor=current_user.username,
            organization_id=current_user.organization_id,
            action=AuditAction.ASSET_CREATED,
            object_type="asset",
            object_id=created.id,
            result="SUCCESS",
            details={"name": created.name, "type": created.type.value, "target_value": created.target_value},
        )
    )
    return created


@router.get("/{asset_id}", summary="Get Asset Details & Posture Status")
async def get_asset(
    asset_id: str,
    current_user: UserProfile = Depends(get_current_user),
) -> Asset:
    """Retrieves asset details. Enforces strict tenant ownership (IDOR denial)."""
    asset = db_manager.get_asset(asset_id)
    if not asset or not authorize_asset_access(current_user, asset, action="read"):
        raise HTTPException(status_code=404, detail=f"Asset '{asset_id}' not found.")
    return asset


@router.put("/{asset_id}", summary="Update Asset Metadata & Posture")
async def update_asset(
    asset_id: str,
    payload: UpdateAssetRequest,
    current_user: UserProfile = Depends(require_dev_or_higher),
) -> Asset:
    """Updates asset metadata. Enforces tenant ownership."""
    asset = db_manager.get_asset(asset_id)
    if not asset or not authorize_asset_access(current_user, asset, action="write"):
        raise HTTPException(status_code=404, detail=f"Asset '{asset_id}' not found.")

    if payload.name:
        asset.name = payload.name.strip()
    if payload.criticality:
        asset.criticality = payload.criticality
    if payload.internet_exposed is not None:
        asset.internet_exposed = payload.internet_exposed
    if payload.tags is not None:
        asset.tags = payload.tags
    if payload.owner:
        asset.owner = payload.owner
    if payload.lifecycle_status:
        asset.lifecycle_status = payload.lifecycle_status
    asset.updated_at = utc_now()

    updated = db_manager.create_asset(asset)

    db_manager.record_audit_event(
        AuditEvent(
            actor=current_user.username,
            organization_id=current_user.organization_id,
            action=AuditAction.ASSET_UPDATED,
            object_type="asset",
            object_id=asset_id,
            result="SUCCESS",
        )
    )
    return updated


@router.delete("/{asset_id}", summary="Delete Monitored Asset")
async def delete_asset(
    asset_id: str,
    current_user: UserProfile = Depends(require_admin),
) -> Dict[str, Any]:
    """Deletes an asset from the inventory. Enforces tenant ownership."""
    asset = db_manager.get_asset(asset_id)
    if not asset or not authorize_asset_access(current_user, asset, action="delete"):
        raise HTTPException(status_code=404, detail=f"Asset '{asset_id}' not found.")

    deleted = db_manager.delete_asset(asset_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Asset '{asset_id}' not found.")

    db_manager.record_audit_event(
        AuditEvent(
            actor=current_user.username,
            organization_id=current_user.organization_id,
            action=AuditAction.ASSET_DELETED,
            object_type="asset",
            object_id=asset_id,
            result="SUCCESS",
        )
    )
    return {"asset_id": asset_id, "deleted": True, "message": "Asset deleted successfully."}
