"""
Contract 04 §1.2 & Contract 08 §1:
Continuous Attack Surface Asset Inventory & Posture Tracking Router.
Enforces multi-tenant organization scoping and prevents IDOR cross-tenant access.
"""

from __future__ import annotations
import ipaddress
import re
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse
from fastapi import APIRouter, HTTPException, Depends, Query, status
from pydantic import BaseModel, Field

from app.core.models import Asset, AssetType, AssetCriticality, AssetLifecycleStatus, AuditEvent, AuditAction, PrincipalType, utc_now
from app.core.auth import require_permission, UserProfile, UserRole, authorize_asset_access
from app.core.db import db_manager
from app.core.storage import get_scan

router = APIRouter()
_DOMAIN_PATTERN = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


def _organization_scope(user: UserProfile) -> Optional[str]:
    if user.principal_type == PrincipalType.SYSTEM_PRINCIPAL and user.role == UserRole.ADMIN:
        return None
    return user.organization_id


def _validate_inventory_hostname(hostname: str) -> None:
    """Validate an inventory hostname without performing network I/O.

    Inventory admission is not execution authorization. Offline/unresolved assets
    may be recorded, but literal loopback/link-local/metadata/reserved targets
    remain forbidden. Execution re-runs the authoritative DNS/SSRF gateway.
    """
    from app.core.ssrf_protector import BLOCKED_HOSTNAMES, is_ip_allowed, SSRFProtectionError

    host = (hostname or "").strip().lower().strip("[]")
    if not host:
        raise SSRFProtectionError("Asset target is missing a hostname.")
    if host in BLOCKED_HOSTNAMES:
        raise SSRFProtectionError(f"Asset hostname '{host}' is a forbidden loopback/metadata name.")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not _DOMAIN_PATTERN.fullmatch(host):
            raise SSRFProtectionError(f"Asset hostname '{host}' is not a valid domain name.")
        return
    allowed, reason = is_ip_allowed(host, allow_internal=True)
    if not allowed:
        raise SSRFProtectionError(reason or "Asset IP violates inventory safety policy.")


def _assert_safe_inventory_target(asset_type: AssetType, target_value: str) -> None:
    """Validate asset identity only; never resolve DNS or make network calls."""
    from app.core.ssrf_protector import SSRFProtectionError, validate_target_security
    from app.core.path_sandbox import validate_path_sandbox

    value = target_value.strip()
    if not value:
        raise SSRFProtectionError("Asset target cannot be empty.")

    if asset_type in (AssetType.WEB_APPLICATION, AssetType.API_ENDPOINT):
        parsed = urlparse(value)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            raise SSRFProtectionError("Web/API assets must use an http:// or https:// URL with a valid hostname.")
        if parsed.username or parsed.password:
            raise SSRFProtectionError("Asset URLs must not embed credentials.")
        _validate_inventory_hostname(parsed.hostname)
        return

    if asset_type == AssetType.DOMAIN:
        _validate_inventory_hostname(value.split(":", 1)[0])
        return

    if asset_type == AssetType.IP_ADDRESS:
        _validate_inventory_hostname(value)
        return

    if asset_type == AssetType.GIT_REPOSITORY:
        if value.startswith(("http://", "https://")):
            parsed = urlparse(value)
            if not parsed.hostname:
                raise SSRFProtectionError("Git repository URL is missing a hostname.")
            if parsed.username or parsed.password:
                raise SSRFProtectionError("Git repository URLs must not embed credentials.")
            _validate_inventory_hostname(parsed.hostname)
            return
        if value.startswith("git@") and ":" in value:
            _validate_inventory_hostname(value.split("@", 1)[1].split(":", 1)[0])
            return
        allowed, reason = validate_path_sandbox(value)
        if not allowed:
            raise SSRFProtectionError(reason or "Git repository path violates workspace policy.")
        return

    if asset_type == AssetType.IAC_TEMPLATE:
        allowed, reason = validate_path_sandbox(value)
        if not allowed:
            raise SSRFProtectionError(reason or "IaC path violates workspace policy.")
        return

    # Container/cloud/Kubernetes identifiers do not require DNS at inventory
    # time; reuse the no-network branches of the authoritative format validator.
    allowed, reason = validate_target_security(asset_type.value, value, allow_internal=False)
    if not allowed:
        raise SSRFProtectionError(reason or "Asset target violates security policy.")


class CreateAssetRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=120)
    type: AssetType = Field(...)
    target_value: str = Field(..., min_length=1, max_length=1024)
    criticality: AssetCriticality = Field(default=AssetCriticality.MEDIUM)
    internet_exposed: bool = Field(default=True)
    active_probing_granted: bool = Field(default=False, description="Explicit authorization for intrusive probing")
    live_secret_verification_granted: bool = Field(default=False, description="Explicit authorization for live secret verification")
    tags: List[str] = Field(default_factory=list)
    owner: Optional[str] = Field(default=None)


class UpdateAssetRequest(BaseModel):
    name: Optional[str] = Field(default=None, min_length=2, max_length=120)
    criticality: Optional[AssetCriticality] = Field(default=None)
    internet_exposed: Optional[bool] = Field(default=None)
    tags: Optional[List[str]] = Field(default=None)
    owner: Optional[str] = Field(default=None)
    lifecycle_status: Optional[AssetLifecycleStatus] = Field(default=None)
    active_probing_granted: Optional[bool] = Field(default=None, description="Explicit authorization for intrusive probing")
    live_secret_verification_granted: Optional[bool] = Field(default=None, description="Explicit authorization for live secret verification")


class AdmitDiscoveredAssetRequest(BaseModel):
    model_config = {"extra": "forbid"}
    scan_id: str = Field(..., min_length=1, max_length=120)
    domain: str = Field(..., min_length=1, max_length=253)
    name: Optional[str] = Field(default=None, min_length=2, max_length=120)
    criticality: AssetCriticality = Field(default=AssetCriticality.MEDIUM)
    internet_exposed: bool = True
    tags: List[str] = Field(default_factory=list)


@router.get("", summary="List Monitored Organization Assets")
@router.get("/", summary="List Monitored Organization Assets", include_in_schema=False)
async def list_assets(
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    current_user: UserProfile = Depends(require_permission(required_scope="asset:read")),
) -> Dict[str, Any]:
    assets, total = db_manager.list_assets(organization_id=_organization_scope(current_user), limit=limit, offset=offset)
    return {"total": total, "limit": limit, "offset": offset, "items": [a.model_dump(mode="json") for a in assets]}


@router.post("", status_code=status.HTTP_201_CREATED, summary="Register New Monitored Asset")
@router.post("/", status_code=status.HTTP_201_CREATED, include_in_schema=False)
async def create_asset(
    payload: CreateAssetRequest,
    current_user: UserProfile = Depends(require_permission(required_scope="asset:write", allowed_roles=[UserRole.ADMIN, UserRole.SECURITY_ANALYST, UserRole.DEVELOPER])),
) -> Asset:
    from app.core.ssrf_protector import SSRFProtectionError

    if payload.active_probing_granted and current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only an organization administrator may grant intrusive probing authorization.")
    if payload.live_secret_verification_granted and current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only an organization administrator may grant live secret verification authorization.")
    try:
        _assert_safe_inventory_target(payload.type, payload.target_value)
    except SSRFProtectionError as err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Asset target rejected by security policy: {str(err)}")

    asset = Asset(
        organization_id=current_user.organization_id,
        name=payload.name.strip(),
        type=payload.type,
        target_value=payload.target_value.strip(),
        criticality=payload.criticality,
        internet_exposed=payload.internet_exposed,
        active_probing_granted=payload.active_probing_granted,
        live_secret_verification_granted=payload.live_secret_verification_granted,
        tags=payload.tags,
        owner=payload.owner or current_user.username,
        created_at=utc_now(),
        updated_at=utc_now(),
    )
    created = db_manager.create_asset(asset)
    db_manager.record_audit_event(AuditEvent(
        actor=current_user.username,
        organization_id=current_user.organization_id,
        action=AuditAction.ASSET_CREATED,
        object_type="asset",
        object_id=created.id,
        result="SUCCESS",
        details={"name": created.name, "type": created.type.value, "target_value": created.target_value},
    ))
    return created


@router.post("/admit-discovery", status_code=status.HTTP_201_CREATED, summary="Explicitly Admit a Passive Discovery into Asset Inventory")
async def admit_discovered_asset(
    payload: AdmitDiscoveredAssetRequest,
    current_user: UserProfile = Depends(require_permission(required_scope="asset:write", allowed_roles=[UserRole.ADMIN, UserRole.SECURITY_ANALYST, UserRole.DEVELOPER])),
) -> Asset:
    scan = get_scan(payload.scan_id, organization_id=_organization_scope(current_user))
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Source scan not found.")

    from app.adapters.subfinder_adapter import SubfinderAdapter
    domain = SubfinderAdapter.normalize_domain(payload.domain)
    if not domain:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="A normalized domain is required.")
    observation = next((candidate for candidate in scan.discovered_subdomains if candidate.domain == domain), None)
    if observation is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Domain was not recorded as a discovery in the source scan.")
    if observation.organization_id != scan.organization_id or observation.assessment_id != scan.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Discovery provenance does not match the source scan.")
    if observation.dns_status != "UNRESOLVED":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Only unresolved passive discoveries may be admitted through this workflow.")
    if observation.authorized_root and SubfinderAdapter.classify_scope(domain, observation.authorized_root) != "IN_SCOPE":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Discovery is outside the recorded authorized root.")

    asset = Asset(
        organization_id=current_user.organization_id,
        project_id=scan.project_id,
        name=(payload.name or domain).strip(),
        type=AssetType.DOMAIN,
        target_value=domain,
        criticality=payload.criticality,
        internet_exposed=payload.internet_exposed,
        active_probing_granted=False,
        live_secret_verification_granted=False,
        tags=payload.tags,
        owner=current_user.username,
        lifecycle_status=AssetLifecycleStatus.DISCOVERED,
        created_at=utc_now(),
        updated_at=utc_now(),
    )
    created = db_manager.create_asset(asset)
    db_manager.record_audit_event(AuditEvent(
        actor=current_user.username,
        organization_id=current_user.organization_id,
        action=AuditAction.ASSET_CREATED,
        object_type="asset",
        object_id=created.id,
        result="SUCCESS",
        details={"admission": "PASSIVE_DISCOVERY", "source_scan_id": scan.id, "source_tool": observation.discovered_via, "sources": observation.sources},
    ))
    return created


@router.get("/{asset_id}", summary="Get Asset Details & Posture Status")
async def get_asset(
    asset_id: str,
    current_user: UserProfile = Depends(require_permission(required_scope="asset:read")),
) -> Asset:
    asset = db_manager.get_asset(asset_id, organization_id=_organization_scope(current_user))
    if not asset or not authorize_asset_access(current_user, asset, action="read"):
        raise HTTPException(status_code=404, detail=f"Asset '{asset_id}' not found.")
    return asset


@router.put("/{asset_id}", summary="Update Asset Metadata & Posture")
async def update_asset(
    asset_id: str,
    payload: UpdateAssetRequest,
    current_user: UserProfile = Depends(require_permission(required_scope="asset:write", allowed_roles=[UserRole.ADMIN, UserRole.SECURITY_ANALYST, UserRole.DEVELOPER])),
) -> Asset:
    asset = db_manager.get_asset(asset_id, organization_id=_organization_scope(current_user))
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
    if "active_probing_granted" in payload.model_fields_set:
        if current_user.role != UserRole.ADMIN:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only an organization administrator may change intrusive probing authorization.")
        asset.active_probing_granted = bool(payload.active_probing_granted)
    if "live_secret_verification_granted" in payload.model_fields_set:
        if current_user.role != UserRole.ADMIN:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only an organization administrator may change live secret verification authorization.")
        asset.live_secret_verification_granted = bool(payload.live_secret_verification_granted)
    asset.updated_at = utc_now()
    updated = db_manager.create_asset(asset)
    db_manager.record_audit_event(AuditEvent(
        actor=current_user.username,
        organization_id=current_user.organization_id,
        action=AuditAction.ASSET_UPDATED,
        object_type="asset",
        object_id=asset_id,
        result="SUCCESS",
    ))
    return updated


@router.delete("/{asset_id}", summary="Delete Monitored Asset")
async def delete_asset(
    asset_id: str,
    current_user: UserProfile = Depends(require_permission(required_scope="asset:delete", allowed_roles=[UserRole.ADMIN])),
) -> Dict[str, Any]:
    asset = db_manager.get_asset(asset_id, organization_id=_organization_scope(current_user))
    if not asset or not authorize_asset_access(current_user, asset, action="delete"):
        raise HTTPException(status_code=404, detail=f"Asset '{asset_id}' not found.")
    deleted = db_manager.delete_asset(asset_id, organization_id=_organization_scope(current_user))
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Asset '{asset_id}' not found.")
    db_manager.record_audit_event(AuditEvent(
        actor=current_user.username,
        organization_id=current_user.organization_id,
        action=AuditAction.ASSET_DELETED,
        object_type="asset",
        object_id=asset_id,
        result="SUCCESS",
    ))
    return {"asset_id": asset_id, "deleted": True, "message": "Asset deleted successfully."}
