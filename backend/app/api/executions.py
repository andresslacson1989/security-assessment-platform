"""Contract 03/04 typed execution request, approval, and revocation API."""

from __future__ import annotations

from datetime import timedelta
import hashlib
import json
import os
import secrets
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel, Field

from app.core.auth import UserProfile, UserRole, authorize_internal_target, decode_access_token, require_permission
from app.core.db import db_manager
from app.core.models import AssetType, ExecutionRequestRecord, Target, TargetType, utc_now
from app.core.ssrf_protector import SSRFProtectionError, create_validated_target
from app.core.tool_operation_policy import OPERATION_POLICY_REVISION, get_operation_policy

router = APIRouter()


class ExecutionRequestPayload(BaseModel):
    """Typed request input; executable paths, shell text, and credential values are not fields."""

    target_type: TargetType
    target_value: str = Field(..., min_length=1, max_length=2048)
    asset_id: str = Field(..., min_length=1, max_length=128)
    project_id: Optional[str] = Field(default=None, max_length=128)
    tool_id: str = Field(..., min_length=1, max_length=64)
    operation_family: str = Field(..., min_length=1, max_length=128)
    operation_options: Dict[str, Any] = Field(default_factory=dict)
    resource_budget: Dict[str, int] = Field(default_factory=dict)
    account_impact_budget: Dict[str, int] = Field(default_factory=dict)
    credential_scope: Dict[str, str] = Field(default_factory=dict)
    expires_in_seconds: int = Field(default=900, ge=60, le=3600)


class ApprovalPayload(BaseModel):
    request_fingerprint: str = Field(..., min_length=64, max_length=64)
    confirm_owned_target: bool = Field(..., description="Explicit acknowledgement that the target is owned or authorized.")


def _session_jti(authorization: Optional[str], current_user: UserProfile) -> str:
    if not authorization:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Bearer session is required.")
    parts = authorization.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Bearer session is required.")
    payload = decode_access_token(parts[1].strip())
    if str(payload.get("sub", "")) != current_user.id or str(payload.get("org_id", "")) != current_user.organization_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Approval session does not match the authenticated principal.")
    jti = payload.get("jti")
    if not isinstance(jti, str) or not jti:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authenticated session has no decision binding.")
    return jti


def _asset_target_type(asset_type: AssetType) -> TargetType:
    mapping = {
        AssetType.WEB_APPLICATION: TargetType.URL,
        AssetType.API_ENDPOINT: TargetType.URL,
        AssetType.DOMAIN: TargetType.DOMAIN,
        AssetType.IP_ADDRESS: TargetType.IP,
        AssetType.IAC_TEMPLATE: TargetType.IAC_MANIFEST,
        AssetType.CLOUD_ACCOUNT: TargetType.CLOUD_ACCOUNT,
        AssetType.KUBERNETES_CLUSTER: TargetType.KUBERNETES_CLUSTER,
    }
    try:
        return mapping[asset_type]
    except KeyError as exc:
        raise HTTPException(status_code=422, detail="Asset type is not executable through this API.") from exc


def _validate_policy_input(payload: ExecutionRequestPayload) -> dict[str, Any]:
    policy = get_operation_policy(payload.tool_id, payload.operation_family)
    if policy is None:
        raise HTTPException(status_code=422, detail="Requested operation is not represented by the canonical policy.")
    required = dict(policy.get("required_options", {}))
    if payload.operation_options != required:
        raise HTTPException(status_code=422, detail="Operation options must exactly match the typed canonical operation schema.")
    forbidden = {"shell", "shell_command", "executable", "executable_path", "output_path", "credential_path", "provider_config", "env", "destination"}
    if any(str(key).lower() in forbidden for key in payload.operation_options):
        raise HTTPException(status_code=422, detail="Operation contains a forbidden client-controlled execution field.")
    max_budget = dict(policy.get("resource_budget", {}))
    resource_budget = payload.resource_budget or max_budget
    if set(resource_budget) - set(max_budget) or any(
        not isinstance(value, int) or value <= 0 or value > max_budget[key]
        for key, value in resource_budget.items()
    ):
        raise HTTPException(status_code=422, detail="Requested resource budget exceeds the canonical policy ceiling.")
    account_budget = payload.account_impact_budget or {"max_operations": 1}
    if any(not isinstance(value, int) or value < 0 for value in account_budget.values()) or account_budget.get("max_operations", 0) > 1:
        raise HTTPException(status_code=422, detail="Requested account-impact budget exceeds the canonical policy ceiling.")
    if payload.credential_scope != {"provider": "aws"}:
        raise HTTPException(status_code=422, detail="Credential scope must exactly match the approved provider boundary.")
    return {"policy": policy, "resource_budget": resource_budget, "account_budget": account_budget}


def _fingerprint(values: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(values, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


@router.post("", status_code=status.HTTP_202_ACCEPTED)
@router.post("/", status_code=status.HTTP_202_ACCEPTED, include_in_schema=False)
async def create_execution_request(
    payload: ExecutionRequestPayload,
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
    current_user: UserProfile = Depends(require_permission(required_scope="execution:request")),
) -> Dict[str, Any]:
    if not idempotency_key or not idempotency_key.strip() or len(idempotency_key.strip()) > 128:
        raise HTTPException(status_code=422, detail="A unique Idempotency-Key header is required.")
    policy_data = _validate_policy_input(payload)
    asset = db_manager.get_asset(payload.asset_id, organization_id=current_user.organization_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Authorized inventory asset not found.")
    expected_type = _asset_target_type(asset.type)
    if expected_type != payload.target_type or asset.project_id != payload.project_id or asset.target_value.strip() != payload.target_value.strip():
        raise HTTPException(status_code=409, detail="Execution target does not exactly match the authorized inventory asset.")
    if not asset.active_probing_granted:
        raise HTTPException(status_code=403, detail="The inventory asset has no active-assessment authorization.")
    try:
        validated_target = create_validated_target(
            Target(name=asset.name, type=expected_type, value=asset.target_value.strip()),
            organization_id=current_user.organization_id,
            project_id=asset.project_id,
            asset_id=asset.id,
            active_probing_granted=True,
            allow_internal=authorize_internal_target(current_user, asset.target_value),
        )
    except SSRFProtectionError as exc:
        raise HTTPException(status_code=400, detail=f"Target authorization failed: {exc}") from exc
    fingerprint_values = {
        "organization_id": current_user.organization_id, "project_id": asset.project_id,
        "asset_id": asset.id, "target_id": validated_target.target_id,
        "authorization_decision_id": validated_target.authorization_decision_id,
        "target_policy_version": validated_target.policy_version, "tool_id": payload.tool_id,
        "operation_family": payload.operation_family, "operation_options": payload.operation_options,
        "operation_policy_revision": OPERATION_POLICY_REVISION,
        "resource_budget": policy_data["resource_budget"], "account_impact_budget": policy_data["account_budget"],
        "credential_scope": payload.credential_scope,
    }
    request = ExecutionRequestRecord(
        id=f"req-{secrets.token_hex(12)}", idempotency_key=idempotency_key.strip(),
        request_fingerprint=_fingerprint(fingerprint_values), organization_id=current_user.organization_id,
        project_id=asset.project_id, asset_id=asset.id, target_id=validated_target.target_id,
        authorization_decision_id=validated_target.authorization_decision_id,
        target_policy_version=validated_target.policy_version, tool_id=payload.tool_id,
        operation_family=payload.operation_family, operation_options=payload.operation_options,
        operation_policy_revision=OPERATION_POLICY_REVISION, resource_budget=policy_data["resource_budget"],
        account_impact_budget=policy_data["account_budget"], credential_scope=payload.credential_scope,
        requested_by_user_id=current_user.id, expires_at=utc_now() + timedelta(seconds=payload.expires_in_seconds),
    )
    try:
        saved = db_manager.create_execution_request(request)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail="Execution request idempotency or authority conflict.") from exc
    return {
        "request_id": saved.id, "state": saved.state, "request_fingerprint": saved.request_fingerprint,
        "warning": "Approval permits the exact operation only against the owned or authorized target. It must not affect any other person’s property or website.",
        "expires_at": saved.expires_at.isoformat(), "operation_policy_revision": saved.operation_policy_revision,
    }


@router.post("/{request_id}/approve", status_code=status.HTTP_202_ACCEPTED)
async def approve_execution_request(
    request_id: str,
    payload: ApprovalPayload,
    authorization: Optional[str] = Header(default=None),
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
    current_user: UserProfile = Depends(require_permission(required_scope="execution:approve", allowed_roles=[UserRole.ADMIN])),
) -> Dict[str, Any]:
    if not idempotency_key:
        raise HTTPException(status_code=422, detail="A unique Idempotency-Key header is required.")
    if not payload.confirm_owned_target:
        raise HTTPException(status_code=400, detail="Explicit owned-target acknowledgement is required before approval.")
    result, decision_id, execution_id = db_manager.approve_execution_request(
        request_id, current_user.organization_id, payload.request_fingerprint,
        idempotency_key,
        current_user.id, _session_jti(authorization, current_user), os.environ.get("CYBERASSESS_WORKER_IDENTITY", "").strip(),
    )
    if result == "NOT_FOUND":
        raise HTTPException(status_code=404, detail="Execution request not found.")
    if result == "REPLAY":
        return {"request_id": request_id, "decision_id": decision_id, "execution_id": execution_id, "state": "AUTHORIZED", "idempotent_replay": True}
    if result == "EXPIRED":
        raise HTTPException(status_code=409, detail="Execution request has expired.")
    if result == "CORRELATION_REQUIRED":
        raise HTTPException(status_code=503, detail="Execution observability context is unavailable; approval was not applied.")
    if result != "AUTHORIZED":
        raise HTTPException(status_code=409, detail="Execution request cannot be authorized in its current state.")
    return {"request_id": request_id, "decision_id": decision_id, "execution_id": execution_id, "state": "AUTHORIZED", "idempotent_replay": False}


@router.get("/{request_id}")
async def get_execution_request(request_id: str, current_user: UserProfile = Depends(require_permission(required_scope="execution:read"))) -> Dict[str, Any]:
    request = db_manager.get_execution_request(request_id, organization_id=current_user.organization_id)
    if not request:
        raise HTTPException(status_code=404, detail="Execution request not found.")
    run = db_manager.get_execution_run_for_request(request.id, current_user.organization_id)
    if request.state == "AUTHORIZED" and run is None:
        raise HTTPException(status_code=409, detail="Execution authority invariant failed: authorized request has no durable run.")
    return {"request_id": request.id, "state": request.state, "request_fingerprint": request.request_fingerprint,
            "organization_id": request.organization_id, "project_id": request.project_id, "asset_id": request.asset_id,
            "target_id": request.target_id, "tool_id": request.tool_id, "operation_family": request.operation_family,
            "operation_policy_revision": request.operation_policy_revision, "created_at": request.created_at.isoformat(),
            "expires_at": request.expires_at.isoformat(), "approved_decision_id": request.approved_decision_id,
            "execution_run": run}


@router.post("/{request_id}/revoke")
async def revoke_execution_request(request_id: str, current_user: UserProfile = Depends(require_permission(required_scope="execution:revoke", allowed_roles=[UserRole.ADMIN]))) -> Dict[str, Any]:
    if not db_manager.revoke_execution_request(request_id, organization_id=current_user.organization_id, actor=current_user.username):
        raise HTTPException(status_code=404, detail="Execution request or decision not found.")
    return {"request_id": request_id, "revoked": True}
