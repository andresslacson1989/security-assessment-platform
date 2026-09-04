"""Contract 03/04 execution-decision request and lifecycle endpoints."""

from __future__ import annotations

from datetime import timedelta
import os
import secrets
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel, Field

from app.core.auth import UserProfile, authorize_internal_target, decode_access_token, require_admin
from app.core.db import db_manager
from app.core.models import ExecutionDecisionRecord, Target, TargetType, utc_now
from app.core.ssrf_protector import SSRFProtectionError, create_validated_target
from app.core.tool_operation_policy import OPERATION_POLICY_REVISION, get_operation_policy

router = APIRouter()


class ExecutionDecisionRequest(BaseModel):
    """Server-validated operation request; executable paths and shell text are forbidden."""

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
    confirm_owned_target: bool = Field(..., description="Explicit acknowledgement that the target is owned or authorized.")


def _session_jti(authorization: Optional[str]) -> str:
    if not authorization:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Bearer session is required.")
    parts = authorization.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Bearer session is required.")
    payload = decode_access_token(parts[1].strip())
    jti = payload.get("jti")
    if not isinstance(jti, str) or not jti:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authenticated session has no decision binding.")
    return jti


@router.post("/request", status_code=status.HTTP_201_CREATED)
async def request_execution_decision(
    payload: ExecutionDecisionRequest,
    authorization: Optional[str] = Header(default=None),
    current_user: UserProfile = Depends(require_admin),
) -> Dict[str, Any]:
    """Create one explicit admin-approved, tenant-bound execution decision."""
    if not payload.confirm_owned_target:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Explicit owned-target acknowledgement is required before approval.")
    policy = get_operation_policy(payload.tool_id, payload.operation_family)
    if policy is None or any(payload.operation_options.get(k) != v for k, v in policy.get("required_options", {}).items()):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Requested operation is not represented by the canonical policy.")
    asset = db_manager.get_asset(payload.asset_id, organization_id=current_user.organization_id)
    if not asset or (payload.project_id is not None and asset.project_id != payload.project_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Authorized inventory asset not found.")
    jti = _session_jti(authorization)
    worker_identity = os.environ.get("CYBERASSESS_WORKER_IDENTITY", "").strip()
    if not worker_identity:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="No authoritative worker identity is configured.")
    try:
        validated_target = create_validated_target(
            Target(name=asset.name, type=payload.target_type, value=payload.target_value.strip()),
            organization_id=current_user.organization_id,
            project_id=asset.project_id,
            asset_id=asset.id,
            active_probing_granted=True,
            allow_internal=authorize_internal_target(current_user, payload.target_value),
        )
    except SSRFProtectionError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Target authorization failed: {exc}") from exc
    decision = ExecutionDecisionRecord(
        id=f"exec-{secrets.token_hex(12)}",
        organization_id=current_user.organization_id,
        project_id=asset.project_id,
        asset_id=asset.id,
        target_id=validated_target.target_id,
        authorization_decision_id=validated_target.authorization_decision_id,
        target_policy_version=validated_target.policy_version,
        tool_id=payload.tool_id,
        operation_family=payload.operation_family,
        operation_options=payload.operation_options,
        operation_policy_revision=OPERATION_POLICY_REVISION,
        approval_state="APPROVED",
        approver_user_id=current_user.id,
        session_jti=jti,
        worker_identity=worker_identity,
        resource_budget=payload.resource_budget or dict(policy.get("resource_budget", {})),
        account_impact_budget=payload.account_impact_budget,
        credential_scope=payload.credential_scope,
        expires_at=utc_now() + timedelta(seconds=payload.expires_in_seconds),
    )
    try:
        db_manager.create_execution_decision(decision)
    except (ValueError, KeyError) as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Execution decision failed authoritative validation.") from exc
    return {
        "decision_id": decision.id,
        "approval_state": decision.approval_state,
        "warning": "This approval permits the requested operation only against the owned or authorized target. It must not affect any other person’s property or website.",
        "expires_at": decision.expires_at.isoformat(),
        "operation_policy_revision": decision.operation_policy_revision,
    }


@router.get("/{decision_id}")
async def get_execution_decision(decision_id: str, current_user: UserProfile = Depends(require_admin)) -> Dict[str, Any]:
    decision = db_manager.get_execution_decision(decision_id, organization_id=current_user.organization_id)
    if not decision:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Execution decision not found.")
    return decision.model_dump(exclude={"credential_scope"})


@router.post("/{decision_id}/revoke")
async def revoke_execution_decision(decision_id: str, current_user: UserProfile = Depends(require_admin)) -> Dict[str, Any]:
    if not db_manager.revoke_execution_decision(decision_id, organization_id=current_user.organization_id, actor=current_user.username):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Execution decision not found or already revoked.")
    return {"decision_id": decision_id, "revoked": True}
