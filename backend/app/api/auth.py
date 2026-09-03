"""
Contract 04 §1.1 & Contract 08 §1:
Authentication, One-Time Bootstrap, RFC 8725 JWT & Scoped API Key Router.
"""

from __future__ import annotations
import hashlib
import json
import secrets
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, HTTPException, Depends, Header, Request, status
from pydantic import BaseModel, Field

from app.core.auth import (
    UserProfile,
    UserRole,
    hash_password,
    verify_password,
    validate_password_strength,
    create_access_token,
    revoke_token,
    get_current_user,
    require_admin,
    require_analyst_or_admin,
    scopes_for_user,
    API_KEYS_CACHE,
    MIN_SINGLE_FACTOR_PASSWORD_LENGTH,
)
from app.core.db import db_manager
from app.core.models import AuditEvent, AuditAction, Organization, PrincipalType, utc_now

router = APIRouter()

API_KEY_ALLOWED_SCOPES = frozenset({
    "scan:create", "scan:read", "scan:cancel", "scan:delete", "scan:repeater", "scan:internal",
    "asset:read", "asset:write", "asset:delete",
    "finding:read", "finding:write", "finding:triage", "finding:risk_accept",
    "report:read", "tool:read", "tool:install",
})


class BootstrapRequest(BaseModel):
    admin_username: str = Field(..., min_length=3, max_length=50)
    admin_email: str = Field(..., min_length=3, max_length=254)
    admin_password: str = Field(..., min_length=MIN_SINGLE_FACTOR_PASSWORD_LENGTH, max_length=128)
    organization_name: str = Field(default="Default Organization", min_length=2, max_length=120)


class BootstrapResponse(BaseModel):
    message: str
    admin_user: UserProfile
    organization: Organization
    access_token: str


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1)
    password: str = Field(..., min_length=1)


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int = 86400
    user: UserProfile


class CreateUserRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: str = Field(..., min_length=3, max_length=254)
    password: str = Field(..., min_length=MIN_SINGLE_FACTOR_PASSWORD_LENGTH, max_length=128)
    role: UserRole = Field(default=UserRole.VIEWER)
    organization_id: Optional[str] = Field(default=None)


class CreateAPIKeyRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=50)
    scopes: List[str] = Field(default_factory=lambda: ["scan:create", "scan:read", "finding:read", "asset:read"], min_length=1, max_length=20)
    expires_in_days: Optional[int] = Field(default=90, ge=1, le=365)


class APIKeyCreatedResponse(BaseModel):
    key_id: str
    plaintext_key: str
    name: str
    scopes: List[str]
    created_at: str
    expires_at: Optional[str] = None
    warning: str = "Store this key safely now. You will not be able to view the plaintext key again."


@router.get("/status", summary="Check Platform Initialization Status")
async def get_auth_status() -> Dict[str, Any]:
    initialized = db_manager.is_initialized()
    return {
        "initialized": initialized,
        "mode": "INITIALIZING" if not initialized else "READY",
        "requires_bootstrap": not initialized,
    }


@router.post("/bootstrap", response_model=BootstrapResponse, status_code=status.HTTP_201_CREATED, summary="One-Time Administrator Bootstrap Setup")
async def bootstrap(payload: BootstrapRequest, request: Request) -> BootstrapResponse:
    if db_manager.is_initialized():
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Platform is already initialized with an administrator. Bootstrap is closed.")

    valid, err_msg = validate_password_strength(payload.admin_password)
    if not valid:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=err_msg)

    hashed_pw = hash_password(payload.admin_password)
    try:
        user, org = db_manager.bootstrap_system(
            admin_username=payload.admin_username.strip(),
            admin_email=payload.admin_email.strip(),
            hashed_password=hashed_pw,
            org_name=payload.organization_name.strip(),
        )
    except ValueError as exc:
        if "already been initialized" not in str(exc):
            raise
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Platform is already initialized with an administrator. Bootstrap is closed.") from exc

    user.scopes = scopes_for_user(user)
    token = create_access_token(user)
    return BootstrapResponse(
        message="CyberAssess platform bootstrapped successfully.",
        admin_user=user,
        organization=org,
        access_token=token,
    )


@router.post("/login", response_model=LoginResponse, summary="User Authentication & Token Issuance")
async def login(payload: LoginRequest, request: Request) -> LoginResponse:
    """Authenticate against the authoritative relational identity store."""
    username = payload.username.strip()
    source_ip = request.client.host if request.client else None

    with db_manager._connection_scope() as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username = ?", (username,))
        row = cur.fetchone()

        if not row or not verify_password(payload.password, row["hashed_password"]):
            fail_event = AuditEvent(
                actor=username or "unknown",
                action=AuditAction.LOGIN_FAILURE,
                object_type="user",
                object_id=username or "unknown",
                result="DENIED",
                source_ip=source_ip,
                details={"reason": "Invalid credentials"},
            )
            db_manager._insert_audit_event_conn(conn, fail_event)
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password.", headers={"WWW-Authenticate": "Bearer"})

        if not bool(row["is_active"]):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User account has been deactivated.")

        principal_type_value = row["principal_type"] if "principal_type" in row.keys() else PrincipalType.TENANT_PRINCIPAL.value
        try:
            principal_type = PrincipalType(principal_type_value)
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="User identity metadata is invalid.") from exc

        user = UserProfile(
            id=row["id"],
            username=row["username"],
            email=row["email"],
            role=UserRole(row["role"]),
            principal_type=principal_type,
            organization_id=row["organization_id"],
            scopes=[],
            is_active=bool(row["is_active"]),
            created_at=utc_now(),
        )
        user.scopes = scopes_for_user(user)

        conn.execute("UPDATE users SET last_login_at = ? WHERE id = ?", (utc_now().isoformat(), user.id))
        success_event = AuditEvent(
            actor=user.username,
            organization_id=user.organization_id,
            action=AuditAction.LOGIN_SUCCESS,
            object_type="user",
            object_id=user.id,
            result="SUCCESS",
            source_ip=source_ip,
        )
        db_manager._insert_audit_event_conn(conn, success_event)

        token = create_access_token(user)
        return LoginResponse(access_token=token, user=user)


@router.get("/me", response_model=UserProfile, summary="Get Current Authenticated User Profile")
async def get_current_user_profile(current_user: UserProfile = Depends(get_current_user)) -> UserProfile:
    return current_user


@router.post("/logout", summary="Revoke Active Session Token")
async def logout(
    authorization: Optional[str] = Header(None),
    current_user: UserProfile = Depends(get_current_user),
) -> Dict[str, Any]:
    if authorization:
        parts = authorization.strip().split(" ")
        if len(parts) == 2 and parts[0].lower() == "bearer":
            if not revoke_token(parts[1]):
                raise HTTPException(status_code=400, detail="The session token could not be revoked.")

    db_manager.record_audit_event(
        AuditEvent(
            actor=current_user.username,
            organization_id=current_user.organization_id,
            action=AuditAction.LOGOUT,
            object_type="user",
            object_id=current_user.id,
            result="SUCCESS",
        )
    )
    return {"message": "Session token revoked successfully."}


@router.post("/users", response_model=UserProfile, status_code=status.HTTP_201_CREATED, summary="Create User Profile (Admin)")
async def create_user(
    payload: CreateUserRequest,
    current_user: UserProfile = Depends(require_admin),
) -> UserProfile:
    valid, err = validate_password_strength(payload.password)
    if not valid:
        raise HTTPException(status_code=400, detail=err)

    user_id = f"usr-{secrets.token_hex(6)}"
    hashed = hash_password(payload.password)
    is_system_admin = current_user.principal_type == PrincipalType.SYSTEM_PRINCIPAL and current_user.role == UserRole.ADMIN
    if payload.organization_id and not is_system_admin and payload.organization_id != current_user.organization_id:
        raise HTTPException(status_code=403, detail="Tenant administrators may only create users in their own organization.")
    org_id = payload.organization_id or current_user.organization_id

    with db_manager._connection_scope() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id FROM users WHERE username = ?", (payload.username.strip(),))
        if cur.fetchone():
            raise HTTPException(status_code=400, detail=f"Username '{payload.username}' is already taken.")
        conn.execute(
            "INSERT INTO users (id, username, email, hashed_password, role, organization_id, is_active, created_at) VALUES (?, ?, ?, ?, ?, ?, 1, ?)",
            (user_id, payload.username.strip(), payload.email.strip(), hashed, payload.role.value, org_id, utc_now().isoformat()),
        )

    db_manager.record_audit_event(
        AuditEvent(
            actor=current_user.username,
            organization_id=org_id,
            action=AuditAction.USER_CREATED,
            object_type="user",
            object_id=user_id,
            result="SUCCESS",
            details={"created_username": payload.username, "role": payload.role.value},
        )
    )

    created_user = UserProfile(
        id=user_id,
        username=payload.username.strip(),
        email=payload.email.strip(),
        role=payload.role,
        organization_id=org_id,
        scopes=[],
    )
    created_user.scopes = scopes_for_user(created_user)
    return created_user


@router.post("/api-keys", response_model=APIKeyCreatedResponse, status_code=status.HTTP_201_CREATED, summary="Create Programmatic API Key")
async def create_api_key(
    payload: CreateAPIKeyRequest,
    current_user: UserProfile = Depends(require_analyst_or_admin),
) -> APIKeyCreatedResponse:
    requested_scopes = {scope.strip() for scope in payload.scopes if isinstance(scope, str) and scope.strip()}
    if not requested_scopes or "*" in requested_scopes or not requested_scopes.issubset(API_KEY_ALLOWED_SCOPES):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="API key scopes must be a non-empty subset of the platform scope allowlist.")

    caller_scopes = set(current_user.scopes or [])
    is_system_wildcard = current_user.principal_type == PrincipalType.SYSTEM_PRINCIPAL and current_user.role == UserRole.ADMIN and "*" in caller_scopes
    if not is_system_wildcard and not requested_scopes.issubset(caller_scopes):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="API key scopes cannot exceed the caller's effective permissions.")

    scopes = sorted(requested_scopes)
    key_id = f"ca_key_{secrets.token_hex(6)}"
    raw_secret = f"ca_live_{secrets.token_urlsafe(32)}"
    key_hash = hashlib.sha256(raw_secret.encode("utf-8")).hexdigest()

    expires_at_str = None
    if payload.expires_in_days:
        from datetime import timedelta
        expires_at_str = (utc_now() + timedelta(days=payload.expires_in_days)).isoformat()
    now_str = utc_now().isoformat()

    with db_manager._connection_scope() as conn:
        conn.execute(
            """
            INSERT INTO api_keys (key_id, key_hash, organization_id, user_id, name, scopes_json, created_at, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (key_id, key_hash, current_user.organization_id, current_user.id, payload.name.strip(), json.dumps(scopes), now_str, expires_at_str),
        )

    db_manager.record_audit_event(
        AuditEvent(
            actor=current_user.username,
            organization_id=current_user.organization_id,
            action=AuditAction.API_KEY_CREATED,
            object_type="api_key",
            object_id=key_id,
            result="SUCCESS",
            details={"name": payload.name, "scopes": scopes},
        )
    )

    return APIKeyCreatedResponse(
        key_id=key_id,
        plaintext_key=raw_secret,
        name=payload.name,
        scopes=scopes,
        created_at=now_str,
        expires_at=expires_at_str,
    )


@router.get("/api-keys", summary="List Active Organization API Keys")
async def list_api_keys(current_user: UserProfile = Depends(require_analyst_or_admin)) -> List[Dict[str, Any]]:
    with db_manager._connection_scope() as conn:
        cur = conn.cursor()
        now_str = utc_now().isoformat()
        active_predicate = "status = 'ACTIVE' AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?)"
        is_system_admin = current_user.principal_type == PrincipalType.SYSTEM_PRINCIPAL and current_user.role == UserRole.ADMIN
        if is_system_admin:
            cur.execute(
                "SELECT key_id, name, scopes_json, created_at, expires_at, revoked_at, last_used_at FROM api_keys WHERE " + active_predicate,
                (now_str,),
            )
        else:
            cur.execute(
                "SELECT key_id, name, scopes_json, created_at, expires_at, revoked_at, last_used_at FROM api_keys WHERE organization_id = ? AND " + active_predicate,
                (current_user.organization_id, now_str),
            )
        rows = cur.fetchall()
        return [
            {
                "key_id": r["key_id"],
                "name": r["name"],
                "scopes": json.loads(r["scopes_json"]),
                "created_at": r["created_at"],
                "expires_at": r["expires_at"],
                "revoked_at": r["revoked_at"],
                "last_used_at": r["last_used_at"],
                "is_active": True,
            }
            for r in rows
        ]


@router.delete("/api-keys/{key_id}", summary="Revoke API Key")
async def revoke_api_key(
    key_id: str,
    current_user: UserProfile = Depends(require_analyst_or_admin),
) -> Dict[str, Any]:
    with db_manager._connection_scope() as conn:
        cur = conn.cursor()
        is_system_admin = current_user.principal_type == PrincipalType.SYSTEM_PRINCIPAL and current_user.role == UserRole.ADMIN
        if is_system_admin:
            cur.execute("UPDATE api_keys SET revoked_at = ?, status = 'REVOKED' WHERE key_id = ?", (utc_now().isoformat(), key_id))
        else:
            cur.execute("UPDATE api_keys SET revoked_at = ?, status = 'REVOKED' WHERE key_id = ? AND organization_id = ?", (utc_now().isoformat(), key_id, current_user.organization_id))
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail=f"API key '{key_id}' not found.")

    API_KEYS_CACHE.clear()
    db_manager.record_audit_event(
        AuditEvent(
            actor=current_user.username,
            organization_id=current_user.organization_id,
            action=AuditAction.API_KEY_REVOKED,
            object_type="api_key",
            object_id=key_id,
            result="SUCCESS",
        )
    )
    return {"key_id": key_id, "revoked": True, "message": "API key revoked."}
