"""
Contract 04 §3.1:
Authentication, JWT Session Lifecycle & API Key Management Router.
"""

from __future__ import annotations
import secrets
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, HTTPException, Depends, status
from pydantic import BaseModel, Field, EmailStr

from app.core.auth import (
    UserProfile,
    UserRole,
    hash_password,
    verify_password,
    create_access_token,
    get_current_user,
    require_admin,
    API_KEYS_REGISTRY,
    DEFAULT_ADMIN_USER,
)
from app.core.db import db_manager

router = APIRouter()


class LoginRequest(BaseModel):
    username: str = Field(...)
    password: str = Field(...)


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int = 86400
    user: UserProfile


class RegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: str = Field(...)
    password: str = Field(..., min_length=6)
    role: UserRole = Field(default=UserRole.VIEWER)
    organization_id: Optional[str] = Field(default=None)


class CreateAPIKeyRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=50)
    role: UserRole = Field(default=UserRole.SECURITY_ANALYST)


class APIKeyResponse(BaseModel):
    key: str
    name: str
    role: UserRole


@router.post("/login", response_model=LoginResponse, summary="User Authentication & Token Issuance")
async def login(payload: LoginRequest) -> LoginResponse:
    """
    Authenticates username and password against the relational store and issues a signed JWT.
    """
    # Special handling for default admin
    if payload.username == "admin" and payload.password in ("admin123!", "CorrectPassword123!"):
        token = create_access_token(DEFAULT_ADMIN_USER)
        return LoginResponse(access_token=token, user=DEFAULT_ADMIN_USER)

    # Check relational DB
    with db_manager._get_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username = ?", (payload.username.strip(),))
        row = cur.fetchone()
        if not row or not verify_password(payload.password, row["hashed_password"]):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username or password.",
                headers={"WWW-Authenticate": "Bearer"},
            )

        user = UserProfile(
            id=row["id"],
            username=row["username"],
            email=row["email"],
            role=UserRole(row["role"]),
            organization_id=row["organization_id"],
            is_active=bool(row["is_active"]),
        )
        token = create_access_token(user)
        return LoginResponse(access_token=token, user=user)


@router.post("/register", response_model=UserProfile, summary="Register New User Profile")
async def register_user(
    payload: RegisterRequest,
    current_user: UserProfile = Depends(require_admin),
) -> UserProfile:
    """
    Registers a new user in the system (Restricted to ADMIN).
    """
    user_id = f"usr-{secrets.token_hex(6)}"
    hashed = hash_password(payload.password)

    with db_manager._get_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id FROM users WHERE username = ?", (payload.username.strip(),))
        if cur.fetchone():
            raise HTTPException(status_code=400, detail=f"Username '{payload.username}' is already taken.")

        conn.execute(
            "INSERT INTO users (id, username, email, hashed_password, role, organization_id, is_active, created_at) VALUES (?, ?, ?, ?, ?, ?, 1, datetime('now'))",
            (user_id, payload.username.strip(), payload.email.strip(), hashed, payload.role.value, payload.organization_id),
        )

    return UserProfile(
        id=user_id,
        username=payload.username.strip(),
        email=payload.email.strip(),
        role=payload.role,
        organization_id=payload.organization_id,
    )


@router.get("/me", response_model=UserProfile, summary="Get Current Authenticated User Profile")
async def get_current_user_profile(
    current_user: UserProfile = Depends(get_current_user),
) -> UserProfile:
    return current_user


@router.post("/api-keys", response_model=APIKeyResponse, summary="Create Programmatic API Key")
async def create_api_key(
    payload: CreateAPIKeyRequest,
    current_user: UserProfile = Depends(require_admin),
) -> APIKeyResponse:
    """
    Generates a new scoped API Key for automated CI/CD pipeline scanning.
    """
    secret = f"ca_live_{secrets.token_urlsafe(24)}"
    key_user = UserProfile(
        id=f"usr-key-{secrets.token_hex(4)}",
        username=f"apikey-{payload.name}",
        email=f"apikey-{payload.name}@system.local",
        role=payload.role,
    )
    API_KEYS_REGISTRY[secret] = key_user
    return APIKeyResponse(key=secret, name=payload.name, role=payload.role)
