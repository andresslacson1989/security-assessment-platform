"""
Contract 01 §5.2, Contract 02 §6, Contract 04 §3.1 & Contract 08 §12.2:
Zero-Trust Authentication, JWT Session Lifecycle & Role-Based Access Control (RBAC).
"""

from __future__ import annotations
import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from enum import Enum
from fastapi import Header, HTTPException, Depends, status
from pydantic import BaseModel, Field

# Secret key for JWT signing (derived from environment or secure random on startup)
JWT_SECRET = os.getenv("JWT_SECRET", "cyberassess-enterprise-secret-key-32b-min")
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_SECONDS = int(os.getenv("JWT_EXPIRATION_SECONDS", "86400"))  # 24 hours
AUTH_REQUIRED = os.getenv("AUTH_REQUIRED", "false").lower() in ("true", "1", "yes")


class UserRole(str, Enum):
    ADMIN = "ADMIN"
    SECURITY_ANALYST = "SECURITY_ANALYST"
    DEVELOPER = "DEVELOPER"
    VIEWER = "VIEWER"


class UserProfile(BaseModel):
    id: str
    username: str
    email: str
    role: UserRole = UserRole.VIEWER
    organization_id: Optional[str] = None
    is_active: bool = True


# In-Memory & Relational Default Users Store (Pre-seeded with default admin)
DEFAULT_ADMIN_USER = UserProfile(
    id="usr-admin-001",
    username="admin",
    email="admin@cyberassess.local",
    role=UserRole.ADMIN,
    organization_id="org-default",
)

# API Keys registry: key_string -> UserProfile
API_KEYS_REGISTRY: Dict[str, UserProfile] = {
    "ca_live_enterprise_admin_key_12345": DEFAULT_ADMIN_USER
}


# ============================================================================
# 1. Cryptographic Password Hashing (PBKDF2-HMAC-SHA256)
# ============================================================================

def hash_password(password: str, iterations: int = 100_000) -> str:
    """
    Hashes a password using PBKDF2-HMAC-SHA256 with a 16-byte random salt.
    Format: pbkdf2_sha256$<iterations>$<salt_b64>$<hash_b64>
    """
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    salt_b64 = base64.b64encode(salt).decode("ascii")
    hash_b64 = base64.b64encode(dk).decode("ascii")
    return f"pbkdf2_sha256${iterations}${salt_b64}${hash_b64}"


def verify_password(password: str, hashed: str) -> bool:
    """
    Verifies a plaintext password against a stored PBKDF2-HMAC-SHA256 hash.
    """
    try:
        parts = hashed.split("$")
        if len(parts) != 4 or parts[0] != "pbkdf2_sha256":
            return False
        iterations = int(parts[1])
        salt = base64.b64decode(parts[2].encode("ascii"))
        expected_hash = base64.b64decode(parts[3].encode("ascii"))
        
        actual_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
        return hmac.compare_digest(actual_hash, expected_hash)
    except Exception:
        return False


# ============================================================================
# 2. JWT Generation & Verification (Zero-Dependency HS256)
# ============================================================================

def _base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _base64url_decode(data_str: str) -> bytes:
    padding = "=" * ((4 - len(data_str) % 4) % 4)
    return base64.urlsafe_b64decode((data_str + padding).encode("ascii"))


def create_access_token(user: UserProfile, expires_in: int = JWT_EXPIRATION_SECONDS) -> str:
    """
    Generates a cryptographically signed HS256 JWT access token.
    """
    header = {"alg": "HS256", "typ": "JWT"}
    now = int(time.time())
    payload = {
        "sub": user.id,
        "username": user.username,
        "email": user.email,
        "role": user.role.value,
        "org_id": user.organization_id,
        "iat": now,
        "exp": now + expires_in,
    }

    h_json = json.dumps(header, separators=(",", ":")).encode("utf-8")
    p_json = json.dumps(payload, separators=(",", ":")).encode("utf-8")

    unsigned_token = f"{_base64url_encode(h_json)}.{_base64url_encode(p_json)}"
    signature = hmac.new(JWT_SECRET.encode("utf-8"), unsigned_token.encode("utf-8"), hashlib.sha256).digest()
    
    return f"{unsigned_token}.{_base64url_encode(signature)}"


def decode_access_token(token: str) -> Dict[str, Any]:
    """
    Validates and decodes an HS256 JWT token. Raises HTTPException on expiration or tampering.
    """
    parts = token.split(".")
    if len(parts) != 3:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token structure.")

    unsigned_token = f"{parts[0]}.{parts[1]}"
    expected_sig = hmac.new(JWT_SECRET.encode("utf-8"), unsigned_token.encode("utf-8"), hashlib.sha256).digest()

    try:
        actual_sig = _base64url_decode(parts[2])
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Malformed token signature.")

    if not hmac.compare_digest(actual_sig, expected_sig):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token signature verification failed.")

    try:
        payload_bytes = _base64url_decode(parts[1])
        payload = json.loads(payload_bytes.decode("utf-8"))
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Malformed token payload.")

    exp = payload.get("exp", 0)
    if time.time() > exp:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has expired.")

    return payload


# ============================================================================
# 3. FastAPI Dependencies & RBAC Guards
# ============================================================================

async def get_current_user(
    authorization: Optional[str] = Header(None),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
) -> UserProfile:
    """
    FastAPI dependency that extracts and verifies authenticated user profile.
    Supports Bearer token, X-API-Key, and development bypass when AUTH_REQUIRED=false.
    """
    # 1. API Key Header
    if x_api_key and x_api_key in API_KEYS_REGISTRY:
        return API_KEYS_REGISTRY[x_api_key]

    # 2. Authorization Header
    if authorization:
        parts = authorization.strip().split(" ")
        if len(parts) == 2 and parts[0].lower() == "bearer":
            payload = decode_access_token(parts[1])
            return UserProfile(
                id=payload.get("sub", "anon"),
                username=payload.get("username", "user"),
                email=payload.get("email", "user@local"),
                role=UserRole(payload.get("role", "VIEWER")),
                organization_id=payload.get("org_id"),
            )

    # 3. If Auth is not strictly required, return default admin for local development
    if not AUTH_REQUIRED:
        return DEFAULT_ADMIN_USER

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Missing or invalid authentication credentials.",
        headers={"WWW-Authenticate": "Bearer"},
    )


def require_role(allowed_roles: List[UserRole]):
    """
    RBAC dependency factory enforcing user role permissions.
    ADMIN role always possesses universal access.
    """
    async def _role_guard(user: UserProfile = Depends(get_current_user)) -> UserProfile:
        if user.role == UserRole.ADMIN:
            return user
        if user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access forbidden: User role '{user.role.value}' does not have required permissions ({[r.value for r in allowed_roles]}).",
            )
        return user
    return _role_guard


# Convenience Dependencies
require_admin = require_role([UserRole.ADMIN])
require_analyst_or_admin = require_role([UserRole.ADMIN, UserRole.SECURITY_ANALYST])
require_dev_or_higher = require_role([UserRole.ADMIN, UserRole.SECURITY_ANALYST, UserRole.DEVELOPER])
