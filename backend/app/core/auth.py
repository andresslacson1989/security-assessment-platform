"""
Contract 01 §3, Contract 02 §2, Contract 04 §2 & Contract 08 §1:
Zero-Trust Authentication, RFC 8725 JWT Session Governance & Multi-Tenant Authorization Engine.
"""

from __future__ import annotations
import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import time
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Tuple
from enum import Enum
from fastapi import Header, HTTPException, Depends, status
from pydantic import BaseModel, Field

from app.core.models import (
    UserProfile,
    UserRole,
    OperatingMode,
    Asset,
    ScanJob,
    CanonicalFinding,
    utc_now,
)
from app.core.version import APP_NAME

logger = logging.getLogger("cyberassess.auth")

# Environment & Operational Configuration
OPERATING_MODE_STR = os.getenv("OPERATING_MODE", "PRODUCTION").upper()
OPERATING_MODE = OperatingMode.PRODUCTION if OPERATING_MODE_STR == "PRODUCTION" else (
    OperatingMode.DEVELOPMENT if OPERATING_MODE_STR == "DEVELOPMENT" else OperatingMode.TEST
)

JWT_SECRET = os.getenv("JWT_SECRET", "cyberassess-enterprise-secret-key-32b-min")
JWT_ALGORITHM = "HS256"
ALLOWED_JWT_ALGORITHMS = ["HS256"]
JWT_ISSUER = "CyberAssess-Control-Plane"
JWT_AUDIENCE = "CyberAssess-Platform"
JWT_EXPIRATION_SECONDS = int(os.getenv("JWT_EXPIRATION_SECONDS", "86400"))  # 24 hours

# Development mode fallback user (Restricted to VIEWER; NEVER ADMIN)
ANONYMOUS_DEV_USER = UserProfile(
    id="usr-dev-anon",
    username="dev-viewer",
    email="dev@cyberassess.local",
    role=UserRole.VIEWER,
    organization_id="org-default",
)

# Active In-Memory Token Revocation Registry
REVOKED_TOKENS_REGISTRY: set = set()

# Programmatic API Key In-Memory Cache (hashed token -> (UserProfile, List[str]))
API_KEYS_CACHE: Dict[str, Tuple[UserProfile, List[str]]] = {}


# ============================================================================
# 1. Password Policy & Cryptographic Hashing (PBKDF2-HMAC-SHA256)
# ============================================================================

def validate_password_strength(password: str) -> Tuple[bool, Optional[str]]:
    """
    Validates password strength according to OWASP / NIST SP 800-63B recommendations.
    Enforces minimum 8 chars, max 128 chars, rejects trivial strings.
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters in length."
    if len(password) > 128:
        return False, "Password must not exceed 128 characters in length."
    if password.lower() in ("password", "admin123", "administrator", "cyberassess", "12345678"):
        return False, "Password is too common or easily guessable."
    return True, None


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
    Verifies a plaintext password against a stored PBKDF2-HMAC-SHA256 hash in constant time.
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
# 2. RFC 8725 Compliant JWT Generation & Validation
# ============================================================================

def _base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _base64url_decode(data_str: str) -> bytes:
    padding = "=" * ((4 - len(data_str) % 4) % 4)
    return base64.urlsafe_b64decode((data_str + padding).encode("ascii"))


def create_access_token(
    user: UserProfile,
    expires_in: int = JWT_EXPIRATION_SECONDS,
    scopes: Optional[List[str]] = None,
) -> str:
    """
    Generates a signed HS256 JWT access token conforming to RFC 8725.
    """
    header = {"alg": JWT_ALGORITHM, "typ": "JWT"}
    now = int(time.time())
    payload = {
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "sub": user.id,
        "username": user.username,
        "email": user.email,
        "role": user.role.value,
        "org_id": user.organization_id,
        "scopes": scopes or ["*"],
        "iat": now,
        "nbf": now,
        "exp": now + expires_in,
        "jti": secrets.token_hex(16),
    }

    h_json = json.dumps(header, separators=(",", ":")).encode("utf-8")
    p_json = json.dumps(payload, separators=(",", ":")).encode("utf-8")

    unsigned_token = f"{_base64url_encode(h_json)}.{_base64url_encode(p_json)}"
    signature = hmac.new(JWT_SECRET.encode("utf-8"), unsigned_token.encode("utf-8"), hashlib.sha256).digest()
    
    return f"{unsigned_token}.{_base64url_encode(signature)}"


def decode_access_token(token: str) -> Dict[str, Any]:
    """
    Validates and decodes an HS256 JWT token under strict RFC 8725 requirements.
    Rejects algorithm confusion (alg=none), unauthorized algorithms, and revoked tokens.
    """
    if token in REVOKED_TOKENS_REGISTRY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    parts = token.split(".")
    if len(parts) != 3:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token format.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 1. Parse and validate Header
    try:
        header_bytes = _base64url_decode(parts[0])
        header = json.loads(header_bytes.decode("utf-8"))
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Malformed token header.")

    alg = header.get("alg")
    if not alg or alg not in ALLOWED_JWT_ALGORITHMS or alg.lower() == "none":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Unsupported or forbidden token algorithm '{alg}'.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 2. Cryptographic Signature Verification
    unsigned_token = f"{parts[0]}.{parts[1]}"
    expected_sig = hmac.new(JWT_SECRET.encode("utf-8"), unsigned_token.encode("utf-8"), hashlib.sha256).digest()

    try:
        actual_sig = _base64url_decode(parts[2])
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Malformed token signature.")

    if not hmac.compare_digest(actual_sig, expected_sig):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token signature verification failed.")

    # 3. Payload Claims Validation
    try:
        payload_bytes = _base64url_decode(parts[1])
        payload = json.loads(payload_bytes.decode("utf-8"))
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Malformed token payload.")

    now = time.time()
    exp = payload.get("exp", 0)
    if now > exp:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    nbf = payload.get("nbf", 0)
    if now < nbf:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token is not yet valid.")

    iss = payload.get("iss")
    if iss and iss != JWT_ISSUER:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token issuer.")

    aud = payload.get("aud")
    if aud and aud != JWT_AUDIENCE:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token audience.")

    return payload


def revoke_token(token: str) -> None:
    """Adds a token to the active revocation blacklist."""
    REVOKED_TOKENS_REGISTRY.add(token)


# ============================================================================
# 3. Centralized Multi-Layer Authorization Service (Contract 08 §1)
# ============================================================================

def authorize_asset_access(user: UserProfile, asset: Asset, action: str = "read") -> bool:
    """
    Enforces multi-tenant ownership boundaries and role permissions on Asset resources.
    Prevents IDOR across organizations.
    """
    if user.role == UserRole.ADMIN and user.organization_id is None:
        return True  # System super-admin
    if asset.organization_id and user.organization_id and asset.organization_id != user.organization_id:
        return False  # Deny cross-tenant access
    if action == "write" and user.role not in (UserRole.ADMIN, UserRole.SECURITY_ANALYST, UserRole.DEVELOPER):
        return False
    if action == "delete" and user.role != UserRole.ADMIN:
        return False
    return True


def authorize_scan_access(user: UserProfile, scan: ScanJob, action: str = "read") -> bool:
    """
    Enforces multi-tenant ownership boundaries on ScanJob resources.
    """
    if user.role == UserRole.ADMIN and user.organization_id is None:
        return True
    if scan.organization_id and user.organization_id and scan.organization_id != user.organization_id:
        return False
    if action in ("control", "cancel", "delete") and user.role not in (UserRole.ADMIN, UserRole.SECURITY_ANALYST, UserRole.DEVELOPER):
        return False
    return True


def authorize_finding_access(user: UserProfile, finding: CanonicalFinding, action: str = "read") -> bool:
    """
    Enforces multi-tenant ownership boundaries on CanonicalFinding resources.
    """
    if user.role == UserRole.ADMIN and user.organization_id is None:
        return True
    if finding.organization_id and user.organization_id and finding.organization_id != user.organization_id:
        return False
    if action == "triage" and user.role not in (UserRole.ADMIN, UserRole.SECURITY_ANALYST, UserRole.DEVELOPER):
        return False
    return True


def authorize_internal_target(user: UserProfile, target_value: str) -> bool:
    """
    Checks if a user is explicitly authorized to scan internal/private network addresses.
    Restricted to ADMIN or verified approved internal targets.
    """
    return user.role == UserRole.ADMIN


# ============================================================================
# 4. FastAPI Dependencies & Route Access Guards
# ============================================================================

async def get_current_user(
    authorization: Optional[str] = Header(None),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
) -> UserProfile:
    """
    FastAPI dependency resolving authenticated UserProfile.
    Enforces strict zero-trust authentication in PRODUCTION mode.
    """
    # 1. API Key Authentication (Hashed Token Lookup)
    if x_api_key:
        key_hash = hashlib.sha256(x_api_key.encode("utf-8")).hexdigest()
        if key_hash in API_KEYS_CACHE:
            user, _ = API_KEYS_CACHE[key_hash]
            return user

        from app.core.db import db_manager
        key_record, user_profile = db_manager.verify_api_key_hash(key_hash)
        if key_record and user_profile:
            API_KEYS_CACHE[key_hash] = (user_profile, key_record.scopes)
            return user_profile
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid, expired, or revoked API key.",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    # 2. JWT Bearer Token Authentication
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

    # 3. Explicit Development Mode Bypass (Restricted to VIEWER role)
    if OPERATING_MODE == OperatingMode.DEVELOPMENT:
        logger.warning("Unauthenticated request processed under DEVELOPMENT mode. Scoped to VIEWER.")
        return ANONYMOUS_DEV_USER

    # 4. Fail closed in PRODUCTION & TEST modes
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required. Please provide a valid Bearer token or X-API-Key.",
        headers={"WWW-Authenticate": "Bearer"},
    )


def require_role(allowed_roles: List[UserRole]):
    """
    RBAC dependency factory enforcing minimum role level.
    """
    async def _role_guard(user: UserProfile = Depends(get_current_user)) -> UserProfile:
        if user.role == UserRole.ADMIN:
            return user
        if user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access forbidden: User role '{user.role.value}' does not possess required privileges ({[r.value for r in allowed_roles]}).",
            )
        return user
    return _role_guard


require_admin = require_role([UserRole.ADMIN])
require_analyst_or_admin = require_role([UserRole.ADMIN, UserRole.SECURITY_ANALYST])
require_dev_or_higher = require_role([UserRole.ADMIN, UserRole.SECURITY_ANALYST, UserRole.DEVELOPER])
