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
import jwt
from fastapi import Header, Query, HTTPException, Depends, status
from pydantic import BaseModel, Field

from app.core.models import (
    UserProfile,
    UserRole,
    PrincipalType,
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

_raw_secret = os.getenv("JWT_SECRET")
if not _raw_secret or _raw_secret.strip() in ("", "cyberassess-enterprise-secret-key-32b-min", "secret", "changeme", "default"):
    # Generate an ephemeral, cryptographically secure 256-bit secret on boot
    # Guarantees ZERO static predictable production default credentials
    JWT_SECRET = secrets.token_hex(32)
else:
    JWT_SECRET = _raw_secret.strip()

JWT_ALGORITHM = "HS256"
ALLOWED_JWT_ALGORITHMS = ["HS256", "RS256"]
JWT_ISSUER = "CyberAssess-Control-Plane"
JWT_AUDIENCE = "CyberAssess-Platform"
JWT_EXPIRATION_SECONDS = int(os.getenv("JWT_EXPIRATION_SECONDS", "86400"))  # 24 hours

# JWT Key Rotation Store (kid -> signing/verification key)
ACTIVE_KEY_ID = os.getenv("JWT_ACTIVE_KEY_ID", "k-primary")
JWT_KEY_ROTATION_STORE: Dict[str, str] = {ACTIVE_KEY_ID: JWT_SECRET}


def rotate_signing_key(new_kid: str, new_secret: str) -> None:
    """
    Contract 01 §3 & Contract 08 §1: Rotates active JWT signing key.
    Allows seamless token transition by preserving previous verification keys.
    """
    global ACTIVE_KEY_ID
    JWT_KEY_ROTATION_STORE[new_kid] = new_secret
    ACTIVE_KEY_ID = new_kid


def retire_signing_key(old_kid: str) -> None:
    """
    Contract 01 §3: Retires old verification key from the active set.
    """
    if old_kid in JWT_KEY_ROTATION_STORE and len(JWT_KEY_ROTATION_STORE) > 1:
        JWT_KEY_ROTATION_STORE.pop(old_kid, None)

# Development mode fallback user (Restricted to VIEWER; NEVER ADMIN)
ANONYMOUS_DEV_USER = UserProfile(
    id="usr-dev-anon",
    username="dev-viewer",
    email="dev@cyberassess.local",
    role=UserRole.VIEWER,
    principal_type=PrincipalType.TENANT_PRINCIPAL,
    organization_id="org-default",
    scopes=["scan:read", "asset:read", "finding:read", "report:read"],
)

# Active In-Memory Token Revocation Registry
REVOKED_TOKENS_REGISTRY: set = set()

# Retained for compatibility with the logout/admin invalidation endpoint. API-key
# authentication itself is database-authoritative and does not serve identities
# from this cache, because revocation must take effect immediately.
API_KEYS_CACHE: Dict[str, Tuple[UserProfile, List[str], float]] = {}


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
# 2. RFC 8725 Compliant JWT Generation & Validation (PyJWT)
# ============================================================================

def create_access_token(
    user: UserProfile,
    expires_in: int = JWT_EXPIRATION_SECONDS,
    scopes: Optional[List[str]] = None,
) -> str:
    """
    Generates a signed HS256 JWT access token conforming to RFC 8725 using mature PyJWT.
    """
    now = int(time.time())
    payload = {
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "sub": user.id,
        "username": user.username,
        "email": user.email,
        "role": user.role.value if hasattr(user.role, "value") else str(user.role),
        "principal_type": user.principal_type.value if hasattr(user.principal_type, "value") else str(user.principal_type),
        "org_id": user.organization_id,
        "scopes": scopes or user.scopes or ["*"],
        "iat": now,
        "nbf": now,
        "exp": now + expires_in,
        "jti": secrets.token_hex(16),
    }
    signing_key = JWT_KEY_ROTATION_STORE.get(ACTIVE_KEY_ID, JWT_SECRET)
    return jwt.encode(
        payload,
        signing_key,
        algorithm=JWT_ALGORITHM,
        headers={"typ": "JWT", "kid": ACTIVE_KEY_ID},
    )


def decode_access_token(token: str) -> Dict[str, Any]:
    """
    Validates and decodes an HS256 JWT token under strict RFC 8725 requirements using PyJWT.
    Rejects algorithm confusion (alg=none), unauthorized algorithms, missing claims, and revoked tokens.
    """
    if not token or not isinstance(token, str):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token format.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if token in REVOKED_TOKENS_REGISTRY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 1. Unverified Header Inspection: strictly forbid alg=none and unapproved algorithms
    try:
        unverified_header = jwt.get_unverified_header(token)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token format.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    alg = unverified_header.get("alg")
    if not alg or alg not in ALLOWED_JWT_ALGORITHMS or str(alg).lower() == "none":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Unsupported or forbidden token algorithm '{alg}'.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    kid = unverified_header.get("kid", ACTIVE_KEY_ID)
    verification_key = JWT_KEY_ROTATION_STORE.get(kid, JWT_SECRET)

    # 2. Strict PyJWT Verification
    try:
        payload = jwt.decode(
            token,
            verification_key,
            algorithms=ALLOWED_JWT_ALGORITHMS,
            audience=JWT_AUDIENCE,
            issuer=JWT_ISSUER,
            options={"require": ["iss", "aud", "sub", "exp", "iat", "nbf"]},
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.ImmatureSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token is not yet valid.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidIssuerError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token issuer.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidAudienceError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token audience.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidAlgorithmError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Unsupported or forbidden token algorithm: {e}",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.MissingRequiredClaimError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Mandatory claim missing: {e}",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.PyJWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Token signature verification failed: {e}",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Token validation failed: {e}",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 3. Authoritative DB Token Revocation Check
    jti = payload.get("jti")
    if jti:
        from app.core.db import db_manager
        if db_manager.is_token_revoked(jti):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has been revoked.",
                headers={"WWW-Authenticate": "Bearer"},
            )

    return payload


def revoke_token(token: str) -> None:
    """Adds a token to the active revocation registry and authoritative database."""
    REVOKED_TOKENS_REGISTRY.add(token)
    try:
        payload = jwt.decode(token, options={"verify_signature": False})
        jti = payload.get("jti")
        exp = payload.get("exp")
        if jti:
            from app.core.db import db_manager
            exp_str = datetime.fromtimestamp(exp, tz=timezone.utc).isoformat() if exp else None
            token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
            db_manager.revoke_token(jti, token_hash=token_hash, expires_at=exp_str)
    except Exception:
        pass


# ============================================================================
# 3. Centralized Multi-Layer Authorization Service (Contract 08 §1)
# ============================================================================

def authorize_asset_access(user: UserProfile, asset: Asset, action: str = "read") -> bool:
    """
    Enforces multi-tenant ownership boundaries and role permissions on Asset resources.
    Prevents IDOR across organizations.
    """
    if user.principal_type == PrincipalType.SYSTEM_PRINCIPAL and user.role == UserRole.ADMIN:
        return True  # System super-admin
    if not asset.organization_id or asset.organization_id != user.organization_id:
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
    if user.principal_type == PrincipalType.SYSTEM_PRINCIPAL and user.role == UserRole.ADMIN:
        return True
    if not scan.organization_id or scan.organization_id != user.organization_id:
        return False
    if action in ("control", "cancel", "delete") and user.role not in (UserRole.ADMIN, UserRole.SECURITY_ANALYST, UserRole.DEVELOPER):
        return False
    return True


def authorize_finding_access(user: UserProfile, finding: CanonicalFinding, action: str = "read") -> bool:
    """
    Enforces multi-tenant ownership boundaries on CanonicalFinding resources.
    """
    if user.principal_type == PrincipalType.SYSTEM_PRINCIPAL and user.role == UserRole.ADMIN:
        return True
    if not finding.organization_id or finding.organization_id != user.organization_id:
        return False
    if action == "triage" and user.role not in (UserRole.ADMIN, UserRole.SECURITY_ANALYST, UserRole.DEVELOPER):
        return False
    return True


def authorize_internal_target(user: UserProfile, target_value: str) -> bool:
    """
    Checks if a user is explicitly authorized to scan internal/private network addresses.
    Restricted to ADMIN or caller with explicit 'scan:internal' scope.
    """
    if user.role == UserRole.ADMIN:
        return True
    scopes = user.scopes or []
    return "*" in scopes or "scan:internal" in scopes


# ============================================================================
# 4. FastAPI Dependencies & Route Access Guards
# ============================================================================

async def get_current_user(
    authorization: Optional[str] = Header(None),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    token: Optional[str] = Query(None),
) -> UserProfile:
    """
    FastAPI dependency resolving authenticated UserProfile.
    Enforces strict zero-trust authentication in PRODUCTION mode.
    Supports Bearer header, X-API-Key header, and ?token= query parameter (for SSE EventSource).
    """
    # 1. API Key Authentication (Hashed Token Lookup)
    if x_api_key:
        key_hash = hashlib.sha256(x_api_key.encode("utf-8")).hexdigest()

        from app.core.db import db_manager
        key_record, user_profile = db_manager.verify_api_key_hash(key_hash)
        if key_record and user_profile:
            if not user_profile.is_active or key_record.status != "ACTIVE" or key_record.revoked_at is not None:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid, expired, or revoked API key.",
                    headers={"WWW-Authenticate": "ApiKey"},
            )
            user_profile.scopes = key_record.scopes
            return user_profile
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid, expired, or revoked API key.",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    # 2. JWT Bearer Token Authentication (via Header or SSE Query Param)
    raw_jwt = None
    if authorization:
        parts = authorization.strip().split(" ")
        if len(parts) == 2 and parts[0].lower() == "bearer":
            raw_jwt = parts[1]
    elif token:
        raw_jwt = token.strip()

    if raw_jwt:
        payload = decode_access_token(raw_jwt)
        from app.core.db import db_manager

        subject_id = str(payload.get("sub", "")).strip()
        authoritative_user = db_manager.get_user_by_id(subject_id) if subject_id else None
        if authoritative_user is not None:
            if not authoritative_user.is_active:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="User account has been deactivated.",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            p_type_val = payload.get("principal_type", "TENANT_PRINCIPAL")
            p_type = PrincipalType(p_type_val) if p_type_val in [p.value for p in PrincipalType] else PrincipalType.TENANT_PRINCIPAL
            authoritative_user.principal_type = p_type
            authoritative_user.scopes = payload.get("scopes", ["*"])
            return authoritative_user

        p_type_val = payload.get("principal_type", "TENANT_PRINCIPAL")
        p_type = PrincipalType(p_type_val) if p_type_val in [p.value for p in PrincipalType] else PrincipalType.TENANT_PRINCIPAL
        
        user = UserProfile(
            id=payload.get("sub", "anon"),
            username=payload.get("username", "user"),
            email=payload.get("email", "user@local"),
            role=UserRole(payload.get("role", "VIEWER")),
            principal_type=p_type,
            organization_id=payload.get("org_id", "org-default"),
            scopes=payload.get("scopes", ["*"]),
            is_active=True,
            created_at=datetime.fromtimestamp(payload.get("iat", time.time()), tz=timezone.utc),
        )
        return user

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


def require_permission(required_scope: Optional[str] = None, allowed_roles: Optional[List[UserRole]] = None):
    """
    RBAC & Scope-based dependency factory enforcing both role level and API key scope.
    """
    async def _permission_guard(user: UserProfile = Depends(get_current_user)) -> UserProfile:
        # 0. Active check
        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User account is deactivated.",
            )

        # 1. Role validation
        if allowed_roles and user.role != UserRole.ADMIN:
            if user.role not in allowed_roles:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Access forbidden: User role '{user.role.value}' does not possess required privileges ({[r.value for r in allowed_roles]}).",
                )
        
        # 2. Scope validation (for API keys or restricted tokens)
        if required_scope:
            user_scopes = user.scopes or []
            if "*" not in user_scopes and required_scope not in user_scopes:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Access forbidden: Credentials lack required scope '{required_scope}'.",
                )
        return user
    return _permission_guard


def require_role(allowed_roles: List[UserRole]):
    return require_permission(allowed_roles=allowed_roles)


def require_scope(required_scope: str):
    return require_permission(required_scope=required_scope)


require_admin = require_permission(allowed_roles=[UserRole.ADMIN])
require_analyst_or_admin = require_permission(allowed_roles=[UserRole.ADMIN, UserRole.SECURITY_ANALYST])
require_dev_or_higher = require_permission(allowed_roles=[UserRole.ADMIN, UserRole.SECURITY_ANALYST, UserRole.DEVELOPER])
