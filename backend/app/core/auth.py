"""
Contract 01 §3, Contract 02 §2, Contract 04 §2 & Contract 08 §1:
Zero-Trust Authentication, RFC 8725 JWT Session Governance & Multi-Tenant Authorization Engine.
"""

from __future__ import annotations
import base64
import hashlib
import hmac
import logging
import os
import secrets
import time
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Tuple
import jwt
from fastapi import Header, HTTPException, Depends, status

from app.core.models import (
    UserProfile,
    UserRole,
    PrincipalType,
    OperatingMode,
    Asset,
    ScanJob,
    CanonicalFinding,
)

logger = logging.getLogger("cyberassess.auth")

# Environment & Operational Configuration
OPERATING_MODE_STR = os.getenv("OPERATING_MODE", "PRODUCTION").upper()
OPERATING_MODE = OperatingMode.PRODUCTION if OPERATING_MODE_STR == "PRODUCTION" else (
    OperatingMode.DEVELOPMENT if OPERATING_MODE_STR == "DEVELOPMENT" else OperatingMode.TEST
)

_raw_secret = os.getenv("JWT_SECRET")
_invalid_secret_values = {"", "cyberassess-enterprise-secret-key-32b-min", "secret", "changeme", "default"}
if not _raw_secret or _raw_secret.strip().lower() in _invalid_secret_values or len(_raw_secret.strip()) < 32:
    if OPERATING_MODE == OperatingMode.PRODUCTION:
        raise RuntimeError("JWT_SECRET must be configured with at least 32 characters in PRODUCTION mode.")
    JWT_SECRET = secrets.token_hex(32)
else:
    JWT_SECRET = _raw_secret.strip()

# This deployment uses one algorithm family and one typed key store. Do not mix
# symmetric and asymmetric algorithms in the same verification path.
JWT_ALGORITHM = "HS256"
ALLOWED_JWT_ALGORITHMS = [JWT_ALGORITHM]
JWT_ISSUER = "CyberAssess-Control-Plane"
JWT_AUDIENCE = "CyberAssess-Platform"
JWT_EXPIRATION_SECONDS = int(os.getenv("JWT_EXPIRATION_SECONDS", "86400"))

ACTIVE_KEY_ID = os.getenv("JWT_ACTIVE_KEY_ID", "k-primary")
JWT_KEY_ROTATION_STORE: Dict[str, str] = {ACTIVE_KEY_ID: JWT_SECRET}

# Tenant session authority is derived from the current authoritative role on
# every request. `scan:internal` is intentionally absent from every tenant role:
# internal-network access requires a separately governed capability and must
# never be obtained merely by logging in as an analyst/developer/admin.
ROLE_SCOPES: Dict[UserRole, frozenset[str]] = {
    UserRole.VIEWER: frozenset({
        "scan:read",
        "asset:read",
        "finding:read",
        "report:read",
        "tool:read",
    }),
    UserRole.DEVELOPER: frozenset({
        "scan:create", "scan:read", "scan:cancel", "scan:repeater",
        "asset:read", "asset:write",
        "finding:read", "finding:write", "finding:triage",
        "report:read", "tool:read",
    }),
    UserRole.SECURITY_ANALYST: frozenset({
        "scan:create", "scan:read", "scan:cancel", "scan:repeater",
        "asset:read", "asset:write",
        "finding:read", "finding:write", "finding:triage", "finding:risk_accept",
        "report:read", "tool:read",
    }),
    UserRole.ADMIN: frozenset({
        "scan:create", "scan:read", "scan:cancel", "scan:delete", "scan:repeater",
        "asset:read", "asset:write", "asset:delete",
        "finding:read", "finding:write", "finding:triage", "finding:risk_accept",
        "report:read", "tool:read", "tool:install",
    }),
}


def scopes_for_user(user: UserProfile) -> List[str]:
    """Return server-authoritative session scopes for the current identity."""
    if user.principal_type == PrincipalType.SYSTEM_PRINCIPAL and user.role == UserRole.ADMIN:
        return ["*"]
    return sorted(ROLE_SCOPES.get(user.role, frozenset()))


def restrict_scopes_to_authority(user: UserProfile, requested: Optional[List[str]]) -> List[str]:
    """Intersect token-carried scopes with current durable role authority.

    This prevents a stale or previously over-privileged bearer token from
    retaining permissions after the user's authoritative role changes.
    """
    authority = scopes_for_user(user)
    if authority == ["*"]:
        if not requested:
            return ["*"]
        return list(dict.fromkeys(str(scope) for scope in requested if scope))
    authority_set = set(authority)
    if not requested:
        return authority
    return sorted({str(scope) for scope in requested if str(scope) in authority_set})


def rotate_signing_key(new_kid: str, new_secret: str) -> None:
    """Rotate the active HS256 key while preserving old verification keys."""
    if not isinstance(new_kid, str) or not new_kid.strip() or len(new_kid) > 128:
        raise ValueError("JWT key identifier must be a non-empty string of at most 128 characters.")
    normalized_secret = new_secret.strip() if isinstance(new_secret, str) else ""
    if len(normalized_secret) < 32 or normalized_secret.lower() in _invalid_secret_values:
        raise ValueError("JWT signing keys must contain at least 32 non-trivial characters.")
    global ACTIVE_KEY_ID
    normalized_kid = new_kid.strip()
    JWT_KEY_ROTATION_STORE[normalized_kid] = normalized_secret
    ACTIVE_KEY_ID = normalized_kid


def retire_signing_key(old_kid: str) -> None:
    """Retire an old verification key while retaining at least one active key."""
    if old_kid in JWT_KEY_ROTATION_STORE and len(JWT_KEY_ROTATION_STORE) > 1:
        JWT_KEY_ROTATION_STORE.pop(old_kid, None)


ANONYMOUS_DEV_USER = UserProfile(
    id="usr-dev-anon",
    username="dev-viewer",
    email="dev@cyberassess.local",
    role=UserRole.VIEWER,
    principal_type=PrincipalType.TENANT_PRINCIPAL,
    organization_id="org-default",
    scopes=sorted(ROLE_SCOPES[UserRole.VIEWER]),
)

REVOKED_TOKENS_REGISTRY: set = set()
API_KEYS_CACHE: Dict[str, Tuple[UserProfile, List[str], float]] = {}

# OWASP Password Storage Cheat Sheet baseline for PBKDF2-HMAC-SHA256.
PBKDF2_SHA256_ITERATIONS = 600_000
MIN_SINGLE_FACTOR_PASSWORD_LENGTH = 15
MAX_PASSWORD_LENGTH = 128


def validate_password_strength(password: str) -> Tuple[bool, Optional[str]]:
    """Validate new single-factor passwords against the platform baseline."""
    if len(password) < MIN_SINGLE_FACTOR_PASSWORD_LENGTH:
        return False, f"Password must be at least {MIN_SINGLE_FACTOR_PASSWORD_LENGTH} characters in length."
    if len(password) > MAX_PASSWORD_LENGTH:
        return False, f"Password must not exceed {MAX_PASSWORD_LENGTH} characters in length."
    if password.lower() in ("password", "admin123", "administrator", "cyberassess", "12345678"):
        return False, "Password is too common or easily guessable."
    return True, None


def hash_password(password: str, iterations: int = PBKDF2_SHA256_ITERATIONS) -> str:
    """Hash a password with PBKDF2-HMAC-SHA256 and a unique 128-bit salt."""
    if iterations < PBKDF2_SHA256_ITERATIONS:
        raise ValueError(f"PBKDF2-HMAC-SHA256 requires at least {PBKDF2_SHA256_ITERATIONS} iterations for new hashes.")
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    salt_b64 = base64.b64encode(salt).decode("ascii")
    hash_b64 = base64.b64encode(dk).decode("ascii")
    return f"pbkdf2_sha256${iterations}${salt_b64}${hash_b64}"


def verify_password(password: str, hashed: str) -> bool:
    """Verify current and legacy PBKDF2 hashes in constant time."""
    try:
        parts = hashed.split("$")
        if len(parts) != 4 or parts[0] != "pbkdf2_sha256":
            return False
        iterations = int(parts[1])
        if iterations <= 0:
            return False
        salt = base64.b64decode(parts[2].encode("ascii"), validate=True)
        expected_hash = base64.b64decode(parts[3].encode("ascii"), validate=True)
        actual_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
        return hmac.compare_digest(actual_hash, expected_hash)
    except Exception:
        return False


def create_access_token(
    user: UserProfile,
    expires_in: int = JWT_EXPIRATION_SECONDS,
    scopes: Optional[List[str]] = None,
) -> str:
    """Generate a signed HS256 JWT whose scopes cannot exceed current authority."""
    now = int(time.time())
    token_scopes = restrict_scopes_to_authority(user, scopes if scopes is not None else scopes_for_user(user))
    payload = {
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "sub": user.id,
        "username": user.username,
        "email": user.email,
        "role": user.role.value if hasattr(user.role, "value") else str(user.role),
        "principal_type": user.principal_type.value if hasattr(user.principal_type, "value") else str(user.principal_type),
        "org_id": user.organization_id,
        "scopes": token_scopes,
        "iat": now,
        "nbf": now,
        "exp": now + expires_in,
        "jti": secrets.token_hex(16),
    }
    signing_key = JWT_KEY_ROTATION_STORE.get(ACTIVE_KEY_ID, JWT_SECRET)
    return jwt.encode(payload, signing_key, algorithm=JWT_ALGORITHM, headers={"typ": "JWT", "kid": ACTIVE_KEY_ID})


def decode_access_token(token: str) -> Dict[str, Any]:
    """Validate an HS256 JWT with explicit algorithm, issuer, audience and key ID."""
    if not token or not isinstance(token, str):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token format.", headers={"WWW-Authenticate": "Bearer"})
    if token in REVOKED_TOKENS_REGISTRY:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has been revoked.", headers={"WWW-Authenticate": "Bearer"})
    try:
        unverified_header = jwt.get_unverified_header(token)
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token format.", headers={"WWW-Authenticate": "Bearer"})

    alg = unverified_header.get("alg")
    if alg != JWT_ALGORITHM:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Unsupported or forbidden token algorithm '{alg}'.", headers={"WWW-Authenticate": "Bearer"})
    kid = unverified_header.get("kid")
    if not isinstance(kid, str) or not kid.strip() or kid not in JWT_KEY_ROTATION_STORE:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unknown or missing token key identifier.", headers={"WWW-Authenticate": "Bearer"})

    try:
        payload = jwt.decode(
            token,
            JWT_KEY_ROTATION_STORE[kid],
            algorithms=[JWT_ALGORITHM],
            audience=JWT_AUDIENCE,
            issuer=JWT_ISSUER,
            options={"require": ["iss", "aud", "sub", "exp", "iat", "nbf", "jti"]},
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has expired.", headers={"WWW-Authenticate": "Bearer"})
    except jwt.ImmatureSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token is not yet valid.", headers={"WWW-Authenticate": "Bearer"})
    except jwt.InvalidIssuerError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token issuer.", headers={"WWW-Authenticate": "Bearer"})
    except jwt.InvalidAudienceError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token audience.", headers={"WWW-Authenticate": "Bearer"})
    except jwt.MissingRequiredClaimError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Mandatory claim missing: {exc}", headers={"WWW-Authenticate": "Bearer"})
    except jwt.PyJWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token signature verification failed.", headers={"WWW-Authenticate": "Bearer"})

    from app.core.db import db_manager
    if db_manager.is_token_revoked(str(payload["jti"])):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has been revoked.", headers={"WWW-Authenticate": "Bearer"})
    return payload


def revoke_token(token: str) -> bool:
    """Durably revoke a JWT before updating the process-local acceleration cache."""
    try:
        payload = decode_access_token(token)
        jti = payload.get("jti")
        exp = payload.get("exp")
        if jti:
            from app.core.db import db_manager
            exp_str = datetime.fromtimestamp(exp, tz=timezone.utc).isoformat() if exp else None
            token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
            db_manager.revoke_token(jti, token_hash=token_hash, expires_at=exp_str)
            REVOKED_TOKENS_REGISTRY.add(token)
            return True
    except HTTPException:
        return False
    return False


def authorize_asset_access(user: UserProfile, asset: Asset, action: str = "read") -> bool:
    if user.principal_type == PrincipalType.SYSTEM_PRINCIPAL and user.role == UserRole.ADMIN:
        return True
    if not asset.organization_id or asset.organization_id != user.organization_id:
        return False
    if action == "write" and user.role not in (UserRole.ADMIN, UserRole.SECURITY_ANALYST, UserRole.DEVELOPER):
        return False
    if action == "delete" and user.role != UserRole.ADMIN:
        return False
    return True


def authorize_scan_access(user: UserProfile, scan: ScanJob, action: str = "read") -> bool:
    if user.principal_type == PrincipalType.SYSTEM_PRINCIPAL and user.role == UserRole.ADMIN:
        return True
    if not scan.organization_id or scan.organization_id != user.organization_id:
        return False
    if action in ("control", "cancel", "delete") and user.role not in (UserRole.ADMIN, UserRole.SECURITY_ANALYST, UserRole.DEVELOPER):
        return False
    return True


def authorize_finding_access(user: UserProfile, finding: CanonicalFinding, action: str = "read") -> bool:
    if user.principal_type == PrincipalType.SYSTEM_PRINCIPAL and user.role == UserRole.ADMIN:
        return True
    if not finding.organization_id or finding.organization_id != user.organization_id:
        return False
    if action == "triage" and user.role not in (UserRole.ADMIN, UserRole.SECURITY_ANALYST, UserRole.DEVELOPER):
        return False
    return True


def authorize_internal_target(user: UserProfile, target_value: str) -> bool:
    """Return whether this identity carries explicit internal-target authority."""
    scopes = user.scopes or []
    if user.principal_type == PrincipalType.SYSTEM_PRINCIPAL and user.role == UserRole.ADMIN and "*" in scopes:
        return True
    return "scan:internal" in scopes


async def get_current_user(
    authorization: Optional[str] = Header(None),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
) -> UserProfile:
    """Resolve a database-authoritative bearer or API-key identity."""
    if x_api_key:
        key_hash = hashlib.sha256(x_api_key.encode("utf-8")).hexdigest()
        from app.core.db import db_manager
        key_record, user_profile = db_manager.verify_api_key_hash(key_hash)
        if key_record and user_profile:
            if not user_profile.is_active or key_record.status != "ACTIVE" or key_record.revoked_at is not None:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid, expired, or revoked API key.", headers={"WWW-Authenticate": "ApiKey"})
            user_profile.scopes = list(key_record.scopes)
            return user_profile
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid, expired, or revoked API key.", headers={"WWW-Authenticate": "ApiKey"})

    raw_jwt = None
    if authorization:
        parts = authorization.strip().split(" ")
        if len(parts) == 2 and parts[0].lower() == "bearer":
            raw_jwt = parts[1]
    if raw_jwt:
        payload = decode_access_token(raw_jwt)
        from app.core.db import db_manager
        subject_id = str(payload.get("sub", "")).strip()
        authoritative_user = db_manager.get_user_by_id(subject_id) if subject_id else None
        if authoritative_user is not None:
            if not authoritative_user.is_active:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User account has been deactivated.", headers={"WWW-Authenticate": "Bearer"})
            authoritative_user.scopes = restrict_scopes_to_authority(authoritative_user, payload.get("scopes"))
            return authoritative_user

        if OPERATING_MODE == OperatingMode.PRODUCTION:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authenticated user identity is not present in the authoritative database.", headers={"WWW-Authenticate": "Bearer"})

        p_type_val = payload.get("principal_type", "TENANT_PRINCIPAL")
        p_type = PrincipalType(p_type_val) if p_type_val in [p.value for p in PrincipalType] else PrincipalType.TENANT_PRINCIPAL
        user = UserProfile(
            id=payload.get("sub", "anon"),
            username=payload.get("username", "user"),
            email=payload.get("email", "user@local"),
            role=UserRole(payload.get("role", "VIEWER")),
            principal_type=p_type,
            organization_id=payload.get("org_id", "org-default"),
            scopes=[],
            is_active=True,
            created_at=datetime.fromtimestamp(payload.get("iat", time.time()), tz=timezone.utc),
        )
        user.scopes = restrict_scopes_to_authority(user, payload.get("scopes"))
        return user

    if OPERATING_MODE == OperatingMode.DEVELOPMENT:
        logger.warning("Unauthenticated request processed under DEVELOPMENT mode. Scoped to VIEWER.")
        return ANONYMOUS_DEV_USER

    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required. Please provide a valid Bearer token or X-API-Key.", headers={"WWW-Authenticate": "Bearer"})


def require_permission(required_scope: Optional[str] = None, allowed_roles: Optional[List[UserRole]] = None):
    """Require both a permitted role (when specified) and explicit credential scope."""
    async def _permission_guard(user: UserProfile = Depends(get_current_user)) -> UserProfile:
        if not user.is_active:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User account is deactivated.")
        if allowed_roles and not (user.principal_type == PrincipalType.SYSTEM_PRINCIPAL and user.role == UserRole.ADMIN):
            if user.role not in allowed_roles:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"Access forbidden: User role '{user.role.value}' does not possess required privileges ({[r.value for r in allowed_roles]}).")
        if required_scope:
            user_scopes = user.scopes or []
            wildcard_authorized = user.principal_type == PrincipalType.SYSTEM_PRINCIPAL and user.role == UserRole.ADMIN and "*" in user_scopes
            if not wildcard_authorized and required_scope not in user_scopes:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"Access forbidden: Credentials lack required scope '{required_scope}'.")
        return user
    return _permission_guard


def require_role(allowed_roles: List[UserRole]):
    return require_permission(allowed_roles=allowed_roles)


def require_scope(required_scope: str):
    return require_permission(required_scope=required_scope)


require_admin = require_permission(allowed_roles=[UserRole.ADMIN])
require_analyst_or_admin = require_permission(allowed_roles=[UserRole.ADMIN, UserRole.SECURITY_ANALYST])
require_dev_or_higher = require_permission(allowed_roles=[UserRole.ADMIN, UserRole.SECURITY_ANALYST, UserRole.DEVELOPER])
