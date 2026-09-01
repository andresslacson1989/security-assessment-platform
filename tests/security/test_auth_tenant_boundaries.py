"""Regression coverage for authoritative authentication and tenant query boundaries."""

from __future__ import annotations

import hashlib

import pytest

from app.core.auth import create_access_token, get_current_user
from app.core.db import DatabaseManager
from app.core.models import AuditAction, AuditEvent, OperatingMode, PrincipalType, ScanJob, Target, TargetType, UserProfile, UserRole
from app.core.orchestrator import ScanOrchestrator


@pytest.mark.asyncio
async def test_api_key_revocation_is_checked_against_database_each_request(tmp_path, monkeypatch):
    """A revoked API key cannot be accepted from an in-memory identity cache."""
    db = DatabaseManager(db_path=tmp_path / "auth-boundary.db")
    raw_key = "test-api-key"
    key_hash = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
    with db._get_connection() as conn:
        conn.execute(
            "INSERT INTO api_keys (key_id, key_hash, organization_id, name, scopes_json, created_at, status) "
            "VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE')",
            ("key-cache-regression", key_hash, "org-one", "regression", '["finding:read"]', "2026-01-01T00:00:00+00:00"),
        )

    import app.core.db as db_module
    monkeypatch.setattr(db_module, "db_manager", db)

    first = await get_current_user(x_api_key=raw_key)
    assert first.organization_id == "org-one"
    db.revoke_api_key("key-cache-regression", organization_id="org-one")

    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc_info:
        await get_current_user(x_api_key=raw_key)
    assert exc_info.value.status_code == 401


def test_bootstrap_audit_event_is_chained_and_correlated(tmp_path):
    """Bootstrap must use the authoritative tamper-evident audit writer."""
    import app.core.correlation as correlation_module

    db = DatabaseManager(db_path=tmp_path / "bootstrap-audit.db")
    token = correlation_module.set_correlation_id("corr-bootstrap")
    try:
        user, _ = db.bootstrap_system(
            admin_username="bootstrap-admin",
            admin_email="bootstrap@example.test",
            hashed_password="stored-test-hash",
            org_name="Bootstrap Organization",
        )
    finally:
        correlation_module.reset_correlation_id(token)

    events, total = db.list_audit_events(organization_id=user.organization_id)
    assert total == 1
    assert len(events) == 1
    assert events[0].event_hash
    assert events[0].correlation_id == "corr-bootstrap"
    valid, bad_id = db.verify_audit_log_integrity(user.organization_id)
    assert valid is True
    assert bad_id is None


def test_audit_writer_serializes_outermost_sqlite_transaction(tmp_path):
    """Audit chaining starts an immediate transaction before reading its predecessor."""
    db = DatabaseManager(db_path=tmp_path / "audit-lock.db")
    first = AuditEvent(
        actor="system",
        organization_id="org-lock",
        action=AuditAction.SCAN_CREATED,
        object_type="scan",
        object_id="scan-lock-1",
    )
    db.record_audit_event(first)
    assert first.event_hash
    valid, bad_id = db.verify_audit_log_integrity("org-lock")
    assert valid is True
    assert bad_id is None


@pytest.mark.asyncio
async def test_bearer_identity_rechecks_authoritative_user_status(tmp_path, monkeypatch):
    """A signed token cannot keep a database-backed account active after deactivation."""
    db = DatabaseManager(db_path=tmp_path / "jwt-boundary.db")
    with db._get_connection() as conn:
        conn.execute(
            "INSERT INTO users (id, username, email, hashed_password, role, organization_id, is_active, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, 1, ?)",
            (
                "usr-jwt-boundary",
                "jwt-boundary",
                "jwt-boundary@example.test",
                "unused",
                "SECURITY_ANALYST",
                "org-one",
                "2026-01-01T00:00:00+00:00",
            ),
        )

    import app.core.db as db_module
    monkeypatch.setattr(db_module, "db_manager", db)
    token = create_access_token(UserProfile(
        id="usr-jwt-boundary",
        username="jwt-boundary",
        email="jwt-boundary@example.test",
        role=UserRole.SECURITY_ANALYST,
        organization_id="org-one",
    ))

    current = await get_current_user(authorization=f"Bearer {token}", x_api_key=None)
    assert current.organization_id == "org-one"
    with db._get_connection() as conn:
        conn.execute("UPDATE users SET is_active = 0 WHERE id = ?", ("usr-jwt-boundary",))

    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc_info:
        await get_current_user(authorization=f"Bearer {token}", x_api_key=None)
    assert exc_info.value.status_code == 401


@pytest.mark.asyncio
async def test_production_rejects_signed_token_for_missing_authoritative_user(tmp_path, monkeypatch):
    """A signed JWT cannot create a production identity outside the user store."""
    db = DatabaseManager(db_path=tmp_path / "missing-user.db")

    import app.core.auth as auth_module
    import app.core.db as db_module
    monkeypatch.setattr(db_module, "db_manager", db)
    monkeypatch.setattr(auth_module, "OPERATING_MODE", OperatingMode.PRODUCTION)

    token = create_access_token(UserProfile(
        id="usr-never-provisioned",
        username="missing-user",
        email="missing@example.test",
        role=UserRole.ADMIN,
        organization_id="org-missing",
    ))

    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc_info:
        await get_current_user(authorization=f"Bearer {token}", x_api_key=None)
    assert exc_info.value.status_code == 401


def test_user_bound_api_key_fails_when_bound_user_is_deactivated(tmp_path):
    """A user-bound API key cannot outlive the authoritative user identity."""
    db = DatabaseManager(db_path=tmp_path / "bound-key.db")
    raw_key = "bound-api-key"
    key_hash = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
    with db._get_connection() as conn:
        conn.execute(
            "INSERT INTO organizations (id, name, slug, created_at) VALUES (?, ?, ?, ?)",
            ("org-bound", "Bound Org", "bound-org", "2026-01-01T00:00:00+00:00"),
        )
        conn.execute(
            "INSERT INTO users (id, username, email, hashed_password, role, organization_id, is_active, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, 1, ?)",
            (
                "usr-bound",
                "bound-user",
                "bound@example.test",
                "unused",
                "SECURITY_ANALYST",
                "org-bound",
                "2026-01-01T00:00:00+00:00",
            ),
        )
        conn.execute(
            "INSERT INTO api_keys (key_id, key_hash, organization_id, user_id, name, scopes_json, created_at, status) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, 'ACTIVE')",
            (
                "key-bound",
                key_hash,
                "org-bound",
                "usr-bound",
                "bound-key",
                '["scan:read"]',
                "2026-01-01T00:00:00+00:00",
            ),
        )

    record, user = db.verify_api_key_hash(key_hash)
    assert record is not None
    assert user is not None
    assert user.id == "usr-bound"

    with db._get_connection() as conn:
        conn.execute("UPDATE users SET is_active = 0 WHERE id = ?", ("usr-bound",))
    record, user = db.verify_api_key_hash(key_hash)
    assert record is None
    assert user is None


@pytest.mark.asyncio
async def test_bearer_principal_type_cannot_be_elevated_by_token_claim(tmp_path, monkeypatch):
    """The durable user principal type outranks a forged-but-signed claim."""
    db = DatabaseManager(db_path=tmp_path / "principal-boundary.db")
    with db._get_connection() as conn:
        conn.execute(
            "INSERT INTO organizations (id, name, slug, created_at) VALUES (?, ?, ?, ?)",
            ("org-principal", "Principal Org", "principal-org", "2026-01-01T00:00:00+00:00"),
        )
        conn.execute(
            "INSERT INTO users (id, username, email, hashed_password, role, organization_id, is_active, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, 1, ?)",
            (
                "usr-principal",
                "principal-user",
                "principal@example.test",
                "unused",
                "ADMIN",
                "org-principal",
                "2026-01-01T00:00:00+00:00",
            ),
        )

    import app.core.db as db_module
    monkeypatch.setattr(db_module, "db_manager", db)
    token = create_access_token(UserProfile(
        id="usr-principal",
        username="principal-user",
        email="principal@example.test",
        role=UserRole.ADMIN,
        principal_type=PrincipalType.SYSTEM_PRINCIPAL,
        organization_id="org-principal",
    ))
    current = await get_current_user(authorization=f"Bearer {token}", x_api_key=None)
    assert current.principal_type == PrincipalType.TENANT_PRINCIPAL


def test_principal_type_is_explicit_for_system_scope():
    """Tenant admins and system admins are distinct authorization principals."""
    from app.core.models import UserProfile

    tenant_admin = UserProfile(
        username="tenant-admin", email="tenant@example.test", role=UserRole.ADMIN,
        principal_type=PrincipalType.TENANT_PRINCIPAL, organization_id="org-one",
    )
    system_admin = UserProfile(
        username="system-admin", email="system@example.test", role=UserRole.ADMIN,
        principal_type=PrincipalType.SYSTEM_PRINCIPAL, organization_id="org-system",
    )
    assert tenant_admin.principal_type != system_admin.principal_type


def test_active_job_lookup_enforces_requested_tenant_scope():
    """In-memory active jobs must obey the same tenant boundary as persisted scans."""
    orchestrator = ScanOrchestrator()
    job = ScanJob(
        id="scan-tenant-one",
        organization_id="org-one",
        target=Target(name="example", type=TargetType.DOMAIN, value="example.com"),
    )
    orchestrator._active_jobs[job.id] = job

    assert orchestrator.get_active_job(job.id, organization_id="org-one") is job
    assert orchestrator.get_active_job(job.id, organization_id="org-two") is None
    assert orchestrator.get_active_job(job.id) is job
