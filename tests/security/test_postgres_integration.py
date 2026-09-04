"""Opt-in real PostgreSQL schema assurance tests.

These tests deliberately require an explicitly supplied, isolated database URL.
They never discover or mutate an ambient application database.
"""

import os
import hashlib
import json
import uuid
from contextlib import contextmanager
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import pytest
import psycopg

from app.core.db import PostgresDatabaseManager
from app.core.models import AuditAction, AuditEvent
from app.core.tool_operation_policy import OPERATION_POLICY_REVISION


POSTGRES_TEST_URL = os.getenv("CYBERASSESS_POSTGRES_TEST_URL", "").strip()
POSTGRES_TEST_ACK = os.getenv("CYBERASSESS_POSTGRES_TEST_ACK", "").strip()


def _assert_audit_event_hash(event):
    details = event["details_json"]
    canonical = "|".join(str(value) for value in (
        event["id"], event["timestamp"], event["actor"], event["organization_id"],
        event["action"], event["object_type"], event["object_id"], event["result"],
        details, event["previous_event_hash"] or "",
    ))
    assert event["event_hash"] == hashlib.sha256(canonical.encode("utf-8")).hexdigest()


pytestmark = pytest.mark.skipif(
    not POSTGRES_TEST_URL,
    reason="CYBERASSESS_POSTGRES_TEST_URL is required for the isolated PostgreSQL integration suite",
)


def _disposable_database_url() -> str:
    """Require the caller to identify a local, disposable test database."""
    parts = urlsplit(POSTGRES_TEST_URL)
    if parts.hostname not in {"127.0.0.1", "::1"}:
        raise RuntimeError("PostgreSQL integration tests require the literal loopback IP")
    if POSTGRES_TEST_ACK != "I_UNDERSTAND_DISPOSABLE_DATABASE_MUTATION":
        raise RuntimeError("PostgreSQL integration tests require explicit disposable-database acknowledgment")
    if not (parts.path.rstrip("/").endswith("_ci") or parts.path.rstrip("/").endswith("_test")):
        raise RuntimeError("PostgreSQL integration tests require a database ending in _ci or _test")
    schema = "cyberassess_test_" + uuid.uuid4().hex
    with psycopg.connect(POSTGRES_TEST_URL, autocommit=True) as connection:
        connection.execute(f'CREATE SCHEMA "{schema}"')
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    query["options"] = f"-csearch_path={schema}"
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment)), schema


@contextmanager
def _isolated_manager():
    url, schema = _disposable_database_url()
    manager = None
    try:
        manager = PostgresDatabaseManager(url)
        yield manager
    finally:
        if manager is not None:
            manager._pool.close()
        with psycopg.connect(POSTGRES_TEST_URL, autocommit=True) as connection:
            connection.execute(f'DROP SCHEMA "{schema}" CASCADE')


def _seed_request_and_run(manager):
    now = "2026-01-01T00:00:00+00:00"
    with manager._connection_scope() as conn:
        conn.execute(
            "INSERT INTO organizations (id, name, slug, created_at) VALUES (%s, %s, %s, %s)",
            ("org-preflight", "Preflight Org", "preflight-org", now),
        )
        conn.execute("""
            INSERT INTO users (id, username, email, hashed_password, organization_id, created_at)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, ("user-preflight", "preflight-user", "preflight@example.invalid", "not-a-password", "org-preflight", now))
        conn.execute("""
            INSERT INTO assets (id, organization_id, name, type, target_value, created_at, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, ("asset-preflight", "org-preflight", "Preflight Asset", "DOMAIN", "example.invalid", now, now))
        conn.execute("""
            INSERT INTO execution_requests (
                id, idempotency_key, request_fingerprint, organization_id,
                asset_id, target_id, authorization_decision_id,
                target_policy_version, tool_id, operation_family,
                operation_policy_revision, requested_by_user_id,
                state, created_at, expires_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, ("request-preflight", "idem-preflight", "fingerprint-preflight", "org-preflight",
              "asset-preflight", "target-preflight", "decision-preflight", "policy-1",
              "nmap", "SAFE", "revision-1", "user-preflight", "REQUESTED", now, now))
        conn.execute("""
            INSERT INTO execution_runs (
                execution_id, request_id, organization_id, state,
                assurance_state, coverage_state, created_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, ("run-preflight", "request-preflight", "org-preflight", "FAILED", "UNVERIFIED", "UNAVAILABLE", now))


def _drop_execution_run_foreign_keys(manager):
    with manager._connection_scope() as conn:
        constraints = conn.execute("""
            SELECT c.conname
            FROM pg_constraint c
            JOIN pg_class t ON t.oid = c.conrelid
            JOIN pg_namespace n ON n.oid = t.relnamespace
            WHERE t.relname = 'execution_runs'
              AND n.nspname = current_schema()
              AND c.contype = 'f'
        """).fetchall()
        for constraint in constraints:
            name = '"' + str(constraint["conname"]).replace('"', '""') + '"'
            conn.execute(f"ALTER TABLE execution_runs DROP CONSTRAINT {name}")


def test_postgres_bootstrap_health_and_rerun_are_real_backend_operations():
    with _isolated_manager() as manager:
        with manager._connection_scope() as conn:
            versions = [row["version"] for row in conn.execute(
                "SELECT version FROM schema_migrations ORDER BY version"
            ).fetchall()]
                assert versions == [1, 2, 3, 4, 5, 6, 7, 8]

            run_index = conn.execute("""
            SELECT i.relname, am.amname, x.indisunique, x.indpred,
                   x.indisvalid, x.indisready, x.indnkeyatts, x.indnatts,
                   array_agg(a.attname ORDER BY key_cols.ordinality) AS columns
            FROM pg_class i
            JOIN pg_index x ON x.indexrelid = i.oid
            JOIN pg_class t ON t.oid = x.indrelid
            JOIN pg_namespace n ON n.oid = t.relnamespace
            JOIN pg_am am ON am.oid = i.relam
            JOIN unnest(x.indkey) WITH ORDINALITY AS key_cols(attnum, ordinality) ON TRUE
            JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = key_cols.attnum
            WHERE i.relname = 'uq_execution_runs_request'
              AND t.relname = 'execution_runs' AND n.nspname = current_schema()
            GROUP BY i.oid, am.amname, x.indisunique, x.indpred,
                     x.indisvalid, x.indisready, x.indnkeyatts, x.indnatts
            """).fetchall()
            assert len(run_index) == 1
            index = run_index[0]
            assert index["amname"] == "btree"
            assert index["indisunique"] and index["indpred"] is None
            assert index["indisvalid"] and index["indisready"]
            assert index["indnkeyatts"] == index["indnatts"] == 2
            assert list(index["columns"]) == ["request_id", "organization_id"]

            fk = conn.execute("""
            SELECT c.convalidated,
                   array_agg(a.attname ORDER BY local_cols.ordinality) AS local_columns,
                   array_agg(pa.attname ORDER BY local_cols.ordinality) AS parent_columns
            FROM pg_constraint c
            JOIN pg_class t ON t.oid = c.conrelid
            JOIN pg_class pt ON pt.oid = c.confrelid
            JOIN pg_namespace n ON n.oid = t.relnamespace
            JOIN pg_namespace pn ON pn.oid = pt.relnamespace
            JOIN unnest(c.conkey) WITH ORDINALITY AS local_cols(attnum, ordinality) ON TRUE
            JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = local_cols.attnum
            JOIN unnest(c.confkey) WITH ORDINALITY AS parent_cols(attnum, ordinality)
              ON parent_cols.ordinality = local_cols.ordinality
            JOIN pg_attribute pa ON pa.attrelid = pt.oid AND pa.attnum = parent_cols.attnum
            WHERE t.relname = 'execution_runs' AND pt.relname = 'execution_requests'
              AND n.nspname = current_schema() AND pn.nspname = current_schema()
              AND c.contype = 'f'
            GROUP BY c.oid, c.convalidated
            """).fetchall()
            exact = [row for row in fk if row["convalidated"]
                     and list(row["local_columns"]) == ["request_id", "organization_id"]
                     and list(row["parent_columns"]) == ["id", "organization_id"]]
            assert len(exact) == 1
            legacy = conn.execute("""
                SELECT COUNT(*) AS count
                FROM pg_constraint c
                JOIN pg_class t ON t.oid = c.conrelid
                JOIN pg_class pt ON pt.oid = c.confrelid
                JOIN pg_namespace n ON n.oid = t.relnamespace
                JOIN pg_namespace pn ON pn.oid = pt.relnamespace
                WHERE t.relname = 'execution_runs' AND pt.relname = 'execution_requests'
                  AND n.nspname = current_schema() AND pn.nspname = current_schema()
                  AND c.contype = 'f' AND array_length(c.conkey, 1) = 1
                  AND pg_get_constraintdef(c.oid) LIKE 'FOREIGN KEY (request_id)%'
            """).fetchone()
            assert legacy["count"] == 0

        # A second manager initialization exercises migration idempotency and
        # the startup health path after the first transaction has completed.
        second = PostgresDatabaseManager(manager.database_url)
        second._pool.close()


def test_postgres_version_two_remediates_legacy_request_fk():
    with _isolated_manager() as manager:
        with manager._connection_scope() as conn:
            conn.execute("ALTER TABLE execution_runs ADD CONSTRAINT execution_runs_legacy_request_fk FOREIGN KEY (request_id) REFERENCES execution_requests(id)")
            conn.execute("DELETE FROM schema_migrations WHERE version = 2")
        repaired = PostgresDatabaseManager(manager.database_url)
        try:
            with repaired._connection_scope() as conn:
                legacy = conn.execute("""
                    SELECT COUNT(*) AS count
                    FROM pg_constraint c
                    JOIN pg_class t ON t.oid = c.conrelid
                    JOIN pg_class pt ON pt.oid = c.confrelid
                    JOIN pg_namespace n ON n.oid = t.relnamespace
                    JOIN pg_namespace pn ON pn.oid = pt.relnamespace
                    WHERE t.relname = 'execution_runs' AND pt.relname = 'execution_requests'
                      AND n.nspname = current_schema() AND pn.nspname = current_schema()
                      AND c.contype = 'f' AND array_length(c.conkey, 1) = 1
                      AND pg_get_constraintdef(c.oid) LIKE 'FOREIGN KEY (request_id)%'
                """).fetchone()
                assert legacy["count"] == 0
                assert conn.execute("SELECT 1 FROM schema_migrations WHERE version = 2").fetchone()
        finally:
            repaired._pool.close()


def test_postgres_health_rejects_same_name_wrong_column_index():
    with _isolated_manager() as manager:
        with manager._connection_scope() as conn:
            conn.execute("DROP INDEX uq_execution_runs_request")
            conn.execute("CREATE UNIQUE INDEX uq_execution_runs_request ON execution_runs(request_id, state)")
        with pytest.raises(ValueError, match="schema health check"):
            PostgresDatabaseManager(manager.database_url)


def test_postgres_health_rejects_same_name_wrong_column_parent_index():
    with _isolated_manager() as manager:
        with manager._connection_scope() as conn:
            conn.execute("DROP INDEX uq_execution_requests_id_org")
            conn.execute("CREATE UNIQUE INDEX uq_execution_requests_id_org ON execution_requests(id, created_at)")
        with pytest.raises(ValueError, match="schema health check"):
            PostgresDatabaseManager(manager.database_url)


def test_postgres_missing_linked_decision_failure_is_durable_and_state_preserving():
    from app.core.correlation import reset_correlation_id, set_correlation_id

    with _isolated_manager() as manager:
        now = "2026-01-01T00:00:00+00:00"
        with manager._connection_scope() as conn:
            conn.execute(
                "INSERT INTO organizations (id, name, slug, created_at) VALUES (%s, %s, %s, %s)",
                ("org-invariant", "Invariant Org", "invariant-org", now),
            )
            conn.execute("""
                INSERT INTO users (id, username, email, hashed_password, organization_id, created_at)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, ("user-invariant", "invariant-user", "invariant@example.invalid", "not-a-password", "org-invariant", now))
            conn.execute("""
                INSERT INTO assets (id, organization_id, name, type, target_value, created_at, updated_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, ("asset-invariant", "org-invariant", "Invariant Asset", "DOMAIN", "example.invalid", now, now))
            conn.execute("""
                INSERT INTO execution_requests (
                    id, idempotency_key, request_fingerprint, organization_id,
                    asset_id, target_id, authorization_decision_id, target_policy_version,
                    tool_id, operation_family, operation_policy_revision,
                    requested_by_user_id, state, created_at, expires_at, approved_decision_id
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, ("req-invariant", "idem-invariant", "f" * 64, "org-invariant", "asset-invariant",
                  "target-invariant", "auth-invariant", "v1", "nmap", "safe", OPERATION_POLICY_REVISION,
                  "user-invariant", "AUTHORIZED", now, "2099-01-01T00:00:00+00:00", "missing-decision"))

        correlation_token = set_correlation_id("corr-pg-missing-decision")
        try:
            with pytest.raises(ValueError, match="invalid approved decision"):
                manager.revoke_execution_request("req-invariant", "org-invariant", "admin")
        finally:
            reset_correlation_id(correlation_token)

        with manager._connection_scope() as conn:
            request = conn.execute("SELECT state FROM execution_requests WHERE id = %s", ("req-invariant",)).fetchone()
            events = conn.execute("""
                SELECT id, timestamp, action, object_type, object_id, result, actor, organization_id, correlation_id,
                       details_json, previous_event_hash, event_hash, sequence_number
                FROM audit_events WHERE object_id = %s
            """, ("req-invariant",)).fetchall()
        assert request["state"] == "AUTHORIZED"
        assert len(events) == 1
        assert events[0]["action"] == "EXECUTION_AUTHORITY_INVARIANT_FAILED"
        assert events[0]["object_type"] == "execution_request"
        assert events[0]["result"] == "FAILURE"
        assert events[0]["actor"] == "admin"
        assert events[0]["organization_id"] == "org-invariant"
        assert events[0]["correlation_id"] == "corr-pg-missing-decision"
        assert events[0]["event_hash"]
        assert events[0]["previous_event_hash"] is None
        assert events[0]["sequence_number"] == 1
        _assert_audit_event_hash(events[0])
        assert "APPROVED_DECISION_REFERENCE_MISSING" in events[0]["details_json"]

        request = conn.execute(
            "SELECT approved_decision_id FROM execution_requests WHERE id = %s AND organization_id = %s",
            ("req-invariant", "org-invariant"),
        ).fetchone()
        decision = conn.execute(
            "SELECT id FROM execution_decisions WHERE id = %s AND organization_id = %s",
            ("missing-decision", "org-invariant"),
        ).fetchone()
        assert request["approved_decision_id"] == "missing-decision"
        assert decision is None


def test_postgres_approval_requires_correlation_without_authority_mutation():
    from app.core.correlation import reset_correlation_id, set_correlation_id

    with _isolated_manager() as manager:
        now = "2026-01-01T00:00:00+00:00"
        expires = "2099-01-01T00:00:00+00:00"
        options = '{"output_format":"json-asff","provider":"aws","quiet":true}'
        budget = '{"max_output_bytes":10485760,"timeout_seconds":120}'
        account_budget = '{"read_only":1}'
        credentials = '{"provider":"aws"}'
        with manager._connection_scope() as conn:
            conn.execute("INSERT INTO organizations (id, name, slug, created_at) VALUES (%s, %s, %s, %s)", ("org-correlation", "Correlation Org", "correlation-org", now))
            conn.execute("INSERT INTO assets (id, organization_id, name, type, target_value, active_probing_granted, created_at, updated_at) VALUES (%s, %s, 'asset', 'CLOUD_ACCOUNT', %s, 1, %s, %s)", ("asset-correlation", "org-correlation", "aws://123456789012", now, now))
            conn.execute("INSERT INTO users (id, username, email, hashed_password, role, organization_id, created_at) VALUES (%s, 'admin', 'admin@example.invalid', 'hash', 'ADMIN', %s, %s)", ("user-correlation", "org-correlation", now))
            conn.execute(
                "INSERT INTO execution_requests (id, idempotency_key, request_fingerprint, organization_id, asset_id, target_id, authorization_decision_id, target_policy_version, tool_id, operation_family, operation_options_json, operation_policy_revision, resource_budget_json, account_impact_budget_json, credential_scope_json, requested_by_user_id, state, created_at, expires_at) VALUES (%s, %s, %s, %s, %s, %s, %s, 'v1', 'prowler', 'cloud_audit', %s, %s, %s, %s, %s, %s, 'REQUESTED', %s, %s)",
                ("req-correlation", "idem-correlation", "f" * 64, "org-correlation", "asset-correlation", "target-correlation", "auth-correlation", options, OPERATION_POLICY_REVISION, budget, account_budget, credentials, "user-correlation", now, expires),
            )

        token = set_correlation_id("")
        try:
            result = manager.approve_execution_request(
                "req-correlation", "org-correlation", "f" * 64, "approval-correlation",
                "user-correlation", "session-correlation", "worker-correlation",
            )
        finally:
            reset_correlation_id(token)
        assert result == ("CORRELATION_REQUIRED", None, None)
        with manager._connection_scope() as conn:
            request = conn.execute("SELECT state, approved_decision_id FROM execution_requests WHERE id = %s", ("req-correlation",)).fetchone()
            decisions = conn.execute("SELECT COUNT(*) AS count FROM execution_decisions WHERE organization_id = %s", ("org-correlation",)).fetchone()
            runs = conn.execute("SELECT COUNT(*) AS count FROM execution_runs WHERE organization_id = %s", ("org-correlation",)).fetchone()
            events = conn.execute("SELECT id, timestamp, action, result, actor, organization_id, object_type, object_id, details_json, correlation_id, previous_event_hash, event_hash, sequence_number FROM audit_events WHERE object_id = %s AND organization_id = %s", ("req-correlation", "org-correlation")).fetchall()
        assert request["state"] == "REQUESTED"
        assert request["approved_decision_id"] is None
        assert decisions["count"] == 0
        assert runs["count"] == 0
        assert len(events) == 1
        event = events[0]
        assert event["action"] == "EXECUTION_AUTHORITY_INVARIANT_FAILED"
        assert event["result"] == "FAILURE"
        assert event["actor"] == "system"
        assert event["organization_id"] == "org-correlation"
        assert event["object_type"] == "execution_request"
        assert event["object_id"] == "req-correlation"
        assert event["correlation_id"].startswith("corr-")
        assert event["previous_event_hash"] is None
        assert event["event_hash"]
        assert event["sequence_number"] == 1
        assert '"reason_code": "CORRELATION_REQUIRED"' in event["details_json"]
        assert manager.verify_audit_log_integrity() == (True, None)
        _assert_audit_event_hash(event)


def test_postgres_revoke_does_not_disclose_same_decision_id_owned_by_other_tenant():
    from app.core.correlation import reset_correlation_id, set_correlation_id

    with _isolated_manager() as manager:
        now = "2026-01-01T00:00:00+00:00"
        expires = "2099-01-01T00:00:00+00:00"
        with manager._connection_scope() as conn:
            for org, suffix in (("org-a", "a"), ("org-b", "b")):
                conn.execute(
                    "INSERT INTO organizations (id, name, slug, created_at) VALUES (%s, %s, %s, %s)",
                    (org, f"Org {suffix.upper()}", f"org-{suffix}", now),
                )
                conn.execute(
                    "INSERT INTO assets (id, organization_id, name, type, target_value, created_at, updated_at) "
                    "VALUES (%s, %s, %s, 'DOMAIN', %s, %s, %s)",
                    (f"asset-{suffix}", org, "asset", "example.invalid", now, now),
                )
                conn.execute(
                    "INSERT INTO users (id, username, email, hashed_password, role, organization_id, created_at) "
                    "VALUES (%s, %s, %s, 'hash', 'ADMIN', %s, %s)",
                    (f"user-{suffix}", f"user-{suffix}", f"{suffix}@example.invalid", org, now),
                )
            conn.execute(
                "INSERT INTO execution_decisions (id, organization_id, project_id, asset_id, target_id, "
                "authorization_decision_id, target_policy_version, tool_id, operation_family, "
                "operation_policy_revision, approval_state, approver_user_id, session_jti, worker_identity, "
                "created_at, expires_at) VALUES (%s, %s, NULL, %s, %s, %s, 'v1', 'nmap', 'safe', %s, "
                "'APPROVED', 'user-b', 'session-b', 'worker-b', %s, %s)",
                ("shared-id", "org-b", "asset-b", "target-b", "auth-b", OPERATION_POLICY_REVISION, now, expires),
            )
            conn.execute(
                "INSERT INTO execution_requests (id, idempotency_key, request_fingerprint, organization_id, "
                "asset_id, target_id, authorization_decision_id, target_policy_version, tool_id, operation_family, "
                "operation_policy_revision, requested_by_user_id, state, created_at, expires_at, approved_decision_id) "
                "VALUES (%s, %s, %s, 'org-a', 'asset-a', 'target-a', 'auth-a', 'v1', 'nmap', 'safe', %s, "
                "'user-a', 'AUTHORIZED', %s, %s, %s)",
                ("req-a", "idem-a", "f" * 64, OPERATION_POLICY_REVISION, now, expires, "shared-id"),
            )

        correlation_token = set_correlation_id("corr-pg-cross-tenant")
        try:
            with pytest.raises(ValueError, match="invalid approved decision"):
                manager.revoke_execution_request("req-a", "org-a", "admin")
        finally:
            reset_correlation_id(correlation_token)
        with manager._connection_scope() as conn:
            request = conn.execute(
                "SELECT state, approved_decision_id FROM execution_requests WHERE id = %s AND organization_id = %s",
                ("req-a", "org-a"),
            ).fetchone()
            events = conn.execute(
                "SELECT id, timestamp, organization_id, actor, action, object_type, object_id, result, correlation_id, details_json, "
                "previous_event_hash, event_hash, sequence_number FROM audit_events WHERE object_id = %s",
                ("req-a",),
            ).fetchall()
        assert request["state"] == "AUTHORIZED"
        assert request["approved_decision_id"] == "shared-id"
        assert len(events) == 1
        assert events[0]["organization_id"] == "org-a"
        assert events[0]["actor"] == "admin"
        assert events[0]["action"] == "EXECUTION_AUTHORITY_INVARIANT_FAILED"
        assert events[0]["object_type"] == "execution_request"
        assert events[0]["result"] == "FAILURE"
        assert events[0]["correlation_id"] is not None
        assert events[0]["event_hash"]
        assert events[0]["previous_event_hash"] is None
        assert events[0]["sequence_number"] == 1
        _assert_audit_event_hash(events[0])
        assert '"reason_code": "APPROVED_DECISION_REFERENCE_MISSING"' in events[0]["details_json"]
        assert "shared-id" not in events[0]["details_json"]


def test_postgres_audit_chain_continuity_is_verified_for_multiple_events():
    with _isolated_manager() as manager:
        manager.record_audit_event(AuditEvent(
            id="pg-audit-chain-one", actor="admin", organization_id="org-chain",
            action=AuditAction.EXECUTION_REQUESTED, object_type="execution_request",
            object_id="request-chain", result="SUCCESS", details={"step": 1},
            correlation_id="corr-chain",
        ))
        manager.record_audit_event(AuditEvent(
            id="pg-audit-chain-two", actor="admin", organization_id="org-chain",
            action=AuditAction.EXECUTION_CANCEL_REQUESTED, object_type="execution_request",
            object_id="request-chain", result="SUCCESS", details={"step": 2},
            correlation_id="corr-chain",
        ))
        with manager._connection_scope() as conn:
            events = conn.execute(
                "SELECT id, timestamp, action, object_type, object_id, result, actor, organization_id, "
                "details_json, correlation_id, previous_event_hash, event_hash, sequence_number "
                "FROM audit_events ORDER BY sequence_number",
            ).fetchall()
        assert len(events) == 2
        assert [event["id"] for event in events] == ["pg-audit-chain-one", "pg-audit-chain-two"]
        assert all(event["organization_id"] == "org-chain" for event in events)
        assert all(event["object_type"] == "execution_request" for event in events)
        assert all(event["object_id"] == "request-chain" for event in events)
        assert all(event["actor"] == "admin" and event["result"] == "SUCCESS" for event in events)
        assert all(event["correlation_id"] == "corr-chain" for event in events)
        assert [event["action"] for event in events] == [
            "EXECUTION_REQUESTED", "EXECUTION_CANCEL_REQUESTED",
        ]
        for event in events:
            _assert_audit_event_hash(event)
        assert events[0]["sequence_number"] == 1
        assert events[0]["previous_event_hash"] is None
        assert events[1]["sequence_number"] == 2
        assert events[1]["previous_event_hash"] == events[0]["event_hash"]
        assert manager.verify_audit_log_integrity() == (True, None)


def test_postgres_audit_chain_detects_details_json_tampering():
    with _isolated_manager() as manager:
        manager.record_audit_event(AuditEvent(
            id="pg-audit-tamper-one", actor="admin", organization_id="org-tamper",
            action=AuditAction.EXECUTION_REQUESTED, object_type="execution_request",
            object_id="request-tamper", result="SUCCESS", details={"step": 1},
            correlation_id="corr-tamper",
        ))
        with manager._connection_scope() as conn:
            conn.execute(
                "UPDATE audit_events SET details_json = %s WHERE id = %s",
                ('{ "step": 1 }', "pg-audit-tamper-one"),
            )
        assert manager.verify_audit_log_integrity() == (False, "pg-audit-tamper-one")


def test_postgres_migration_rejects_duplicate_runs_before_recording_version():
    with _isolated_manager() as manager:
        _seed_request_and_run(manager)
        with manager._connection_scope() as conn:
            conn.execute("DROP INDEX uq_execution_runs_request")
            conn.execute("""
                INSERT INTO execution_runs (
                    execution_id, request_id, organization_id, state,
                    assurance_state, coverage_state, created_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, ("run-preflight-duplicate", "request-preflight", "org-preflight", "FAILED", "UNVERIFIED", "UNAVAILABLE", "2026-01-01T00:00:01+00:00"))
            conn.execute("DELETE FROM schema_migrations WHERE version = 1")
            conn.execute("DELETE FROM schema_migrations WHERE version = 2")
        with pytest.raises(ValueError, match="duplicate runs"):
            PostgresDatabaseManager(manager.database_url)


def test_postgres_migration_rejects_orphaned_run_before_recording_version():
    with _isolated_manager() as manager:
        _drop_execution_run_foreign_keys(manager)
        with manager._connection_scope() as conn:
            conn.execute("DROP INDEX uq_execution_runs_request")
            conn.execute("""
                INSERT INTO execution_runs (
                    execution_id, request_id, organization_id, state,
                    assurance_state, coverage_state, created_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, ("run-preflight-orphan", "missing-request", "missing-org", "FAILED", "UNVERIFIED", "UNAVAILABLE", "2026-01-01T00:00:00+00:00"))
            conn.execute("DELETE FROM schema_migrations WHERE version = 1")
            conn.execute("DELETE FROM schema_migrations WHERE version = 2")
        with pytest.raises(ValueError, match="orphaned or cross-tenant"):
            PostgresDatabaseManager(manager.database_url)
        with psycopg.connect(manager.database_url, autocommit=True) as connection:
            assert connection.execute("SELECT 1 FROM schema_migrations WHERE version IN (1, 2)").fetchone() is None


def test_postgres_migration_rejects_cross_tenant_run_reference():
    with _isolated_manager() as manager:
        _seed_request_and_run(manager)
        _drop_execution_run_foreign_keys(manager)
        with manager._connection_scope() as conn:
            conn.execute(
                "INSERT INTO organizations (id, name, slug, created_at) VALUES (%s, %s, %s, %s)",
                ("org-other", "Other Org", "other-org", "2026-01-01T00:00:00+00:00"),
            )
            conn.execute("DROP INDEX uq_execution_runs_request")
            conn.execute("""
                INSERT INTO execution_runs (
                    execution_id, request_id, organization_id, state,
                    assurance_state, coverage_state, created_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, ("run-cross-tenant", "request-preflight", "org-other", "FAILED", "UNVERIFIED", "UNAVAILABLE", "2026-01-01T00:00:00+00:00"))
            conn.execute("DELETE FROM schema_migrations WHERE version = 1")
            conn.execute("DELETE FROM schema_migrations WHERE version = 2")
        with pytest.raises(ValueError, match="orphaned or cross-tenant"):
            PostgresDatabaseManager(manager.database_url)
        with psycopg.connect(manager.database_url, autocommit=True) as connection:
            assert connection.execute("SELECT 1 FROM schema_migrations WHERE version IN (1, 2)").fetchone() is None
