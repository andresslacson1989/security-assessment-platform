"""Adversarial tests for the durable worker execution-decision boundary."""

from datetime import datetime, timedelta, timezone
import hashlib
import inspect
import json
import sqlite3

import pytest

from app.core.execution_decision import ExecutionDecisionError, issue_execution_capability
from app.core.db import DatabaseManager
from app.core.migration_registry import MIGRATION_REGISTRY, _EXPECTED_CHECKSUMS
from app.core.migration_artifacts import FORWARD_APPLY_ARTIFACT_REVISION
from app.core.models import AuditAction, AuditEvent, ExecutionDecisionRecord, ExecutionLeaseClaim, ExecutionRunRecord, Target, TargetType
from app.core.models import UserProfile, UserRole
from app.core.ssrf_protector import create_validated_target
from app.core.tool_operation_policy import OPERATION_POLICY_REVISION


def _assert_audit_event_hash(event):
    details = event["details_json"]
    canonical = "|".join(str(value) for value in (
        event["id"], event["timestamp"], event["actor"], event["organization_id"],
        event["action"], event["object_type"], event["object_id"], event["result"],
        details, event["previous_event_hash"] or "",
    ))
    assert event["event_hash"] == hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class FakeDecisionStore:
    def __init__(self, decision, revoked=False):
        self.decision = decision
        self.revoked = revoked

    def get_execution_decision(self, decision_id, organization_id=None):
        if decision_id != self.decision.id or organization_id != self.decision.organization_id:
            return None
        return self.decision

    def is_token_revoked(self, _jti):
        return self.revoked

    def claim_execution_decision(self, decision_id, organization_id, session_jti, worker_identity, policy_revision, now=None):
        if self.revoked or self.decision.consumed_at is not None:
            return None
        lease_time = now or datetime.now(timezone.utc)
        self.decision = self.decision.model_copy(update={"claim_owner": worker_identity, "claim_token": "test-claim", "claim_expires_at": lease_time + timedelta(seconds=30)})
        return ExecutionLeaseClaim(token="test-claim", owner=worker_identity, expires_at=lease_time + timedelta(seconds=30))


def _target():
    return create_validated_target(
        Target(name="AWS account", type=TargetType.CLOUD_ACCOUNT, value="aws://123456789012"),
        organization_id="org-a", project_id="project-a", asset_id="asset-a",
        active_probing_granted=True,
    )


def test_migration_registry_has_fixed_executable_verifier_vectors():
    assert [spec.version for spec in MIGRATION_REGISTRY] == list(range(1, 10))
    assert all(callable(spec.apply) and callable(spec.reconcile) for spec in MIGRATION_REGISTRY)
    assert all(spec.apply_artifact.startswith("sha256:") and len(spec.apply_artifact) == 71 for spec in MIGRATION_REGISTRY)
    assert all(callable(spec.verify) for spec in MIGRATION_REGISTRY)
    assert {spec.version: spec.checksum for spec in MIGRATION_REGISTRY} == _EXPECTED_CHECKSUMS


def test_fresh_database_records_one_durable_outcome_per_registered_migration(tmp_path):
    database = DatabaseManager(tmp_path / "coordinator.sqlite3")
    with database._connection_scope() as conn:
        rows = conn.execute(
            "SELECT migration_version, event_sequence, event_type, context_json "
            "FROM schema_migration_events ORDER BY migration_version, event_sequence"
        ).fetchall()

    assert [(row["migration_version"], row["event_sequence"], row["event_type"]) for row in rows] == [
        item for version in range(1, 10) for item in ((version, 1, "STARTED"), (version, 2, "SUCCEEDED"))
    ]
    for row in rows:
        context = json.loads(row["context_json"])
        assert context["coordinator"] == "registry"
        assert context["provenance_format"] == "registry-coordinator-v2"
        assert context["apply_artifact_revision"] == "execution-migration-apply-v1"
        assert context["apply_artifact"].startswith("sha256:")
        assert context["apply_manifest"]


def test_forward_apply_artifact_vectors_match_runtime_serialization():
    for spec in MIGRATION_REGISTRY:
        for backend in ("sqlite", "postgresql"):
            material = "\n".join((
                inspect.getsource(DatabaseManager._init_db),
                inspect.getsource(DatabaseManager._apply_migration_version),
                FORWARD_APPLY_ARTIFACT_REVISION,
                json.dumps(spec.apply_manifest, sort_keys=True, separators=(",", ":")),
                backend,
            )).encode("utf-8")
            actual = "sha256:" + hashlib.sha256(material).hexdigest()
            assert spec.apply_artifact[backend] == actual


def test_migration_provenance_rejects_malformed_or_mismatched_transaction_context():
    manager = DatabaseManager.__new__(DatabaseManager)
    spec = MIGRATION_REGISTRY[0]
    digest = spec.apply_artifact["sqlite"].split(":", 1)[1]
    context = {
        "coordinator": "registry",
        "provenance_format": "registry-coordinator-v2",
        "apply_artifact_revision": "execution-migration-apply-v1",
        "apply_artifact": spec.apply_artifact["sqlite"],
        "apply_artifacts": spec.apply_artifact,
        "apply_manifest": spec.apply_manifest,
        "backend_policy": spec.backend_policy,
    }
    row = {"transaction_context_id": f"txp-0123456789abcdef0123456789abcdef-{digest}"}
    manager._validate_migration_event_provenance(row, spec, context)

    for transaction_context_id in (
        f"txp-not-a-uuid-{digest}",
        f"txp-0123456789abcdef0123456789abcdef-{'0' * 64}",
    ):
        with pytest.raises(RuntimeError, match="transaction provenance identity"):
            manager._validate_migration_event_provenance({"transaction_context_id": transaction_context_id}, spec, context)

    with pytest.raises(RuntimeError, match="partial forward-apply provenance"):
        manager._validate_migration_event_provenance(
            {"transaction_context_id": f"tx-{'1' * 32}"}, spec, {"apply_artifact": spec.apply_artifact["sqlite"]}
        )

    for tampered_context in (
        {key: value for key, value in context.items() if key != "coordinator"},
        {**context, "coordinator": "operator"},
    ):
        with pytest.raises(RuntimeError, match="forward-apply provenance|provenance identity"):
            manager._validate_migration_event_provenance({"transaction_context_id": f"txp-{'2' * 32}-{digest}"}, spec, tampered_context)

    for transaction_context_id in ("tx-legacy", "tx-1"):
        with pytest.raises(RuntimeError, match="transaction context format"):
            manager._validate_migration_event_provenance({"transaction_context_id": transaction_context_id}, spec, {})

    legacy_context_with_claim = {"coordinator": "operator", "apply_artifact": spec.apply_artifact["sqlite"]}
    with pytest.raises(RuntimeError, match="partial forward-apply provenance"):
        manager._validate_migration_event_provenance({"transaction_context_id": f"tx-{'3' * 32}"}, spec, legacy_context_with_claim)


def test_v7_dispatch_postcondition_rejects_v8_lease_shape():
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    connection.executescript("""
        PRAGMA foreign_keys = ON;
        CREATE TABLE organizations (id TEXT PRIMARY KEY);
        CREATE TABLE execution_runs (
            execution_id TEXT NOT NULL, organization_id TEXT NOT NULL,
            PRIMARY KEY (execution_id), UNIQUE (execution_id, organization_id)
        );
        CREATE TABLE execution_dispatch_intents (
            execution_id TEXT NOT NULL PRIMARY KEY, organization_id TEXT NOT NULL,
            state TEXT NOT NULL DEFAULT 'PENDING' CHECK (state IN ('PENDING','CLAIMED','COMPLETED','FAILED','BLOCKED')),
            attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
            created_at TEXT NOT NULL, claimed_at TEXT, completed_at TEXT, last_error TEXT,
            FOREIGN KEY (execution_id, organization_id) REFERENCES execution_runs(execution_id, organization_id),
            FOREIGN KEY (organization_id) REFERENCES organizations(id)
        );
    """)
    manager = DatabaseManager.__new__(DatabaseManager)
    manager._verify_migration_v7_postconditions(connection)
    connection.execute("ALTER TABLE execution_dispatch_intents ADD COLUMN claimed_by TEXT")
    with pytest.raises(RuntimeError, match="pre-lease target"):
        manager._verify_migration_v7_postconditions(connection)
    for column in ("claim_token", "lease_expires_at", "correlation_id"):
        connection.execute(f"ALTER TABLE execution_dispatch_intents ADD COLUMN {column} TEXT")
    manager._verify_migration_v8_postconditions(connection)


def test_v9_repairs_an_already_applied_legacy_parent_index_and_is_idempotent(tmp_path):
    path = tmp_path / "legacy-parent-index.sqlite3"
    database = DatabaseManager(path)
    with database._connection_scope() as connection:
        connection.execute("CREATE UNIQUE INDEX uq_execution_requests_id_org ON execution_requests(id, organization_id)")
        connection.execute("DELETE FROM schema_migrations WHERE version = 9")

    repaired = DatabaseManager(path)
    with repaired._connection_scope() as connection:
        assert connection.execute("SELECT 1 FROM pragma_index_list('execution_requests') WHERE name = 'uq_execution_requests_id_org'").fetchone() is None
        assert connection.execute("SELECT 1 FROM schema_migrations WHERE version = 9").fetchone() is not None
        success_count = connection.execute("SELECT COUNT(*) AS count FROM schema_migration_events WHERE migration_version = 9 AND event_type = 'SUCCEEDED'").fetchone()["count"]

    DatabaseManager(path)
    with repaired._connection_scope() as connection:
        assert connection.execute("SELECT COUNT(*) AS count FROM schema_migration_events WHERE migration_version = 9 AND event_type = 'SUCCEEDED'").fetchone()["count"] == success_count


def test_v9_rejects_an_ambiguous_same_name_parent_index(tmp_path):
    path = tmp_path / "ambiguous-parent-index.sqlite3"
    database = DatabaseManager(path)
    with database._connection_scope() as connection:
        connection.execute("CREATE INDEX uq_execution_requests_id_org ON execution_requests(organization_id, id)")
        connection.execute("DELETE FROM schema_migrations WHERE version = 9")

    with pytest.raises(ValueError, match="ambiguous migration-owned artifact"):
        DatabaseManager(path)


def _decision(target, **changes):
    values = {
        "id": "decision-1",
        "organization_id": target.organization_id,
        "project_id": target.project_id,
        "asset_id": target.asset_id,
        "target_id": target.target_id,
        "authorization_decision_id": target.authorization_decision_id,
        "target_policy_version": target.policy_version,
        "tool_id": "prowler",
        "operation_family": "cloud_audit",
        "operation_options": {"provider": "aws", "output_format": "json-asff", "quiet": True},
        "operation_policy_revision": OPERATION_POLICY_REVISION,
        "approval_state": "APPROVED",
        "approver_user_id": "admin-1",
        "session_jti": "session-1",
        "worker_identity": "worker-1",
        "resource_budget": {"timeout_seconds": 120, "max_output_bytes": 10485760},
        "account_impact_budget": {"read_only": 1},
        "credential_scope": {"provider": "aws"},
        "expires_at": datetime.now(timezone.utc) + timedelta(minutes=5),
    }
    values.update(changes)
    return ExecutionDecisionRecord(**values)


def test_migration_ledger_records_registry_identity(tmp_path):
    database = DatabaseManager(tmp_path / "identity.sqlite3")
    with database._connection_scope() as conn:
        rows = conn.execute(
            "SELECT migration_version, migration_id, registry_revision, event_type "
            "FROM schema_migration_events ORDER BY rowid"
        ).fetchall()

    assert rows
    expected = {spec.version: (spec.migration_id, spec.registry_revision) for spec in MIGRATION_REGISTRY}
    assert all((row["migration_id"], row["registry_revision"]) == expected[row["migration_version"]] for row in rows)
    assert {row["event_type"] for row in rows} == {"STARTED", "SUCCEEDED"}


def test_legacy_migration_ledger_is_upgraded_with_verified_identity(tmp_path):
    path = tmp_path / "legacy-ledger.sqlite3"
    spec = next(spec for spec in MIGRATION_REGISTRY if spec.version == 8)
    conn = sqlite3.connect(path)
    conn.executescript("""
        CREATE TABLE schema_migration_events (
            event_id TEXT PRIMARY KEY, attempt_id TEXT NOT NULL, migration_version INTEGER NOT NULL,
            migration_name TEXT NOT NULL, event_type TEXT NOT NULL, event_at TEXT NOT NULL,
            backend TEXT NOT NULL, schema_name TEXT NOT NULL, previous_schema_version INTEGER,
            target_schema_version INTEGER NOT NULL, migration_checksum TEXT NOT NULL,
            runner_identity TEXT NOT NULL, transaction_context_id TEXT NOT NULL,
            error_code TEXT, error_class TEXT, error_message TEXT,
            context_json TEXT NOT NULL DEFAULT '{}', rollback_status TEXT NOT NULL,
            UNIQUE (attempt_id, event_type)
        );
    """)
    conn.execute(
        "INSERT INTO schema_migration_events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ("event-1", "attempt-1", 8, spec.name, "STARTED", "2026-01-01T00:00:00+00:00", "SQLITE", "legacy", 7, 8, spec.checksum, "test", f"tx-{'1' * 32}", None, None, None, "{}", "PENDING"),
    )
    conn.execute(
        "INSERT INTO schema_migration_events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ("event-2", "attempt-1", 8, spec.name, "SUCCEEDED", "2026-01-01T00:00:01+00:00", "SQLITE", "legacy", 7, 8, spec.checksum, "test", f"tx-{'1' * 32}", None, None, None, "{}", "NOT_APPLICABLE"),
    )
    conn.commit()
    conn.close()

    DatabaseManager(path)
    with sqlite3.connect(path) as upgraded:
        upgraded.row_factory = sqlite3.Row
        row = upgraded.execute(
            "SELECT migration_id, registry_revision FROM schema_migration_events WHERE event_id = 'event-1'"
        ).fetchone()

    assert (row["migration_id"], row["registry_revision"]) == (spec.migration_id, spec.registry_revision)


def test_legacy_migration_ledger_fails_closed_on_forged_identity(tmp_path):
    path = tmp_path / "forged-ledger.sqlite3"
    conn = sqlite3.connect(path)
    conn.executescript("""
        CREATE TABLE schema_migration_events (
            event_id TEXT PRIMARY KEY, attempt_id TEXT NOT NULL, migration_version INTEGER NOT NULL,
            migration_name TEXT NOT NULL, event_type TEXT NOT NULL, event_at TEXT NOT NULL,
            backend TEXT NOT NULL, schema_name TEXT NOT NULL, previous_schema_version INTEGER,
            target_schema_version INTEGER NOT NULL, migration_checksum TEXT NOT NULL,
            runner_identity TEXT NOT NULL, transaction_context_id TEXT NOT NULL,
            error_code TEXT, error_class TEXT, error_message TEXT,
            context_json TEXT NOT NULL DEFAULT '{}', rollback_status TEXT NOT NULL,
            UNIQUE (attempt_id, event_type)
        );
    """)
    conn.execute(
        "INSERT INTO schema_migration_events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ("event-1", "attempt-1", 8, "FORGED-NAME", "SUCCEEDED", "2026-01-01T00:00:00+00:00", "SQLITE", "legacy", 7, 8, "sha256:forged", "test", f"tx-{'2' * 32}", None, None, None, "{}", "NOT_APPLICABLE"),
    )
    conn.commit()
    conn.close()

    with pytest.raises(RuntimeError, match="identity mismatch"):
        DatabaseManager(path)

    with sqlite3.connect(path) as unchanged:
        row = unchanged.execute(
            "SELECT migration_name, migration_checksum FROM schema_migration_events WHERE event_id = 'event-1'"
        ).fetchone()
    assert row == ("FORGED-NAME", "sha256:forged")


def test_current_migration_ledger_fails_closed_on_row_tampering(tmp_path):
    path = tmp_path / "current-ledger.sqlite3"
    DatabaseManager(path)
    conn = sqlite3.connect(path)
    conn.executescript("DROP TRIGGER schema_migration_events_no_update; DROP TRIGGER schema_migration_events_no_delete;")
    conn.execute("UPDATE schema_migration_events SET migration_checksum = 'sha256:forged' WHERE event_type = 'SUCCEEDED'")
    conn.execute("""CREATE TRIGGER schema_migration_events_no_update
        BEFORE UPDATE ON schema_migration_events BEGIN SELECT RAISE(ABORT, 'schema_migration_events is append-only'); END""")
    conn.execute("""CREATE TRIGGER schema_migration_events_no_delete
        BEFORE DELETE ON schema_migration_events BEGIN SELECT RAISE(ABORT, 'schema_migration_events is append-only'); END""")
    conn.commit()
    conn.close()

    with pytest.raises(RuntimeError, match="row identity"):
        DatabaseManager(path)


def test_failure_ledger_sequence_is_causal_when_timestamps_match(tmp_path):
    path = tmp_path / "failure-sequence.sqlite3"
    database = DatabaseManager(path)
    database._migration_attempt_id = "failure-attempt"
    database._migration_transaction_id = "failure-tx"
    database._migration_schema_name = str(path)
    database._migration_spec = MIGRATION_REGISTRY[-1]
    spec = database._migration_spec
    with database._connection_scope() as connection:
        connection.execute(
            "INSERT INTO schema_migration_events (event_id, attempt_id, migration_version, migration_id, migration_name, registry_revision, event_sequence, event_type, event_at, backend, schema_name, previous_schema_version, target_schema_version, migration_checksum, runner_identity, transaction_context_id, context_json, rollback_status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("failure-start", "failure-attempt", spec.version, spec.migration_id, spec.name, spec.registry_revision, 1, "STARTED", "2026-01-01T00:00:00+00:00", "SQLITE", str(path), spec.previous_version, spec.target_version, spec.checksum, "test", "failure-tx", "{}", "PENDING"),
        )
    database._record_migration_failure(RuntimeError("controlled failure"))

    with sqlite3.connect(path) as connection:
        rows = connection.execute(
            "SELECT event_type, event_sequence FROM schema_migration_events "
            "WHERE attempt_id = 'failure-attempt' ORDER BY event_sequence"
        ).fetchall()
    assert rows == [("FAILED", 2), ("ROLLBACK_FAILED", 3)]

    DatabaseManager(path)


def test_orphaned_migration_attempt_is_durably_reconciled(tmp_path):
    path = tmp_path / "orphaned-migration.sqlite3"
    database = DatabaseManager(path)
    spec = MIGRATION_REGISTRY[-1]
    with database._connection_scope() as connection:
        connection.execute(
            "INSERT INTO schema_migration_events (event_id, attempt_id, migration_version, migration_id, migration_name, registry_revision, event_sequence, event_type, event_at, backend, schema_name, previous_schema_version, target_schema_version, migration_checksum, runner_identity, transaction_context_id, context_json, rollback_status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("orphan-start", "orphan-attempt", spec.version, spec.migration_id, spec.name, spec.registry_revision, 1, "STARTED", "2026-01-01T00:00:00+00:00", "SQLITE", str(path), spec.previous_version, spec.target_version, spec.checksum, "test", f"tx-{'4' * 32}", "{}", "PENDING"),
        )

    with pytest.raises(RuntimeError, match="unresolved migration attempt"):
        DatabaseManager(path)
    with sqlite3.connect(path) as connection:
        row = connection.execute(
            "SELECT event_type, event_sequence, rollback_status FROM schema_migration_events WHERE attempt_id = 'orphan-attempt' ORDER BY event_sequence DESC LIMIT 1"
        ).fetchone()
    assert row == ("RECONCILIATION_REQUIRED", 2, "UNKNOWN")


def test_dispatch_reaper_closes_expired_request_and_lease_without_success(tmp_path):
    from app.core.db import DatabaseManager
    from app.core.correlation import reset_correlation_id, set_correlation_id

    database = DatabaseManager(tmp_path / "dispatch-reaper.db")
    now = datetime.now(timezone.utc)
    now_text = now.isoformat()
    expires = (now + timedelta(minutes=5)).isoformat()
    options = json.dumps({"provider": "aws", "output_format": "json-asff", "quiet": True}, separators=(",", ":"), sort_keys=True)
    budget = json.dumps({"timeout_seconds": 120, "max_output_bytes": 10485760}, separators=(",", ":"), sort_keys=True)
    account_budget = json.dumps({"read_only": 1}, separators=(",", ":"), sort_keys=True)
    credentials = json.dumps({"provider": "aws"}, separators=(",", ":"), sort_keys=True)
    with database._connection_scope() as conn:
        conn.execute("INSERT INTO organizations (id, name, slug, created_at, is_active) VALUES ('org-r', 'Org R', 'org-r', ?, 1)", (now_text,))
        conn.execute("INSERT INTO assets (id, organization_id, name, type, target_value, active_probing_granted, created_at, updated_at) VALUES ('asset-r', 'org-r', 'asset', 'CLOUD_ACCOUNT', 'aws://123456789012', 1, ?, ?)", (now_text, now_text))
        conn.execute("INSERT INTO users (id, username, email, hashed_password, role, organization_id, is_active, created_at) VALUES ('admin-r', 'admin-r', 'r@example.test', 'hash', 'ADMIN', 'org-r', 1, ?)", (now_text,))
        conn.execute(
            "INSERT INTO execution_requests (id, idempotency_key, request_fingerprint, organization_id, asset_id, target_id, authorization_decision_id, target_policy_version, tool_id, operation_family, operation_options_json, operation_policy_revision, resource_budget_json, account_impact_budget_json, credential_scope_json, requested_by_user_id, state, created_at, expires_at) VALUES (?, 'idem-r', ?, 'org-r', 'asset-r', 'target-r', 'auth-r', 'v1', 'prowler', 'cloud_audit', ?, ?, ?, ?, ?, 'admin-r', 'REQUESTED', ?, ?)",
            ("req-r", "f" * 64, options, OPERATION_POLICY_REVISION, budget, account_budget, credentials, now_text, expires),
        )
    token = set_correlation_id("corr-reaper")
    try:
        result, _decision_id, execution_id = database.approve_execution_request(
            "req-r", "org-r", "f" * 64, "approval-r", "admin-r", "session-r", "worker-r",
        )
    finally:
        reset_correlation_id(token)
    assert result == "AUTHORIZED"
    lease = database.claim_execution_dispatch_intent(execution_id, "org-r", "worker-r")
    assert lease is not None
    past = (now - timedelta(minutes=1)).isoformat()
    with database._connection_scope() as conn:
        conn.execute("UPDATE execution_requests SET expires_at = ? WHERE id = ?", (past, "req-r"))
        conn.execute("UPDATE execution_dispatch_intents SET lease_expires_at = ? WHERE execution_id = ?", (past, execution_id))
    assert database.claim_execution_dispatch_intent(execution_id, "org-r", "worker-r") is None
    assert database.reap_execution_dispatch(
        execution_id, "org-r", terminal_state="TIMED_OUT", reason_code="EXECUTION_AUTHORITY_EXPIRED",
    ) is True
    with database._connection_scope() as conn:
        run = conn.execute("SELECT state, reason_code FROM execution_runs WHERE execution_id = ?", (execution_id,)).fetchone()
        intent = conn.execute("SELECT state, last_error, claim_token FROM execution_dispatch_intents WHERE execution_id = ?", (execution_id,)).fetchone()
    assert run == ("TIMED_OUT", "EXECUTION_AUTHORITY_EXPIRED")
    assert intent == ("FAILED", "EXECUTION_AUTHORITY_EXPIRED", None)


def _issue(store, target, **kwargs):
    import os
    os.environ["CYBERASSESS_WORKER_IDENTITY"] = "worker-1"
    options = {"provider": "aws", "output_format": "json-asff", "quiet": True}
    options.update(kwargs.pop("operation_options", {}))
    return issue_execution_capability(
        decision_id="decision-1", validated_target=target, tool_id="prowler",
        operation_family="cloud_audit", operation_options=options,
        command=["/managed/prowler", "aws", "-M", "json-asff"],
        worker_identity="worker-1", database=store,
    )


def test_factory_issued_capability_binds_exact_request(monkeypatch):
    monkeypatch.setenv("CYBERASSESS_WORKER_IDENTITY", "worker-1")
    target = _target()
    capability = _issue(FakeDecisionStore(_decision(target)), target)
    capability.assert_valid_for_launch(
        tool_id="prowler", operation_family="cloud_audit",
        operation_options={"provider": "aws", "output_format": "json-asff", "quiet": True},
        command=["/managed/prowler", "aws", "-M", "json-asff"], worker_identity="worker-1",
    )
    with pytest.raises(ExecutionDecisionError):
        capability.assert_valid_for_launch(
            tool_id="sqlmap", operation_family="cloud_audit",
            operation_options={"provider": "aws", "output_format": "json-asff", "quiet": True},
            command=["/managed/prowler", "aws", "-M", "json-asff"], worker_identity="worker-1",
        )


def test_launch_revalidation_consumes_decision_once_and_enforces_budget(monkeypatch):
    monkeypatch.setenv("CYBERASSESS_WORKER_IDENTITY", "worker-1")
    target = _target()
    store = FakeDecisionStore(_decision(target))
    capability = _issue(store, target)
    options = {"provider": "aws", "output_format": "json-asff", "quiet": True}
    command = ["/managed/prowler", "aws", "-M", "json-asff"]

    capability.revalidate_and_claim(
        tool_id="prowler", operation_family="cloud_audit", operation_options=options,
        command=command, worker_identity="worker-1", timeout=120, max_output_bytes=10485760,
    )
    with pytest.raises(ExecutionDecisionError, match="consumed|changed"):
        capability.revalidate_and_claim(
            tool_id="prowler", operation_family="cloud_audit", operation_options=options,
            command=command, worker_identity="worker-1", timeout=120, max_output_bytes=10485760,
        )


def test_launch_revalidation_rejects_expired_or_over_budget_decision(monkeypatch):
    monkeypatch.setenv("CYBERASSESS_WORKER_IDENTITY", "worker-1")
    target = _target()
    store = FakeDecisionStore(_decision(target))
    capability = _issue(store, target)
    with pytest.raises(ExecutionDecisionError, match="budget"):
        capability.revalidate_and_claim(
            tool_id="prowler", operation_family="cloud_audit",
            operation_options={"provider": "aws", "output_format": "json-asff", "quiet": True},
            command=["/managed/prowler", "aws", "-M", "json-asff"],
            worker_identity="worker-1", timeout=121, max_output_bytes=10485760,
        )
    store.decision = store.decision.model_copy(update={"expires_at": datetime.now(timezone.utc) - timedelta(seconds=1)})
    with pytest.raises(ExecutionDecisionError, match="changed|expired"):
        capability.revalidate_and_claim(
            tool_id="prowler", operation_family="cloud_audit",
            operation_options={"provider": "aws", "output_format": "json-asff", "quiet": True},
            command=["/managed/prowler", "aws", "-M", "json-asff"],
            worker_identity="worker-1", timeout=120, max_output_bytes=10485760,
        )


@pytest.mark.parametrize("changes", [
    {"approval_state": "REVOKED"},
    {"expires_at": datetime.now(timezone.utc) - timedelta(seconds=1)},
    {"organization_id": "org-other"},
    {"tool_id": "sqlmap"},
    {"operation_family": "sql_injection"},
])
def test_decision_mismatch_or_expiry_fails_closed(monkeypatch, changes):
    monkeypatch.setenv("CYBERASSESS_WORKER_IDENTITY", "worker-1")
    target = _target()
    store = FakeDecisionStore(_decision(target, **changes), revoked=changes.get("approval_state") == "REVOKED")
    with pytest.raises(ExecutionDecisionError):
        _issue(store, target)


def test_revoked_approver_session_fails_closed(monkeypatch):
    monkeypatch.setenv("CYBERASSESS_WORKER_IDENTITY", "worker-1")
    target = _target()
    with pytest.raises(ExecutionDecisionError):
        _issue(FakeDecisionStore(_decision(target), revoked=True), target)


def test_sqlite_standalone_decision_cannot_enter_execution_dispatch(tmp_path):
    from app.core.db import DatabaseManager

    database = DatabaseManager(tmp_path / "authority.db")
    now = datetime.now(timezone.utc).isoformat()
    with database._connection_scope() as conn:
        conn.execute("INSERT INTO organizations (id, name, slug, created_at, is_active) VALUES (?, ?, ?, ?, 1)", ("org-a", "Org A", "org-a", now))
        conn.execute("INSERT INTO projects (id, organization_id, name, created_at) VALUES (?, ?, ?, ?)", ("project-a", "org-a", "Project A", now))
        conn.execute("INSERT INTO assets (id, organization_id, project_id, name, type, target_value, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", ("asset-a", "org-a", "project-a", "AWS account", "CLOUD_ACCOUNT", "aws://123456789012", now, now))
        conn.execute("INSERT INTO users (id, username, email, hashed_password, role, organization_id, is_active, created_at) VALUES (?, ?, ?, ?, 'ADMIN', ?, 1, ?)", ("admin-1", "admin", "admin@example.test", "hash", "org-a", now))

    target = _target()
    decision = _decision(target)
    database.create_execution_decision(decision)
    assert database.get_execution_decision(decision.id, organization_id="org-a").id == decision.id
    assert database.claim_execution_decision(decision.id, "org-a", "session-1", "worker-1", OPERATION_POLICY_REVISION) is None
    assert not database.claim_execution_decision(decision.id, "org-a", "session-1", "worker-1", OPERATION_POLICY_REVISION)
    assert database.claim_execution_decision(decision.id, "org-a", "wrong-session", "worker-1", OPERATION_POLICY_REVISION) is None
    stored = database.get_execution_decision(decision.id, organization_id="org-a")
    assert stored.consumed_at is None
    assert stored.claim_owner is None
    assert stored.claim_token is None
    events, _ = database.list_audit_events(organization_id="org-a", limit=20)
    assert {event.action.value for event in events} >= {
        "EXECUTION_DECISION_CREATED", "EXECUTION_DECISION_CLAIM_REJECTED",
    }


def test_approval_atomically_creates_one_durable_execution_run(tmp_path):
    from app.core.db import DatabaseManager
    from app.core.correlation import reset_correlation_id, set_correlation_id

    database = DatabaseManager(tmp_path / "approval-run.db")
    now = datetime.now(timezone.utc).isoformat()
    expires = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
    options = json.dumps({"provider": "aws", "output_format": "json-asff", "quiet": True}, separators=(",", ":"), sort_keys=True)
    budget = json.dumps({"timeout_seconds": 120, "max_output_bytes": 10485760}, separators=(",", ":"), sort_keys=True)
    account_budget = json.dumps({"read_only": 1}, separators=(",", ":"), sort_keys=True)
    credentials = json.dumps({"provider": "aws"}, separators=(",", ":"), sort_keys=True)
    with database._connection_scope() as conn:
        conn.execute("INSERT INTO organizations (id, name, slug, created_at, is_active) VALUES (?, ?, ?, ?, 1)", ("org-a", "Org A", "org-a", now))
        conn.execute("INSERT INTO assets (id, organization_id, name, type, target_value, active_probing_granted, created_at, updated_at) VALUES (?, ?, ?, 'CLOUD_ACCOUNT', ?, 1, ?, ?)", ("asset-a", "org-a", "asset", "aws://123456789012", now, now))
        conn.execute("INSERT INTO users (id, username, email, hashed_password, role, organization_id, is_active, created_at) VALUES (?, ?, ?, 'hash', 'ADMIN', ?, 1, ?)", ("admin-a", "admin", "admin@example.test", "org-a", now))
        conn.execute(
            "INSERT INTO execution_requests (id, idempotency_key, request_fingerprint, organization_id, asset_id, target_id, authorization_decision_id, target_policy_version, tool_id, operation_family, operation_options_json, operation_policy_revision, resource_budget_json, account_impact_budget_json, credential_scope_json, requested_by_user_id, state, created_at, expires_at) "
            "VALUES (?, ?, ?, 'org-a', 'asset-a', 'target-a', 'auth-a', 'v1', 'prowler', 'cloud_audit', ?, ?, ?, ?, ?, 'admin-a', 'REQUESTED', ?, ?)",
            ("req-a", "idem-a", "f" * 64, options, OPERATION_POLICY_REVISION, budget, account_budget, credentials, now, expires),
        )

    token = set_correlation_id("corr-approval-run")
    try:
        result, decision_id, execution_id = database.approve_execution_request(
            "req-a", "org-a", "f" * 64, "approval-idem", "admin-a", "session-a", "worker-a",
        )
        assert result == "AUTHORIZED"
        assert decision_id
        assert execution_id.startswith("run-")
        replay = database.approve_execution_request(
            "req-a", "org-a", "f" * 64, "approval-idem", "admin-a", "session-a", "worker-a",
        )
    finally:
        reset_correlation_id(token)
    assert replay == ("REPLAY", decision_id, execution_id)
    with database._connection_scope() as conn:
        runs = conn.execute(
            "SELECT execution_id, request_id, organization_id, approved_decision_id, target_policy_version, "
            "operation_policy_revision, request_fingerprint, operation_options_json, resource_budget_json, "
            "account_impact_budget_json, credential_scope_json, state, worker_identity, assurance_state, "
            "coverage_state, correlation_id FROM execution_runs WHERE request_id = ? AND organization_id = ?",
            ("req-a", "org-a"),
        ).fetchall()
        run_events = conn.execute(
            "SELECT action, object_type, organization_id, correlation_id, details_json FROM audit_events "
            "WHERE object_type = 'execution_run' AND organization_id = ?",
            ("org-a",),
        ).fetchall()
        intents = conn.execute(
            "SELECT execution_id, organization_id, state, attempt_count FROM execution_dispatch_intents WHERE execution_id = ?",
            (execution_id,),
        ).fetchall()
    assert len(runs) == 1
    assert runs[0]["request_id"] == "req-a"
    assert runs[0]["approved_decision_id"] == decision_id
    assert runs[0]["target_policy_version"] == "v1"
    assert runs[0]["operation_policy_revision"] == OPERATION_POLICY_REVISION
    assert runs[0]["request_fingerprint"] == "f" * 64
    assert json.loads(runs[0]["operation_options_json"]) == {"output_format": "json-asff", "provider": "aws", "quiet": True}
    assert json.loads(runs[0]["resource_budget_json"]) == {"max_output_bytes": 10485760, "timeout_seconds": 120}
    assert json.loads(runs[0]["account_impact_budget_json"]) == {"read_only": 1}
    assert json.loads(runs[0]["credential_scope_json"]) == {"provider": "aws"}
    assert runs[0]["state"] == "REQUESTED"
    assert runs[0]["worker_identity"] == "worker-a"
    assert runs[0]["assurance_state"] == "UNVERIFIED"
    assert runs[0]["coverage_state"] == "UNAVAILABLE"
    assert runs[0]["correlation_id"] == "corr-approval-run"
    assert len(intents) == 1
    assert intents[0]["execution_id"] == execution_id
    assert intents[0]["organization_id"] == "org-a"
    assert intents[0]["state"] == "PENDING"
    assert intents[0]["attempt_count"] == 0
    assert len(run_events) == 1
    assert run_events[0]["action"] == AuditAction.EXECUTION_RUN_CREATED.value
    assert run_events[0]["object_type"] == "execution_run"
    assert run_events[0]["correlation_id"] == "corr-approval-run"

    authority = database.claim_execution_authority(
        decision_id, "org-a", "session-a", "worker-a", OPERATION_POLICY_REVISION,
    )
    assert authority is not None
    assert authority.execution_id == execution_id
    assert authority.correlation_id == "corr-approval-run"
    assert authority.decision.owner == "worker-a"
    assert authority.dispatch.owner == "worker-a"
    assert database.release_execution_authority(
        decision_id, "org-a", "worker-a", authority.decision.token, authority.dispatch.token,
    )
    with database._connection_scope() as conn:
        lifecycle_events = conn.execute(
            "SELECT action, correlation_id FROM audit_events WHERE organization_id = ? AND object_id IN (?, ?) ORDER BY sequence_number",
            ("org-a", decision_id, execution_id),
        ).fetchall()
    assert lifecycle_events
    assert {event["correlation_id"] for event in lifecycle_events} == {"corr-approval-run"}

    stale = database.claim_execution_authority(
        decision_id, "org-a", "session-a", "worker-a", OPERATION_POLICY_REVISION,
    )
    assert stale is not None
    with database._connection_scope() as conn:
        expired_claim = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
        conn.execute(
            "UPDATE execution_decisions SET claim_owner = ?, claim_expires_at = ? WHERE id = ? AND organization_id = ?",
            ("crashed-worker", expired_claim, decision_id, "org-a"),
        )
    recovered = database.claim_execution_authority(
        decision_id, "org-a", "session-a", "worker-a", OPERATION_POLICY_REVISION,
        dispatch_claim_token=stale.dispatch.token,
    )
    assert recovered is not None
    assert recovered.decision.token != stale.decision.token
    assert database.release_execution_authority(
        decision_id, "org-a", "worker-a", recovered.decision.token, recovered.dispatch.token,
    )

    decision_claim = database.claim_execution_decision(
        decision_id, "org-a", "session-a", "worker-a", OPERATION_POLICY_REVISION,
    )
    assert decision_claim is not None
    with database._connection_scope() as conn:
        conn.execute(
            "UPDATE execution_requests SET expires_at = ? WHERE id = ? AND organization_id = ?",
            ((datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(), "req-a", "org-a"),
        )
    assert not database.mark_execution_decision_started(
        decision_id, "org-a", "worker-a", decision_claim.token,
    )
    with database._connection_scope() as conn:
        conn.execute(
            "UPDATE execution_requests SET expires_at = ? WHERE id = ? AND organization_id = ?",
            (expires, "req-a", "org-a"),
        )

    assert database.claim_execution_dispatch_intent(execution_id, "org-a", "worker-b", lease_seconds=30) is None
    lease = database.claim_execution_dispatch_intent(execution_id, "org-a", "worker-a", lease_seconds=30)
    assert lease is not None
    assert lease.attempt_count == 1
    renewed = database.renew_execution_dispatch_lease(
        execution_id, "org-a", "worker-a", lease.token, lease_seconds=45,
    )
    assert renewed is not None and renewed > lease.expires_at
    with database._connection_scope() as conn:
        conn.execute(
            "UPDATE execution_requests SET expires_at = ? WHERE id = ? AND organization_id = ?",
            ((datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(), "req-a", "org-a"),
        )
    assert database.renew_execution_dispatch_lease(
        execution_id, "org-a", "worker-a", lease.token, lease_seconds=45,
    ) is None
    with database._connection_scope() as conn:
        conn.execute(
            "UPDATE execution_requests SET expires_at = ? WHERE id = ? AND organization_id = ?",
            (expires, "req-a", "org-a"),
        )
    assert not database.renew_execution_dispatch_lease(
        execution_id, "org-a", "other-worker", lease.token,
    )
    assert database.revoke_execution_decision(decision_id, "org-a", "admin-a") is True
    assert database.revoke_execution_request("req-a", "org-a", "admin-a") is True
    assert database.acknowledge_execution_cancellation(
        execution_id, "org-a", "worker-a", lease.token,
    ) is True
    assert database.settle_execution_dispatch_intent(
        execution_id, "org-a", "worker-a", lease.token, success=True,
    ) is False
    with database._connection_scope() as conn:
        dispatch = conn.execute(
            "SELECT state, attempt_count, completed_at, last_error, claimed_by, claim_token, lease_expires_at "
            "FROM execution_dispatch_intents WHERE execution_id = ? AND organization_id = ?",
            (execution_id, "org-a"),
        ).fetchone()
        run = conn.execute(
            "SELECT state, reason_code, finished_at FROM execution_runs WHERE execution_id = ? AND organization_id = ?",
            (execution_id, "org-a"),
        ).fetchone()
    assert dispatch["state"] == "BLOCKED"
    assert dispatch["attempt_count"] == 1
    assert dispatch["completed_at"]
    assert dispatch["last_error"] == "EXECUTION_CANCELLED_ACKNOWLEDGED"
    assert dispatch["claimed_by"] is None
    assert dispatch["claim_token"] is None
    assert dispatch["lease_expires_at"] is None
    assert run["state"] == "CANCELLED"
    assert run["reason_code"] == "EXECUTION_CANCELLED_ACKNOWLEDGED"
    assert run["finished_at"]


def test_approval_requires_correlation_before_any_authority_mutation(tmp_path):
    from app.core.db import DatabaseManager

    database = DatabaseManager(tmp_path / "missing-correlation.db")
    now = datetime.now(timezone.utc).isoformat()
    expires = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
    options = json.dumps({"provider": "aws", "output_format": "json-asff", "quiet": True}, separators=(",", ":"), sort_keys=True)
    budget = json.dumps({"timeout_seconds": 120, "max_output_bytes": 10485760}, separators=(",", ":"), sort_keys=True)
    account_budget = json.dumps({"read_only": 1}, separators=(",", ":"), sort_keys=True)
    credentials = json.dumps({"provider": "aws"}, separators=(",", ":"), sort_keys=True)
    with database._connection_scope() as conn:
        conn.execute("INSERT INTO organizations (id, name, slug, created_at, is_active) VALUES (?, ?, ?, ?, 1)", ("org-a", "Org A", "org-a", now))
        conn.execute("INSERT INTO assets (id, organization_id, name, type, target_value, active_probing_granted, created_at, updated_at) VALUES (?, ?, ?, 'CLOUD_ACCOUNT', ?, 1, ?, ?)", ("asset-a", "org-a", "asset", "aws://123456789012", now, now))
        conn.execute("INSERT INTO users (id, username, email, hashed_password, role, organization_id, is_active, created_at) VALUES (?, ?, ?, 'hash', 'ADMIN', ?, 1, ?)", ("admin-a", "admin", "admin@example.test", "org-a", now))
        conn.execute(
            "INSERT INTO execution_requests (id, idempotency_key, request_fingerprint, organization_id, asset_id, target_id, authorization_decision_id, target_policy_version, tool_id, operation_family, operation_options_json, operation_policy_revision, resource_budget_json, account_impact_budget_json, credential_scope_json, requested_by_user_id, state, created_at, expires_at) VALUES (?, ?, ?, 'org-a', 'asset-a', 'target-a', 'auth-a', 'v1', 'prowler', 'cloud_audit', ?, ?, ?, ?, ?, 'admin-a', 'REQUESTED', ?, ?)",
            ("req-a", "idem-a", "f" * 64, options, OPERATION_POLICY_REVISION, budget, account_budget, credentials, now, expires),
        )
    assert database.approve_execution_request(
        "req-a", "org-a", "f" * 64, "approval-idem", "admin-a", "session-a", "worker-a",
    ) == ("CORRELATION_REQUIRED", None, None)
    with database._connection_scope() as conn:
        request = conn.execute("SELECT state, approved_decision_id FROM execution_requests WHERE id = ?", ("req-a",)).fetchone()
        decisions = conn.execute("SELECT COUNT(*) AS count FROM execution_decisions WHERE organization_id = ?", ("org-a",)).fetchone()
        runs = conn.execute("SELECT COUNT(*) AS count FROM execution_runs WHERE organization_id = ?", ("org-a",)).fetchone()
        events = conn.execute(
            "SELECT id, timestamp, action, object_type, object_id, result, actor, organization_id, "
            "details_json, correlation_id, previous_event_hash, event_hash, sequence_number "
            "FROM audit_events WHERE object_id = ?",
            ("req-a",),
        ).fetchall()
    assert request["state"] == "REQUESTED"
    assert request["approved_decision_id"] is None
    assert decisions["count"] == 0
    assert runs["count"] == 0
    assert len(events) == 1
    assert events[0]["action"] == AuditAction.EXECUTION_AUTHORITY_INVARIANT_FAILED.value
    assert events[0]["result"] == "FAILURE"
    assert events[0]["actor"] == "system"
    assert events[0]["organization_id"] == "org-a"
    assert events[0]["object_type"] == "execution_request"
    assert events[0]["object_id"] == "req-a"
    assert events[0]["sequence_number"] == 1
    assert events[0]["previous_event_hash"] is None
    assert events[0]["event_hash"]
    _assert_audit_event_hash(events[0])
    assert json.loads(events[0]["details_json"]) == {"reason_code": "CORRELATION_REQUIRED"}
    assert events[0]["correlation_id"].startswith("corr-")


def test_authorized_request_without_run_fails_closed_at_api_observation_boundary(monkeypatch):
    import asyncio
    from fastapi import HTTPException
    from app.api import executions
    from app.core.models import ExecutionRequestRecord

    request = ExecutionRequestRecord(
        id="req-orphan", idempotency_key="idem", request_fingerprint="f" * 64,
        organization_id="org-a", asset_id="asset-a", target_id="target-a",
        authorization_decision_id="auth-a", target_policy_version="v1", tool_id="nmap",
        operation_family="safe", operation_policy_revision=OPERATION_POLICY_REVISION,
        requested_by_user_id="admin-a", state="AUTHORIZED",
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5), approved_decision_id="decision-a",
    )

    class InconsistentStore:
        def get_execution_request(self, request_id, organization_id=None):
            return request if request_id == request.id and organization_id == request.organization_id else None

        def get_execution_run_for_request(self, request_id, organization_id):
            return None

    original = executions.db_manager
    executions.db_manager = InconsistentStore()
    try:
        user = UserProfile(id="admin-a", username="admin", email="admin@example.test", role=UserRole.ADMIN, organization_id="org-a")
        with pytest.raises(HTTPException) as exc_info:
            asyncio.run(executions.get_execution_request("req-orphan", user))
    finally:
        executions.db_manager = original
    assert exc_info.value.status_code == 409


def test_api_approval_maps_missing_correlation_to_sanitized_503(monkeypatch):
    import asyncio
    from fastapi import HTTPException
    from app.api import executions

    class CorrelationUnavailableStore:
        def approve_execution_request(self, *args, **kwargs):
            return "CORRELATION_REQUIRED", None, None

    original_store = executions.db_manager
    original_session = executions._session_jti
    executions.db_manager = CorrelationUnavailableStore()
    executions._session_jti = lambda authorization, current_user: "session-a"
    try:
        user = UserProfile(id="admin-a", username="admin", email="admin@example.test", role=UserRole.ADMIN, organization_id="org-a")
        with pytest.raises(HTTPException) as exc_info:
            asyncio.run(executions.approve_execution_request(
                "req-a",
                executions.ApprovalPayload(request_fingerprint="f" * 64, confirm_owned_target=True),
                authorization="Bearer token",
                idempotency_key="approval-idem",
                current_user=user,
            ))
    finally:
        executions.db_manager = original_store
        executions._session_jti = original_session
    assert exc_info.value.status_code == 503
    assert exc_info.value.detail == "Execution observability context is unavailable; approval was not applied."


@pytest.mark.asyncio
async def test_http_api_approval_returns_503_and_correlation_header(monkeypatch):
    import httpx
    from app.main import app
    from app.core.models import PrincipalType
    from app.core.auth import create_access_token

    class CorrelationUnavailableStore:
        def approve_execution_request(self, *args, **kwargs):
            return "CORRELATION_REQUIRED", None, None

    user = UserProfile(
        id="admin-a", username="admin", email="admin@example.test", role=UserRole.ADMIN,
        organization_id="org-a", principal_type=PrincipalType.SYSTEM_PRINCIPAL, scopes=["*"],
    )
    from app.api import executions
    original_store = executions.db_manager
    original_session = executions._session_jti
    original_overrides = dict(app.dependency_overrides)
    executions.db_manager = CorrelationUnavailableStore()
    executions._session_jti = lambda authorization, current_user: "session-a"
    for route in app.routes:
        if getattr(route, "path", "") == "/api/system/executions/{request_id}/approve":
            for dependency in route.dependant.dependencies:
                app.dependency_overrides[dependency.call] = lambda: user
    try:
        token = create_access_token(user)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post(
                "/api/system/executions/req-a/approve",
                headers={"Authorization": f"Bearer {token}", "Idempotency-Key": "approval-idem"},
                json={"request_fingerprint": "f" * 64, "confirm_owned_target": True},
            )
    finally:
        executions.db_manager = original_store
        executions._session_jti = original_session
        app.dependency_overrides.clear()
        app.dependency_overrides.update(original_overrides)
    assert response.status_code == 503
    assert response.json()["detail"] == "Execution observability context is unavailable; approval was not applied."
    assert response.headers["x-correlation-id"].startswith("corr-")


def test_revoke_route_resolves_request_id_to_linked_decision():
    import asyncio
    from app.api import executions

    class RequestAwareStore:
        def __init__(self):
            self.called = None

        def revoke_execution_request(self, *args, **kwargs):
            self.called = (args, kwargs)
            return True

    store = RequestAwareStore()
    original = executions.db_manager
    executions.db_manager = store
    try:
        user = UserProfile(id="admin-1", username="admin", email="admin@example.test", role=UserRole.ADMIN, organization_id="org-a")
        result = asyncio.run(executions.revoke_execution_request("request-1", user))
    finally:
        executions.db_manager = original
    assert result == {"request_id": "request-1", "revoked": True}
    assert store.called == (("request-1",), {"organization_id": "org-a", "actor": "admin"})


def test_approval_session_must_match_authenticated_principal(monkeypatch):
    from app.api import executions

    monkeypatch.setattr(executions, "decode_access_token", lambda _token: {"sub": "other-user", "org_id": "org-other", "jti": "session-1"})
    user = UserProfile(id="admin-1", username="admin", email="admin@example.test", role=UserRole.ADMIN, organization_id="org-a")
    with pytest.raises(Exception, match="does not match"):
        executions._session_jti("Bearer token", user)


def test_revoke_fails_closed_on_missing_linked_decision(tmp_path):
    from app.core.db import DatabaseManager
    from app.core.correlation import reset_correlation_id, set_correlation_id

    database = DatabaseManager(tmp_path / "missing-decision.db")
    now = datetime.now(timezone.utc).isoformat()
    expires = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
    with database._connection_scope() as conn:
        conn.execute("INSERT INTO organizations (id, name, slug, created_at) VALUES ('org-a', 'Org A', 'missing-decision-org', ?)", (now,))
        conn.execute("INSERT INTO assets (id, organization_id, name, type, target_value, created_at, updated_at) VALUES ('asset-a', 'org-a', 'asset', 'CLOUD_ACCOUNT', 'aws://123456789012', ?, ?)", (now, now))
        conn.execute("INSERT INTO users (id, username, email, hashed_password, role, organization_id, created_at) VALUES ('user-a', 'user-a', 'missing@example.test', 'hash', 'ADMIN', 'org-a', ?)", (now,))
        conn.execute("""
            INSERT INTO execution_requests (
                id, idempotency_key, request_fingerprint, organization_id,
                asset_id, target_id, authorization_decision_id, target_policy_version,
                tool_id, operation_family, operation_policy_revision,
                requested_by_user_id, state, created_at, expires_at, approved_decision_id
            ) VALUES ('req-a', 'idem-a', ?, 'org-a', 'asset-a', 'target-a', 'auth-a', 'v1',
                      'prowler', 'cloud_audit', ?, 'user-a', 'AUTHORIZED', ?, ?, 'missing-decision')
        """, ("f" * 64, OPERATION_POLICY_REVISION, now, expires))

    correlation_token = set_correlation_id("corr-missing-decision")
    try:
        with pytest.raises(ValueError, match="invalid approved decision"):
            database.revoke_execution_request("req-a", "org-a", "admin")
    finally:
        reset_correlation_id(correlation_token)
    request = database.get_execution_request("req-a", organization_id="org-a")
    assert request is not None and request.state == "AUTHORIZED"
    with database._connection_scope() as conn:
        events = conn.execute(
            "SELECT id, timestamp, action, object_type, object_id, result, actor, organization_id, correlation_id, "
            "details_json, previous_event_hash, event_hash, sequence_number "
            "FROM audit_events WHERE object_id = ? ORDER BY timestamp",
            ("req-a",),
        ).fetchall()
    assert len(events) == 1
    assert events[0]["action"] == AuditAction.EXECUTION_AUTHORITY_INVARIANT_FAILED.value
    assert events[0]["object_type"] == "execution_request"
    assert events[0]["result"] == "FAILURE"
    assert events[0]["actor"] == "admin"
    assert events[0]["organization_id"] == "org-a"
    assert events[0]["correlation_id"] == "corr-missing-decision"
    assert events[0]["event_hash"]
    assert events[0]["previous_event_hash"] is None
    assert events[0]["sequence_number"] == 1
    _assert_audit_event_hash(events[0])
    assert "APPROVED_DECISION_REFERENCE_MISSING" in events[0]["details_json"]
    with database._connection_scope() as conn:
        reference = conn.execute(
            "SELECT approved_decision_id FROM execution_requests WHERE id = ? AND organization_id = ?",
            ("req-a", "org-a"),
        ).fetchone()
        decision = conn.execute(
            "SELECT id FROM execution_decisions WHERE id = ? AND organization_id = ?",
            ("missing-decision", "org-a"),
        ).fetchone()
    assert reference["approved_decision_id"] == "missing-decision"
    assert decision is None


def test_revoke_does_not_disclose_same_decision_id_owned_by_other_tenant(tmp_path):
    from app.core.db import DatabaseManager

    database = DatabaseManager(tmp_path / "cross-tenant-decision.db")
    now = datetime.now(timezone.utc).isoformat()
    expires = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
    with database._connection_scope() as conn:
        for org, suffix in (("org-a", "a"), ("org-b", "b")):
            conn.execute(
                "INSERT INTO organizations (id, name, slug, created_at) VALUES (?, ?, ?, ?)",
                (org, f"Org {suffix.upper()}", f"org-{suffix}", now),
            )
            conn.execute(
                "INSERT INTO assets (id, organization_id, name, type, target_value, created_at, updated_at) "
                "VALUES (?, ?, ?, 'DOMAIN', ?, ?, ?)",
                (f"asset-{suffix}", org, "asset", "example.invalid", now, now),
            )
            conn.execute(
                "INSERT INTO users (id, username, email, hashed_password, role, organization_id, created_at) "
                "VALUES (?, ?, ?, 'hash', 'ADMIN', ?, ?)",
                (f"user-{suffix}", f"user-{suffix}", f"{suffix}@example.invalid", org, now),
            )
        conn.execute(
            "INSERT INTO execution_decisions (id, organization_id, project_id, asset_id, target_id, "
            "authorization_decision_id, target_policy_version, tool_id, operation_family, "
            "operation_policy_revision, approval_state, approver_user_id, session_jti, worker_identity, "
            "created_at, expires_at) VALUES (?, ?, NULL, ?, ?, ?, 'v1', 'nmap', 'safe', ?, 'APPROVED', "
            "'user-b', 'session-b', 'worker-b', ?, ?)",
            ("shared-id", "org-b", "asset-b", "target-b", "auth-b", OPERATION_POLICY_REVISION, now, expires),
        )
        conn.execute(
            "INSERT INTO execution_requests (id, idempotency_key, request_fingerprint, organization_id, "
            "asset_id, target_id, authorization_decision_id, target_policy_version, tool_id, operation_family, "
            "operation_policy_revision, requested_by_user_id, state, created_at, expires_at, approved_decision_id) "
            "VALUES (?, ?, ?, 'org-a', 'asset-a', 'target-a', 'auth-a', 'v1', 'nmap', 'safe', ?, 'user-a', "
            "'AUTHORIZED', ?, ?, ?)",
            ("req-a", "idem-a", "f" * 64, OPERATION_POLICY_REVISION, now, expires, "shared-id"),
        )

    from app.core.correlation import reset_correlation_id, set_correlation_id
    correlation_token = set_correlation_id("corr-cross-tenant")
    try:
        with pytest.raises(ValueError, match="invalid approved decision"):
            database.revoke_execution_request("req-a", "org-a", "admin")
    finally:
        reset_correlation_id(correlation_token)
    with database._connection_scope() as conn:
        request = conn.execute(
            "SELECT state, approved_decision_id FROM execution_requests WHERE id = ? AND organization_id = ?",
            ("req-a", "org-a"),
        ).fetchone()
        events = conn.execute(
            "SELECT organization_id, actor, action, object_type, result, correlation_id, details_json, "
            "previous_event_hash, event_hash, sequence_number FROM audit_events WHERE object_id = ?",
            ("req-a",),
        ).fetchall()
    assert request["state"] == "AUTHORIZED"
    assert request["approved_decision_id"] == "shared-id"
    assert len(events) == 1
    assert events[0]["organization_id"] == "org-a"
    assert events[0]["actor"] == "admin"
    assert events[0]["action"] == AuditAction.EXECUTION_AUTHORITY_INVARIANT_FAILED.value
    assert events[0]["object_type"] == "execution_request"
    assert events[0]["result"] == "FAILURE"
    assert events[0]["correlation_id"] == "corr-cross-tenant"
    assert events[0]["event_hash"]
    assert events[0]["previous_event_hash"] is None
    assert events[0]["sequence_number"] == 1
    with database._connection_scope() as conn:
        event = conn.execute(
            "SELECT id, timestamp, action, object_type, object_id, result, actor, organization_id, "
            "details_json, previous_event_hash, event_hash FROM audit_events WHERE object_id = ?",
            ("req-a",),
        ).fetchone()
    _assert_audit_event_hash(event)
    assert json.loads(events[0]["details_json"]) == {"reason_code": "APPROVED_DECISION_REFERENCE_MISSING"}
    assert "shared-id" not in events[0]["details_json"]


def test_audit_chain_continuity_is_verified_for_multiple_events(tmp_path):
    from app.core.db import DatabaseManager

    database = DatabaseManager(tmp_path / "audit-chain.db")
    database.record_audit_event(AuditEvent(
        id="audit-chain-one", actor="admin", organization_id="org-chain",
        action=AuditAction.EXECUTION_REQUESTED, object_type="execution_request",
        object_id="request-chain", result="SUCCESS", details={"step": 1},
        correlation_id="corr-chain",
    ))
    database.record_audit_event(AuditEvent(
        id="audit-chain-two", actor="admin", organization_id="org-chain",
        action=AuditAction.EXECUTION_CANCEL_REQUESTED, object_type="execution_request",
        object_id="request-chain", result="SUCCESS", details={"step": 2},
        correlation_id="corr-chain",
    ))

    with database._connection_scope() as conn:
        events = conn.execute(
            "SELECT id, timestamp, action, object_type, object_id, result, actor, organization_id, "
            "details_json, previous_event_hash, event_hash, sequence_number "
            "FROM audit_events ORDER BY sequence_number",
        ).fetchall()
    assert len(events) == 2
    for event in events:
        _assert_audit_event_hash(event)
    assert events[0]["sequence_number"] == 1
    assert events[0]["previous_event_hash"] is None
    assert events[1]["sequence_number"] == 2
    assert events[1]["previous_event_hash"] == events[0]["event_hash"]
    assert database.verify_audit_log_integrity() == (True, None)


def test_audit_chain_detects_details_json_tampering(tmp_path):
    from app.core.db import DatabaseManager

    database = DatabaseManager(tmp_path / "audit-tamper.db")
    database.record_audit_event(AuditEvent(
        id="audit-tamper-one", actor="admin", organization_id="org-tamper",
        action=AuditAction.EXECUTION_REQUESTED, object_type="execution_request",
        object_id="request-tamper", result="SUCCESS", details={"step": 1},
        correlation_id="corr-tamper",
    ))
    with database._connection_scope() as conn:
        conn.execute(
            "UPDATE audit_events SET details_json = ? WHERE id = ?",
            ('{ "step": 1 }', "audit-tamper-one"),
        )
    assert database.verify_audit_log_integrity() == (False, "audit-tamper-one")


def test_execution_run_rejects_cross_tenant_request_and_invalid_transitions(tmp_path):
    from app.core.db import DatabaseManager
    from app.core.models import ExecutionRunRecord

    database = DatabaseManager(tmp_path / "runs.db")
    now = datetime.now(timezone.utc).isoformat()
    with database._connection_scope() as conn:
        conn.execute("INSERT INTO organizations (id, name, slug, created_at, is_active) VALUES (?, ?, ?, ?, 1)", ("org-a", "Org A", "org-a", now))
        conn.execute("INSERT INTO organizations (id, name, slug, created_at, is_active) VALUES (?, ?, ?, ?, 1)", ("org-b", "Org B", "org-b", now))
        for org in ("org-a", "org-b"):
            conn.execute("INSERT INTO assets (id, organization_id, name, type, target_value, created_at, updated_at) VALUES (?, ?, ?, 'CLOUD_ACCOUNT', ?, ?, ?)", (f"asset-{org[-1]}", org, "account", "aws://123456789012", now, now))
            conn.execute("INSERT INTO users (id, username, email, hashed_password, role, organization_id, is_active, created_at) VALUES (?, ?, ?, 'hash', 'ADMIN', ?, 1, ?)", (f"user-{org[-1]}", f"user-{org[-1]}", f"{org}@example.test", org, now))
        conn.execute("INSERT INTO execution_requests (id, idempotency_key, request_fingerprint, organization_id, asset_id, target_id, authorization_decision_id, target_policy_version, tool_id, operation_family, operation_policy_revision, requested_by_user_id, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", ("req-b", "idem-b", "f" * 64, "org-b", "asset-b", "target-b", "auth-b", "v1", "prowler", "cloud_audit", OPERATION_POLICY_REVISION, "user-b", now, now))
    run = ExecutionRunRecord(execution_id="run-a", request_id="req-b", organization_id="org-a")
    with pytest.raises(ValueError, match="tenant-bound"):
        database.create_execution_run(run)


def test_execution_run_transition_matrix_and_terminal_immutability(tmp_path):
    from app.core.db import DatabaseManager
    from app.core.models import ExecutionRunRecord

    database = DatabaseManager(tmp_path / "run-state.db")
    now = datetime.now(timezone.utc).isoformat()
    with database._connection_scope() as conn:
        conn.execute("INSERT INTO organizations (id, name, slug, created_at, is_active) VALUES (?, ?, ?, ?, 1)", ("org-a", "Org A", "org-a", now))
        conn.execute("INSERT INTO assets (id, organization_id, name, type, target_value, created_at, updated_at) VALUES ('asset-a', 'org-a', 'account', 'CLOUD_ACCOUNT', 'aws://123456789012', ?, ?)", (now, now))
        conn.execute("INSERT INTO users (id, username, email, hashed_password, role, organization_id, is_active, created_at) VALUES ('user-a', 'user-a', 'a@example.test', 'hash', 'ADMIN', 'org-a', 1, ?)", (now,))
        conn.execute("INSERT INTO execution_requests (id, idempotency_key, request_fingerprint, organization_id, asset_id, target_id, authorization_decision_id, target_policy_version, tool_id, operation_family, operation_policy_revision, requested_by_user_id, state, created_at, expires_at, approved_decision_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'AUTHORIZED', ?, ?, ?)", ("req-a", "idem-a", "f" * 64, "org-a", "asset-a", "target-a", "auth-a", "v1", "prowler", "cloud_audit", OPERATION_POLICY_REVISION, "user-a", now, (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(), "decision-a"))
        conn.execute("INSERT INTO execution_decisions (id, organization_id, project_id, asset_id, target_id, authorization_decision_id, target_policy_version, tool_id, operation_family, operation_policy_revision, approval_state, approver_user_id, session_jti, worker_identity, created_at, expires_at) VALUES ('decision-a', 'org-a', NULL, 'asset-a', 'target-a', 'auth-a', 'v1', 'prowler', 'cloud_audit', ?, 'APPROVED', 'user-a', 'session-a', 'worker-a', ?, ?)", (OPERATION_POLICY_REVISION, now, (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()))
    database.create_execution_run(ExecutionRunRecord(execution_id="run-a", request_id="req-a", organization_id="org-a"))
    with database._connection_scope() as conn:
        conn.execute(
            "INSERT INTO execution_dispatch_intents (execution_id, organization_id, state, attempt_count, created_at) VALUES (?, ?, 'PENDING', 0, ?)",
            ("run-a", "org-a", now),
        )
    assert not database.transition_execution_run("run-a", "org-a", "REQUESTED", "STARTING")
    lease = database.claim_execution_dispatch_intent("run-a", "org-a", "worker-a")
    assert lease is not None
    assert not database.transition_execution_run("run-a", "org-a", "REQUESTED", "SUCCEEDED")
    assert database.transition_execution_run("run-a", "org-a", "REQUESTED", "STARTING", worker_identity="worker-a", dispatch_claim_token=lease.token)
    assert database.transition_execution_run("run-a", "org-a", "STARTING", "RUNNING", worker_identity="worker-a", dispatch_claim_token=lease.token)
    assert database.transition_execution_run("run-a", "org-a", "RUNNING", "SUCCEEDED", worker_identity="worker-a", dispatch_claim_token=lease.token)
    assert not database.transition_execution_run("run-a", "org-a", "SUCCEEDED", "RUNNING")


def test_execution_run_rejects_request_decision_authority_mismatch(tmp_path):
    from app.core.db import DatabaseManager
    from app.core.models import ExecutionRunRecord

    database = DatabaseManager(tmp_path / "authority-binding.db")
    now = datetime.now(timezone.utc).isoformat()
    expires = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
    with database._connection_scope() as conn:
        conn.execute("INSERT INTO organizations (id, name, slug, created_at, is_active) VALUES ('org-a', 'Org A', 'org-a', ?, 1)", (now,))
        conn.execute("INSERT INTO assets (id, organization_id, name, type, target_value, created_at, updated_at) VALUES ('asset-a', 'org-a', 'account', 'CLOUD_ACCOUNT', 'aws://123456789012', ?, ?)", (now, now))
        conn.execute("INSERT INTO users (id, username, email, hashed_password, role, organization_id, is_active, created_at) VALUES ('user-a', 'user-a', 'a@example.test', 'hash', 'ADMIN', 'org-a', 1, ?)", (now,))
        conn.execute("INSERT INTO execution_requests (id, idempotency_key, request_fingerprint, organization_id, asset_id, target_id, authorization_decision_id, target_policy_version, tool_id, operation_family, operation_policy_revision, requested_by_user_id, state, created_at, expires_at, approved_decision_id) VALUES ('req-a', 'idem-a', ?, 'org-a', 'asset-a', 'target-a', 'auth-a', 'v1', 'prowler', 'cloud_audit', ?, 'user-a', 'AUTHORIZED', ?, ?, 'decision-a')", ("f" * 64, OPERATION_POLICY_REVISION, now, expires))
        conn.execute("INSERT INTO execution_decisions (id, organization_id, project_id, asset_id, target_id, authorization_decision_id, target_policy_version, tool_id, operation_family, operation_policy_revision, approval_state, approver_user_id, session_jti, worker_identity, created_at, expires_at) VALUES ('decision-a', 'org-a', NULL, 'asset-a', 'target-other', 'auth-a', 'v1', 'prowler', 'cloud_audit', ?, 'APPROVED', 'user-a', 'session-a', 'worker-a', ?, ?)", (OPERATION_POLICY_REVISION, now, expires))

    with pytest.raises(ValueError, match="authority binding"):
        database.create_execution_run(ExecutionRunRecord(execution_id="run-a", request_id="req-a", organization_id="org-a"))


def test_execution_run_is_unique_per_authorized_request(tmp_path):
    from app.core.db import DatabaseManager
    from app.core.models import ExecutionRunRecord

    database = DatabaseManager(tmp_path / "run-uniqueness.db")
    now = datetime.now(timezone.utc).isoformat()
    expires = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
    with database._connection_scope() as conn:
        conn.execute("INSERT INTO organizations (id, name, slug, created_at, is_active) VALUES ('org-a', 'Org A', 'org-a', ?, 1)", (now,))
        conn.execute("INSERT INTO assets (id, organization_id, name, type, target_value, created_at, updated_at) VALUES ('asset-a', 'org-a', 'account', 'CLOUD_ACCOUNT', 'aws://123456789012', ?, ?)", (now, now))
        conn.execute("INSERT INTO users (id, username, email, hashed_password, role, organization_id, is_active, created_at) VALUES ('user-a', 'user-a', 'a@example.test', 'hash', 'ADMIN', 'org-a', 1, ?)", (now,))
        conn.execute("INSERT INTO execution_requests (id, idempotency_key, request_fingerprint, organization_id, asset_id, target_id, authorization_decision_id, target_policy_version, tool_id, operation_family, operation_policy_revision, requested_by_user_id, state, created_at, expires_at, approved_decision_id) VALUES ('req-a', 'idem-a', ?, 'org-a', 'asset-a', 'target-a', 'auth-a', 'v1', 'prowler', 'cloud_audit', ?, 'user-a', 'AUTHORIZED', ?, ?, 'decision-a')", ("f" * 64, OPERATION_POLICY_REVISION, now, expires))
        conn.execute("INSERT INTO execution_decisions (id, organization_id, project_id, asset_id, target_id, authorization_decision_id, target_policy_version, tool_id, operation_family, operation_policy_revision, approval_state, approver_user_id, session_jti, worker_identity, created_at, expires_at) VALUES ('decision-a', 'org-a', NULL, 'asset-a', 'target-a', 'auth-a', 'v1', 'prowler', 'cloud_audit', ?, 'APPROVED', 'user-a', 'session-a', 'worker-a', ?, ?)", (OPERATION_POLICY_REVISION, now, expires))
    database.create_execution_run(ExecutionRunRecord(execution_id="run-a", request_id="req-a", organization_id="org-a"))

    with pytest.raises(Exception):
        database.create_execution_run(ExecutionRunRecord(execution_id="run-b", request_id="req-a", organization_id="org-a"))


def test_postgres_execution_run_validation_locks_request_row(monkeypatch):
    from app.core.db import PostgresDatabaseManager

    class Connection:
        def __init__(self):
            self.queries = []

        def execute(self, sql, params=()):
            self.queries.append(sql)
            return self

        def fetchone(self):
            return None

    connection = Connection()

    class Scope:
        def __enter__(self):
            return connection

        def __exit__(self, *_):
            return False

    manager = object.__new__(PostgresDatabaseManager)
    monkeypatch.setattr(manager, "_connection_scope", lambda: Scope())
    with pytest.raises(ValueError, match="not tenant-bound"):
        manager.create_execution_run(ExecutionRunRecord(execution_id="run-lock", request_id="req-lock", organization_id="org-lock"))
    assert "FOR UPDATE" in connection.queries[0]


def test_legacy_execution_runs_schema_is_rebuilt_with_tenant_fk(tmp_path):
    import sqlite3
    from app.core.db import DatabaseManager

    db_path = tmp_path / "legacy-runs.db"
    database = DatabaseManager(db_path)
    now = datetime.now(timezone.utc).isoformat()
    with database._connection_scope() as conn:
        conn.execute("INSERT INTO organizations (id, name, slug, created_at, is_active) VALUES ('org-a', 'Org A', 'org-a', ?, 1)", (now,))
        conn.execute("INSERT INTO assets (id, organization_id, name, type, target_value, created_at, updated_at) VALUES ('asset-a', 'org-a', 'account', 'CLOUD_ACCOUNT', 'aws://123456789012', ?, ?)", (now, now))
        conn.execute("INSERT INTO users (id, username, email, hashed_password, role, organization_id, is_active, created_at) VALUES ('user-a', 'user-a', 'a@example.test', 'hash', 'ADMIN', 'org-a', 1, ?)", (now,))
        conn.execute("INSERT INTO execution_requests (id, idempotency_key, request_fingerprint, organization_id, asset_id, target_id, authorization_decision_id, target_policy_version, tool_id, operation_family, operation_policy_revision, requested_by_user_id, state, created_at, expires_at) VALUES ('req-a', 'idem-a', ?, 'org-a', 'asset-a', 'target-a', 'auth-a', 'v1', 'prowler', 'cloud_audit', ?, 'user-a', 'REQUESTED', ?, ?)", ("f" * 64, OPERATION_POLICY_REVISION, now, now))
        conn.execute("DELETE FROM schema_migrations WHERE version = 1")
        conn.execute("DELETE FROM schema_migrations WHERE version = 4")
        conn.execute("DROP INDEX uq_execution_runs_request")
        conn.execute("ALTER TABLE execution_runs RENAME TO execution_runs_legacy")
        conn.execute("""CREATE TABLE execution_runs (execution_id TEXT PRIMARY KEY, request_id TEXT NOT NULL, organization_id TEXT NOT NULL, state TEXT NOT NULL, worker_identity TEXT, process_id INTEGER, process_group_id TEXT, assurance_state TEXT NOT NULL, coverage_state TEXT NOT NULL, reason_code TEXT, evidence_ref TEXT, correlation_id TEXT, created_at TEXT NOT NULL, started_at TEXT, finished_at TEXT, FOREIGN KEY (request_id) REFERENCES execution_requests(id), FOREIGN KEY (organization_id) REFERENCES organizations(id))""")
        conn.execute(
            "INSERT INTO execution_runs (execution_id, request_id, organization_id, state, worker_identity, "
            "process_id, process_group_id, assurance_state, coverage_state, reason_code, evidence_ref, "
            "correlation_id, created_at, started_at, finished_at) "
            "SELECT execution_id, request_id, organization_id, state, worker_identity, process_id, "
            "process_group_id, assurance_state, coverage_state, reason_code, evidence_ref, correlation_id, "
            "created_at, started_at, finished_at FROM execution_runs_legacy WHERE 0"
        )
        conn.execute("DROP TABLE execution_runs_legacy")
    with pytest.raises(RuntimeError, match="execution dispatch schema lacks"):
        DatabaseManager(db_path)


def test_legacy_execution_runs_duplicate_preflight_fails_closed(tmp_path):
    from app.core.db import DatabaseManager

    db_path = tmp_path / "legacy-duplicate-runs.db"
    database = DatabaseManager(db_path)
    now = datetime.now(timezone.utc).isoformat()
    with database._connection_scope() as conn:
        conn.execute("INSERT INTO organizations (id, name, slug, created_at, is_active) VALUES ('org-a', 'Org A', 'org-a', ?, 1)", (now,))
        conn.execute("INSERT INTO assets (id, organization_id, name, type, target_value, created_at, updated_at) VALUES ('asset-a', 'org-a', 'account', 'CLOUD_ACCOUNT', 'aws://123456789012', ?, ?)", (now, now))
        conn.execute("INSERT INTO users (id, username, email, hashed_password, role, organization_id, is_active, created_at) VALUES ('user-a', 'user-a', 'a@example.test', 'hash', 'ADMIN', 'org-a', 1, ?)", (now,))
        conn.execute("INSERT INTO execution_requests (id, idempotency_key, request_fingerprint, organization_id, asset_id, target_id, authorization_decision_id, target_policy_version, tool_id, operation_family, operation_policy_revision, requested_by_user_id, state, created_at, expires_at) VALUES ('req-a', 'idem-a', ?, 'org-a', 'asset-a', 'target-a', 'auth-a', 'v1', 'prowler', 'cloud_audit', ?, 'user-a', 'REQUESTED', ?, ?)", ("f" * 64, OPERATION_POLICY_REVISION, now, now))
        conn.execute("DELETE FROM schema_migrations WHERE version = 1")
        conn.execute("DROP INDEX uq_execution_runs_request")
        conn.execute("INSERT INTO execution_runs (execution_id, request_id, organization_id, state, assurance_state, coverage_state, created_at) VALUES ('run-a', 'req-a', 'org-a', 'FAILED', 'UNVERIFIED', 'UNAVAILABLE', ?), ('run-b', 'req-a', 'org-a', 'FAILED', 'UNVERIFIED', 'UNAVAILABLE', ?)", (now, now))
    with pytest.raises(ValueError, match="duplicate runs"):
        DatabaseManager(db_path)


def test_execution_migration_version_two_reruns_without_reconciling_fresh_schema(tmp_path):
    from app.core.db import DatabaseManager

    db_path = tmp_path / "version-two-rerun.db"
    database = DatabaseManager(db_path)
    with database._connection_scope() as conn:
        conn.execute("DELETE FROM schema_migrations WHERE version = 2")
    DatabaseManager(db_path)
    with database._connection_scope() as conn:
        versions = [row["version"] for row in conn.execute("SELECT version FROM schema_migrations ORDER BY version").fetchall()]
        assert versions[-3:] == [7, 8, 9]


def test_execution_schema_drift_after_version_two_fails_closed(tmp_path):
    from app.core.db import DatabaseManager

    db_path = tmp_path / "version-two-drift.db"
    database = DatabaseManager(db_path)
    with database._connection_scope() as conn:
        conn.execute("DROP INDEX uq_execution_runs_request")
    with pytest.raises(ValueError, match="schema health check"):
        DatabaseManager(db_path)


def test_execution_schema_wrong_column_index_fails_closed(tmp_path):
    from app.core.db import DatabaseManager

    db_path = tmp_path / "wrong-run-index.db"
    database = DatabaseManager(db_path)
    with database._connection_scope() as conn:
        conn.execute("DROP INDEX uq_execution_runs_request")
        conn.execute("CREATE UNIQUE INDEX uq_execution_runs_request ON execution_runs(execution_id)")
    with pytest.raises(ValueError, match="schema health check"):
        DatabaseManager(db_path)


def test_execution_snapshot_schema_drift_fails_closed_even_when_version_three_is_recorded(tmp_path):
    from app.core.db import DatabaseManager

    db_path = tmp_path / "snapshot-schema-drift.db"
    DatabaseManager(db_path)
    with sqlite3.connect(db_path) as conn:
        conn.execute("ALTER TABLE execution_runs RENAME TO execution_runs_backup")
        conn.execute("CREATE TABLE execution_runs (execution_id TEXT PRIMARY KEY, request_id TEXT NOT NULL, organization_id TEXT NOT NULL, approved_decision_id TEXT, target_policy_version TEXT, operation_policy_revision TEXT, request_fingerprint TEXT, operation_options_json TEXT NOT NULL DEFAULT '{}', resource_budget_json TEXT NOT NULL DEFAULT '{}', account_impact_budget_json TEXT NOT NULL DEFAULT '{}', credential_scope_json TEXT NOT NULL DEFAULT '{}', state TEXT NOT NULL, assurance_state TEXT NOT NULL, coverage_state TEXT NOT NULL, created_at TEXT NOT NULL)")
        conn.commit()
    with pytest.raises(RuntimeError, match="snapshot schema verification failed"):
        DatabaseManager(db_path)


def test_execution_snapshot_schema_wrong_definition_fails_closed(tmp_path):
    from app.core.db import DatabaseManager

    db_path = tmp_path / "snapshot-schema-definition.db"
    DatabaseManager(db_path)
    with sqlite3.connect(db_path) as conn:
        conn.execute("ALTER TABLE execution_runs RENAME TO execution_runs_backup")
        conn.execute("CREATE TABLE execution_runs (execution_id TEXT PRIMARY KEY, request_id TEXT NOT NULL, organization_id TEXT NOT NULL, approved_decision_id TEXT, target_policy_version TEXT, operation_policy_revision TEXT, request_fingerprint TEXT, operation_options_json TEXT NOT NULL DEFAULT '[]', resource_budget TEXT, account_impact_budget_json TEXT NOT NULL DEFAULT '{}', credential_scope_json TEXT NOT NULL DEFAULT '{}', snapshot_completeness TEXT NOT NULL DEFAULT 'LEGACY_SNAPSHOT_UNAVAILABLE', state TEXT NOT NULL, assurance_state TEXT NOT NULL, coverage_state TEXT NOT NULL, created_at TEXT NOT NULL)")
        conn.commit()
    with pytest.raises(RuntimeError, match="snapshot schema verification failed"):
        DatabaseManager(db_path)


def test_execution_v6_schema_drift_fails_closed_after_version_is_recorded(tmp_path):
    from app.core.db import DatabaseManager

    db_path = tmp_path / "execution-v6-drift.db"
    DatabaseManager(db_path)
    with sqlite3.connect(db_path) as conn:
        conn.execute("ALTER TABLE execution_decisions DROP COLUMN claim_token")
        conn.commit()
    with pytest.raises(RuntimeError, match="execution compatibility schema verification failed"):
        DatabaseManager(db_path)


def test_execution_schema_partial_index_fails_closed(tmp_path):
    from app.core.db import DatabaseManager

    db_path = tmp_path / "partial-run-index.db"
    database = DatabaseManager(db_path)
    with database._connection_scope() as conn:
        conn.execute("DROP INDEX uq_execution_runs_request")
        conn.execute("CREATE UNIQUE INDEX uq_execution_runs_request ON execution_runs(request_id, organization_id) WHERE state = 'SUCCEEDED'")
    with pytest.raises(ValueError, match="schema health check"):
        DatabaseManager(db_path)


def test_v5_cleans_only_the_known_migration_owned_parent_key(tmp_path):
    from app.core.db import DatabaseManager

    db_path = tmp_path / "known-v4-duplicate.db"
    DatabaseManager(db_path)
    with sqlite3.connect(db_path) as conn:
        conn.execute("CREATE UNIQUE INDEX uq_execution_decisions_id_org ON execution_decisions(id, organization_id)")
        conn.execute("DELETE FROM schema_migrations WHERE version = 5")
        conn.commit()
    DatabaseManager(db_path)
    with sqlite3.connect(db_path) as conn:
        names = {row[1] for row in conn.execute("PRAGMA index_list(execution_decisions)").fetchall()}
        versions = {row[0] for row in conn.execute("SELECT version FROM schema_migrations").fetchall()}
    assert "uq_execution_decisions_id_org" not in names
    assert 5 in versions


def test_v5_rejects_unknown_parent_key_duplicates_without_recording_success(tmp_path):
    from app.core.db import DatabaseManager

    db_path = tmp_path / "unknown-v4-duplicate.db"
    DatabaseManager(db_path)
    with sqlite3.connect(db_path) as conn:
        conn.execute("CREATE UNIQUE INDEX operator_owned_decision_parent_key ON execution_decisions(id, organization_id)")
        conn.execute("DELETE FROM schema_migrations WHERE version = 5")
        conn.commit()
    with pytest.raises(ValueError, match="unknown duplicate decision parent keys"):
        DatabaseManager(db_path)
    with sqlite3.connect(db_path) as conn:
        assert conn.execute("SELECT 1 FROM schema_migrations WHERE version = 5").fetchone() is None
        assert conn.execute("SELECT 1 FROM sqlite_master WHERE name = 'operator_owned_decision_parent_key'").fetchone()
