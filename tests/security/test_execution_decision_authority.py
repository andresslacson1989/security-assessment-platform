"""Adversarial tests for the durable worker execution-decision boundary."""

from datetime import datetime, timedelta, timezone
from dataclasses import replace
import hashlib
import inspect
import json
import sqlite3
from types import SimpleNamespace

import pytest

from app.core.execution_decision import ExecutionDecisionError, issue_execution_capability
from app.core.db import DatabaseManager
from app.core.migration_registry import MIGRATION_REGISTRY, _EXPECTED_CHECKSUMS
from app.core.migration_artifacts import FORWARD_APPLY_ARTIFACT_REVISION
from app.core.scan_request_migration_v13 import apply_artifact_digest
from app.core.models import AuditAction, AuditEvent, ExecutionAuthorityLease, ExecutionDecisionRecord, ExecutionDispatchLease, ExecutionLeaseClaim, ExecutionRunRecord, Target, TargetType, EXECUTION_REASON_CODES, is_canonical_execution_reason_code, is_valid_execution_terminal_outcome
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

    def claim_execution_authority(
        self, decision_id, organization_id, session_jti, worker_identity,
        policy_revision, dispatch_claim_token=None, now=None,
    ):
        decision_claim = self.claim_execution_decision(
            decision_id, organization_id, session_jti, worker_identity,
            policy_revision, now=now,
        )
        if decision_claim is None:
            return None
        lease_time = now or datetime.now(timezone.utc)
        return ExecutionAuthorityLease(
            decision=decision_claim,
            dispatch=ExecutionDispatchLease(
                execution_id="run-test",
                organization_id=organization_id,
                owner=worker_identity,
                token=dispatch_claim_token or "dispatch-claim",
                expires_at=lease_time + timedelta(seconds=30),
                attempt_count=1,
            ),
            execution_id="run-test",
            correlation_id="corr-run-test",
        )


def _target():
    return create_validated_target(
        Target(name="AWS account", type=TargetType.CLOUD_ACCOUNT, value="aws://123456789012"),
        organization_id="org-a", project_id="project-a", asset_id="asset-a",
        active_probing_granted=True,
    )


def test_production_worker_identity_and_generation_fail_closed_when_unconfigured(monkeypatch):
    import app.core.execution_service as execution_service

    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.delenv("OPERATING_MODE", raising=False)
    monkeypatch.delenv("CYBERASSESS_WORKER_IDENTITY", raising=False)
    monkeypatch.delenv("CYBERASSESS_WORKER_GENERATION", raising=False)

    with pytest.raises(RuntimeError, match="CYBERASSESS_WORKER_IDENTITY"):
        execution_service.get_worker_identity()
    with pytest.raises(RuntimeError, match="CYBERASSESS_WORKER_GENERATION"):
        execution_service.get_worker_generation()


def test_migration_registry_has_fixed_executable_verifier_vectors():
    assert [spec.version for spec in MIGRATION_REGISTRY] == list(range(1, len(MIGRATION_REGISTRY) + 1))
    assert all(callable(spec.apply) and callable(spec.reconcile) for spec in MIGRATION_REGISTRY)
    assert all(
        all(artifact.startswith("sha256:") and len(artifact) == 71 for artifact in spec.apply_artifact.values())
        for spec in MIGRATION_REGISTRY
    )
    assert all(callable(spec.verify) for spec in MIGRATION_REGISTRY)
    assert {spec.version: spec.checksum for spec in MIGRATION_REGISTRY} == _EXPECTED_CHECKSUMS


def test_execution_reason_codes_are_bounded_and_allowlisted():
    assert EXECUTION_REASON_CODES
    assert all(is_canonical_execution_reason_code(code) for code in EXECUTION_REASON_CODES)
    assert is_canonical_execution_reason_code("PROCESS_EXIT_NONZERO")
    assert not is_canonical_execution_reason_code("free-form failure detail")
    assert not is_canonical_execution_reason_code("PROCESS_EXIT_NONZERO\nINJECTED")
    assert not is_canonical_execution_reason_code("A" * 65)
    assert is_valid_execution_terminal_outcome("SUCCEEDED", None)
    assert is_valid_execution_terminal_outcome("TIMED_OUT", "EXECUTION_TIMEOUT")
    assert not is_valid_execution_terminal_outcome("TIMED_OUT", "PROCESS_EXIT_NONZERO")
    assert not is_valid_execution_terminal_outcome("FAILED", "EXECUTION_CANCELLED")


def test_fresh_database_records_one_durable_outcome_per_registered_migration(tmp_path):
    database = DatabaseManager(tmp_path / "coordinator.sqlite3")
    with database._connection_scope() as conn:
        rows = conn.execute(
            "SELECT migration_version, event_sequence, event_type, context_json "
            "FROM schema_migration_events ORDER BY migration_version, event_sequence"
        ).fetchall()

    assert [(row["migration_version"], row["event_sequence"], row["event_type"]) for row in rows] == [
        item for version in range(1, len(MIGRATION_REGISTRY) + 1) for item in ((version, 1, "STARTED"), (version, 2, "SUCCEEDED"))
    ]
    for row in rows:
        context = json.loads(row["context_json"])
        assert context["coordinator"] == "registry"
        assert context["provenance_format"] == "registry-coordinator-v2"
        assert context["apply_artifact_revision"] == "execution-migration-apply-v1"
        assert context["apply_artifact"].startswith("sha256:")
        assert context["apply_manifest"]


def test_forward_apply_artifact_vectors_match_runtime_serialization():
    manager = DatabaseManager.__new__(DatabaseManager)
    for spec in MIGRATION_REGISTRY:
        for backend in ("sqlite", "postgresql"):
            if spec.version == 13:
                actual = apply_artifact_digest(manager, backend=backend, manifest=spec.apply_manifest)
            else:
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
    with pytest.raises(RuntimeError, match="pre-lease target|column definitions drifted"):
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

    with pytest.raises(RuntimeError, match="schema migration versions are not contiguous"):
        DatabaseManager(path)


def test_v9_rejects_an_ambiguous_same_name_parent_index(tmp_path):
    path = tmp_path / "ambiguous-parent-index.sqlite3"
    database = DatabaseManager(path)
    with database._connection_scope() as connection:
        connection.execute("CREATE INDEX uq_execution_requests_id_org ON execution_requests(organization_id, id)")
        connection.execute("DELETE FROM schema_migrations WHERE version = 9")

    with pytest.raises(RuntimeError, match="schema migration versions are not contiguous"):
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


@pytest.mark.parametrize("version", [8, 10])
def test_legacy_migration_ledger_is_upgraded_with_verified_identity(tmp_path, version):
    path = tmp_path / f"legacy-ledger-v{version}.sqlite3"
    spec = next(spec for spec in MIGRATION_REGISTRY if spec.version == version)
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
        ("event-1", "attempt-1", version, spec.name, "STARTED", "2026-01-01T00:00:00+00:00", "SQLITE", "legacy", spec.previous_version, spec.target_version, spec.checksum, "test", f"tx-{'1' * 32}", None, None, None, "{}", "PENDING"),
    )
    conn.execute(
        "INSERT INTO schema_migration_events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ("event-2", "attempt-1", version, spec.name, "SUCCEEDED", "2026-01-01T00:00:01+00:00", "SQLITE", "legacy", spec.previous_version, spec.target_version, spec.checksum, "test", f"tx-{'1' * 32}", None, None, None, "{}", "NOT_APPLICABLE"),
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
    database._migration_schema_name = str(path)
    database._migration_spec = MIGRATION_REGISTRY[-1]
    database._migration_started_durable = True
    spec = database._migration_spec
    digest = spec.apply_artifact["sqlite"].split(":", 1)[1]
    database._migration_transaction_id = f"txp-{'0' * 32}-{digest}"
    context = json.dumps({
        "coordinator": "registry",
        "provenance_format": "registry-coordinator-v2",
        "migration_version": spec.version,
        "apply_artifact_revision": FORWARD_APPLY_ARTIFACT_REVISION,
        "apply_artifact": spec.apply_artifact["sqlite"],
        "apply_artifacts": spec.apply_artifact,
        "apply_manifest": spec.apply_manifest,
        "backend_policy": spec.backend_policy,
    }, sort_keys=True, separators=(",", ":"))
    with database._connection_scope() as connection:
        connection.execute(
            "INSERT INTO schema_migration_events (event_id, attempt_id, migration_version, migration_id, migration_name, registry_revision, event_sequence, event_type, event_at, backend, schema_name, previous_schema_version, target_schema_version, migration_checksum, runner_identity, transaction_context_id, context_json, rollback_status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("failure-start", "failure-attempt", spec.version, spec.migration_id, spec.name, spec.registry_revision, 1, "STARTED", "2026-01-01T00:00:00+00:00", "SQLITE", str(path), spec.previous_version, spec.target_version, spec.checksum, "test", database._migration_transaction_id, context, "PENDING"),
        )
    database._record_migration_failure(RuntimeError("controlled failure"))

    with sqlite3.connect(path) as connection:
        rows = connection.execute(
            "SELECT event_type, event_sequence FROM schema_migration_events "
            "WHERE attempt_id = 'failure-attempt' ORDER BY event_sequence"
        ).fetchall()
    assert rows == [("STARTED", 1), ("FAILED", 2), ("ROLLBACK_FAILED", 3)]

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
            "req-r", "org-r", "f" * 64, "approval-r", "admin-r", "session-r", "worker-r", "generation-r",
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
    assert tuple(run) == ("TIMED_OUT", "EXECUTION_AUTHORITY_EXPIRED")
    assert tuple(intent) == ("FAILED", "EXECUTION_AUTHORITY_EXPIRED", None)


def _issue(store, target, **kwargs):
    import os
    os.environ["CYBERASSESS_WORKER_IDENTITY"] = "worker-1"
    options = {"provider": "aws", "output_format": "json-asff", "quiet": True}
    options.update(kwargs.pop("operation_options", {}))
    return issue_execution_capability(
        decision_id="decision-1", validated_target=target, tool_id="prowler",
        operation_family="cloud_audit", operation_options=options,
        command=["/managed/prowler", "aws", "-M", "json-asff"],
        database=store,
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
            "req-a", "org-a", "f" * 64, "approval-idem", "admin-a", "session-a", "worker-a", "generation-a",
        )
        assert result == "AUTHORIZED"
        assert decision_id
        assert execution_id.startswith("run-")
        replay = database.approve_execution_request(
            "req-a", "org-a", "f" * 64, "approval-idem", "admin-a", "session-a", "worker-a", "generation-a",
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
        conn.execute(
            "UPDATE execution_dispatch_intents SET lease_expires_at = ? WHERE execution_id = ? AND organization_id = ?",
            (expired_claim, execution_id, "org-a"),
        )
    reclaimed_dispatch = database.claim_execution_dispatch_intent(
        execution_id, "org-a", "worker-a",
    )
    assert reclaimed_dispatch is not None
    assert reclaimed_dispatch.token != stale.dispatch.token
    assert database.claim_execution_authority(
        decision_id, "org-a", "session-a", "worker-a", OPERATION_POLICY_REVISION,
        dispatch_claim_token=stale.dispatch.token,
    ) is None
    recovered = database.claim_execution_authority(
        decision_id, "org-a", "session-a", "worker-a", OPERATION_POLICY_REVISION,
        dispatch_claim_token=reclaimed_dispatch.token,
    )
    assert recovered is not None
    assert recovered.decision.token != stale.decision.token
    assert not database.release_execution_authority(
        decision_id, "org-a", "crashed-worker", stale.decision.token, stale.dispatch.token,
    )
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
    assert lease.attempt_count == 4
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
    assert dispatch["attempt_count"] == 4
    assert dispatch["completed_at"]
    assert dispatch["last_error"] == "EXECUTION_CANCELLED_ACKNOWLEDGED"
    assert dispatch["claimed_by"] is None
    assert dispatch["claim_token"] is None
    assert dispatch["lease_expires_at"] is None
    assert run["state"] == "CANCELLED"
    assert run["reason_code"] == "EXECUTION_CANCELLED_ACKNOWLEDGED"
    assert run["finished_at"]
    # A retry is idempotent only for the exact durable outcome.  A worker must
    # not be able to rewrite a cancellation as success or as a different
    # terminal result merely by reusing its old dispatch token.
    assert database.finish_execution(
        execution_id, "org-a", "worker-a", lease.token,
        terminal_state="CANCELLED", reason_code="EXECUTION_CANCELLED_ACKNOWLEDGED",
    ) is True
    assert database.finish_execution(
        execution_id, "org-a", "worker-a", lease.token,
        terminal_state="FAILED", reason_code="PROCESS_EXIT_NONZERO",
    ) is False
    assert database.finish_execution(
        execution_id, "org-a", "worker-a", lease.token,
        terminal_state="FAILED", reason_code="unreviewed diagnostic",
    ) is False
    # The reason may be canonical for more than one failure class, but the
    # requested terminal state must still equal the durable state.
    with database._connection_scope() as conn:
        conn.execute(
            "UPDATE execution_runs SET state = 'FAILED', reason_code = ? WHERE execution_id = ? AND organization_id = ?",
            ("EXECUTION_AUTHORITY_EXPIRED", execution_id, "org-a"),
        )
        conn.execute(
            "UPDATE execution_dispatch_intents SET state = 'FAILED', last_error = ? WHERE execution_id = ? AND organization_id = ?",
            ("EXECUTION_AUTHORITY_EXPIRED", execution_id, "org-a"),
        )
    assert database.finish_execution(
        execution_id, "org-a", "worker-a", lease.token,
        terminal_state="TIMED_OUT", reason_code="EXECUTION_AUTHORITY_EXPIRED",
    ) is False


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
        "req-a", "org-a", "f" * 64, "approval-idem", "admin-a", "session-a", "worker-a", "generation-a",
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

        def get_execution_run_for_request(self, *args, **kwargs):
            return None

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
    assert result == {
        "request_id": "request-1",
        "execution_id": None,
        "revoked": True,
        "cancellation_status": "NOT_FOUND",
        "durable_terminal": True,
        "recovery_required": False,
    }
    assert store.called == (("request-1", "org-a", "admin"), {})


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


def _seed_execution_for_termination_settlement(
    database: DatabaseManager,
    *,
    execution_id: str,
    request_id: str,
    decision_id: str,
    claim_dispatch: bool = True,
    running: bool = True,
    no_external_process: bool = False,
):
    """Create one realistic authorized execution lifecycle for DAL tests."""
    from app.core.execution_service import record_no_process, record_posix_launch
    from app.core.models import ExecutionRunRecord

    now = datetime.now(timezone.utc)
    created_at = now.isoformat()
    expires_at = (now + timedelta(minutes=5)).isoformat()
    operation_options = json.dumps(
        {"output_format": "json-asff", "provider": "aws", "quiet": True},
        sort_keys=True,
        separators=(",", ":"),
    )
    with database._connection_scope() as conn:
        conn.execute(
            "INSERT INTO organizations (id, name, slug, created_at, is_active) VALUES (?, ?, ?, ?, 1)",
            ("org-settlement", "Settlement Org", "org-settlement", created_at),
        )
        conn.execute(
            "INSERT INTO assets (id, organization_id, name, type, target_value, created_at, updated_at) "
            "VALUES (?, ?, ?, 'CLOUD_ACCOUNT', ?, ?, ?)",
            ("asset-settlement", "org-settlement", "settlement-account", "aws://123456789012", created_at, created_at),
        )
        conn.execute(
            "INSERT INTO users (id, username, email, hashed_password, role, organization_id, is_active, created_at) "
            "VALUES (?, ?, ?, 'hash', 'ADMIN', ?, 1, ?)",
            ("admin-settlement", "admin-settlement", "settlement@example.test", "org-settlement", created_at),
        )
        conn.execute(
            """INSERT INTO execution_requests
               (id, idempotency_key, request_fingerprint, organization_id, asset_id,
                target_id, authorization_decision_id, target_policy_version, tool_id,
                operation_family, operation_options_json, operation_policy_revision,
                requested_by_user_id, state, created_at, expires_at, approved_decision_id)
               VALUES (?, ?, ?, 'org-settlement', 'asset-settlement', 'target-settlement',
                       'auth-settlement', 'v1', 'prowler', 'cloud_audit', ?, ?,
                       'admin-settlement', 'AUTHORIZED', ?, ?, ?)""",
            (request_id, f"idem-{request_id}", "f" * 64, operation_options,
             OPERATION_POLICY_REVISION, created_at, expires_at, decision_id),
        )
        conn.execute(
            """INSERT INTO execution_decisions
               (id, organization_id, project_id, asset_id, target_id,
                authorization_decision_id, target_policy_version, tool_id,
                operation_family, operation_options_json, operation_policy_revision,
                approval_state, approver_user_id, session_jti, worker_identity,
                created_at, expires_at)
               VALUES (?, 'org-settlement', NULL, 'asset-settlement', 'target-settlement',
                       'auth-settlement', 'v1', 'prowler', 'cloud_audit', ?, ?,
                       'APPROVED', 'admin-settlement', 'session-settlement',
                       'worker-settlement', ?, ?)""",
            (decision_id, operation_options, OPERATION_POLICY_REVISION, created_at, expires_at),
        )

    database.create_execution_run(
        ExecutionRunRecord(
            execution_id=execution_id,
            request_id=request_id,
            organization_id="org-settlement",
            worker_identity="worker-settlement",
            worker_generation="generation-settlement",
            correlation_id=f"corr-{execution_id}",
        )
    )
    with database._connection_scope() as conn:
        conn.execute(
            "INSERT INTO execution_dispatch_intents "
            "(execution_id, organization_id, state, attempt_count, created_at) "
            "VALUES (?, 'org-settlement', 'PENDING', 0, ?)",
            (execution_id, created_at),
        )

    authority = None
    if claim_dispatch:
        authority = database.claim_execution_authority(
            decision_id,
            "org-settlement",
            "session-settlement",
            "worker-settlement",
            OPERATION_POLICY_REVISION,
        )
        assert authority is not None
        if running:
            assert database.transition_execution_run(
                execution_id,
                "org-settlement",
                "STARTING",
                "RUNNING",
                worker_identity="worker-settlement",
                dispatch_claim_token=authority.dispatch.token,
            )

    capability = SimpleNamespace(
        execution_id=execution_id,
        decision=SimpleNamespace(id=decision_id, organization_id="org-settlement"),
        claim_token=authority.decision.token if authority is not None else "unclaimed",
        dispatch_claim_token=authority.dispatch.token if authority is not None else "unclaimed",
        worker_identity="worker-settlement",
        worker_generation="generation-settlement",
        database=database,
    )
    identity = None
    if no_external_process:
        assert record_no_process(
            capability,
            proof_code="EXECUTION_CANCELLED_BEFORE_PROCESS_CREATION",
            reason_code="EXECUTION_CANCELLED_BEFORE_PROCESS_CREATION",
        )
    elif claim_dispatch:
        identity = record_posix_launch(
            capability,
            pid=4242,
            process_group_id=4242,
            session_id=4242,
            start_token="posix:00000000-0000-0000-0000-000000000001:12345",
            member_snapshot=(SimpleNamespace(
                pid=4242,
                process_group_id=4242,
                session_id=4242,
                start_token="posix:00000000-0000-0000-0000-000000000001:12345",
            ),),
        )

    return authority, identity


def _capability_for_seed(database, execution_id, decision_id, authority=None):
    return SimpleNamespace(
        execution_id=execution_id,
        decision=SimpleNamespace(id=decision_id, organization_id="org-settlement"),
        claim_token=authority.decision.token if authority is not None else "unclaimed",
        dispatch_claim_token=authority.dispatch.token if authority is not None else "unclaimed",
        worker_identity="worker-settlement",
        worker_generation="generation-settlement",
        database=database,
    )


def test_committed_launch_uncertainty_transitions_to_recovery_blocked_without_rewriting_identity(tmp_path):
    """Post-commit uncertainty uses the durable committed identity as its only source."""
    from app.core.execution_service import record_launch_uncertain, record_terminal
    from app.core.models import ProcessOwnershipState

    database = DatabaseManager(tmp_path / "committed-launch-recovery.db")
    authority, _attestation = _seed_execution_for_termination_settlement(
        database,
        execution_id="run-committed-launch-recovery",
        request_id="request-committed-launch-recovery",
        decision_id="decision-committed-launch-recovery",
    )
    capability = _capability_for_seed(
        database,
        "run-committed-launch-recovery",
        "decision-committed-launch-recovery",
        authority,
    )
    before = database.get_process_ownership(
        "run-committed-launch-recovery", "org-settlement"
    )
    assert before is not None
    assert before["ownership_state"] == ProcessOwnershipState.EXTERNAL_PROCESS_GOVERNED.value
    assert before["launch_commit_state"] == "COMMITTED"

    # Conflicting caller values must be ignored after the committed row exists.
    assert record_launch_uncertain(
        capability,
        pid=9999,
        process_group_id=9999,
        start_token="posix:00000000-0000-0000-0000-000000000001:99999",
        session_id=9999,
        member_snapshot=(),
    ) is True

    after = database.get_process_ownership(
        "run-committed-launch-recovery", "org-settlement"
    )
    assert after is not None
    assert after["ownership_state"] == ProcessOwnershipState.RECOVERY_BLOCKED.value
    assert after["launch_commit_state"] == before["launch_commit_state"]
    for field_name in (
        "execution_id", "organization_id", "container_type", "container_identity",
        "root_process_id", "root_process_start_token", "process_group_id", "session_id",
        "worker_generation", "identity_attestation", "correlation_id", "created_at",
        "launched_at", "last_verified_at", "terminalized_at",
    ):
        assert after[field_name] == before[field_name], field_name

    with database._connection_scope() as conn:
        recovery = conn.execute(
            "SELECT status, attempt_number, next_retry_at, escalation_level "
            "FROM execution_recovery_state WHERE execution_id=? AND organization_id=?",
            ("run-committed-launch-recovery", "org-settlement"),
        ).fetchone()
    assert tuple(recovery) == ("REQUESTED", 0, None, 0)

    lease = database.claim_recovery(
        "run-committed-launch-recovery",
        "org-settlement",
        "worker-settlement",
        "generation-settlement",
        lease_seconds=30,
    )
    assert lease is not None
    assert lease["attempt_number"] == 1
    assert lease["lease_expires_at"]
    with database._connection_scope() as conn:
        recovery = conn.execute(
            "SELECT status, attempt_number, owner, worker_generation "
            "FROM execution_recovery_state WHERE execution_id=? AND organization_id=?",
            ("run-committed-launch-recovery", "org-settlement"),
        ).fetchone()
    assert tuple(recovery) == ("IN_PROGRESS", 1, "worker-settlement", "generation-settlement")

    assert record_terminal(
        capability,
        terminal_state="FAILED",
        reason_code="PROCESS_EXIT_NONZERO",
        process_id=before["root_process_id"],
        process_group_id=before["process_group_id"],
        process_start_token=before["root_process_start_token"],
        session_id=int(before["session_id"]),
        termination_status="ALREADY_EXITED",
    ) is False
    assert database.get_process_ownership(
        "run-committed-launch-recovery", "org-settlement"
    )["ownership_state"] == ProcessOwnershipState.RECOVERY_BLOCKED.value

    # The dedicated recovery primitive consumes the persisted attestation and
    # is the only path used here to terminalize the blocked ownership.
    assert database.settle_recovery_execution(
        "run-committed-launch-recovery",
        "org-settlement",
        "worker-settlement",
        lease["lease_token"],
        "generation-settlement",
    ) is True
    settled = database.get_process_ownership(
        "run-committed-launch-recovery", "org-settlement"
    )
    assert settled["ownership_state"] == ProcessOwnershipState.TERMINAL.value
    assert settled["identity_attestation"] == before["identity_attestation"]


@pytest.mark.parametrize("complete", [True, False])
def test_launch_uncertain_production_path_preserves_complete_identity_or_blocks_incomplete(tmp_path, complete):
    """The real pre-commit uncertainty path never manufactures signal authority."""
    from app.core.execution_service import load_durable_process_identity, record_launch_uncertain
    from app.core.process_supervisor import ProcessIdentity, ProcessMemberIdentity

    execution_id = f"run-precommit-uncertain-{complete}"
    decision_id = f"decision-precommit-uncertain-{complete}"
    database = DatabaseManager(tmp_path / f"precommit-uncertain-{complete}.db")
    authority, _ = _seed_execution_for_termination_settlement(
        database,
        execution_id=execution_id,
        request_id=f"request-precommit-uncertain-{complete}",
        decision_id=decision_id,
        claim_dispatch=False,
        running=False,
    )
    capability = _capability_for_seed(database, execution_id, decision_id, authority)
    token = "posix:00000000-0000-0000-0000-000000000001:12345"
    member = ProcessMemberIdentity(4242, 4242, 4242, token)
    assert record_launch_uncertain(
        capability,
        pid=4242,
        process_group_id=4242,
        start_token=token,
        session_id=4242,
        member_snapshot=(member,) if complete else (),
    ) is True
    ownership = database.get_process_ownership(execution_id, "org-settlement")
    assert ownership["ownership_state"] == "LAUNCH_UNCERTAIN"
    if complete:
        assert ownership["container_type"] == "POSIX_SESSION"
        assert ownership["identity_attestation"]
        assert load_durable_process_identity(database, execution_id, "org-settlement") == ProcessIdentity(
            pid=4242,
            process_group_id=4242,
            start_token=token,
            session_id=4242,
            member_snapshot=(member,),
        )
    else:
        assert ownership["identity_attestation"] is None
        assert load_durable_process_identity(database, execution_id, "org-settlement") is None


def test_post_commit_recovery_uses_exact_identity_after_database_restart(tmp_path):
    """A fresh database context can recover only from the committed durable attestation."""
    from app.core.execution_context import decode_execution_proof
    from app.core.execution_service import load_durable_process_identity, record_launch_uncertain

    path = tmp_path / "post-commit-restart-recovery.db"
    database = DatabaseManager(path)
    authority, _ = _seed_execution_for_termination_settlement(
        database,
        execution_id="run-post-commit-restart",
        request_id="request-post-commit-restart",
        decision_id="decision-post-commit-restart",
    )
    capability = _capability_for_seed(
        database, "run-post-commit-restart", "decision-post-commit-restart", authority
    )
    committed = database.get_process_ownership("run-post-commit-restart", "org-settlement")
    assert committed is not None
    assert record_launch_uncertain(
        capability,
        pid=1,
        process_group_id=1,
        start_token="posix:00000000-0000-0000-0000-000000000001:1",
        session_id=1,
        member_snapshot=(),
    ) is True

    restarted = DatabaseManager(path)
    identity = load_durable_process_identity(restarted, "run-post-commit-restart", "org-settlement")
    assert identity is not None
    assert identity.start_token == committed["root_process_start_token"]
    lease = restarted.claim_recovery(
        "run-post-commit-restart", "org-settlement", "worker-settlement", "generation-settlement"
    )
    assert lease is not None
    assert restarted.settle_recovery_execution(
        "run-post-commit-restart", "org-settlement", "worker-settlement",
        lease["lease_token"], "generation-settlement",
    ) is True
    settled = restarted.get_process_ownership("run-post-commit-restart", "org-settlement")
    proof = decode_execution_proof(settled["no_process_proof"], expected_proof_type="TERMINATION_CONFIRMED")
    assert proof["identity_attestation"] == committed["identity_attestation"]
    assert proof["process_start_token"] == committed["root_process_start_token"]
    assert proof["launch_commit_state"] == "COMMITTED"


@pytest.mark.parametrize("tamper", ["generation", "tenant", "execution", "root_token", "group", "session", "attestation_digest", "member_snapshot"])
def test_post_commit_recovery_transition_rejects_conflicting_or_tampered_identity(tmp_path, tamper):
    """The committed-to-recovery fence is immutable and tenant/generation bound."""
    from app.core.execution_service import record_launch_uncertain

    execution_id = f"run-recovery-tamper-{tamper}"
    decision_id = f"decision-recovery-tamper-{tamper}"
    database = DatabaseManager(tmp_path / f"recovery-tamper-{tamper}.db")
    authority, _ = _seed_execution_for_termination_settlement(
        database, execution_id=execution_id,
        request_id=f"request-recovery-tamper-{tamper}", decision_id=decision_id,
    )
    capability = _capability_for_seed(database, execution_id, decision_id, authority)
    before = database.get_process_ownership(execution_id, "org-settlement")
    if tamper in {"root_token", "group", "session", "attestation_digest", "member_snapshot"}:
        with database._connection_scope() as conn:
            if tamper == "root_token":
                conn.execute("UPDATE execution_process_ownership SET root_process_start_token=? WHERE execution_id=? AND organization_id=?", ("posix:00000000-0000-0000-0000-000000000001:99999", execution_id, "org-settlement"))
            elif tamper == "group":
                conn.execute("UPDATE execution_process_ownership SET process_group_id=? WHERE execution_id=? AND organization_id=?", ("9999", execution_id, "org-settlement"))
            elif tamper == "session":
                conn.execute("UPDATE execution_process_ownership SET session_id=? WHERE execution_id=? AND organization_id=?", ("9999", execution_id, "org-settlement"))
            else:
                payload = json.loads(before["identity_attestation"])
                if tamper == "attestation_digest":
                    payload["digest"] = "0" * 64
                else:
                    payload["member_snapshot"][0]["start_token"] = "posix:00000000-0000-0000-0000-000000000001:99999"
                conn.execute("UPDATE execution_process_ownership SET identity_attestation=? WHERE execution_id=? AND organization_id=?", (json.dumps(payload), execution_id, "org-settlement"))
    attempted_state = database.get_process_ownership(execution_id, "org-settlement")
    result = capability.database.transition_committed_process_to_recovery_blocked(
        "other-execution" if tamper == "execution" else execution_id,
        "other-tenant" if tamper == "tenant" else "org-settlement",
        "worker-settlement",
        "generation-attacker" if tamper == "generation" else "generation-settlement",
    )
    assert result is False
    assert database.get_process_ownership(execution_id, "org-settlement") == attempted_state
    assert attempted_state["ownership_state"] == "EXTERNAL_PROCESS_GOVERNED"


def test_post_commit_recovery_transition_is_single_winner_under_concurrency(tmp_path):
    """Concurrent downgrade attempts cannot replay or overwrite the committed row."""
    from concurrent.futures import ThreadPoolExecutor

    execution_id = "run-recovery-transition-race"
    decision_id = "decision-recovery-transition-race"
    path = tmp_path / "recovery-transition-race.db"
    database = DatabaseManager(path)
    authority, _ = _seed_execution_for_termination_settlement(
        database, execution_id=execution_id,
        request_id="request-recovery-transition-race", decision_id=decision_id,
    )

    def transition():
        return database.transition_committed_process_to_recovery_blocked(
            execution_id, "org-settlement", "worker-settlement", "generation-settlement",
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _item: transition(), (1, 2)))
    assert sorted(results) == [False, True]
    assert database.get_process_ownership(execution_id, "org-settlement")["ownership_state"] == "RECOVERY_BLOCKED"


def test_confirmed_termination_settlement_requires_revocation_and_exact_identity(tmp_path):
    from app.core.execution_service import load_durable_process_identity
    from app.core.process_supervisor import ProcessIdentity, ProcessMemberIdentity

    database = DatabaseManager(tmp_path / "confirmed-termination.db")
    _authority, _attestation = _seed_execution_for_termination_settlement(
        database,
        execution_id="run-settlement",
        request_id="request-settlement",
        decision_id="decision-settlement",
    )
    identity = ProcessIdentity(
        pid=4242,
        process_group_id=4242,
        start_token="posix:00000000-0000-0000-0000-000000000001:12345",
        session_id=4242,
        member_snapshot=(ProcessMemberIdentity(
            pid=4242,
            process_group_id=4242,
            session_id=4242,
            start_token="posix:00000000-0000-0000-0000-000000000001:12345",
        ),),
    )
    assert load_durable_process_identity(
        database, "run-settlement", "org-settlement"
    ) == identity

    settlement_args = {
        "terminal_state": "CANCELLED",
        "reason_code": "EXECUTION_CANCELLED",
        "termination_status": "KILLED",
        "process_id": identity.pid,
        "process_group_id": str(identity.process_group_id),
        "process_start_token": identity.start_token,
        "session_id": identity.session_id,
        "worker_generation": "generation-settlement",
        "worker_identity": "worker-settlement",
    }
    # The dedicated post-revocation primitive cannot replace the ordinary
    # authority-held terminal transition.
    assert database.settle_execution_after_confirmed_termination(
        "run-settlement", "org-settlement", **settlement_args
    ) is False
    with database._connection_scope() as conn:
        active = conn.execute(
            "SELECT p.ownership_state, r.state, i.state, s.status "
        "FROM execution_process_ownership p "
        "JOIN execution_runs r ON r.execution_id=p.execution_id AND r.organization_id=p.organization_id "
        "JOIN execution_dispatch_intents i ON i.execution_id=p.execution_id AND i.organization_id=p.organization_id "
        "JOIN execution_recovery_state s ON s.execution_id=p.execution_id AND s.organization_id=p.organization_id "
            "WHERE p.execution_id=? AND p.organization_id=?",
            ("run-settlement", "org-settlement"),
        ).fetchone()
    assert tuple(active) == ("EXTERNAL_PROCESS_GOVERNED", "RUNNING", "CLAIMED", "REQUESTED")

    assert database.revoke_execution_request(
        "request-settlement", "org-settlement", "admin-settlement"
    ) is True
    mismatched = replace(identity, process_group_id=identity.process_group_id + 1)
    assert database.settle_execution_after_confirmed_termination(
        "run-settlement",
        "org-settlement",
        **{
            **settlement_args,
            "process_group_id": str(mismatched.process_group_id),
        },
    ) is False
    with database._connection_scope() as conn:
        still_active = conn.execute(
            "SELECT ownership_state FROM execution_process_ownership "
            "WHERE execution_id=? AND organization_id=?",
            ("run-settlement", "org-settlement"),
        ).fetchone()
    assert still_active["ownership_state"] == "EXTERNAL_PROCESS_GOVERNED"

    assert database.settle_execution_after_confirmed_termination(
        "run-settlement", "org-settlement", **settlement_args
    ) is True
    # Replays return the same result without adding a second terminalization.
    assert database.settle_execution_after_confirmed_termination(
        "run-settlement", "org-settlement", **settlement_args
    ) is True
    with database._connection_scope() as conn:
        final = conn.execute(
            "SELECT p.ownership_state, p.no_process_proof, r.state AS run_state, "
            "r.reason_code, i.state AS dispatch_state, i.last_error, "
            "s.status, s.owner, s.lease_token, s.worker_generation, "
            "s.attempt_number, s.last_outcome, s.last_error AS recovery_last_error, "
            "s.next_retry_at, s.escalation_level "
            "FROM execution_process_ownership p "
            "JOIN execution_runs r ON r.execution_id=p.execution_id AND r.organization_id=p.organization_id "
            "JOIN execution_dispatch_intents i ON i.execution_id=p.execution_id AND i.organization_id=p.organization_id "
            "JOIN execution_recovery_state s ON s.execution_id=p.execution_id AND s.organization_id=p.organization_id "
            "WHERE p.execution_id=? AND p.organization_id=?",
            ("run-settlement", "org-settlement"),
        ).fetchone()
        attempts = conn.execute(
            "SELECT COUNT(*) AS count FROM execution_recovery_attempts "
            "WHERE execution_id=? AND organization_id=? AND status='CONFIRMED_TERMINATED'",
            ("run-settlement", "org-settlement"),
        ).fetchone()
    assert final["ownership_state"] == "TERMINAL"
    assert final["no_process_proof"].startswith("TERMINATION_CONFIRMED:v2:")
    assert final["run_state"] == "CANCELLED"
    assert final["reason_code"] == "EXECUTION_CANCELLED"
    assert final["dispatch_state"] == "BLOCKED"
    assert final["last_error"] == "EXECUTION_CANCELLED"
    assert final["status"] == "CONFIRMED_TERMINATED"
    assert final["owner"] is None and final["lease_token"] is None
    assert final["worker_generation"] == "generation-settlement"
    assert final["attempt_number"] == 1
    assert final["last_outcome"] == final["no_process_proof"]
    assert final["recovery_last_error"] is None
    assert final["next_retry_at"] is None
    assert final["escalation_level"] == 0
    assert attempts["count"] == 1


@pytest.mark.parametrize(
    ("ownership_state", "launch_commit_state"),
    (
        ("LAUNCH_UNCERTAIN", "UNCERTAIN"),
        ("RECOVERY_BLOCKED", "COMMITTED"),
    ),
)
def test_restart_loader_preserves_attested_identity_for_uncertain_states(
    tmp_path, ownership_state, launch_commit_state
):
    """Restart recovery must not degrade a durable attestation into a PID-only identity."""
    from app.core.execution_service import load_durable_process_identity
    from app.core.process_supervisor import ProcessIdentity, ProcessMemberIdentity

    database = DatabaseManager(tmp_path / f"restart-loader-{ownership_state}.db")
    _authority, _attestation = _seed_execution_for_termination_settlement(
        database,
        execution_id=f"run-loader-{ownership_state}",
        request_id=f"request-loader-{ownership_state}",
        decision_id=f"decision-loader-{ownership_state}",
    )
    with database._connection_scope() as conn:
        conn.execute(
            "UPDATE execution_process_ownership SET ownership_state=?, launch_commit_state=? "
            "WHERE execution_id=? AND organization_id=?",
            (
                ownership_state,
                launch_commit_state,
                f"run-loader-{ownership_state}",
                "org-settlement",
            ),
        )
    expected = ProcessIdentity(
        pid=4242,
        process_group_id=4242,
        start_token="posix:00000000-0000-0000-0000-000000000001:12345",
        session_id=4242,
        member_snapshot=(ProcessMemberIdentity(
            pid=4242,
            process_group_id=4242,
            session_id=4242,
            start_token="posix:00000000-0000-0000-0000-000000000001:12345",
        ),),
    )
    assert load_durable_process_identity(
        database,
        f"run-loader-{ownership_state}",
        "org-settlement",
    ) == expected


def test_restart_loader_blocks_incomplete_uncertain_attestation(tmp_path):
    """A recovery row with a missing member snapshot remains operator-visible and blocked."""
    from app.core.execution_service import load_durable_process_identity

    database = DatabaseManager(tmp_path / "restart-loader-incomplete.db")
    _authority, _attestation = _seed_execution_for_termination_settlement(
        database,
        execution_id="run-loader-incomplete",
        request_id="request-loader-incomplete",
        decision_id="decision-loader-incomplete",
    )
    with database._connection_scope() as conn:
        conn.execute(
            "UPDATE execution_process_ownership SET ownership_state='LAUNCH_UNCERTAIN', "
            "launch_commit_state='UNCERTAIN', identity_attestation=? "
            "WHERE execution_id=? AND organization_id=?",
            (json.dumps({"schema_version": "posix-process-attestation-v1"}), "run-loader-incomplete", "org-settlement"),
        )
    assert load_durable_process_identity(
        database,
        "run-loader-incomplete",
        "org-settlement",
    ) is None


@pytest.mark.parametrize(
    "tamper",
    (
        "recovery_generation",
        "recovery_timestamp",
        "recovery_attempt_worker_identity",
        "terminalized_timestamp",
    ),
)
def test_confirmed_termination_replay_rejects_durable_metadata_tampering(tmp_path, tamper):
    """The database replay fence rejects altered recovery metadata read-only."""
    from app.core.execution_service import load_durable_process_identity

    database = DatabaseManager(tmp_path / f"confirmed-termination-{tamper}.db")
    _authority, _attestation = _seed_execution_for_termination_settlement(
        database,
        execution_id=f"run-replay-{tamper}",
        request_id=f"request-replay-{tamper}",
        decision_id=f"decision-replay-{tamper}",
    )

    identity = load_durable_process_identity(
        database, f"run-replay-{tamper}", "org-settlement"
    )
    assert identity is not None
    settlement_args = {
        "terminal_state": "CANCELLED",
        "reason_code": "EXECUTION_CANCELLED",
        "termination_status": "KILLED",
        "process_id": identity.pid,
        "process_group_id": str(identity.process_group_id),
        "process_start_token": identity.start_token,
        "session_id": identity.session_id,
        "worker_generation": "generation-settlement",
        "worker_identity": "worker-settlement",
    }
    execution_id = f"run-replay-{tamper}"
    assert database.revoke_execution_request(
        f"request-replay-{tamper}", "org-settlement", "admin-settlement"
    ) is True
    assert database.settle_execution_after_confirmed_termination(
        execution_id, "org-settlement", **settlement_args
    ) is True

    with database._connection_scope() as conn:
        attempt = conn.execute(
            "SELECT * FROM execution_recovery_attempts "
            "WHERE execution_id=? AND organization_id=? "
            "ORDER BY completed_at DESC, attempt_id DESC LIMIT 1",
            (execution_id, "org-settlement"),
        ).fetchone()
        assert attempt is not None
        if tamper == "recovery_generation":
            conn.execute(
                "UPDATE execution_recovery_state SET worker_generation=? "
                "WHERE execution_id=? AND organization_id=?",
                ("tampered-recovery-generation", execution_id, "org-settlement"),
            )
        elif tamper in {"recovery_timestamp", "recovery_attempt_worker_identity"}:
            conn.execute(
                "INSERT INTO execution_recovery_attempts "
                "(attempt_id, execution_id, organization_id, worker_identity, "
                "worker_generation, attempt_number, status, cancellation_status, "
                "reason_code, correlation_id, requested_at, started_at, completed_at, "
                "error_code, escalation_level, health_reference) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    "tampered-recovery-attempt",
                    execution_id,
                    "org-settlement",
                    (
                        "tampered-recovery-worker"
                        if tamper == "recovery_attempt_worker_identity"
                        else attempt["worker_identity"]
                    ),
                    attempt["worker_generation"],
                    attempt["attempt_number"],
                    "CONFIRMED_TERMINATED",
                    attempt["cancellation_status"],
                    attempt["reason_code"],
                    attempt["correlation_id"],
                    (
                        attempt["requested_at"]
                        if tamper == "recovery_attempt_worker_identity"
                        else "2026-09-10T12:00:00"
                    ),
                    attempt["started_at"],
                    "9999-12-31T00:00:00+00:00",
                    None,
                    attempt["escalation_level"],
                    "tampered-recovery-health",
                ),
            )
        else:
            conn.execute(
                "UPDATE execution_process_ownership SET terminalized_at=? "
                "WHERE execution_id=? AND organization_id=?",
                ("2026-09-10T12:00:00", execution_id, "org-settlement"),
            )
        before = conn.execute(
            "SELECT p.ownership_state, p.no_process_proof, p.terminalized_at, "
            "r.state, r.reason_code, i.state, s.status, s.worker_generation, "
            "s.attempt_number, s.last_outcome, s.last_error, s.owner, s.lease_token, "
            "s.lease_expires_at, s.next_retry_at, s.escalation_level "
            "FROM execution_process_ownership p "
            "JOIN execution_runs r ON r.execution_id=p.execution_id AND r.organization_id=p.organization_id "
            "JOIN execution_dispatch_intents i ON i.execution_id=p.execution_id AND i.organization_id=p.organization_id "
            "JOIN execution_recovery_state s ON s.execution_id=p.execution_id AND s.organization_id=p.organization_id "
            "WHERE p.execution_id=? AND p.organization_id=?",
            (execution_id, "org-settlement"),
        ).fetchone()
        audit_count = conn.execute(
            "SELECT COUNT(*) AS count FROM audit_events WHERE organization_id=?",
            ("org-settlement",),
        ).fetchone()["count"]
        recovery_attempt_count = conn.execute(
            "SELECT COUNT(*) AS count FROM execution_recovery_attempts "
            "WHERE execution_id=? AND organization_id=?",
            (execution_id, "org-settlement"),
        ).fetchone()["count"]

    assert database.settle_execution_after_confirmed_termination(
        execution_id, "org-settlement", **settlement_args
    ) is False

    with database._connection_scope() as conn:
        after = conn.execute(
            "SELECT p.ownership_state, p.no_process_proof, p.terminalized_at, "
            "r.state, r.reason_code, i.state, s.status, s.worker_generation, "
            "s.attempt_number, s.last_outcome, s.last_error, s.owner, s.lease_token, "
            "s.lease_expires_at, s.next_retry_at, s.escalation_level "
            "FROM execution_process_ownership p "
            "JOIN execution_runs r ON r.execution_id=p.execution_id AND r.organization_id=p.organization_id "
            "JOIN execution_dispatch_intents i ON i.execution_id=p.execution_id AND i.organization_id=p.organization_id "
            "JOIN execution_recovery_state s ON s.execution_id=p.execution_id AND s.organization_id=p.organization_id "
            "WHERE p.execution_id=? AND p.organization_id=?",
            (execution_id, "org-settlement"),
        ).fetchone()
        assert tuple(after) == tuple(before)
        assert conn.execute(
            "SELECT COUNT(*) AS count FROM audit_events WHERE organization_id=?",
            ("org-settlement",),
        ).fetchone()["count"] == audit_count
        assert conn.execute(
            "SELECT COUNT(*) AS count FROM execution_recovery_attempts "
            "WHERE execution_id=? AND organization_id=?",
            (execution_id, "org-settlement"),
        ).fetchone()["count"] == recovery_attempt_count


def test_process_ownership_dal_rejects_worker_identity_and_generation_mismatch(tmp_path):
    """Ownership transitions must bind worker identity before any mutation."""
    from app.core.models import ExecutionProcessOwnershipRecord, ProcessOwnershipState

    database = DatabaseManager(tmp_path / "process-worker-binding.db")
    _authority, _identity = _seed_execution_for_termination_settlement(
        database,
        execution_id="run-process-worker-binding",
        request_id="request-process-worker-binding",
        decision_id="decision-process-worker-binding",
    )
    existing = database.get_process_ownership(
        "run-process-worker-binding", "org-settlement"
    )
    assert existing is not None
    record = ExecutionProcessOwnershipRecord.model_validate(existing)

    with database._connection_scope() as conn:
        audit_count = conn.execute(
            "SELECT COUNT(*) AS count FROM audit_events WHERE organization_id=?",
            ("org-settlement",),
        ).fetchone()["count"]

    assert database.transition_process_ownership(
        record,
        ProcessOwnershipState.EXTERNAL_PROCESS_GOVERNED,
        worker_identity="worker-attacker",
        actor="worker-attacker",
    ) is False
    assert database.get_process_ownership(
        "run-process-worker-binding", "org-settlement"
    ) == existing

    generation_tampered = record.model_copy(
        update={"worker_generation": "generation-attacker"}
    )
    assert database.transition_process_ownership(
        generation_tampered,
        ProcessOwnershipState.EXTERNAL_PROCESS_GOVERNED,
        worker_identity="worker-settlement",
        actor="worker-settlement",
    ) is False
    assert database.get_process_ownership(
        "run-process-worker-binding", "org-settlement"
    ) == existing
    with database._connection_scope() as conn:
        assert conn.execute(
            "SELECT COUNT(*) AS count FROM audit_events WHERE organization_id=?",
            ("org-settlement",),
        ).fetchone()["count"] == audit_count


def test_recovery_settlement_rejects_owner_not_bound_to_durable_run_read_only(tmp_path):
    """A recovery lease owner cannot terminalize another worker's process."""
    database = DatabaseManager(tmp_path / "recovery-worker-binding.db")
    _authority, identity = _seed_execution_for_termination_settlement(
        database,
        execution_id="run-recovery-worker-binding",
        request_id="request-recovery-worker-binding",
        decision_id="decision-recovery-worker-binding",
    )
    assert identity is not None
    with database._connection_scope() as conn:
        conn.execute(
            "UPDATE execution_process_ownership "
            "SET ownership_state='LAUNCH_UNCERTAIN', launch_commit_state='UNCERTAIN' "
            "WHERE execution_id=? AND organization_id=?",
            ("run-recovery-worker-binding", "org-settlement"),
        )

    lease = database.claim_recovery(
        "run-recovery-worker-binding",
        "org-settlement",
        "worker-attacker",
        "generation-settlement",
    )
    assert lease is not None

    def snapshot():
        with database._connection_scope() as conn:
            return (
                tuple(conn.execute(
                    "SELECT ownership_state, launch_commit_state, worker_generation, "
                    "no_process_proof, terminalized_at FROM execution_process_ownership "
                    "WHERE execution_id=? AND organization_id=?",
                    ("run-recovery-worker-binding", "org-settlement"),
                ).fetchone()),
                tuple(conn.execute(
                    "SELECT state, reason_code, finished_at FROM execution_runs "
                    "WHERE execution_id=? AND organization_id=?",
                    ("run-recovery-worker-binding", "org-settlement"),
                ).fetchone()),
                tuple(conn.execute(
                    "SELECT status, owner, lease_token, worker_generation, attempt_number, "
                    "last_outcome, last_error FROM execution_recovery_state "
                    "WHERE execution_id=? AND organization_id=?",
                    ("run-recovery-worker-binding", "org-settlement"),
                ).fetchone()),
                conn.execute(
                    "SELECT COUNT(*) AS count FROM audit_events WHERE organization_id=?",
                    ("org-settlement",),
                ).fetchone()["count"],
            )

    before = snapshot()
    assert database.settle_recovery_execution(
        "run-recovery-worker-binding",
        "org-settlement",
        "worker-attacker",
        lease["lease_token"],
        "generation-settlement",
    ) is False
    assert snapshot() == before


def test_terminal_process_settlement_replay_requires_the_original_proof_tuple(tmp_path):
    from app.core.execution_service import record_terminal
    from app.core.execution_context import decode_execution_proof, encode_execution_proof

    database = DatabaseManager(tmp_path / "terminal-proof-idempotence.db")
    authority, _attestation = _seed_execution_for_termination_settlement(
        database,
        execution_id="run-terminal-proof-idempotence",
        request_id="request-terminal-proof-idempotence",
        decision_id="decision-terminal-proof-idempotence",
    )
    capability = SimpleNamespace(
        execution_id="run-terminal-proof-idempotence",
        decision=SimpleNamespace(
            id="decision-terminal-proof-idempotence",
            organization_id="org-settlement",
        ),
        worker_identity="worker-settlement",
        worker_generation="generation-settlement",
        claim_token=authority.decision.token,
        dispatch_claim_token=authority.dispatch.token,
        database=database,
    )
    original = {
        "terminal_state": "FAILED",
        "reason_code": "PROCESS_EXIT_NONZERO",
        "process_id": 4242,
        "process_group_id": "4242",
        "process_start_token": "posix:00000000-0000-0000-0000-000000000001:12345",
        "session_id": 4242,
        "termination_status": "ALREADY_EXITED",
    }
    assert record_terminal(capability, **original) is True
    assert record_terminal(capability, **original) is True
    for omitted_field in (
        "process_id",
        "process_group_id",
        "process_start_token",
        "session_id",
        "termination_status",
    ):
        before_ownership = database.get_process_ownership(
            capability.execution_id,
            "org-settlement",
        )
        with database._connection_scope() as conn:
            before_audit_count = conn.execute(
                "SELECT COUNT(*) AS count FROM audit_events"
            ).fetchone()["count"]
        assert record_terminal(
            capability,
            **{**original, omitted_field: None},
        ) is False
        assert database.get_process_ownership(
            capability.execution_id,
            "org-settlement",
        ) == before_ownership
        with database._connection_scope() as conn:
            assert conn.execute(
                "SELECT COUNT(*) AS count FROM audit_events"
            ).fetchone()["count"] == before_audit_count
    assert record_terminal(
        capability,
        **{**original, "process_id": 4243},
    ) is False
    assert record_terminal(
        capability,
        **{**original, "reason_code": "EXECUTION_TIMEOUT"},
    ) is False

    # A digest-valid proof with a changed observation timestamp is still not
    # the durable terminal record.  Replay must bind the timestamp to the
    # immutable ownership terminalization time before returning idempotent
    # success.
    with database._connection_scope() as conn:
        proof_row = conn.execute(
            "SELECT no_process_proof FROM execution_process_ownership "
            "WHERE execution_id=? AND organization_id=?",
            (capability.execution_id, "org-settlement"),
        ).fetchone()
        assert proof_row is not None
        proof_payload = decode_execution_proof(
            proof_row["no_process_proof"],
            expected_proof_type="TERMINATION_CONFIRMED",
        )
        proof_payload["observed_at"] = (datetime.now(timezone.utc) + timedelta(seconds=1)).isoformat()
        conn.execute(
            "UPDATE execution_process_ownership SET no_process_proof=? "
            "WHERE execution_id=? AND organization_id=?",
            (
                encode_execution_proof("TERMINATION_CONFIRMED", proof_payload),
                capability.execution_id,
                "org-settlement",
            ),
        )
    assert record_terminal(capability, **original) is False

    # Restore the original proof so the independent correlation vector below
    # continues to exercise the correlation fence rather than the timestamp
    # fence.
    with database._connection_scope() as conn:
        conn.execute(
            "UPDATE execution_process_ownership SET no_process_proof=? "
            "WHERE execution_id=? AND organization_id=?",
            (
                proof_row["no_process_proof"],
                capability.execution_id,
                "org-settlement",
            ),
        )

    # A terminal replay must bind the immutable ownership correlation to the
    # run correlation before returning an idempotent success.  This direct SQL
    # change is a negative tamper fixture only; the production transition API
    # does not permit rewriting the ownership correlation.
    with database._connection_scope() as conn:
        conn.execute(
            "UPDATE execution_process_ownership SET correlation_id=? "
            "WHERE execution_id=? AND organization_id=?",
            ("tampered-terminal-correlation", capability.execution_id, "org-settlement"),
        )
        audit_count = conn.execute("SELECT COUNT(*) AS count FROM audit_events").fetchone()["count"]
    assert record_terminal(capability, **original) is False
    with database._connection_scope() as conn:
        ownership = conn.execute(
            "SELECT correlation_id FROM execution_process_ownership "
            "WHERE execution_id=? AND organization_id=?",
            (capability.execution_id, "org-settlement"),
        ).fetchone()
        assert conn.execute("SELECT COUNT(*) AS count FROM audit_events").fetchone()["count"] == audit_count
    assert ownership["correlation_id"] == "tampered-terminal-correlation"


def test_no_external_process_and_pre_dispatch_settlement_are_durable(tmp_path):
    database = DatabaseManager(tmp_path / "no-process-settlement.db")
    _seed_execution_for_termination_settlement(
        database,
        execution_id="run-no-process",
        request_id="request-no-process",
        decision_id="decision-no-process",
        running=False,
        no_external_process=True,
    )
    assert database.revoke_execution_request(
        "request-no-process", "org-settlement", "admin-settlement"
    ) is True
    assert database.settle_execution_after_confirmed_termination(
        "run-no-process",
        "org-settlement",
        terminal_state="CANCELLED",
        reason_code="EXECUTION_CANCELLED_BEFORE_PROCESS_CREATION",
        termination_status="NO_EXTERNAL_PROCESS",
        worker_generation="generation-settlement",
        worker_identity="worker-settlement",
    ) is True

    # A request cancelled before the dispatch claim uses a distinct proof and
    # cannot be confused with a worker's pre-Popen no-process assertion.  Use
    # a separate database so each fixture has one tenant-owned identity set.
    database = DatabaseManager(tmp_path / "pre-dispatch-settlement.db")
    _seed_execution_for_termination_settlement(
        database,
        execution_id="run-pre-dispatch",
        request_id="request-pre-dispatch",
        decision_id="decision-pre-dispatch",
        claim_dispatch=False,
    )
    assert database.revoke_execution_request(
        "request-pre-dispatch", "org-settlement", "admin-settlement"
    ) is True
    assert database.settle_execution_after_confirmed_termination(
        "run-pre-dispatch",
        "org-settlement",
        terminal_state="CANCELLED",
        reason_code="EXECUTION_CANCELLED_BEFORE_DISPATCH",
        termination_status="PRE_DISPATCH",
        worker_generation="generation-settlement",
        worker_identity="worker-settlement",
    ) is True
    with database._connection_scope() as conn:
        states = conn.execute(
            "SELECT p.ownership_state, r.state, i.state, s.status "
            "FROM execution_process_ownership p "
            "JOIN execution_runs r ON r.execution_id=p.execution_id AND r.organization_id=p.organization_id "
            "JOIN execution_dispatch_intents i ON i.execution_id=p.execution_id AND i.organization_id=p.organization_id "
            "JOIN execution_recovery_state s ON s.execution_id=p.execution_id AND s.organization_id=p.organization_id "
            "WHERE p.organization_id=? ORDER BY p.execution_id",
            ("org-settlement",),
        ).fetchall()
    assert [tuple(row) for row in states] == [
        ("TERMINAL", "CANCELLED", "BLOCKED", "CONFIRMED_TERMINATED"),
    ]


@pytest.mark.asyncio
async def test_governed_process_rejection_is_durably_settled_after_authority_claim(tmp_path, monkeypatch):
    from app.core.correlation import reset_correlation_id, set_correlation_id
    from app.core.execution_decision import issue_execution_capability
    from app.core.execution_service import get_worker_generation
    from app.core.models import ExecutionRequestRecord
    from app.core.process_supervisor import ProcessSupervisor

    database = DatabaseManager(tmp_path / "governed-process-rejection.db")
    now = datetime.now(timezone.utc)
    target = create_validated_target(
        Target(
            name="Governed test account",
            type=TargetType.CLOUD_ACCOUNT,
            value="aws://123456789012",
        ),
        organization_id="org-process",
        asset_id="asset-process",
        active_probing_granted=True,
    )
    operation_options = {"provider": "aws", "output_format": "json-asff", "quiet": True}
    resource_budget = {"timeout_seconds": 120, "max_output_bytes": 10485760}
    account_impact_budget = {"read_only": 1}
    credential_scope = {"provider": "aws"}
    created_at = now.isoformat()
    expires_at = (now + timedelta(minutes=5)).isoformat()

    with database._connection_scope() as conn:
        conn.execute(
            "INSERT INTO organizations (id, name, slug, created_at, is_active) VALUES (?, ?, ?, ?, 1)",
            ("org-process", "Process Org", "process-org", created_at),
        )
        conn.execute(
            "INSERT INTO assets (id, organization_id, name, type, target_value, active_probing_granted, created_at, updated_at) "
            "VALUES (?, ?, ?, 'CLOUD_ACCOUNT', ?, 1, ?, ?)",
            ("asset-process", "org-process", "process-account", "aws://123456789012", created_at, created_at),
        )
        conn.execute(
            "INSERT INTO users (id, username, email, hashed_password, role, organization_id, is_active, created_at) "
            "VALUES (?, ?, ?, 'hash', 'ADMIN', ?, 1, ?)",
            ("admin-process", "admin-process", "process@example.test", "org-process", created_at),
        )

    request = ExecutionRequestRecord(
        id="request-process",
        idempotency_key="idempotency-process",
        request_fingerprint="e" * 64,
        organization_id="org-process",
        project_id=None,
        asset_id="asset-process",
        target_id=target.target_id,
        authorization_decision_id=target.authorization_decision_id,
        target_policy_version=target.policy_version,
        tool_id="prowler",
        operation_family="cloud_audit",
        operation_options=operation_options,
        operation_policy_revision=OPERATION_POLICY_REVISION,
        resource_budget=resource_budget,
        account_impact_budget=account_impact_budget,
        credential_scope=credential_scope,
        requested_by_user_id="admin-process",
        expires_at=now + timedelta(minutes=5),
    )
    database.create_execution_request(request)

    worker_identity = "worker-process"
    worker_generation = get_worker_generation()
    monkeypatch.setenv("CYBERASSESS_WORKER_IDENTITY", worker_identity)
    correlation_token = set_correlation_id("corr-process-rejection")
    try:
        approval = database.approve_execution_request(
            "request-process",
            "org-process",
            "e" * 64,
            "approval-process",
            "admin-process",
            "session-process",
            worker_identity,
            worker_generation,
        )
    finally:
        reset_correlation_id(correlation_token)
    assert approval[0] == "AUTHORIZED"
    decision_id, execution_id = approval[1], approval[2]

    command = ["process-test", "--bounded"]
    capability = issue_execution_capability(
        decision_id=decision_id,
        validated_target=target,
        tool_id="prowler",
        operation_family="cloud_audit",
        operation_options=operation_options,
        command=command,
        database=database,
    )
    monkeypatch.setenv("OPERATING_MODE", "STANDALONE")
    monkeypatch.setenv("ENTERPRISE_EGRESS_ENFORCEMENT_REQUIRED", "false")

    result = await ProcessSupervisor().execute(
        command,
        timeout=5,
        max_output_bytes=1024,
        pre_launch_check=lambda: False,
        execution_capability=capability,
        operation_family="cloud_audit",
        operation_options=operation_options,
        tool_id="prowler",
    )

    assert result.returncode in {126, -1}
    assert result.execution_status.value == "SECURITY_REJECTED"
    assert "PROCESS_LAUNCH_REJECTED_SECURITY" in result.stderr
    with database._connection_scope() as conn:
        states = conn.execute(
            "SELECT r.state, r.reason_code, p.ownership_state, i.state "
            "FROM execution_runs r "
            "JOIN execution_process_ownership p ON p.execution_id=r.execution_id AND p.organization_id=r.organization_id "
            "JOIN execution_dispatch_intents i ON i.execution_id=r.execution_id AND i.organization_id=r.organization_id "
            "WHERE r.execution_id=? AND r.organization_id=?",
            (execution_id, "org-process"),
        ).fetchone()
    assert tuple(states) == (
        "EXECUTION_BLOCKED",
        "PROCESS_LAUNCH_REJECTED_SECURITY",
        "NO_EXTERNAL_PROCESS",
        "BLOCKED",
    )


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


def test_legacy_execution_runs_schema_requires_operator_reconciliation(tmp_path):
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
    with pytest.raises(RuntimeError, match="schema migration versions are not contiguous"):
        DatabaseManager(db_path)


def test_legacy_execution_runs_duplicate_preflight_requires_operator_reconciliation(tmp_path):
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
    with pytest.raises(RuntimeError, match="schema migration versions are not contiguous"):
        DatabaseManager(db_path)


def test_execution_migration_version_two_reruns_without_reconciling_fresh_schema(tmp_path):
    from app.core.db import DatabaseManager

    db_path = tmp_path / "version-two-rerun.db"
    database = DatabaseManager(db_path)
    with database._connection_scope() as conn:
        conn.execute("DELETE FROM schema_migrations WHERE version = 2")
    with pytest.raises(RuntimeError, match="schema migration versions are not contiguous"):
        DatabaseManager(db_path)


def test_execution_schema_drift_after_version_two_fails_closed(tmp_path):
    from app.core.db import DatabaseManager

    db_path = tmp_path / "version-two-drift.db"
    database = DatabaseManager(db_path)
    with database._connection_scope() as conn:
        conn.execute("DROP INDEX uq_execution_runs_request")
    with pytest.raises(RuntimeError, match="execution tenant-binding postcondition is not exact"):
        DatabaseManager(db_path)


def test_execution_schema_wrong_column_index_fails_closed(tmp_path):
    from app.core.db import DatabaseManager

    db_path = tmp_path / "wrong-run-index.db"
    database = DatabaseManager(db_path)
    with database._connection_scope() as conn:
        conn.execute("DROP INDEX uq_execution_runs_request")
        conn.execute("CREATE UNIQUE INDEX uq_execution_runs_request ON execution_runs(execution_id)")
    with pytest.raises(RuntimeError, match="execution tenant-binding postcondition is not exact"):
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
    with pytest.raises(RuntimeError, match="execution tenant-binding postcondition is not exact"):
        DatabaseManager(db_path)


def test_missing_migration_ledger_entry_fails_closed_before_v5_reexecution(tmp_path):
    from app.core.db import DatabaseManager

    db_path = tmp_path / "known-v4-duplicate.db"
    DatabaseManager(db_path)
    with sqlite3.connect(db_path) as conn:
        conn.execute("CREATE UNIQUE INDEX uq_execution_decisions_id_org ON execution_decisions(id, organization_id)")
        conn.execute("DELETE FROM schema_migrations WHERE version = 5")
        conn.commit()
    with pytest.raises(RuntimeError, match="schema migration versions are not contiguous"):
        DatabaseManager(db_path)
    with sqlite3.connect(db_path) as conn:
        names = {row[1] for row in conn.execute("PRAGMA index_list(execution_decisions)").fetchall()}
        versions = {row[0] for row in conn.execute("SELECT version FROM schema_migrations").fetchall()}
    assert "uq_execution_decisions_id_org" in names
    assert 5 not in versions


def test_v5_rejects_unknown_parent_key_duplicates_without_recording_success(tmp_path):
    from app.core.db import DatabaseManager

    db_path = tmp_path / "unknown-v4-duplicate.db"
    database = DatabaseManager(db_path)
    with sqlite3.connect(db_path) as conn:
        conn.execute("CREATE UNIQUE INDEX operator_owned_decision_parent_key ON execution_decisions(id, organization_id)")
        conn.execute("CREATE UNIQUE INDEX operator_owned_decision_parent_key_2 ON execution_decisions(id, organization_id)")
        conn.execute("DELETE FROM schema_migrations WHERE version = 5")
        conn.commit()
    with pytest.raises(ValueError, match="unknown duplicate decision parent keys"):
        database._init_db(max_migration_version=5)
    with sqlite3.connect(db_path) as conn:
        assert conn.execute("SELECT 1 FROM schema_migrations WHERE version = 5").fetchone() is None
        assert conn.execute("SELECT 1 FROM sqlite_master WHERE name = 'operator_owned_decision_parent_key'").fetchone()
