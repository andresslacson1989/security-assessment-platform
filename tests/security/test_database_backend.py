"""Contract 01 database backend compatibility and selection tests."""

import asyncio
import copy
import hashlib
import inspect
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import types

import pytest

import app.core.db as db_module
from app.core.db import (
    _MigrationCompatibilityError,
    _MigrationGuardedConnection,
    _PostgresConnection,
    _PostgresRow,
    _qmark_to_postgres,
    _assert_compatibility_column_exact,
    _compatibility_column_metadata,
    _compatibility_ddl,
    _is_postgres_duplicate_column,
    _is_sqlite_duplicate_column,
    DatabaseManager,
    PostgresDatabaseManager,
    is_database_integrity_error,
)
from app.core.migration_artifacts import (
    COMPATIBILITY_RECONCILIATION_ARTIFACT_REVISION,
    COMPATIBILITY_RECONCILIATION_MANIFEST,
    COMPATIBILITY_RECONCILIATION_SOURCE_SHA256,
    CURRENT_COMPATIBILITY_RECONCILIATION_ARTIFACT_REVISION,
    CURRENT_COMPATIBILITY_RECONCILIATION_SOURCE_SHA256,
    CURRENT_FORWARD_APPLY_ARTIFACT_REVISION,
    CURRENT_FORWARD_APPLY_SOURCE_SHA256,
    FORWARD_APPLY_ARTIFACT_REVISION,
    FORWARD_APPLY_MANIFESTS,
    FORWARD_APPLY_SOURCE_SHA256,
    MIGRATION_CHECKSUM_POSTCONDITION_SOURCE_SHA256,
    POSTCONDITION_SOURCE_SHA256,
)
from app.core.migration_registry import MIGRATION_REGISTRY, _EXPECTED_CHECKSUMS


class _Rows:
    def __init__(self, rows):
        self._rows = list(rows)

    def fetchall(self):
        return list(self._rows)

    def fetchone(self):
        return self._rows[0] if self._rows else None


class _PostgresV10Catalog:
    def __init__(self):
        self.statements = []

    def execute(self, sql, params=()):
        self.statements.append(sql)
        if "FROM information_schema.columns" in sql:
            required = {
                "execution_process_ownership": {
                    "execution_id", "organization_id", "ownership_state", "container_type",
                    "container_identity", "root_process_id", "root_process_start_token",
                    "process_group_id", "session_id", "worker_generation", "launch_commit_state",
                    "no_process_proof", "identity_attestation", "correlation_id", "created_at",
                    "launched_at", "last_verified_at", "terminalized_at", "updated_at",
                },
                "execution_recovery_attempts": {
                    "attempt_id", "execution_id", "organization_id", "worker_identity",
                    "worker_generation", "attempt_number", "status", "cancellation_status",
                    "reason_code", "correlation_id", "requested_at", "started_at", "completed_at",
                    "next_retry_at", "error_code", "escalation_level", "health_reference",
                },
                "execution_recovery_state": {
                    "execution_id", "organization_id", "status", "owner", "lease_token",
                    "lease_expires_at", "worker_generation", "attempt_number", "last_outcome",
                    "last_error", "next_retry_at", "escalation_level", "updated_at",
                },
            }
            return _Rows(
                {"table_name": table, "column_name": column}
                for table, columns in required.items()
                for column in columns
            )
        if "FROM pg_constraint c" in sql:
            return _Rows([{"convalidated": True}])
        if "FROM pg_index i" in sql:
            table = params[0]
            columns = ["attempt_id"] if table == "execution_recovery_attempts" else ["execution_id", "organization_id"]
            return _Rows([{"columns": columns}])
        return _Rows([])


class _RequiredSqliteTables:
    def execute(self, sql, params=()):
        if "sqlite_master" in sql:
            return _Rows([{"name": name} for name in (
                "schema_migrations", "schema_migration_events", "users", "organizations",
                "execution_requests", "execution_runs", "execution_decisions",
                "execution_dispatch_intents",
            )])
        return _Rows([])


def _stub_authoritative_schema_dependencies(database, monkeypatch):
    monkeypatch.setattr(database, "_verify_migration_ledger", lambda conn: None)
    monkeypatch.setattr(database, "_verify_forward_apply_artifact", lambda spec: None)


def test_postgres_v10_verifier_executes_qualified_constraint_catalog_query():
    database = object.__new__(PostgresDatabaseManager)
    connection = _PostgresV10Catalog()

    database._verify_migration_v10_postconditions(connection)

    queries = [sql for sql in connection.statements if "pg_get_constraintdef" in sql]
    assert queries
    assert any("pg_get_constraintdef(c.oid)" in sql for sql in queries)
    assert all("pg_get_constraintdef(oid)" not in sql for sql in queries)


def test_database_integrity_error_classifier_accepts_sqlite_without_invalid_type_entries():
    assert is_database_integrity_error(sqlite3.IntegrityError("duplicate"))
    assert not is_database_integrity_error(RuntimeError("not a constraint failure"))


def test_current_verifier_fingerprint_is_separate_from_historical_checksum_material():
    v10 = next(spec for spec in MIGRATION_REGISTRY if spec.version == 10)

    assert v10.checksum == _EXPECTED_CHECKSUMS[10]
    assert MIGRATION_CHECKSUM_POSTCONDITION_SOURCE_SHA256["_verify_migration_v10_postconditions"] == (
        "sha256:0c9dbfd369deee0e3240845793bb61be9bc8e66ac9eeaf2e9612e1dcc00c52f7"
    )
    assert POSTCONDITION_SOURCE_SHA256["_verify_migration_v10_postconditions"] == (
        "sha256:b5a343cd16ced6244b0a426d11c9210e5a005f1b1306e115416cc662b09b959d"
    )
    assert MIGRATION_CHECKSUM_POSTCONDITION_SOURCE_SHA256["_verify_migration_v10_postconditions"] != POSTCONDITION_SOURCE_SHA256[
        "_verify_migration_v10_postconditions"
    ]


def test_current_verifier_fingerprints_match_every_runtime_method():
    expected_names = {f"_verify_migration_v{version}_postconditions" for version in range(1, 14)}
    assert set(POSTCONDITION_SOURCE_SHA256) == expected_names
    actual = {
        name: "sha256:" + hashlib.sha256(inspect.getsource(getattr(DatabaseManager, name)).encode("utf-8")).hexdigest()
        for name in sorted(expected_names)
    }
    assert POSTCONDITION_SOURCE_SHA256 == actual


def test_forward_apply_artifacts_cover_both_supported_database_backends():
    assert set(FORWARD_APPLY_MANIFESTS) == set(range(1, 14))
    assert set(FORWARD_APPLY_SOURCE_SHA256) == set(range(1, 14))
    assert set(CURRENT_FORWARD_APPLY_SOURCE_SHA256) == set(range(1, 13))
    assert all(set(vector) == {"sqlite", "postgresql"} for vector in FORWARD_APPLY_MANIFESTS.values())
    assert all(set(vector) == {"sqlite", "postgresql"} for vector in FORWARD_APPLY_SOURCE_SHA256.values())
    assert all(set(vector) == {"sqlite", "postgresql"} for vector in CURRENT_FORWARD_APPLY_SOURCE_SHA256.values())


def test_current_forward_apply_fingerprints_match_runtime_serialization():
    for spec in MIGRATION_REGISTRY:
        if spec.version == 13:
            continue
        for backend in ("sqlite", "postgresql"):
            material = "\n".join((
                inspect.getsource(DatabaseManager._init_db),
                inspect.getsource(DatabaseManager._apply_migration_version),
                db_module.CURRENT_FORWARD_APPLY_ARTIFACT_REVISION,
                json.dumps(spec.apply_manifest, sort_keys=True, separators=(",", ":")),
                backend,
            )).encode("utf-8")
            actual = "sha256:" + hashlib.sha256(material).hexdigest()
            assert CURRENT_FORWARD_APPLY_SOURCE_SHA256[spec.version][backend] == actual


def test_historical_artifact_epoch_remains_immutable_and_current_epoch_is_distinct():
    assert FORWARD_APPLY_ARTIFACT_REVISION == "execution-migration-apply-v1"
    assert COMPATIBILITY_RECONCILIATION_ARTIFACT_REVISION == "execution-compatibility-reconciliation-v1"
    assert FORWARD_APPLY_SOURCE_SHA256[1] == {
        "sqlite": "sha256:8a0778721d6be2da6acb4c0c3324bff2fd93d81be008e5855d0ef7eae047b8e0",
        "postgresql": "sha256:cad1976d162f7b2feb70c8c3621afd36f96841bca0280b13e9e891af33de1cef",
    }
    assert COMPATIBILITY_RECONCILIATION_SOURCE_SHA256 == {
        "sqlite": "sha256:0ede92db2cbdf4ad7e59176e7c910bcc399a80510b389ce140c50b0e8679cb77",
        "postgresql": "sha256:b10d4bffdb6c0d2293c306322cff1fdae8ff3f959e182a67c3114a564fa59280",
    }
    assert CURRENT_FORWARD_APPLY_ARTIFACT_REVISION == "execution-migration-apply-v2"
    assert CURRENT_COMPATIBILITY_RECONCILIATION_ARTIFACT_REVISION == "execution-compatibility-reconciliation-v2"
    assert CURRENT_FORWARD_APPLY_SOURCE_SHA256 != FORWARD_APPLY_SOURCE_SHA256
    assert CURRENT_COMPATIBILITY_RECONCILIATION_SOURCE_SHA256 != COMPATIBILITY_RECONCILIATION_SOURCE_SHA256


def test_authoritative_schema_rejects_one_byte_mutated_current_verifier_digest(monkeypatch):
    database = object.__new__(DatabaseManager)
    _stub_authoritative_schema_dependencies(database, monkeypatch)
    original = POSTCONDITION_SOURCE_SHA256["_verify_migration_v1_postconditions"]
    replacement = "0" if original[-1] != "0" else "1"
    monkeypatch.setitem(
        db_module.POSTCONDITION_SOURCE_SHA256,
        "_verify_migration_v1_postconditions",
        original[:-1] + replacement,
    )

    with pytest.raises(RuntimeError, match="migration verifier artifact drifted"):
        database._verify_authoritative_schema_state(_RequiredSqliteTables())


def test_authoritative_schema_rejects_verifier_artifact_mismatch(monkeypatch):
    database = object.__new__(DatabaseManager)
    _stub_authoritative_schema_dependencies(database, monkeypatch)
    monkeypatch.setitem(
        db_module.POSTCONDITION_SOURCE_SHA256,
        "_verify_migration_v1_postconditions",
        "sha256:" + "0" * 64,
    )

    with pytest.raises(RuntimeError, match="migration verifier artifact drifted"):
        database._verify_authoritative_schema_state(_RequiredSqliteTables())


def test_authoritative_schema_rejects_mutated_verifier_source(monkeypatch):
    database = object.__new__(DatabaseManager)
    _stub_authoritative_schema_dependencies(database, monkeypatch)

    def mutated_verifier(self, conn):
        return None

    monkeypatch.setattr(DatabaseManager, "_verify_migration_v1_postconditions", mutated_verifier)

    with pytest.raises(RuntimeError, match="migration verifier artifact drifted"):
        database._verify_authoritative_schema_state(_RequiredSqliteTables())


def test_database_import_binds_to_explicit_disposable_path_before_singleton_creation(tmp_path):
    database_path = tmp_path / "explicit-isolated.sqlite3"
    environment = os.environ.copy()
    environment.pop("DATABASE_URL", None)
    environment["CYBERASSESS_DB_PATH"] = str(database_path)
    backend_root = Path(__file__).resolve().parents[2] / "backend"

    result = subprocess.run(
        [sys.executable, "-c", "from app.core.db import db_manager; print(db_manager.db_path)"],
        cwd=backend_root,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )

    assert result.stdout.strip() == str(database_path)
    assert database_path.is_file()


def test_compatibility_manifest_has_exact_governed_inventory_and_savepoints():
    assert [
        (entry["table"], entry["column"], entry["family"])
        for entry in COMPATIBILITY_RECONCILIATION_MANIFEST[:8]
    ] == [
        ("api_keys", "status", "generic"),
        ("users", "principal_type", "generic"),
        ("finding_occurrences", "organization_id", "generic"),
        ("audit_events", "sequence_number", "generic"),
        ("audit_events", "previous_event_hash", "generic"),
        ("audit_events", "event_hash", "generic"),
        ("assets", "active_probing_granted", "generic"),
        ("assets", "live_secret_verification_granted", "generic"),
    ]
    assert [entry["column"] for entry in COMPATIBILITY_RECONCILIATION_MANIFEST[8:]] == [
        "approved_decision_id",
        "target_policy_version",
        "operation_policy_revision",
        "request_fingerprint",
        "operation_options_json",
        "resource_budget_json",
        "account_impact_budget_json",
        "credential_scope_json",
        "snapshot_completeness",
    ]
    assert len(COMPATIBILITY_RECONCILIATION_MANIFEST) == 17
    assert all(entry["savepoint"] for entry in COMPATIBILITY_RECONCILIATION_MANIFEST)
    assert COMPATIBILITY_RECONCILIATION_ARTIFACT_REVISION == "execution-compatibility-reconciliation-v1"


def test_duplicate_race_classification_is_backend_native_and_column_specific():
    entry = next(item for item in COMPATIBILITY_RECONCILIATION_MANIFEST if item["column"] == "status")

    assert _is_sqlite_duplicate_column(
        sqlite3.OperationalError("duplicate column name: status"), entry
    )
    assert not _is_sqlite_duplicate_column(
        sqlite3.OperationalError("already exists: status"), entry
    )
    assert not _is_sqlite_duplicate_column(
        sqlite3.OperationalError("duplicate column name: other"), entry
    )

    class PostgresDuplicate:
        sqlstate = "42701"

    class SameMessageDifferentState:
        sqlstate = "42P07"

        def __str__(self):
            return "duplicate column name: status"

    assert _is_postgres_duplicate_column(PostgresDuplicate())
    assert not _is_postgres_duplicate_column(SameMessageDifferentState())


def test_fresh_sqlite_bootstrap_submits_each_governed_ddl_only_when_missing(tmp_path, monkeypatch):
    traced = []
    original_connect = db_module.sqlite3.connect

    def traced_connect(*args, **kwargs):
        connection = original_connect(*args, **kwargs)
        connection.set_trace_callback(traced.append)
        return connection

    monkeypatch.setattr(db_module.sqlite3, "connect", traced_connect)
    manager = DatabaseManager(db_path=tmp_path / "fresh-governed.sqlite3")
    governed_sql = db_module._compatibility_manifest_by_sql()
    actual = {
        normalized: sum(
            1 for statement in traced
            if db_module._normalize_migration_sql(statement) == normalized
        )
        for normalized in governed_sql
    }
    expected = {
        normalized: 1 if entry["table"] == "users" and entry["column"] == "principal_type" else 0
        for normalized, entry in governed_sql.items()
    }
    assert actual == expected
    with manager._connection_scope() as connection:
        assert [row["version"] for row in connection.execute(
            "SELECT version FROM schema_migrations ORDER BY version"
        ).fetchall()] == list(range(1, 14))
        for entry in COMPATIBILITY_RECONCILIATION_MANIFEST:
            _assert_compatibility_column_exact(
                entry,
                _compatibility_column_metadata(connection, "sqlite", entry),
            )


def test_direct_sqlite_init_uses_scoped_boundary_without_duplicate_compatibility_ddl(tmp_path, monkeypatch):
    traced = []
    original_connect = db_module.sqlite3.connect

    def traced_connect(*args, **kwargs):
        connection = original_connect(*args, **kwargs)
        connection.set_trace_callback(traced.append)
        return connection

    monkeypatch.setattr(db_module.sqlite3, "connect", traced_connect)
    manager = DatabaseManager(db_path=tmp_path / "direct-init.sqlite3")
    baseline_count = len(traced)

    manager._init_db(max_migration_version=2)

    direct_statements = traced[baseline_count:]
    for entry in COMPATIBILITY_RECONCILIATION_MANIFEST:
        normalized = db_module._normalize_migration_sql(_compatibility_ddl(entry))
        assert not any(db_module._normalize_migration_sql(statement) == normalized for statement in direct_statements)
    assert db_module._migration_operation_for(manager) is None


def test_guarded_metadata_cache_is_connection_and_transaction_bounded(tmp_path, monkeypatch):
    entry = next(item for item in COMPATIBILITY_RECONCILIATION_MANIFEST if item["column"] == "status")
    connection = sqlite3.connect(tmp_path / "bounded-cache.sqlite3")
    connection.row_factory = sqlite3.Row
    connection.execute("CREATE TABLE api_keys (key_id TEXT, status TEXT NOT NULL DEFAULT 'ACTIVE')")
    manager = object.__new__(DatabaseManager)
    calls = []
    original_metadata = db_module._compatibility_column_metadata

    def traced_metadata(*args, **kwargs):
        calls.append((args[1], args[2]["table"], args[2]["column"]))
        return original_metadata(*args, **kwargs)

    monkeypatch.setattr(db_module, "_compatibility_column_metadata", traced_metadata)
    with db_module._migration_operation_context(manager, "bounded-cache-test"):
        guarded = _MigrationGuardedConnection(manager, connection)
        guarded.execute("SAVEPOINT schema_migration_2")
        assert guarded.execute(_compatibility_ddl(entry)).rowcount == 0
        guarded.execute("RELEASE SAVEPOINT schema_migration_2")
        guarded.execute("SAVEPOINT schema_migration_2")
        assert guarded.execute(_compatibility_ddl(entry)).rowcount == 0
        guarded.execute("RELEASE SAVEPOINT schema_migration_2")
        assert len(calls) == 1
        guarded.commit()
        guarded.execute("SAVEPOINT schema_migration_2")
        assert guarded.execute(_compatibility_ddl(entry)).rowcount == 0
        guarded.execute("RELEASE SAVEPOINT schema_migration_2")
        assert len(calls) == 2
    connection.close()


def test_guarded_compatibility_ddl_rejects_missing_operation_context(tmp_path):
    entry = next(item for item in COMPATIBILITY_RECONCILIATION_MANIFEST if item["column"] == "status")
    connection = sqlite3.connect(tmp_path / "missing-operation-context.sqlite3")
    connection.row_factory = sqlite3.Row
    connection.execute("CREATE TABLE api_keys (key_id TEXT)")
    manager = object.__new__(DatabaseManager)
    guarded = _MigrationGuardedConnection(manager, connection)
    guarded.execute("SAVEPOINT schema_migration_2")
    with pytest.raises(_MigrationCompatibilityError, match="approved operation context"):
        guarded.execute(_compatibility_ddl(entry))
    connection.rollback()
    connection.close()


def test_migration_connection_does_not_trust_mutable_coordinator_flag(tmp_path):
    connection = sqlite3.connect(tmp_path / "operation-boundary.sqlite3")
    manager = object.__new__(DatabaseManager)
    manager._migration_coordinator_active = True

    assert db_module._migration_connection_for(manager, connection) is connection
    with db_module._migration_operation_context(manager, "boundary-test"):
        guarded = db_module._migration_connection_for(manager, connection)
        assert isinstance(guarded, _MigrationGuardedConnection)
    connection.close()


def test_sqlite_guard_skips_exact_existing_definition_without_submitting_ddl(tmp_path):
    entry = next(item for item in COMPATIBILITY_RECONCILIATION_MANIFEST if item["column"] == "status")
    path = tmp_path / "existing.sqlite3"
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    connection.execute("CREATE TABLE api_keys (key_id TEXT, status TEXT NOT NULL DEFAULT 'ACTIVE')")
    statements = []
    connection.set_trace_callback(statements.append)
    manager = object.__new__(DatabaseManager)
    with db_module._migration_operation_context(manager, "unit-test"):
        guarded = _MigrationGuardedConnection(manager, connection)
        guarded.execute("SAVEPOINT schema_migration_2")
        assert guarded.execute(_compatibility_ddl(entry)).rowcount == 0
        guarded.execute("RELEASE SAVEPOINT schema_migration_2")
    assert not any(db_module._normalize_migration_sql(statement) == db_module._normalize_migration_sql(_compatibility_ddl(entry)) for statement in statements)
    connection.close()


def test_sqlite_guard_adds_missing_definition_and_verifies_postcondition(tmp_path):
    entry = next(item for item in COMPATIBILITY_RECONCILIATION_MANIFEST if item["column"] == "status")
    path = tmp_path / "missing.sqlite3"
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    connection.execute("CREATE TABLE api_keys (key_id TEXT)")
    manager = object.__new__(DatabaseManager)
    with db_module._migration_operation_context(manager, "unit-test"):
        guarded = _MigrationGuardedConnection(manager, connection)
        guarded.execute("SAVEPOINT schema_migration_2")
        guarded.execute(_compatibility_ddl(entry))
        guarded.execute("RELEASE SAVEPOINT schema_migration_2")
    metadata = _compatibility_column_metadata(connection, "sqlite", entry)
    _assert_compatibility_column_exact(entry, metadata)
    connection.close()


def test_sqlite_guard_rejects_wrong_existing_definition(tmp_path):
    entry = next(item for item in COMPATIBILITY_RECONCILIATION_MANIFEST if item["column"] == "principal_type")
    connection = sqlite3.connect(tmp_path / "wrong.sqlite3")
    connection.row_factory = sqlite3.Row
    connection.execute("CREATE TABLE users (principal_type TEXT DEFAULT 'TENANT_PRINCIPAL')")
    manager = object.__new__(DatabaseManager)
    with db_module._migration_operation_context(manager, "unit-test"):
        guarded = _MigrationGuardedConnection(manager, connection)
        guarded.execute("SAVEPOINT schema_migration_3")
        with pytest.raises(_MigrationCompatibilityError, match="not exact"):
            guarded.execute(_compatibility_ddl(entry))
        guarded.execute("ROLLBACK TO SAVEPOINT schema_migration_3")
        guarded.execute("RELEASE SAVEPOINT schema_migration_3")
    connection.close()


def test_sqlite_guard_rejects_missing_table_before_ddl(tmp_path):
    entry = next(item for item in COMPATIBILITY_RECONCILIATION_MANIFEST if item["column"] == "status")
    connection = sqlite3.connect(tmp_path / "missing-table.sqlite3")
    connection.row_factory = sqlite3.Row
    manager = object.__new__(DatabaseManager)
    with db_module._migration_operation_context(manager, "unit-test"):
        guarded = _MigrationGuardedConnection(manager, connection)
        guarded.execute("SAVEPOINT schema_migration_2")
        with pytest.raises(_MigrationCompatibilityError, match="table is missing"):
            guarded.execute(_compatibility_ddl(entry))
        guarded.execute("ROLLBACK TO SAVEPOINT schema_migration_2")
        guarded.execute("RELEASE SAVEPOINT schema_migration_2")
    connection.close()


def test_sqlite_guard_wraps_unexpected_ddl_failure_without_duplicate_fallback(tmp_path):
    entry = next(item for item in COMPATIBILITY_RECONCILIATION_MANIFEST if item["column"] == "status")
    path = tmp_path / "readonly.sqlite3"
    writable = sqlite3.connect(path)
    writable.execute("CREATE TABLE api_keys (key_id TEXT)")
    writable.commit()
    writable.close()
    connection = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    manager = object.__new__(DatabaseManager)
    with db_module._migration_operation_context(manager, "unit-test"):
        guarded = _MigrationGuardedConnection(manager, connection)
        guarded.execute("SAVEPOINT schema_migration_2")
        with pytest.raises(_MigrationCompatibilityError, match="DDL execution failed") as failure:
            guarded.execute(_compatibility_ddl(entry))
        assert "duplicate" not in str(failure.value).lower()
    connection.close()


@pytest.mark.parametrize(
    ("peer_definition", "should_pass"),
    (("TEXT NOT NULL DEFAULT 'ACTIVE'", True), ("TEXT", False)),
)
def test_sqlite_guard_accepts_only_exact_duplicate_race_postcondition(tmp_path, peer_definition, should_pass):
    entry = next(item for item in COMPATIBILITY_RECONCILIATION_MANIFEST if item["column"] == "status")
    path = tmp_path / ("race-exact.sqlite3" if should_pass else "race-wrong.sqlite3")
    peer = sqlite3.connect(path)
    peer.execute("PRAGMA journal_mode=WAL")
    peer.execute("CREATE TABLE api_keys (key_id TEXT)")
    peer.commit()
    state = {"injected": False}
    target_sql = db_module._normalize_migration_sql(_compatibility_ddl(entry))

    class RaceConnection(sqlite3.Connection):
        def execute(self, sql, parameters=()):
            if not state["injected"] and db_module._normalize_migration_sql(sql) == target_sql:
                peer.execute(f"ALTER TABLE api_keys ADD COLUMN status {peer_definition}")
                peer.commit()
                state["injected"] = True
                raise sqlite3.OperationalError("duplicate column name: status")
            return super().execute(sql, parameters)

    connection = sqlite3.connect(path, factory=RaceConnection)
    connection.execute("PRAGMA journal_mode=WAL")
    connection.row_factory = sqlite3.Row
    manager = object.__new__(DatabaseManager)
    manager.db_path = path
    with db_module._migration_operation_context(manager, "unit-test"):
        guarded = _MigrationGuardedConnection(manager, connection)
        guarded.execute("SAVEPOINT schema_migration_2")
        try:
            if should_pass:
                guarded.execute(_compatibility_ddl(entry))
                guarded.execute("RELEASE SAVEPOINT schema_migration_2")
            else:
                with pytest.raises(_MigrationCompatibilityError, match="not exact"):
                    guarded.execute(_compatibility_ddl(entry))
                connection.execute("ROLLBACK TO SAVEPOINT schema_migration_2")
                connection.execute("RELEASE SAVEPOINT schema_migration_2")
        finally:
            connection.close()
            peer.close()


def test_compatibility_artifact_rejects_mutated_current_digest(monkeypatch):
    database = object.__new__(DatabaseManager)
    spec = next(item for item in MIGRATION_REGISTRY if item.version == 1)
    original = CURRENT_COMPATIBILITY_RECONCILIATION_SOURCE_SHA256["sqlite"]
    replacement = "0" if original[-1] != "0" else "1"
    monkeypatch.setitem(
        db_module.CURRENT_COMPATIBILITY_RECONCILIATION_SOURCE_SHA256,
        "sqlite",
        original[:-1] + replacement,
    )
    with pytest.raises(RuntimeError, match="compatibility reconciliation artifact drifted"):
        database._verify_compatibility_reconciliation_artifact(spec)


@pytest.mark.parametrize("backend", ["sqlite", "postgresql"])
def test_current_compatibility_fingerprints_match_runtime_digest(backend):
    assert db_module._compatibility_reconciliation_artifact_digest(backend) == (
        CURRENT_COMPATIBILITY_RECONCILIATION_SOURCE_SHA256[backend]
    )


def _assert_compatibility_artifact_rejects_one_byte_source_mutation(monkeypatch, target):
    database = object.__new__(DatabaseManager)
    spec = next(item for item in MIGRATION_REGISTRY if item.version == 1)
    original_getsource = db_module.inspect.getsource

    def mutated_getsource(candidate):
        source = original_getsource(candidate)
        if candidate is target:
            assert source
            replacement = " " if source[-1] != " " else "\n"
            return source[:-1] + replacement
        return source

    monkeypatch.setattr(db_module.inspect, "getsource", mutated_getsource)
    with pytest.raises(RuntimeError, match="compatibility reconciliation artifact drifted"):
        database._verify_compatibility_reconciliation_artifact(spec)


def test_compatibility_artifact_rejects_source_mutated_coordinator_activation_path(monkeypatch):
    _assert_compatibility_artifact_rejects_one_byte_source_mutation(
        monkeypatch,
        DatabaseManager._run_migration_coordinator,
    )


def test_compatibility_artifact_rejects_source_mutated_direct_activation_path(monkeypatch):
    _assert_compatibility_artifact_rejects_one_byte_source_mutation(
        monkeypatch,
        DatabaseManager._init_db,
    )


def test_compatibility_artifact_rejects_source_mutated_operation_context(monkeypatch):
    _assert_compatibility_artifact_rejects_one_byte_source_mutation(
        monkeypatch,
        db_module._migration_operation_context,
    )


def test_compatibility_artifact_rejects_source_mutated_guarded_callable(monkeypatch):
    _assert_compatibility_artifact_rejects_one_byte_source_mutation(
        monkeypatch,
        db_module._compatibility_column_metadata,
    )


def test_compatibility_artifact_rejects_mutated_security_sensitive_pattern(monkeypatch):
    database = object.__new__(DatabaseManager)
    spec = next(item for item in MIGRATION_REGISTRY if item.version == 1)
    original = db_module._COMPATIBILITY_IDENTIFIER_PATTERN
    mutated_pattern = db_module.re.compile(
        original.pattern.replace("*", "+"),
        original.flags,
    )
    monkeypatch.setattr(db_module, "_COMPATIBILITY_IDENTIFIER_PATTERN", mutated_pattern)
    with pytest.raises(RuntimeError, match="compatibility reconciliation artifact drifted"):
        database._verify_compatibility_reconciliation_artifact(spec)


def test_v13_forward_apply_artifact_verification_does_not_use_compatibility_artifact(monkeypatch):
    database = object.__new__(DatabaseManager)
    spec = next(item for item in MIGRATION_REGISTRY if item.version == 13)
    calls = []

    def unexpected_compatibility_digest(backend):
        calls.append(backend)
        return "sha256:" + ("0" * 64)

    monkeypatch.setattr(db_module, "_compatibility_reconciliation_artifact_digest", unexpected_compatibility_digest)
    database._verify_forward_apply_artifact(spec)
    assert calls == []


def _provenance_context(spec, backend="sqlite", *, current):
    forward_revision = CURRENT_FORWARD_APPLY_ARTIFACT_REVISION if current else FORWARD_APPLY_ARTIFACT_REVISION
    forward_map = CURRENT_FORWARD_APPLY_SOURCE_SHA256 if current else FORWARD_APPLY_SOURCE_SHA256
    compatibility_revision = (
        CURRENT_COMPATIBILITY_RECONCILIATION_ARTIFACT_REVISION
        if current else COMPATIBILITY_RECONCILIATION_ARTIFACT_REVISION
    )
    compatibility_map = (
        CURRENT_COMPATIBILITY_RECONCILIATION_SOURCE_SHA256
        if current else COMPATIBILITY_RECONCILIATION_SOURCE_SHA256
    )
    return {
        "coordinator": "registry",
        "provenance_format": "registry-coordinator-v2",
        "migration_version": spec.version,
        "apply_artifact_revision": forward_revision,
        "apply_artifact": forward_map[spec.version][backend],
        "apply_artifacts": copy.deepcopy(forward_map),
        "apply_manifest": copy.deepcopy(spec.apply_manifest),
        "backend_policy": spec.backend_policy,
        "compatibility_artifact_revision": compatibility_revision,
        "compatibility_artifact": compatibility_map[backend],
        "compatibility_manifest": copy.deepcopy(COMPATIBILITY_RECONCILIATION_MANIFEST),
    }


def _provenance_row(artifact_map, version=1, backend="sqlite"):
    artifact = artifact_map[version][backend]
    return {"transaction_context_id": f"txp-{'a' * 32}-{artifact.split(':', 1)[1]}"}


@pytest.mark.parametrize("current", [False, True], ids=["historical", "current"])
def test_complete_forward_and_compatibility_provenance_epochs_validate_without_rewriting(current):
    database = object.__new__(DatabaseManager)
    spec = next(item for item in MIGRATION_REGISTRY if item.version == 1)
    context = _provenance_context(spec, current=current)
    row = _provenance_row(CURRENT_FORWARD_APPLY_SOURCE_SHA256 if current else FORWARD_APPLY_SOURCE_SHA256)
    row_before = copy.deepcopy(row)
    context_before = copy.deepcopy(context)

    database._validate_migration_event_provenance(row, spec, context)

    assert row == row_before
    assert context == context_before


@pytest.mark.parametrize(
    "mutation,expected_message",
    [
        ("mixed", "provenance pair is invalid"),
        ("partial", "partial paired provenance"),
        ("unknown_revision", "provenance pair is invalid"),
        ("wrong_backend", "provenance pair is invalid"),
        ("wrong_suffix", "provenance pair is invalid"),
        ("forward_mutation", "provenance pair is invalid"),
        ("compatibility_mutation", "provenance pair is invalid"),
        ("manifest_mutation", "provenance pair is invalid"),
    ],
)
def test_paired_migration_provenance_rejects_invalid_or_mixed_claims(mutation, expected_message):
    database = object.__new__(DatabaseManager)
    spec = next(item for item in MIGRATION_REGISTRY if item.version == 1)
    context = _provenance_context(spec, current=True)
    row = _provenance_row(CURRENT_FORWARD_APPLY_SOURCE_SHA256)
    if mutation == "mixed":
        context.update({
            "compatibility_artifact_revision": COMPATIBILITY_RECONCILIATION_ARTIFACT_REVISION,
            "compatibility_artifact": COMPATIBILITY_RECONCILIATION_SOURCE_SHA256["sqlite"],
        })
    elif mutation == "partial":
        context.pop("compatibility_manifest")
    elif mutation == "unknown_revision":
        context["apply_artifact_revision"] = "execution-migration-apply-unknown"
    elif mutation == "wrong_backend":
        database = object.__new__(PostgresDatabaseManager)
    elif mutation == "wrong_suffix":
        row = {"transaction_context_id": f"txp-{'a' * 32}-{'0' * 64}"}
    elif mutation == "forward_mutation":
        context["apply_artifacts"][2]["sqlite"] = context["apply_artifacts"][2]["sqlite"][:-1] + "0"
    elif mutation == "compatibility_mutation":
        original = context["compatibility_artifact"]
        context["compatibility_artifact"] = original[:-1] + ("0" if original[-1] != "0" else "1")
    elif mutation == "manifest_mutation":
        context["apply_manifest"]["sqlite"] = "manifest-mutated"

    with pytest.raises(RuntimeError, match=expected_message):
        database._validate_migration_event_provenance(row, spec, context)


def test_legacy_transaction_context_accepts_only_claimless_rows():
    database = object.__new__(DatabaseManager)
    spec = next(item for item in MIGRATION_REGISTRY if item.version == 1)
    database._validate_migration_event_provenance(
        {"transaction_context_id": f"tx-{'a' * 32}"}, spec, {}
    )
    context = _provenance_context(spec, current=True)
    with pytest.raises(RuntimeError, match="partial forward-apply provenance"):
        database._validate_migration_event_provenance(
            {"transaction_context_id": f"tx-{'a' * 32}"}, spec, context
        )


def test_fresh_disposable_process_imports_after_current_artifact_verification(tmp_path):
    database_path = tmp_path / "fresh-process.db"
    environment = os.environ.copy()
    environment.pop("DATABASE_URL", None)
    environment["CYBERASSESS_DB_PATH"] = str(database_path)
    environment["PYTHONPATH"] = str(Path(__file__).resolve().parents[2] / "backend")
    completed = subprocess.run(
        [sys.executable, "-c", "import app.core.db as db; print(type(db.db_manager).__name__)"],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert "DatabaseManager" in completed.stdout


def test_worker_does_not_reexecute_terminal_authoritative_scan_states():
    from run_worker import should_process_scan
    from app.core.models import ScanStatus

    assert should_process_scan(ScanStatus.PENDING) is True
    assert should_process_scan(ScanStatus.RUNNING) is True
    for terminal_status in (ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED):
        assert should_process_scan(terminal_status) is False


def test_qmark_translation_preserves_quoted_literals():
    sql = "SELECT '?' AS literal, \"?\" AS identifier, value FROM items WHERE id = ?"

    assert _qmark_to_postgres(sql) == (
        "SELECT '?' AS literal, \"?\" AS identifier, value FROM items WHERE id = %s"
    )


def test_qmark_translation_escapes_literal_percent_signs_for_psycopg():
    assert _qmark_to_postgres("SELECT * FROM items WHERE name LIKE '%run%' AND id = ?") == (
        "SELECT * FROM items WHERE name LIKE '%%run%%' AND id = %s"
    )


def test_postgres_row_supports_mapping_and_positional_access():
    row = _PostgresRow(["id", "status"], ("row-1", "READY"))

    assert row["id"] == "row-1"
    assert row[0] == "row-1"
    assert row["status"] == row[1] == "READY"


def test_postgres_schema_execution_tables_are_deferred_until_dependencies_exist():
    class Cursor:
        description = None

        def __init__(self, statements):
            self.statements = statements

        def execute(self, sql, params=()):
            self.statements.append(sql)

    class Connection:
        def __init__(self):
            self.statements = []

        def cursor(self):
            return Cursor(self.statements)

    raw = Connection()
    _PostgresConnection(raw).executescript("""
        CREATE TABLE IF NOT EXISTS execution_requests (id TEXT PRIMARY KEY);
        CREATE TABLE IF NOT EXISTS organizations (id TEXT PRIMARY KEY);
        CREATE TABLE IF NOT EXISTS execution_runs (id TEXT, FOREIGN KEY (request_id) REFERENCES execution_requests(id));
        CREATE UNIQUE INDEX IF NOT EXISTS uq_execution_runs_request ON execution_runs(id);
    """)
    assert raw.statements[:1] == ["CREATE TABLE IF NOT EXISTS organizations (id TEXT PRIMARY KEY)"]
    assert raw.statements[-3:] == [
        "CREATE TABLE IF NOT EXISTS execution_requests (id TEXT PRIMARY KEY)",
        "CREATE TABLE IF NOT EXISTS execution_runs (id TEXT, FOREIGN KEY (request_id) REFERENCES execution_requests(id))",
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_execution_runs_request ON execution_runs(id)",
    ]


def test_database_manager_selects_postgres_for_enterprise_url(monkeypatch):
    class FakePostgresManager:
        def __init__(self, database_url):
            self.database_url = database_url

    monkeypatch.setattr("app.core.db.PostgresDatabaseManager", FakePostgresManager)
    monkeypatch.setenv("DATABASE_URL", "postgresql://user:pass@db/cyberassess")
    original_instance = DatabaseManager._instance
    DatabaseManager._instance = None

    try:
        manager = DatabaseManager.get_instance()
        assert isinstance(manager, FakePostgresManager)
        assert manager.database_url.startswith("postgresql://")
    finally:
        DatabaseManager._instance = original_instance


def test_postgres_manager_closes_pool_when_initialization_fails(monkeypatch):
    class Pool:
        closed = False

        def __init__(self, **kwargs):
            self.kwargs = kwargs

        def close(self):
            self.closed = True

    pool = Pool()
    monkeypatch.setitem(sys.modules, "psycopg_pool", types.SimpleNamespace(ConnectionPool=lambda **kwargs: pool))
    monkeypatch.setattr(DatabaseManager, "_run_migration_coordinator", lambda self: (_ for _ in ()).throw(RuntimeError("schema failure")))

    with pytest.raises(RuntimeError, match="schema failure"):
        PostgresDatabaseManager("postgresql://user:pass@127.0.0.1/cyberassess_test")

    assert pool.closed is True


def test_postgres_manager_preserves_initialization_failure_when_pool_close_fails(monkeypatch, caplog):
    class Pool:
        def close(self):
            raise OSError("pool close failure")

    monkeypatch.setitem(sys.modules, "psycopg_pool", types.SimpleNamespace(ConnectionPool=lambda **kwargs: Pool()))
    monkeypatch.setattr(DatabaseManager, "_run_migration_coordinator", lambda self: (_ for _ in ()).throw(RuntimeError("authoritative schema failure")))

    with caplog.at_level("ERROR", logger="cyberassess.persistence"):
        with pytest.raises(RuntimeError, match="authoritative schema failure"):
            PostgresDatabaseManager("postgresql://user:pass@127.0.0.1/cyberassess_test")

    assert "pool cleanup failed during initialization" in caplog.text
    assert "pool close failure" not in caplog.text


@pytest.mark.asyncio
async def test_queue_records_and_acknowledges_durable_execution_intent():
    from app.core.queue import ScanQueueManager

    class FakeDurableBackend:
        def __init__(self):
            self.events = []

        async def enqueue(self, scan_id, organization_id):
            self.events.append(("enqueue", scan_id, organization_id))
            return "message-1"

        async def complete(self, message_id):
            self.events.append(("complete", message_id))

        async def fail(self, message_id, error_code):
            self.events.append(("fail", message_id, error_code))

    backend = FakeDurableBackend()
    manager = ScanQueueManager(max_concurrent=1, durable_backend=backend)

    async def work():
        return "done"

    assert await manager.execute_bounded("scan-1", work, organization_id="org-1") == "done"
    assert backend.events == [
        ("enqueue", "scan-1", "org-1"),
        ("complete", "message-1"),
    ]


@pytest.mark.asyncio
async def test_queue_manager_enqueue_only_requires_and_uses_durable_backend():
    from app.core.queue import ScanQueueManager

    class Backend:
        async def enqueue(self, scan_id, organization_id):
            self.received = (scan_id, organization_id)
            return "message-queue-only"

    backend = Backend()
    manager = ScanQueueManager(durable_backend=backend)
    assert manager.durable_enabled is True
    assert await manager.enqueue_only("scan-queue-only", "org-queue-only") == "message-queue-only"
    assert backend.received == ("scan-queue-only", "org-queue-only")

    local_manager = ScanQueueManager()
    with pytest.raises(RuntimeError, match="durable execution backend"):
        await local_manager.enqueue_only("scan-local", None)


@pytest.mark.asyncio
async def test_redis_enqueue_is_idempotent_per_tenant_authorization_request():
    """Governed replay must reuse one stream identity, including after a restart."""
    from app.core.queue import (
        DurableQueueIdentityConflict,
        QueueDispatchBinding,
        RedisDurableQueue,
    )

    class FakeRedis:
        def __init__(self):
            self.dedupe = {}
            self.entries = {}
            self.eval_calls = []

        async def eval(self, script, number_of_keys, *keys_and_args):
            self.eval_calls.append((script, number_of_keys, keys_and_args))
            assert number_of_keys == 2
            assert "GET" in script and "XRANGE" in script and "XADD" in script and "SET" in script
            dedupe_key = keys_and_args[0]
            stream_key = keys_and_args[1]
            binding_fields = (
                tuple(keys_and_args[2:4])
                + (keys_and_args[5],)
                + tuple(keys_and_args[8:])
            )
            if dedupe_key in self.dedupe:
                message_id = self.dedupe[dedupe_key]
                if self.entries[(stream_key, message_id)] != binding_fields:
                    return "__CYBERASSESS_QUEUE_IDENTITY_CONFLICT__:MISMATCH"
                return message_id
            message_id = f"message-{len(self.dedupe) + 1}"
            self.dedupe[dedupe_key] = message_id
            self.entries[(stream_key, message_id)] = binding_fields
            return message_id

    queue = object.__new__(RedisDurableQueue)
    queue._redis = FakeRedis()
    queue._consumer_name = "worker-test"
    queue._group_ready = True
    queue._group_lock = asyncio.Lock()

    binding = QueueDispatchBinding.create(
        scan_id="scan-a",
        organization_id="org-a",
        authorization_request_id="request-a",
        manifest_hash="a" * 64,
        execution_ids=("execution-a",),
        operation_ids=("network:nmap",),
    )
    first = await queue.enqueue(
        "scan-a",
        "org-a",
        authorization_request_id="request-a",
        queue_binding=binding,
    )
    replay = await queue.enqueue(
        "scan-a",
        "org-a",
        authorization_request_id="request-a",
        queue_binding=binding,
    )
    other_binding = QueueDispatchBinding.create(
        scan_id="scan-a",
        organization_id="org-b",
        authorization_request_id="request-a",
        manifest_hash="a" * 64,
        execution_ids=("execution-b",),
        operation_ids=("network:nmap",),
    )
    other_tenant = await queue.enqueue(
        "scan-a",
        "org-b",
        authorization_request_id="request-a",
        queue_binding=other_binding,
    )

    assert first == replay == "message-1"
    assert other_tenant == "message-2"
    assert len(queue._redis.eval_calls) == 3
    assert queue._redis.eval_calls[0][2][0] != queue._redis.eval_calls[2][2][0]
    assert queue._redis.eval_calls[0][2][8:] == (
        binding.queue_binding_digest,
        binding.manifest_hash,
        binding.execution_ids_json,
        binding.operation_ids_json,
        binding.schema_version,
        "AUTHORITATIVE_EXECUTION",
    )
    changed_binding = QueueDispatchBinding.create(
        scan_id="scan-changed",
        organization_id="org-a",
        authorization_request_id="request-a",
        manifest_hash="a" * 64,
        execution_ids=("execution-a",),
        operation_ids=("network:nmap",),
    )
    with pytest.raises(DurableQueueIdentityConflict):
        await queue.enqueue(
            "scan-changed",
            "org-a",
            authorization_request_id="request-a",
            queue_binding=changed_binding,
        )


@pytest.mark.asyncio
async def test_redis_enqueue_rejects_authoritative_intent_without_typed_binding():
    from app.core.queue import RedisDurableQueue

    queue = object.__new__(RedisDurableQueue)
    queue._group_ready = True
    queue._group_lock = asyncio.Lock()

    with pytest.raises(ValueError, match="typed queue binding"):
        await queue.enqueue(
            "scan-missing-binding",
            "org-a",
            authorization_request_id="request-missing-binding",
        )


@pytest.mark.asyncio
async def test_redis_consumer_passes_typed_authoritative_binding_to_worker():
    from app.core.queue import QueueDispatchBinding, RedisDurableQueue, _issue_authenticated_quarantine_authorization

    binding = QueueDispatchBinding.create(
        scan_id="scan-consumer-binding",
        organization_id="org-consumer-binding",
        authorization_request_id="request-consumer-binding",
        manifest_hash="b" * 64,
        execution_ids=("execution-consumer-binding",),
        operation_ids=("network:nmap",),
    )

    class FakeRedis:
        async def xautoclaim(self, *args, **kwargs):
            return ("0-0", [], [])

        async def xreadgroup(self, *args, **kwargs):
            return [(
                "stream",
                [(
                    "message-consumer-binding",
                    {
                    "message_kind": "AUTHORITATIVE_EXECUTION",
                    "enqueued_at": "2026-09-11T00:00:00+00:00",
                        "scan_id": binding.scan_id,
                        "organization_id": binding.organization_id,
                        "authorization_request_id": binding.authorization_request_id,
                        "queue_binding_digest": binding.queue_binding_digest,
                        "manifest_hash": binding.manifest_hash,
                        "execution_ids_json": binding.execution_ids_json,
                        "operation_ids_json": binding.operation_ids_json,
                        "queue_binding_schema_version": binding.schema_version,
                    },
                )],
            )]

        async def xack(self, *args):
            self.acked = args[-1]

        async def get(self, _key):
            return None

        async def xpending_range(self, *_args, **_kwargs):
            return [{"times_delivered": 1}]

    queue = object.__new__(RedisDurableQueue)
    queue._redis = FakeRedis()
    queue._consumer_name = "worker-test"
    queue._group_ready = True
    queue._group_lock = asyncio.Lock()
    received = []

    async def handler(scan_id, organization_id, authorization_request_id, envelope, received_binding):
        received.append(
            (scan_id, organization_id, authorization_request_id, envelope, received_binding)
        )

    assert await queue.consume_once(handler, block_ms=0, reclaim_idle_ms=1) is True
    assert received == [(
        binding.scan_id,
        binding.organization_id,
        binding.authorization_request_id,
        None,
        binding,
    )]
    assert queue._redis.acked == "message-consumer-binding"


@pytest.mark.asyncio
async def test_authoritative_queue_failure_stays_in_pel_until_bounded_quarantine_and_explicit_ack(monkeypatch):
    """Authoritative failures are retryable evidence, never implicit ACKs."""
    from app.core import queue as queue_module
    from app.core.queue import QueueDispatchBinding, RedisDurableQueue, _issue_authenticated_quarantine_authorization

    monkeypatch.setattr(queue_module, "_QUEUE_MAX_DELIVERY_ATTEMPTS", 3)
    binding = QueueDispatchBinding.create(
        scan_id="scan-authoritative-failure",
        organization_id="org-authoritative-failure",
        authorization_request_id="request-authoritative-failure",
        manifest_hash="c" * 64,
        execution_ids=("execution-authoritative-failure",),
        operation_ids=("network:nmap",),
    )
    fields = {
        "message_kind": "AUTHORITATIVE_EXECUTION",
        "enqueued_at": "2026-09-11T00:00:00+00:00",
        "scan_id": binding.scan_id,
        "organization_id": binding.organization_id,
        "authorization_request_id": binding.authorization_request_id,
        "queue_binding_digest": binding.queue_binding_digest,
        "manifest_hash": binding.manifest_hash,
        "execution_ids_json": binding.execution_ids_json,
        "operation_ids_json": binding.operation_ids_json,
        "queue_binding_schema_version": binding.schema_version,
    }

    class FakeRedis:
        def __init__(self):
            self.delivery_count = 0
            self.failures = []
            self.acks = []
            self.markers = {}
            self.message_pending = True

        async def xautoclaim(self, *_args, **_kwargs):
            if not self.message_pending:
                return ("0-0", [], [])
            self.delivery_count += 1
            return ("0-0", [("message-authoritative-failure", fields)], [])

        async def xreadgroup(self, *_args, **_kwargs):
            raise AssertionError("new-message read is not expected after the pending delivery is claimed")

        async def xpending_range(self, *_args, **_kwargs):
            return [{"times_delivered": self.delivery_count}]

        async def xadd(self, stream, payload):
            assert stream == "cyberassess:scan-execution:failures"
            self.failures.append(dict(payload))
            return f"failure-{len(self.failures)}"

        async def xack(self, _stream, _group, message_id):
            self.acks.append(message_id)
            self.message_pending = False

        async def get(self, key):
            return self.markers.get(key)

        async def eval(self, _script, number_of_keys, *args):
            assert number_of_keys == 4
            if self.markers.get(args[0]) != args[4] or not self.message_pending:
                return 0
            fields = dict(zip(args[7::2], args[8::2]))
            self.failures.append(fields)
            self.acks.append(args[6])
            self.message_pending = False
            self.markers.pop(args[0], None)
            self.markers.pop(args[1], None)
            return 1

        async def set(self, key, value, *, ex=None):
            if ex is not None:
                assert ex == queue_module._QUEUE_QUARANTINE_TTL_SECONDS
            self.markers[key] = value
            return True

        def pipeline(self, *, transaction):
            assert transaction is True
            parent = self

            class FakePipeline:
                def __init__(self):
                    self.operations = []

                async def watch(self, *_keys):
                    return None

                async def get(self, key):
                    return parent.markers.get(key)

                def multi(self):
                    return self

                async def reset(self):
                    return None

                def set(self, key, value, *, ex=None):
                    self.operations.append(("set", key, value, ex))
                    return self

                def xadd(self, stream, payload):
                    self.operations.append(("xadd", stream, dict(payload)))
                    return self

                def xack(self, stream, group, message_id):
                    self.operations.append(("xack", stream, group, message_id))
                    return self

                def delete(self, *keys):
                    self.operations.append(("delete", *keys))
                    return self

                async def execute(self):
                    results = []
                    for operation in self.operations:
                        if operation[0] == "set":
                            _, key, value, ex = operation
                            if ex is not None:
                                assert ex == queue_module._QUEUE_QUARANTINE_TTL_SECONDS
                            parent.markers[key] = value
                            results.append(True)
                        elif operation[0] == "xadd":
                            _, stream, payload = operation
                            assert stream == "cyberassess:scan-execution:failures"
                            parent.failures.append(payload)
                            results.append(f"failure-{len(parent.failures)}")
                        elif operation[0] == "xack":
                            parent.acks.append(operation[-1])
                            parent.message_pending = False
                            results.append(1)
                        elif operation[0] == "delete":
                            for key in operation[1:]:
                                parent.markers.pop(key, None)
                            results.append(1)
                    return results

            return FakePipeline()

        async def delete(self, key):
            self.markers.pop(key, None)

    queue = object.__new__(RedisDurableQueue)
    queue._redis = FakeRedis()
    queue._consumer_name = "worker-authoritative-failure"
    queue._group_ready = True
    queue._group_lock = asyncio.Lock()
    handler_calls = 0

    async def handler(_scan_id, _organization_id, _request_id, _envelope, _binding):
        nonlocal handler_calls
        handler_calls += 1
        raise RuntimeError("synthetic handler failure; must not be persisted")

    for attempt in range(1, 4):
        assert await queue.consume_once(handler, block_ms=0, reclaim_idle_ms=1) is True
        assert queue._redis.delivery_count == attempt
        assert len(queue._redis.acks) == 0

    assert handler_calls == 3
    assert len(queue._redis.failures) == 3
    assert queue._redis.failures[0]["failure_category"] == "AUTHORITATIVE_DISPATCH"
    assert queue._redis.failures[0]["requeue_required"] == "1"
    assert queue._redis.failures[-1]["attempt_count"] == "3"
    assert queue._redis.failures[-1]["max_attempts"] == "3"
    assert queue._redis.failures[-1]["escalated"] == "1"
    assert queue._redis.failures[-1]["quarantined"] == "1"
    assert queue._redis.failures[-1]["organization_id"] == binding.organization_id
    assert queue._redis.failures[-1]["authorization_request_id"] == binding.authorization_request_id
    assert queue._redis.failures[-1]["queue_binding_digest"] == binding.queue_binding_digest
    assert queue._redis.failures[-1]["operation_ids_json"] == binding.operation_ids_json
    assert queue._redis.failures[-1]["execution_ids_json"] == binding.execution_ids_json
    assert "credential_envelope" not in queue._redis.failures[-1]
    quarantine_key = queue._quarantine_key("message-authoritative-failure")
    quarantine_state_key = queue._quarantine_state_key("message-authoritative-failure")
    assert quarantine_key in queue._redis.markers
    assert quarantine_state_key in queue._redis.markers
    persisted_quarantine = json.loads(queue._redis.markers[quarantine_state_key])
    assert persisted_quarantine["schema_version"] == queue_module._QUEUE_QUARANTINE_SCHEMA_VERSION
    assert persisted_quarantine["status"] == "QUARANTINED"
    assert persisted_quarantine["failure_evidence"] == queue._redis.failures[-1]
    assert persisted_quarantine["failure_evidence_digest"] == hashlib.sha256(
        json.dumps(
            persisted_quarantine["failure_evidence"],
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()
    assert "credential_envelope" not in persisted_quarantine["failure_evidence"]
    tampered_quarantine = json.loads(json.dumps(persisted_quarantine))
    tampered_quarantine["failure_evidence"]["error_code"] = "TAMPERED"
    queue._redis.markers[quarantine_state_key] = json.dumps(tampered_quarantine)
    assert await queue.acknowledge_quarantined(
        "message-authoritative-failure",
        operator=_issue_authenticated_quarantine_authorization(
            actor_id="security-admin", organization_id=binding.organization_id, session_binding="test-session"
        ),
        authorization_request_id=binding.authorization_request_id,
    ) is False
    queue._redis.markers[quarantine_state_key] = json.dumps(persisted_quarantine)

    failure_count = len(queue._redis.failures)
    # The expiring review marker may be gone by the time a delivery is
    # inspected. The persistent quarantine state must still be checked before
    # parsing so inspection cannot re-enter the handler or append duplicates.
    queue._redis.markers.pop(quarantine_key, None)
    fields["operation_ids_json"] = "not-json"
    assert await queue.consume_once(handler, block_ms=0, reclaim_idle_ms=1) is True
    assert handler_calls == 3
    assert len(queue._redis.failures) == failure_count
    assert queue._redis.acks == []

    assert await queue.acknowledge_quarantined(
        "message-authoritative-failure",
        operator=_issue_authenticated_quarantine_authorization(
            actor_id="security-admin", organization_id=binding.organization_id, session_binding="test-session"
        ),
        authorization_request_id=binding.authorization_request_id,
    ) is True
    assert queue._redis.acks == ["message-authoritative-failure"]
    assert quarantine_key not in queue._redis.markers
    assert quarantine_state_key not in queue._redis.markers
    recovery = queue._redis.failures[-1]
    assert recovery["failure_category"] == "AUTHORITATIVE_DISPATCH_RECOVERY"
    assert recovery["recovery_action"] == "ACKNOWLEDGED_AFTER_QUARANTINE"
    assert recovery["recovery_actor"] == "security-admin"
    assert recovery["original_failure_evidence_digest"] == persisted_quarantine["failure_evidence_digest"]
    assert await queue.acknowledge_quarantined(
        "message-authoritative-failure",
        operator=_issue_authenticated_quarantine_authorization(
            actor_id="security-admin", organization_id=binding.organization_id, session_binding="test-session"
        ),
    ) is False


@pytest.mark.asyncio
async def test_authoritative_queue_delivery_counter_failure_quarantines_without_handler_entry():
    """Unavailable XPENDING state fails closed instead of guessing a retry count."""
    from app.core.queue import QueueDispatchBinding, RedisDurableQueue

    binding = QueueDispatchBinding.create(
        scan_id="scan-counter-unavailable",
        organization_id="org-counter-unavailable",
        authorization_request_id="request-counter-unavailable",
        manifest_hash="e" * 64,
        execution_ids=("execution-counter-unavailable",),
        operation_ids=("network:nmap",),
    )
    fields = {
        "message_kind": "AUTHORITATIVE_EXECUTION",
        "enqueued_at": "2026-09-11T00:00:00+00:00",
        "scan_id": binding.scan_id,
        "organization_id": binding.organization_id,
        "authorization_request_id": binding.authorization_request_id,
        "queue_binding_digest": binding.queue_binding_digest,
        "manifest_hash": binding.manifest_hash,
        "execution_ids_json": binding.execution_ids_json,
        "operation_ids_json": binding.operation_ids_json,
        "queue_binding_schema_version": binding.schema_version,
    }

    class FakeRedis:
        def __init__(self):
            self.failures = []
            self.markers = {}
            self.acks = []

        async def xautoclaim(self, *_args, **_kwargs):
            return ("0-0", [("message-counter-unavailable", fields)], [])

        async def xreadgroup(self, *_args, **_kwargs):
            raise AssertionError("new-message read is not expected after the guarded delivery")

        async def get(self, key):
            return self.markers.get(key)

        async def eval(self, _script, number_of_keys, *args):
            assert number_of_keys == 4
            if self.markers.get(args[0]) != args[4]:
                return 0
            self.acks.append(args[6])
            self.markers.pop(args[0], None)
            self.markers.pop(args[1], None)
            return 1

        async def set(self, key, value, *, ex=None):
            self.markers[key] = value
            return True

        def pipeline(self, *, transaction):
            assert transaction is True
            parent = self

            class FakePipeline:
                def __init__(self):
                    self.operations = []

                async def watch(self, *_keys):
                    return None

                async def get(self, key):
                    return parent.markers.get(key)

                def multi(self):
                    return self

                async def reset(self):
                    return None

                def set(self, key, value, *, ex=None):
                    self.operations.append(("set", key, value, ex))
                    return self

                def xadd(self, stream, payload):
                    self.operations.append(("xadd", stream, dict(payload)))
                    return self

                def xack(self, stream, group, message_id):
                    self.operations.append(("xack", stream, group, message_id))
                    return self

                def delete(self, *keys):
                    self.operations.append(("delete", *keys))
                    return self

                async def execute(self):
                    results = []
                    for operation in self.operations:
                        if operation[0] == "set":
                            _, key, value, _ex = operation
                            parent.markers[key] = value
                            results.append(True)
                        elif operation[0] == "xadd":
                            _, stream, payload = operation
                            assert stream == "cyberassess:scan-execution:failures"
                            parent.failures.append(payload)
                            results.append(f"failure-{len(parent.failures)}")
                        elif operation[0] == "xack":
                            parent.acks.append(operation[-1])
                            results.append(1)
                        elif operation[0] == "delete":
                            for key in operation[1:]:
                                parent.markers.pop(key, None)
                            results.append(1)
                    return results

            return FakePipeline()

        async def xadd(self, stream, payload):
            assert stream == "cyberassess:scan-execution:failures"
            self.failures.append(dict(payload))
            return f"failure-{len(self.failures)}"

        async def xack(self, _stream, _group, message_id):
            self.acks.append(message_id)

        async def delete(self, key):
            self.markers.pop(key, None)

    queue = object.__new__(RedisDurableQueue)
    queue._redis = FakeRedis()
    queue._consumer_name = "worker-counter-unavailable"
    queue._group_ready = True
    queue._group_lock = asyncio.Lock()
    handler_calls = 0

    async def handler(*_args):
        nonlocal handler_calls
        handler_calls += 1

    assert await queue.consume_once(handler, block_ms=0, reclaim_idle_ms=1) is True
    assert handler_calls == 0
    assert queue._redis.acks == []
    assert len(queue._redis.failures) == 1
    assert queue._redis.failures[0]["error_code"] == "QUEUE_DELIVERY_COUNTER_UNAVAILABLE"
    assert queue._redis.failures[0]["quarantined"] == "1"
    assert "attempt_count" not in queue._redis.failures[0]
    state_key = queue._quarantine_state_key("message-counter-unavailable")
    marker_key = queue._quarantine_key("message-counter-unavailable")
    assert state_key in queue._redis.markers
    assert marker_key in queue._redis.markers

    # A second reclaim cannot re-enter even though the fake transport exposes
    # no delivery counter and the review marker is not the durable state.
    queue._redis.markers.pop(marker_key, None)
    assert await queue.consume_once(handler, block_ms=0, reclaim_idle_ms=1) is True
    assert handler_calls == 0
    assert len(queue._redis.failures) == 1
    from app.core.queue import _issue_authenticated_quarantine_authorization
    assert await queue.acknowledge_quarantined(
        "message-counter-unavailable",
        operator=_issue_authenticated_quarantine_authorization(
            actor_id="security-admin", organization_id="wrong-tenant", session_binding="test-session"
        ),
        authorization_request_id=binding.authorization_request_id,
    ) is False
    assert queue._redis.acks == []
    assert await queue.acknowledge_quarantined(
        "message-counter-unavailable",
        operator=_issue_authenticated_quarantine_authorization(
            actor_id="security-admin", organization_id=binding.organization_id, session_binding="test-session"
        ),
        authorization_request_id=binding.authorization_request_id,
    ) is False
    assert queue._redis.acks == []


@pytest.mark.asyncio
async def test_authoritative_quarantine_fails_closed_when_transaction_cannot_commit():
    """A failed quarantine transaction cannot fall back to split writes."""
    from app.core.queue import QueueDispatchBinding, RedisDurableQueue

    binding = QueueDispatchBinding.create(
        scan_id="scan-quarantine-transaction-failure",
        organization_id="org-quarantine-transaction-failure",
        authorization_request_id="request-quarantine-transaction-failure",
        manifest_hash="f" * 64,
        execution_ids=("execution-quarantine-transaction-failure",),
        operation_ids=("network:nmap",),
    )

    class FailingPipeline:
        def __init__(self, owner):
            self.owner = owner
            self.operations = []

        def set(self, key, value, *, ex=None):
            self.operations.append(("set", key, value, ex))
            return self

        def xadd(self, stream, payload):
            self.operations.append(("xadd", stream, dict(payload)))
            return self

        async def execute(self):
            self.owner.execute_calls += 1
            raise RuntimeError("synthetic Redis transaction failure")

    class FakeRedis:
        def __init__(self):
            self.execute_calls = 0
            self.direct_writes = []

        def pipeline(self, *, transaction):
            assert transaction is True
            return FailingPipeline(self)

        async def set(self, *args, **kwargs):
            self.direct_writes.append(("set", args, kwargs))

        async def xadd(self, *args, **kwargs):
            self.direct_writes.append(("xadd", args, kwargs))

        async def xack(self, *args, **kwargs):
            self.direct_writes.append(("xack", args, kwargs))

    queue = object.__new__(RedisDurableQueue)
    queue._redis = FakeRedis()
    queue._group_ready = True
    queue._group_lock = asyncio.Lock()

    with pytest.raises(RuntimeError, match="quarantine transaction could not be committed"):
        await queue.fail(
            "message-quarantine-transaction-failure",
            "QUEUE_HANDLER_FAILED",
            acknowledge=False,
            scan_id=binding.scan_id,
            organization_id=binding.organization_id,
            authorization_request_id=binding.authorization_request_id,
            queue_binding_digest=binding.queue_binding_digest,
            manifest_hash=binding.manifest_hash,
            execution_ids=binding.execution_ids,
            operation_ids=binding.operation_ids,
            message_kind="AUTHORITATIVE_EXECUTION",
            attempt_count=5,
            max_attempts=5,
            escalated=True,
            quarantined=True,
        )

    assert queue._redis.execute_calls == 1
    assert queue._redis.direct_writes == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "pending_response",
    ([{"consumer_name": "worker"}], [("message-counter-malformed", "worker", 1)]),
    ids=("missing-delivery-field", "short-pending-tuple"),
)
async def test_authoritative_queue_rejects_malformed_delivery_counter(pending_response):
    """Malformed XPENDING output must never be interpreted as one delivery."""
    from app.core.queue import RedisDurableQueue

    class FakeRedis:
        async def xpending_range(self, *_args, **_kwargs):
            return pending_response

    queue = object.__new__(RedisDurableQueue)
    queue._redis = FakeRedis()
    queue.stream_name = "cyberassess:test:malformed-counter"
    queue.consumer_group = "cyberassess-test-workers"

    with pytest.raises(ValueError, match="delivery counter"):
        await queue._delivery_attempts("message-counter-malformed")


def test_queue_binding_payload_rejects_digest_valid_reordered_wire_tuples():
    from app.core.queue import QueueDispatchBinding, _queue_binding_digest

    canonical = QueueDispatchBinding.create(
        scan_id="scan-canonical-wire",
        organization_id="org-canonical-wire",
        authorization_request_id="request-canonical-wire",
        manifest_hash="d" * 64,
        execution_ids=("execution-a", "execution-b"),
        operation_ids=("network:nmap", "web:httpx"),
    )
    reordered_execution_ids = list(reversed(canonical.execution_ids))
    reordered_operation_ids = list(reversed(canonical.operation_ids))
    fields = {
        "message_kind": "AUTHORITATIVE_EXECUTION",
        "enqueued_at": "2026-09-11T00:00:00+00:00",
        "scan_id": canonical.scan_id,
        "organization_id": canonical.organization_id,
        "authorization_request_id": canonical.authorization_request_id,
        "manifest_hash": canonical.manifest_hash,
        "execution_ids_json": json.dumps(reordered_execution_ids, separators=(",", ":")),
        "operation_ids_json": json.dumps(reordered_operation_ids, separators=(",", ":")),
        "queue_binding_schema_version": canonical.schema_version,
        "queue_binding_digest": _queue_binding_digest(
            canonical.scan_id,
            canonical.organization_id,
            canonical.authorization_request_id,
            canonical.manifest_hash,
            reordered_execution_ids,
            reordered_operation_ids,
        ),
    }
    with pytest.raises(ValueError, match="canonically ordered"):
        QueueDispatchBinding.from_payload(fields)


@pytest.mark.asyncio
async def test_redis_consumer_claims_new_intent_and_acknowledges_after_handler():
    from app.core.queue import RedisDurableQueue

    class FakeRedis:
        def __init__(self):
            self.read_blocks = []

        async def xautoclaim(self, *args, **kwargs):
            return ("0-0", [], [])

        async def xreadgroup(self, *args, **kwargs):
            self.read_blocks.append(kwargs["block"])
            return [(
                "stream",
                [("message-1", {
                    "message_kind": "LEGACY_DIAGNOSTIC",
                    "enqueued_at": "2026-09-11T00:00:00+00:00",
                    "scan_id": "scan-1",
                    "organization_id": "org-1",
                })],
            )]

        async def xack(self, *args):
            self.acked = args[-1]

        async def xadd(self, *args, **kwargs):
            self.failed = (args[0], kwargs)

        async def get(self, _key):
            return None

    queue = object.__new__(RedisDurableQueue)
    queue._redis = FakeRedis()
    queue._consumer_name = "worker-test"
    queue._group_ready = True
    queue._group_lock = asyncio.Lock()
    received = []

    async def handler(scan_id, organization_id):
        received.append((scan_id, organization_id))

    assert await queue.consume_once(handler, block_ms=0, reclaim_idle_ms=1) is True
    assert received == [("scan-1", "org-1")]
    assert queue._redis.acked == "message-1"
    assert queue._redis.read_blocks == [None]


@pytest.mark.asyncio
async def test_redis_consumer_reclaims_pending_intent_before_new_messages():
    from app.core.queue import RedisDurableQueue

    class FakeRedis:
        async def xautoclaim(self, *args, **kwargs):
            return ("0-0", [(
                "reclaimed-1",
                {
                    "message_kind": "LEGACY_DIAGNOSTIC",
                    "enqueued_at": "2026-09-11T00:00:00+00:00",
                    "scan_id": "scan-reclaimed",
                    "organization_id": "org-1",
                },
            )], [])

        async def xreadgroup(self, *args, **kwargs):
            raise AssertionError("new messages must not be read when a pending intent was reclaimed")

        async def xack(self, *args):
            self.acked = args[-1]

        async def xadd(self, *args, **kwargs):
            raise AssertionError("successful reclaimed intent must not enter the failure stream")

        async def get(self, _key):
            return None

    queue = object.__new__(RedisDurableQueue)
    queue._redis = FakeRedis()
    queue._consumer_name = "worker-test"
    queue._group_ready = True
    queue._group_lock = asyncio.Lock()
    received = []

    async def handler(scan_id, organization_id):
        received.append((scan_id, organization_id))

    assert await queue.consume_once(handler, block_ms=0, reclaim_idle_ms=1) is True
    assert received == [("scan-reclaimed", "org-1")]
    assert queue._redis.acked == "reclaimed-1"


@pytest.mark.asyncio
async def test_redis_consumer_moves_handler_failure_to_failure_stream():
    from app.core.queue import RedisDurableQueue

    class FakeRedis:
        async def xautoclaim(self, *args, **kwargs):
            return ("0-0", [], [])

        async def xreadgroup(self, *args, **kwargs):
            return [(
                "stream",
                [("message-2", {
                    "message_kind": "LEGACY_DIAGNOSTIC",
                    "enqueued_at": "2026-09-11T00:00:00+00:00",
                    "scan_id": "scan-2",
                    "organization_id": "org-2",
                })],
            )]

        async def xack(self, *args):
            self.acked = args[-1]

        async def xadd(self, *args, **kwargs):
            self.failure = (args, kwargs)

        async def get(self, _key):
            return None

    queue = object.__new__(RedisDurableQueue)
    queue._redis = FakeRedis()
    queue._consumer_name = "worker-test"
    queue._group_ready = True
    queue._group_lock = asyncio.Lock()

    async def handler(scan_id, organization_id):
        raise ValueError("synthetic failure")

    assert await queue.consume_once(handler, block_ms=0, reclaim_idle_ms=1) is True
    assert queue._redis.failure[0][0] == "cyberassess:scan-execution:failures"
    assert queue._redis.failure[0][1]["message_id"] == "message-2"
    assert queue._redis.acked == "message-2"


def test_queue_failure_evidence_rejects_unknown_and_credential_fields() -> None:
    from app.core.queue import _canonical_failure_evidence

    evidence = {
        "message_id": "message-strict",
        "dispatch_message_id": "message-strict",
        "error_code": "Failure",
        "failure_category": "AUTHORITATIVE_DISPATCH",
        "failure_observed_at": "2026-09-11T00:00:00+00:00",
        "requeue_required": "1",
        "escalated": "1",
        "quarantined": "1",
        "message_kind": "AUTHORITATIVE_EXECUTION",
        "credential_envelope": "must-not-persist",
    }
    with pytest.raises(ValueError, match="unsupported fields"):
        _canonical_failure_evidence("message-strict", evidence)


def test_queue_binding_payload_rejects_non_string_identity_material() -> None:
    from app.core.queue import QueueDispatchBinding

    with pytest.raises(ValueError, match="non-string"):
        QueueDispatchBinding.from_payload({
            "scan_id": "scan-strict",
            "organization_id": "org-strict",
            "authorization_request_id": "request-strict",
            "manifest_hash": "a" * 64,
            "execution_ids_json": ["execution-strict"],
            "operation_ids_json": "[\"network:nmap\"]",
            "queue_binding_digest": "b" * 64,
            "queue_binding_schema_version": "queue-dispatch-binding-v1",
        })


@pytest.mark.asyncio
async def test_queue_failure_requires_explicit_consistent_message_classification() -> None:
    """Missing/partial or cross-classified failure evidence fails before Redis writes."""
    from app.core.queue import RedisDurableQueue

    queue = object.__new__(RedisDurableQueue)
    queue._redis = object()
    queue._group_ready = True
    queue._group_lock = asyncio.Lock()

    with pytest.raises(ValueError, match="message kind is invalid"):
        await queue.fail("message-missing-kind", "QUEUE_FAILURE")

    with pytest.raises(ValueError, match="binding is incomplete"):
        await queue.fail(
            "message-partial-authority",
            "QUEUE_FAILURE",
            acknowledge=False,
            scan_id="scan-partial",
            organization_id="org-partial",
            authorization_request_id="request-partial",
            message_kind="AUTHORITATIVE_EXECUTION",
            quarantined=True,
        )

    with pytest.raises(ValueError, match="legacy queue failure"):
        await queue.fail(
            "message-legacy-authority",
            "QUEUE_FAILURE",
            message_kind="LEGACY_DIAGNOSTIC",
            authorization_request_id="request-legacy",
        )


def test_queue_quarantine_authorization_is_not_data_constructible() -> None:
    from app.core.queue import QueueQuarantineOperatorAuthorization

    with pytest.raises(TypeError):
        QueueQuarantineOperatorAuthorization(
            actor_id="operator",
            organization_id="org",
            session_binding="session",
            permission="execution:recovery",
        )


@pytest.mark.asyncio
async def test_quarantine_acknowledgement_fails_closed_on_compare_and_swap_race(monkeypatch):
    from app.core.queue import RedisDurableQueue, _issue_authenticated_quarantine_authorization

    queue = object.__new__(RedisDurableQueue)
    queue._group_ready = True
    queue._group_lock = asyncio.Lock()
    state = {
        "organization_id": "org-cas",
        "authorization_request_id": "request-cas",
        "message_kind": "AUTHORITATIVE_EXECUTION",
        "failure_evidence_digest": "a" * 64,
        "reason": "QUEUE_FAILURE",
        "scan_id": "scan-cas",
        "queue_binding_digest": "b" * 64,
        "manifest_hash": "c" * 64,
        "execution_ids": ["execution-cas"],
        "operation_ids": ["network:nmap"],
    }

    class FakeRedis:
        async def get(self, _key):
            return "original-state"

        async def eval(self, _script, number_of_keys, *args):
            assert number_of_keys == 4
            assert args[4] == "original-state"
            return 0

    queue._redis = FakeRedis()
    async def fake_get(_message_id):
        return state

    monkeypatch.setattr(queue, "_get_quarantine_state", fake_get)
    operator = _issue_authenticated_quarantine_authorization(
        actor_id="operator-cas",
        organization_id="org-cas",
        session_binding="session-cas",
    )
    assert await queue.acknowledge_quarantined(
        "message-cas",
        operator=operator,
        authorization_request_id="request-cas",
    ) is False
