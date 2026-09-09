"""Contract 01 database backend compatibility and selection tests."""

import asyncio
import hashlib
import inspect
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import types

import pytest

import app.core.db as db_module
from app.core.db import (
    _PostgresConnection,
    _PostgresRow,
    _qmark_to_postgres,
    DatabaseManager,
    PostgresDatabaseManager,
    is_database_integrity_error,
)
from app.core.migration_artifacts import (
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
        "sha256:f7c6b70bc95fe5ee2bb1c1062454a8b4db5121fa483926794c1708b06c211ae8"
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
    assert all(set(vector) == {"sqlite", "postgresql"} for vector in FORWARD_APPLY_MANIFESTS.values())
    assert all(set(vector) == {"sqlite", "postgresql"} for vector in FORWARD_APPLY_SOURCE_SHA256.values())


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
    from app.core.queue import RedisDurableQueue

    class FakeRedis:
        def __init__(self):
            self.dedupe = {}
            self.eval_calls = []

        async def eval(self, script, number_of_keys, *keys_and_args):
            self.eval_calls.append((script, number_of_keys, keys_and_args))
            assert number_of_keys == 2
            assert "GET" in script and "XADD" in script and "SET" in script
            dedupe_key = keys_and_args[0]
            if dedupe_key in self.dedupe:
                return self.dedupe[dedupe_key]
            message_id = f"message-{len(self.dedupe) + 1}"
            self.dedupe[dedupe_key] = message_id
            return message_id

    queue = object.__new__(RedisDurableQueue)
    queue._redis = FakeRedis()
    queue._consumer_name = "worker-test"
    queue._group_ready = True
    queue._group_lock = asyncio.Lock()

    first = await queue.enqueue("scan-a", "org-a", authorization_request_id="request-a")
    replay = await queue.enqueue("scan-a", "org-a", authorization_request_id="request-a")
    other_tenant = await queue.enqueue("scan-a", "org-b", authorization_request_id="request-a")

    assert first == replay == "message-1"
    assert other_tenant == "message-2"
    assert len(queue._redis.eval_calls) == 3
    assert queue._redis.eval_calls[0][2][0] != queue._redis.eval_calls[2][2][0]


@pytest.mark.asyncio
async def test_redis_consumer_claims_new_intent_and_acknowledges_after_handler():
    from app.core.queue import RedisDurableQueue

    class FakeRedis:
        async def xautoclaim(self, *args, **kwargs):
            return ("0-0", [], [])

        async def xreadgroup(self, *args, **kwargs):
            return [("stream", [("message-1", {"scan_id": "scan-1", "organization_id": "org-1"})])]

        async def xack(self, *args):
            self.acked = args[-1]

        async def xadd(self, *args, **kwargs):
            self.failed = (args[0], kwargs)

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


@pytest.mark.asyncio
async def test_redis_consumer_reclaims_pending_intent_before_new_messages():
    from app.core.queue import RedisDurableQueue

    class FakeRedis:
        async def xautoclaim(self, *args, **kwargs):
            return ("0-0", [("reclaimed-1", {"scan_id": "scan-reclaimed", "organization_id": "org-1"})], [])

        async def xreadgroup(self, *args, **kwargs):
            raise AssertionError("new messages must not be read when a pending intent was reclaimed")

        async def xack(self, *args):
            self.acked = args[-1]

        async def xadd(self, *args, **kwargs):
            raise AssertionError("successful reclaimed intent must not enter the failure stream")

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
            return [("stream", [("message-2", {"scan_id": "scan-2", "organization_id": "org-2"})])]

        async def xack(self, *args):
            self.acked = args[-1]

        async def xadd(self, *args, **kwargs):
            self.failure = (args, kwargs)

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
