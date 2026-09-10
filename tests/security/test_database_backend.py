"""Contract 01 database backend compatibility and selection tests."""

import asyncio
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
    from app.core.queue import QueueDispatchBinding, RedisDurableQueue

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
    from app.core.queue import QueueDispatchBinding, RedisDurableQueue

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
        actor="security-admin",
        organization_id=binding.organization_id,
        authorization_request_id=binding.authorization_request_id,
    ) is True
    assert queue._redis.acks == ["message-authoritative-failure"]
    assert quarantine_key not in queue._redis.markers
    assert quarantine_state_key not in queue._redis.markers
    recovery = queue._redis.failures[-1]
    assert recovery["failure_category"] == "AUTHORITATIVE_DISPATCH_RECOVERY"
    assert recovery["recovery_action"] == "ACKNOWLEDGED_AFTER_QUARANTINE"
    assert recovery["recovery_actor"] == "security-admin"
    assert await queue.acknowledge_quarantined(
        "message-authoritative-failure", actor="security-admin"
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

        async def set(self, key, value, *, ex=None):
            self.markers[key] = value
            return True

        def pipeline(self, *, transaction):
            assert transaction is True
            parent = self

            class FakePipeline:
                def __init__(self):
                    self.operations = []

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
    assert await queue.acknowledge_quarantined(
        "message-counter-unavailable",
        actor="security-admin",
        organization_id="wrong-tenant",
        authorization_request_id=binding.authorization_request_id,
    ) is False
    assert queue._redis.acks == []
    assert await queue.acknowledge_quarantined(
        "message-counter-unavailable",
        actor="security-admin",
        organization_id=binding.organization_id,
        authorization_request_id=binding.authorization_request_id,
    ) is True
    assert queue._redis.acks == ["message-counter-unavailable"]


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
