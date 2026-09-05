"""Contract 01 database backend compatibility and selection tests."""

import asyncio
import sys
import types

import pytest

from app.core.db import _PostgresConnection, _PostgresRow, _qmark_to_postgres, DatabaseManager, PostgresDatabaseManager


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
    monkeypatch.setattr(PostgresDatabaseManager, "_init_db", lambda self: (_ for _ in ()).throw(RuntimeError("schema failure")))

    with pytest.raises(RuntimeError, match="schema failure"):
        PostgresDatabaseManager("postgresql://user:pass@127.0.0.1/cyberassess_test")

    assert pool.closed is True


def test_postgres_manager_preserves_initialization_failure_when_pool_close_fails(monkeypatch, caplog):
    class Pool:
        def close(self):
            raise OSError("pool close failure")

    monkeypatch.setitem(sys.modules, "psycopg_pool", types.SimpleNamespace(ConnectionPool=lambda **kwargs: Pool()))
    monkeypatch.setattr(PostgresDatabaseManager, "_init_db", lambda self: (_ for _ in ()).throw(RuntimeError("authoritative schema failure")))

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
