"""Contract 01 database backend compatibility and selection tests."""

import pytest

from app.core.db import _PostgresRow, _qmark_to_postgres, DatabaseManager


def test_qmark_translation_preserves_quoted_literals():
    sql = "SELECT '?' AS literal, \"?\" AS identifier, value FROM items WHERE id = ?"

    assert _qmark_to_postgres(sql) == (
        "SELECT '?' AS literal, \"?\" AS identifier, value FROM items WHERE id = %s"
    )


def test_postgres_row_supports_mapping_and_positional_access():
    row = _PostgresRow(["id", "status"], ("row-1", "READY"))

    assert row["id"] == "row-1"
    assert row[0] == "row-1"
    assert row["status"] == row[1] == "READY"


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
