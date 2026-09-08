"""Real SQLite transaction checks for the isolated v13 migration implementation."""

import sqlite3
import os
import subprocess
import sys
import tarfile
import io
import re
from pathlib import Path

import pytest

from app.core.db import DatabaseManager
from app.core.scan_request_migration_v13 import OPERATION_TABLE_SQL, apply_schema, verify_schema


def _parent(conn, parent_id, *, upgraded):
    """Minimal storage fixture; no claim that its placeholder hash is approvable."""
    conn.execute("INSERT OR IGNORE INTO organizations (id,name,slug,created_at) VALUES ('org-a','A','a','2026-09-05T00:00:00+00:00')")
    conn.execute("""INSERT INTO scans
        (id,organization_id,target_name,target_type,target_value,profile,status,data_json)
        VALUES (?,'org-a','fixture','DOMAIN','example.test','FULL_STACK','PENDING','{}')""", (parent_id,))
    conn.execute("""INSERT INTO scan_authorization_requests
        (scan_request_id,scan_id,organization_id,requested_by_user_id,correlation_id,
         manifest_hash,target_id,target_integrity_seal,target_policy_version,profile,
         selected_engine_ids_json,policy_revision,state,created_at,expires_at)
        VALUES (?,?,'org-a','requester','correlation','unapprovable-fixture','target','seal',
         'policy','FULL_STACK','["network"]','revision','REQUESTED',
         '2026-09-05T00:00:00+00:00','2026-09-05T01:00:00+00:00')""".replace(
             "expires_at)", "expires_at,manifest_json,creation_idempotency_key,creation_fingerprint)"
         ).replace(
             "'2026-09-05T01:00:00+00:00')", "'2026-09-05T01:00:00+00:00','{}',?,'fixture')"
         ) if upgraded else """INSERT INTO scan_authorization_requests
        (scan_request_id,scan_id,organization_id,requested_by_user_id,correlation_id,
         manifest_hash,target_id,target_integrity_seal,target_policy_version,profile,
         selected_engine_ids_json,policy_revision,state,created_at,expires_at)
        VALUES (?,?,'org-a','requester','correlation','unapprovable-fixture','target','seal',
         'policy','FULL_STACK','["network"]','revision','REQUESTED',
         '2026-09-05T00:00:00+00:00','2026-09-05T01:00:00+00:00')""",
         (parent_id, parent_id, parent_id) if upgraded else (parent_id, parent_id))


def _operation(conn, parent_id, tenant="org-a"):
    conn.execute("""INSERT INTO scan_authorization_operations
        (operation_id,scan_request_id,organization_id,tool_id,engine_id,operation_family,
         classification,operation_options_json,operation_policy_revision,target_id,
         authorization_decision_id,resource_budget_json,account_impact_budget_json,
         credential_scope_json,capability_state,selection_state)
        VALUES ('network:nmap',?,?,'nmap','network','network_assessment','ADMIN',
         '{}','revision','target','decision','{}','{}','{}','UNVERIFIED','SELECTED')""",
         (parent_id, tenant))


def test_scan_request_v13_allows_same_operation_under_distinct_parents(tmp_path):
    database = DatabaseManager(tmp_path / "parents.sqlite3")
    with database._connection_scope() as conn:
        conn.execute("BEGIN IMMEDIATE")
        apply_schema(conn, backend="sqlite")
        for parent_id in ("scan-one", "scan-two"):
            _parent(conn, parent_id, upgraded=True)
            _operation(conn, parent_id)
        assert conn.execute("SELECT COUNT(*) FROM scan_authorization_operations").fetchone()[0] == 2
        with pytest.raises(sqlite3.IntegrityError):
            _operation(conn, "scan-one")
        conn.execute("INSERT INTO organizations (id,name,slug,created_at) VALUES ('org-b','B','b','2026-09-05')")
        with pytest.raises(sqlite3.IntegrityError, match="FOREIGN KEY"):
            _operation(conn, "scan-one", "org-b")
        # A partially attached child cannot masquerade as a complete authority.
        with pytest.raises(sqlite3.IntegrityError, match="CHECK constraint"):
            conn.execute("""UPDATE scan_authorization_operations SET child_request_id='missing'
                WHERE scan_request_id='scan-one' AND organization_id='org-a'""")
        with pytest.raises(sqlite3.IntegrityError, match="FOREIGN KEY"):
            conn.execute("""UPDATE scan_authorization_operations
                SET child_request_id='missing', child_decision_id='missing', child_execution_id='missing'
                WHERE scan_request_id='scan-one' AND organization_id='org-a'""")


def test_scan_request_v13_preserves_legacy_request_when_material_is_missing(tmp_path):
    conn = sqlite3.connect(tmp_path / "legacy.sqlite3")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.executescript("""
        CREATE TABLE organizations (id TEXT PRIMARY KEY, name TEXT, slug TEXT, created_at TEXT);
        CREATE TABLE scans (id TEXT PRIMARY KEY, organization_id TEXT, target_name TEXT, target_type TEXT, target_value TEXT, profile TEXT, status TEXT, data_json TEXT);
        CREATE TABLE scan_authorization_requests (scan_request_id TEXT, scan_id TEXT, organization_id TEXT, requested_by_user_id TEXT, correlation_id TEXT, manifest_hash TEXT, target_id TEXT, target_integrity_seal TEXT, target_policy_version TEXT, profile TEXT, selected_engine_ids_json TEXT, policy_revision TEXT, state TEXT, created_at TEXT, expires_at TEXT);
        CREATE TABLE scan_authorization_operations (operation_id TEXT, scan_request_id TEXT, organization_id TEXT, tool_id TEXT, engine_id TEXT, operation_family TEXT, classification TEXT, operation_options_json TEXT, operation_policy_revision TEXT, target_id TEXT, authorization_decision_id TEXT, resource_budget_json TEXT, account_impact_budget_json TEXT, credential_scope_json TEXT, capability_state TEXT, selection_state TEXT, exclusion_reason TEXT, child_request_id TEXT, child_decision_id TEXT, child_execution_id TEXT);
    """)
    conn.execute("INSERT INTO scan_authorization_requests VALUES ('legacy','scan','org-a','requester','corr','hash','target','seal','policy','profile','[]','revision','REQUESTED','2026','2027')")
    conn.commit()
    before = conn.execute("SELECT * FROM scan_authorization_requests").fetchall()
    conn.execute("BEGIN")
    with pytest.raises(RuntimeError, match="legacy manifest/idempotency material is missing"):
        apply_schema(conn, backend="sqlite")
    conn.rollback()
    assert conn.execute("SELECT * FROM scan_authorization_requests").fetchall() == before
    conn.close()


def test_current_schema_v13_uses_parent_key_and_enforced_foreign_keys(tmp_path):
    database = DatabaseManager(tmp_path / "current-v13.sqlite3")
    with database._connection_scope() as conn:
        conn.execute("BEGIN IMMEDIATE")
        apply_schema(conn, backend="sqlite")
        columns = conn.execute("PRAGMA table_info(scan_authorization_operations)").fetchall()
        key = [row["name"] for row in sorted(columns, key=lambda row: row["pk"]) if row["pk"]]
        assert key == ["scan_request_id", "organization_id", "operation_id"]
        assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        assert conn.execute("PRAGMA foreign_key_check").fetchall() == []
        request_org_fks = [
            row for row in conn.execute("PRAGMA foreign_key_list(scan_authorization_requests)").fetchall()
            if row["table"] == "organizations" and row["from"] == "organization_id" and row["to"] == "id"
        ]
        assert len(request_org_fks) == 1
        assert conn.in_transaction


def test_scan_request_v13_does_not_commit_ddl_before_coordinator_settlement(tmp_path):
    conn = sqlite3.connect(tmp_path / "rollback.sqlite3")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.executescript("""
        CREATE TABLE organizations (id TEXT PRIMARY KEY, name TEXT, slug TEXT, created_at TEXT);
        CREATE TABLE scans (id TEXT PRIMARY KEY, organization_id TEXT, target_name TEXT, target_type TEXT, target_value TEXT, profile TEXT, status TEXT, data_json TEXT);
        CREATE TABLE scan_authorization_requests (
            scan_request_id TEXT, scan_id TEXT, organization_id TEXT, requested_by_user_id TEXT,
            correlation_id TEXT, manifest_hash TEXT, target_id TEXT, target_integrity_seal TEXT,
            target_policy_version TEXT, profile TEXT, selected_engine_ids_json TEXT,
            policy_revision TEXT, state TEXT, created_at TEXT, expires_at TEXT,
            UNIQUE(scan_request_id, organization_id),
            FOREIGN KEY (organization_id) REFERENCES organizations(id)
        );
        CREATE TABLE execution_requests (id TEXT NOT NULL, organization_id TEXT NOT NULL, UNIQUE(id, organization_id));
        CREATE TABLE execution_decisions (id TEXT NOT NULL, organization_id TEXT NOT NULL, UNIQUE(id, organization_id));
        CREATE TABLE execution_runs (execution_id TEXT NOT NULL, organization_id TEXT NOT NULL, UNIQUE(execution_id, organization_id));
        CREATE TABLE scan_authorization_operations (
            operation_id TEXT, scan_request_id TEXT, organization_id TEXT, tool_id TEXT,
            engine_id TEXT, operation_family TEXT, classification TEXT,
            operation_options_json TEXT, operation_policy_revision TEXT, target_id TEXT,
            authorization_decision_id TEXT, resource_budget_json TEXT,
            account_impact_budget_json TEXT, credential_scope_json TEXT,
            capability_state TEXT, selection_state TEXT, exclusion_reason TEXT,
            child_request_id TEXT, child_decision_id TEXT, child_execution_id TEXT
        );
    """)
    conn.commit()
    before_request = [tuple(row) for row in conn.execute("PRAGMA table_info(scan_authorization_requests)").fetchall()]
    before_operation = [tuple(row) for row in conn.execute("PRAGMA table_info(scan_authorization_operations)").fetchall()]
    conn.execute("BEGIN IMMEDIATE")
    apply_schema(conn, backend="sqlite")
    conn.rollback()
    after_request = [tuple(row) for row in conn.execute("PRAGMA table_info(scan_authorization_requests)").fetchall()]
    after_operation = [tuple(row) for row in conn.execute("PRAGMA table_info(scan_authorization_operations)").fetchall()]
    assert after_request == before_request
    assert after_operation == before_operation
    assert not conn.execute("SELECT 1 FROM sqlite_master WHERE name='scan_authorization_operations_v13'").fetchone()
    conn.close()


def test_scan_request_v13_rejects_missing_transaction(tmp_path):
    database = DatabaseManager(tmp_path / "transaction.sqlite3")
    with database._connection_scope() as conn:
        with pytest.raises(RuntimeError, match="active SQLite transaction"):
            apply_schema(conn, backend="sqlite")


def _recreate_sqlite_operation_table_without(path, fragment):
    """Create one intentionally tampered v13 operation table in a disposable DB."""
    with sqlite3.connect(path) as conn:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("DROP TABLE scan_authorization_operations")
        sql = OPERATION_TABLE_SQL.replace(
            "scan_authorization_operations_v13", "scan_authorization_operations"
        )
        if fragment == "CHECK":
            sql = sql[:sql.index("    CHECK (")].rstrip().rstrip(",") + "\n)"
        elif fragment == "MALFORMED_CHECK":
            check_start = sql.index("    CHECK (")
            table_end = sql.rfind("\n)")
            check = sql[check_start:table_end]
            sql = sql[:check_start] + check[:-1] + " AND 1=1)" + sql[table_end:]
        else:
            assert fragment in sql
            sql = sql.replace(fragment, "", 1)
        conn.execute(sql)


def _recreate_sqlite_request_table_without(path, *, column=None, organization_fk=False):
    """Recreate the real request/dependent tables with one requested defect."""
    assert (column is None) == organization_fk
    with sqlite3.connect(path) as conn:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        request_sql = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='scan_authorization_requests'"
        ).fetchone()["sql"]
        operation_sql = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='scan_authorization_operations'"
        ).fetchone()["sql"]
        fleet_sql = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='scan_authorization_fleet'"
        ).fetchone()["sql"]
        request_indexes = [
            row["sql"]
            for row in conn.execute(
                "SELECT sql FROM sqlite_master "
                "WHERE type='index' AND tbl_name='scan_authorization_requests' AND sql IS NOT NULL"
            ).fetchall()
        ]

        if column is not None:
            request_sql = re.sub(
                rf",\s*{re.escape(column)}\s+TEXT\s+NOT\s+NULL",
                "",
                request_sql,
                count=1,
                flags=re.IGNORECASE,
            )
        else:
            request_sql = re.sub(
                r",\s*FOREIGN\s+KEY\s*\(\s*organization_id\s*\)\s+"
                r"REFERENCES\s+organizations\s*\(\s*id\s*\)",
                "",
                request_sql,
                count=1,
                flags=re.IGNORECASE,
            )

        conn.execute("DROP TABLE scan_authorization_operations")
        conn.execute("DROP TABLE scan_authorization_fleet")
        conn.execute("DROP TABLE scan_authorization_requests")
        conn.execute(request_sql)
        for index_sql in request_indexes:
            if column == "creation_idempotency_key" and "creation_idempotency_key" in index_sql:
                continue
            conn.execute(index_sql)
        conn.execute(operation_sql)
        conn.execute(fleet_sql)


def _assert_sqlite_v13_tamper_rejected(path):
    with sqlite3.connect(path) as conn:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        with pytest.raises(RuntimeError, match="scan (?:request|authorization migration) v13"):
            verify_schema(conn, backend="sqlite")

    with pytest.raises(RuntimeError, match="scan (?:request|authorization migration) v13"):
        DatabaseManager(path)


@pytest.mark.parametrize(
    ("name", "fragment"),
    (
        (
            "operation-primary-key",
            "    PRIMARY KEY (scan_request_id, organization_id, operation_id),\n",
        ),
        (
            "child-request-unique-key",
            "    UNIQUE (child_request_id, organization_id),\n",
        ),
        (
            "child-decision-unique-key",
            "    UNIQUE (child_decision_id, organization_id),\n",
        ),
        (
            "child-execution-unique-key",
            "    UNIQUE (child_execution_id, organization_id),\n",
        ),
        (
            "parent-composite-foreign-key",
            "    FOREIGN KEY (scan_request_id, organization_id)\n"
            "        REFERENCES scan_authorization_requests(scan_request_id, organization_id),\n",
        ),
        (
            "organization-foreign-key",
            "    FOREIGN KEY (organization_id) REFERENCES organizations(id),\n",
        ),
        (
            "child-request-foreign-key",
            "    FOREIGN KEY (child_request_id, organization_id)\n"
            "        REFERENCES execution_requests(id, organization_id),\n",
        ),
        (
            "child-decision-foreign-key",
            "    FOREIGN KEY (child_decision_id, organization_id)\n"
            "        REFERENCES execution_decisions(id, organization_id),\n",
        ),
        (
            "child-execution-foreign-key",
            "    FOREIGN KEY (child_execution_id, organization_id)\n"
            "        REFERENCES execution_runs(execution_id, organization_id),\n",
        ),
        ("child-link-check", "CHECK"),
        ("malformed-child-link-check", "MALFORMED_CHECK"),
    ),
)
def test_sqlite_v13_rejects_each_required_operation_constraint_tamper(
    tmp_path, name, fragment
):
    path = tmp_path / f"tampered-{name}.sqlite3"
    DatabaseManager(path)
    _recreate_sqlite_operation_table_without(path, fragment)
    _assert_sqlite_v13_tamper_rejected(path)


@pytest.mark.parametrize(
    "tamper",
    (
        "parent-identity-index",
        "request-organization-foreign-key",
        "manifest_json",
        "creation_idempotency_key",
        "creation_fingerprint",
    ),
)
def test_sqlite_v13_rejects_each_required_request_schema_tamper(tmp_path, tamper):
    path = tmp_path / f"tampered-request-{tamper.replace('-', '_')}.sqlite3"
    DatabaseManager(path)
    if tamper == "parent-identity-index":
        with sqlite3.connect(path) as conn:
            conn.execute("DROP INDEX scan_authorization_requests_id_org_uq")
    elif tamper == "request-organization-foreign-key":
        _recreate_sqlite_request_table_without(path, organization_fk=True)
    else:
        _recreate_sqlite_request_table_without(path, column=tamper)
    _assert_sqlite_v13_tamper_rejected(path)


def test_sqlite_v13_rejects_missing_request_idempotency_index_and_column(tmp_path):
    path = tmp_path / "tampered-request-v13.sqlite3"
    DatabaseManager(path)
    with sqlite3.connect(path) as conn:
        conn.execute("DROP INDEX scan_request_creation_idempotency_uq")
        conn.commit()
    _assert_sqlite_v13_tamper_rejected(path)

    path = tmp_path / "tampered-column-v13.sqlite3"
    DatabaseManager(path)
    with sqlite3.connect(path) as conn:
        conn.execute("ALTER TABLE scan_authorization_requests DROP COLUMN creation_fingerprint")
        conn.commit()
    _assert_sqlite_v13_tamper_rejected(path)


def test_sqlite_v13_fast_path_revalidates_schema_before_returning(tmp_path):
    path = tmp_path / "tampered-fast-path.sqlite3"
    DatabaseManager(path)
    with sqlite3.connect(path) as conn:
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("DROP INDEX scan_authorization_requests_id_org_uq")
        conn.commit()

    with sqlite3.connect(path) as conn:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("BEGIN IMMEDIATE")
        with pytest.raises(RuntimeError, match="scan request v13"):
            apply_schema(conn, backend="sqlite")
        conn.rollback()


def test_genuine_frozen_pre_v13_source_upgrades_once_to_v13(tmp_path):
    """Create v12 with the frozen source, then upgrade using the current callable."""
    root = Path(__file__).resolve().parents[2]
    legacy_root = tmp_path / "legacy-source"
    legacy_root.mkdir()
    archive = subprocess.run(
        ["git", "archive", "a1c4fc4"], cwd=root, check=True, capture_output=True,
    ).stdout
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as tar:
        tar.extractall(legacy_root, filter="data")
    database_path = legacy_root / "data" / "cyberassess.db"
    database_path.parent.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["PYTHONPATH"] = str(legacy_root / "backend")
    legacy_result = subprocess.run(
        [sys.executable, "-c", "from app.core.db import db_manager; print(db_manager.get_schema_version())"],
        cwd=legacy_root, env=env, check=False, capture_output=True, text=True,
    )
    if legacy_result.returncode != 0:
        assert "migration forward-apply artifact drifted for version 1" in legacy_result.stderr
        pytest.skip("historical a1c4fc4 fixture is blocked by its committed v1 artifact mismatch")
    with sqlite3.connect(database_path) as conn:
        conn.row_factory = sqlite3.Row
        legacy_versions = [row["version"] for row in conn.execute("SELECT version FROM schema_migrations ORDER BY version")]
        assert legacy_versions
        assert max(legacy_versions) < 13
        legacy_event_count = conn.execute("SELECT COUNT(*) FROM schema_migration_events").fetchone()[0]

    current = DatabaseManager(database_path)
    with current._connection_scope() as conn:
        versions = [row["version"] for row in conn.execute("SELECT version FROM schema_migrations ORDER BY version")]
        assert max(versions) == 13
        assert versions.count(13) == 1
        assert conn.execute("SELECT COUNT(*) FROM schema_migration_events").fetchone()[0] >= legacy_event_count + 1
        assert conn.execute("PRAGMA foreign_key_check").fetchall() == []
        assert [row["name"] for row in conn.execute("PRAGMA table_info(scan_authorization_operations)").fetchall() if row["pk"]] == ["scan_request_id", "organization_id", "operation_id"]

    restarted = DatabaseManager(database_path)
    with restarted._connection_scope() as conn:
        versions_after_restart = [row["version"] for row in conn.execute("SELECT version FROM schema_migrations ORDER BY version")]
        assert versions_after_restart == versions
