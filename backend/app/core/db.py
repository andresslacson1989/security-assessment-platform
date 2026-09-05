"""
Contract 01 §4, Contract 02 §2-§6, Contract 04 §1 & Contract 08 §1:
Authoritative Relational Database Persistence Engine (SQLite & PostgreSQL Enterprise Architecture).
Maintains ACID transactional integrity for Users, Organizations, Projects, Workspaces,
API Keys, Assets, Scans, Canonical Findings, Occurrences, and Append-Only Audit Trails.
"""

from __future__ import annotations
import hashlib
import inspect
import json
import logging
import os
import re
import sqlite3
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
import uuid

logger = logging.getLogger("cyberassess.persistence")


def _quote_postgres_identifier(identifier: str) -> str:
    """Quote a catalog-derived PostgreSQL identifier without interpolation risk."""
    return '"' + str(identifier).replace('"', '""') + '"'

from app.core.models import (
    Asset,
    AssetType,
    AssetCriticality,
    AssetLifecycleStatus,
    CanonicalFinding,
    FindingOccurrence,
    FindingLifecycleStatus,
    FindingComment,
    Severity,
    ScanJob,
    UserProfile,
    UserRole,
    Organization,
    Project,
    Workspace,
    APIKeyRecord,
    AuditEvent,
    AuditAction,
    PrincipalType,
    Evidence,
    ExecutionDecisionRecord,
    ExecutionLeaseClaim,
    ExecutionRunRecord,
    EXECUTION_RUN_STATES, EXECUTION_RUN_TERMINAL_STATES, EXECUTION_RUN_TRANSITIONS,
    ExecutionRequestRecord,
    sanitize_sensitive_data,
    utc_now,
)
from app.core.migration_registry import MIGRATION_REGISTRY
from app.core.migration_artifacts import POSTCONDITION_SOURCE_SHA256
from app.core.tool_operation_policy import get_operation_policy, is_canonical_operation_policy_revision
from app.core.correlation import get_correlation_id

DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent.parent.parent / "data" / "cyberassess.db"
MIGRATION_POSTCONDITION_REVISION = "execution-postconditions-v2"


class _PostgresRow(dict):
    """Mapping row compatible with the SQLite row access used by the DAL."""

    def __init__(self, columns: List[str], values: tuple):
        super().__init__(zip(columns, values))
        self._columns = columns

    def __getitem__(self, key):
        if isinstance(key, int):
            return super().__getitem__(self._columns[key])
        return super().__getitem__(key)


def _qmark_to_postgres(sql: str) -> str:
    """Translate DB-API qmark placeholders while preserving quoted literals."""
    output: List[str] = []
    quote: Optional[str] = None
    index = 0
    while index < len(sql):
        char = sql[index]
        if quote:
            if char == "%":
                output.append("%%")
            else:
                output.append(char)
            if char == quote:
                if index + 1 < len(sql) and sql[index + 1] == quote:
                    output.append(sql[index + 1])
                    index += 1
                else:
                    quote = None
        elif char in ("'", '"'):
            quote = char
            output.append(char)
        elif char == "?":
            output.append("%s")
        elif char == "%":
            # psycopg treats percent signs as placeholder syntax even inside
            # SQL string literals; preserve existing escape/format sequences
            # and escape literal percent signs for DB-API execution.
            next_char = sql[index + 1] if index + 1 < len(sql) else ""
            if next_char in ("%", "s", "b", "t"):
                output.append(char)
            else:
                output.append("%%")
        else:
            output.append(char)
        index += 1
    return "".join(output)


class _PostgresCursor:
    """Small DB-API compatibility adapter for the existing parameterized DAL."""

    def __init__(self, cursor):
        self._cursor = cursor

    def execute(self, sql: str, params=None):
        self._cursor.execute(_qmark_to_postgres(sql), params or ())
        return self

    def executemany(self, sql: str, params):
        self._cursor.executemany(_qmark_to_postgres(sql), params)
        return self

    @property
    def rowcount(self):
        return self._cursor.rowcount

    def _columns(self) -> List[str]:
        return [column.name if hasattr(column, "name") else column[0] for column in (self._cursor.description or [])]

    def _row(self, value):
        return _PostgresRow(self._columns(), tuple(value)) if value is not None else None

    def fetchone(self):
        return self._row(self._cursor.fetchone())

    def fetchall(self):
        return [self._row(value) for value in self._cursor.fetchall()]


class _PostgresConnection:
    """Connection wrapper exposing the SQLite DAL's execute/row contract."""

    def __init__(self, connection):
        self._connection = connection

    def cursor(self):
        return _PostgresCursor(self._connection.cursor())

    def execute(self, sql: str, params=None):
        return _PostgresCursor(self._connection.cursor()).execute(sql, params)

    def executemany(self, sql: str, params):
        return _PostgresCursor(self._connection.cursor()).executemany(sql, params)

    def executescript(self, sql: str):
        # The schema contains independent DDL statements and no procedural
        # blocks; execute each statement so PostgreSQL can plan them normally.
        # Execution tables are deliberately deferred until their referenced
        # inventory/principal tables exist.  This is explicit dependency
        # ordering for PostgreSQL, where forward references are not accepted.
        sql_without_line_comments = re.sub(r"(?m)^\s*--[^\r\n]*", "", sql)
        statements = [statement.strip() for statement in sql_without_line_comments.split(";") if statement.strip()]
        deferred = []
        for statement in statements:
            if re.search(r"CREATE\s+(?:TABLE|(?:UNIQUE\s+)?INDEX)\s+IF\s+NOT\s+EXISTS\s+(?:execution_|idx_execution_|uq_execution_)", statement, re.IGNORECASE):
                deferred.append(statement)
                continue
            self.execute(statement)
        for statement in deferred:
            statement = statement.strip()
            if statement:
                self.execute(statement)
        return self

    def commit(self):
        self._connection.commit()

    def rollback(self):
        self._connection.rollback()

    def close(self):
        self._connection.close()


class PostgresDatabaseManager:
    """PostgreSQL enterprise backend using a bounded connection pool."""

    def __init__(self, database_url: str, allow_unresolved_reconciliation: bool = False):
        try:
            from psycopg_pool import ConnectionPool
        except ImportError as exc:
            raise RuntimeError(
                "Enterprise mode requires psycopg[binary,pool] to be installed."
            ) from exc
        self.database_url = database_url
        self._allow_unresolved_reconciliation = allow_unresolved_reconciliation
        self._pool = None
        try:
            pool_max_size = int(os.getenv("POSTGRES_POOL_MAX_SIZE", "10"))
            if pool_max_size < 2:
                raise ValueError("POSTGRES_POOL_MAX_SIZE must be at least 2 for serialized migration coordination")
            self._pool = ConnectionPool(
                conninfo=database_url,
                min_size=int(os.getenv("POSTGRES_POOL_MIN_SIZE", "1")),
                max_size=pool_max_size,
                open=True,
            )
            if self._allow_unresolved_reconciliation:
                with self._migration_lock():
                    self._ensure_migration_ledger()
                return
            self._run_migration_coordinator()
        except Exception as exc:
            # Initialization can fail after the pool has opened (for example,
            # on schema drift).  Never leak those connections on a failed
            # manager construction.
            if self._pool is not None:
                try:
                    self._record_migration_failure(exc)
                except Exception as audit_exc:
                    logger.error("migration failure event could not be persisted: error_type=%s", type(audit_exc).__name__)
                try:
                    self._pool.close()
                except Exception as cleanup_exc:
                    # Cleanup is best-effort here; preserve the authoritative
                    # initialization failure for the caller and audit trail.
                    logger.error(
                        "PostgreSQL pool cleanup failed during initialization: error_type=%s",
                        type(cleanup_exc).__name__,
                    )
            raise

    @contextmanager
    def _connection_scope(self):
        raw_connection = self._pool.getconn()
        connection = _PostgresConnection(raw_connection)
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            self._pool.putconn(raw_connection)

    def _init_db(self, max_migration_version: Optional[int] = None):
        # Reuse the canonical schema/method implementation from the SQLite DAL.
        DatabaseManager._init_db(self, max_migration_version=max_migration_version)

    @contextmanager
    def _migration_lock(self):
        """Hold a database-scoped advisory lock for the full migration run."""
        raw_connection = self._pool.getconn()
        try:
            raw_connection.execute("SELECT pg_advisory_lock(hashtext('cyberassess:schema-migrations'))")
            yield
        finally:
            try:
                raw_connection.execute("SELECT pg_advisory_unlock(hashtext('cyberassess:schema-migrations'))")
            finally:
                self._pool.putconn(raw_connection)

    def __getattr__(self, name):
        return getattr(DatabaseManager, name).__get__(self, type(self))


class DatabaseManager:
    """
    Universal database manager handling relational tables, migrations, transactions, and tenant queries.
    Uses SQLite with WAL mode by default, supporting thread-safe connection pooling.
    """

    _instance: Optional[Any] = None
    _lock = threading.Lock()

    def __init__(self, db_path: Optional[Path] = None, allow_unresolved_reconciliation: bool = False):
        self.db_path = db_path or DEFAULT_DB_PATH
        self._allow_unresolved_reconciliation = allow_unresolved_reconciliation
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        if self._allow_unresolved_reconciliation:
            with self._migration_lock():
                self._ensure_migration_ledger()
            return
        try:
            self._run_migration_coordinator()
        except Exception as exc:
            self._record_migration_failure(exc)
            raise

    @classmethod
    def get_instance(cls) -> DatabaseManager:
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    database_url = os.getenv("DATABASE_URL", "").strip()
                    if database_url.lower().startswith(("postgresql://", "postgres://")):
                        cls._instance = PostgresDatabaseManager(database_url)
                    else:
                        cls._instance = cls()
        return cls._instance

    @contextmanager
    def _migration_lock(self):
        """Serialize schema coordination across processes for SQLite."""
        lock_path = self.db_path.with_name(self.db_path.name + ".migration.lock")
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        handle = open(lock_path, "a+b")
        try:
            handle.seek(0)
            if not handle.read(1):
                handle.seek(0)
                handle.write(b"0")
                handle.flush()
            handle.seek(0)
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            yield
        finally:
            try:
                if os.name == "nt":
                    import msvcrt
                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            finally:
                handle.close()

    def _run_migration_coordinator(self) -> None:
        """Apply and verify each registered migration as an isolated outcome."""
        with self._migration_lock():
            self._ensure_migration_ledger()
            with self._connection_scope() as conn:
                self._verify_resolved_reconciliation_artifacts(conn)
                unresolved = conn.execute("""SELECT 1 FROM schema_migration_events required
                    WHERE required.event_type = 'RECONCILIATION_REQUIRED' AND required.rollback_status = 'UNKNOWN'
                      AND NOT EXISTS (SELECT 1 FROM schema_migration_events resolved
                        WHERE resolved.attempt_id = required.attempt_id
                          AND resolved.event_type = 'RECONCILIATION_RESOLVED') LIMIT 1""").fetchone()
                if unresolved and not getattr(self, "_allow_unresolved_reconciliation", False):
                    raise RuntimeError("migration reconciliation required: unresolved migration attempt is blocking startup")
                has_schema = conn.execute(
                    "SELECT 1 FROM information_schema.tables WHERE table_schema=current_schema() AND table_name='schema_migrations'"
                ).fetchone() if isinstance(self, PostgresDatabaseManager) else conn.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_migrations'"
                ).fetchone()
                applied = {int(row["version"]) for row in conn.execute("SELECT version FROM schema_migrations").fetchall()} if has_schema else set()
                known_versions = {spec.version for spec in MIGRATION_REGISTRY}
                unknown_versions = applied - known_versions
                if unknown_versions:
                    raise RuntimeError(f"schema migration versions {sorted(unknown_versions)} are not registered; operator reconciliation required")
                if applied and applied != set(range(1, max(applied) + 1)):
                    raise RuntimeError("schema migration versions are not contiguous; operator reconciliation required")
                completed = {
                    int(row["migration_version"]): row for row in conn.execute(
                        "SELECT migration_version, migration_id, registry_revision, migration_checksum, "
                        "event_type FROM schema_migration_events WHERE event_type = 'SUCCEEDED'"
                    ).fetchall()
                }
                if applied and any(version not in completed for version in applied):
                    raise RuntimeError("legacy aggregate migration history requires explicit operator reconciliation before startup")
                for spec in MIGRATION_REGISTRY:
                    success = completed.get(spec.version)
                    if success is not None and (
                        success["migration_id"] != spec.migration_id
                        or success["registry_revision"] != spec.registry_revision
                        or success["migration_checksum"] != spec.checksum
                    ):
                        raise RuntimeError(f"migration v{spec.version} success identity does not match the registry")
            for spec in MIGRATION_REGISTRY:
                if spec.version in applied:
                    if spec.version not in completed:
                        raise RuntimeError(f"migration v{spec.version} is applied without a durable SUCCEEDED event")
                    continue
                self._migration_attempt_id = f"mig-{uuid.uuid4().hex}"
                self._migration_transaction_id = f"tx-{uuid.uuid4().hex}"
                self._migration_schema_name = "public" if isinstance(self, PostgresDatabaseManager) else str(self.db_path)
                self._migration_spec = spec
                self._migration_started_durable = False
                self._migration_coordinator_active = True
                try:
                    self._record_migration_event(spec, "STARTED", 1, "PENDING")
                    self._migration_started_durable = True
                    if spec.apply is None:
                        raise RuntimeError(f"migration v{spec.version} has no registered apply operation")
                    spec.apply(self)
                    with self._connection_scope() as conn:
                        if spec.verify is None:
                            raise RuntimeError(f"migration v{spec.version} has no registered verifier")
                        spec.verify(self, conn)
                    self._record_migration_event(spec, "SUCCEEDED", 2, "NOT_APPLICABLE")
                    applied.add(spec.version)
                except Exception:
                    raise
                finally:
                    self._migration_coordinator_active = False
                    self._migration_started_durable = False
            self._migration_attempt_id = None
            self._migration_transaction_id = None
            self._migration_spec = None

    def _record_migration_event(self, spec, event_type: str, sequence: int, rollback_status: str, exc: Optional[Exception] = None) -> None:
        error_class = type(exc).__name__ if exc else None
        error_message = str(exc)[:500] if exc else None
        with self._connection_scope() as conn:
            conn.execute("""INSERT INTO schema_migration_events
                (event_id,attempt_id,migration_version,migration_id,migration_name,registry_revision,event_sequence,event_type,event_at,backend,schema_name,
                 previous_schema_version,target_schema_version,migration_checksum,runner_identity,transaction_context_id,
                 error_class,error_message,context_json,rollback_status)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (
                f"event-{uuid.uuid4().hex}", self._migration_attempt_id, spec.version,
                spec.migration_id, spec.name, spec.registry_revision, sequence, event_type,
                utc_now().isoformat(), "POSTGRESQL" if isinstance(self, PostgresDatabaseManager) else "SQLITE",
                self._migration_schema_name, spec.previous_version, spec.target_version, spec.checksum,
                "database-startup", self._migration_transaction_id, error_class, error_message,
                json.dumps({"coordinator": "registry", "migration_version": spec.version}, separators=(",", ":")),
                rollback_status))

    def _ensure_migration_ledger(self) -> None:
        """Bootstrap the independent migration-event ledger before schema work."""
        with self._connection_scope() as conn:
            if isinstance(self, PostgresDatabaseManager):
                ledger_exists = conn.execute("SELECT 1 FROM information_schema.tables WHERE table_schema=current_schema() AND table_name='schema_migration_events'").fetchone() is not None
            else:
                ledger_exists = conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_migration_events'").fetchone() is not None
            conn.execute("""CREATE TABLE IF NOT EXISTS schema_migration_events (
                event_id TEXT PRIMARY KEY, attempt_id TEXT NOT NULL, migration_version INTEGER NOT NULL,
                migration_id TEXT NOT NULL, migration_name TEXT NOT NULL, registry_revision TEXT NOT NULL,
                event_sequence INTEGER NOT NULL, event_type TEXT NOT NULL CHECK (event_type IN ('STARTED','SUCCEEDED','FAILED','ROLLED_BACK','ROLLBACK_FAILED','RECONCILIATION_REQUIRED','RECONCILIATION_RESOLVED')),
                event_at TEXT NOT NULL, backend TEXT NOT NULL CHECK (backend IN ('SQLITE','POSTGRESQL')),
                schema_name TEXT NOT NULL, previous_schema_version INTEGER, target_schema_version INTEGER NOT NULL,
                migration_checksum TEXT NOT NULL, runner_identity TEXT NOT NULL, transaction_context_id TEXT NOT NULL,
                error_code TEXT, error_class TEXT, error_message TEXT, context_json TEXT NOT NULL DEFAULT '{}',
                rollback_status TEXT NOT NULL CHECK (rollback_status IN ('NOT_APPLICABLE','PENDING','CONFIRMED','FAILED','UNKNOWN')),
                UNIQUE (attempt_id, event_type), UNIQUE (attempt_id, event_sequence)
            )""")
            if ledger_exists:
                existing = {r["column_name"] for r in conn.execute("SELECT column_name FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='schema_migration_events'").fetchall()} if isinstance(self, PostgresDatabaseManager) else {r["name"] for r in conn.execute("PRAGMA table_info(schema_migration_events)").fetchall()}
                if not {"migration_id", "registry_revision", "event_sequence"}.issubset(existing) or self._migration_ledger_requires_integrity_upgrade(conn):
                    self._upgrade_migration_ledger_identity(conn, existing)
                if not isinstance(self, PostgresDatabaseManager):
                    legacy_index = conn.execute("SELECT 1 FROM pragma_index_list('schema_migration_events') WHERE name='uq_schema_migration_attempt_event'").fetchone()
                    if legacy_index:
                        cols = conn.execute("PRAGMA index_info('uq_schema_migration_attempt_event')").fetchall()
                        if [c["name"] for c in sorted(cols, key=lambda c: c["seqno"])] != ["attempt_id", "event_type"]:
                            raise RuntimeError("migration ledger legacy index identity is ambiguous; reconciliation required")
                        conn.execute("DROP INDEX uq_schema_migration_attempt_event")
                self._verify_migration_ledger(conn)
                self._reconcile_orphaned_attempts(conn)
                self._verify_migration_ledger(conn)
                return
            if isinstance(self, PostgresDatabaseManager):
                conn.execute("""CREATE OR REPLACE FUNCTION schema_migration_events_immutable() RETURNS trigger
                    LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'schema_migration_events is append-only'; END; $$""")
                conn.execute("DROP TRIGGER IF EXISTS schema_migration_events_no_update_delete ON schema_migration_events")
                conn.execute("""CREATE TRIGGER schema_migration_events_no_update_delete
                    BEFORE UPDATE OR DELETE ON schema_migration_events FOR EACH ROW
                    EXECUTE FUNCTION schema_migration_events_immutable()""")
            else:
                conn.executescript("""CREATE TRIGGER IF NOT EXISTS schema_migration_events_no_update
                    BEFORE UPDATE ON schema_migration_events BEGIN SELECT RAISE(ABORT, 'schema_migration_events is append-only'); END;
                    CREATE TRIGGER IF NOT EXISTS schema_migration_events_no_delete
                    BEFORE DELETE ON schema_migration_events BEGIN SELECT RAISE(ABORT, 'schema_migration_events is append-only'); END;""")
            self._verify_migration_ledger(conn)

    def _upgrade_migration_ledger_identity(self, conn, existing_columns: set[str]) -> None:
        """Add registry identity to a legacy ledger without losing its history.

        The identity is derived only from the immutable numeric migration version
        and the checked-in registry.  Unknown versions fail closed.  SQLite uses
        a transactional table rebuild because it cannot add a NOT NULL column to
        a populated table; PostgreSQL uses the equivalent constrained alteration.
        """
        specs_by_version = {spec.version: spec for spec in MIGRATION_REGISTRY}
        rows = conn.execute("SELECT * FROM schema_migration_events ORDER BY event_id").fetchall()
        identities = {}
        sequence_by_event_id = {}
        rows_by_attempt = {}
        for row in rows:
            version = int(row["migration_version"])
            spec = specs_by_version.get(version)
            if spec is None:
                raise RuntimeError(f"migration ledger contains unknown migration version {version}; operator reconciliation required")
            expected_backend = "POSTGRESQL" if isinstance(self, PostgresDatabaseManager) else "SQLITE"
            if (
                row["migration_name"] != spec.name
                or row["migration_checksum"] != spec.checksum
                or row["target_schema_version"] != spec.target_version
                or row["previous_schema_version"] != spec.previous_version
                or row["backend"] != expected_backend
            ):
                raise RuntimeError(
                    f"migration ledger identity mismatch for version {version}; operator reconciliation required"
                )
            identities[row["event_id"]] = (spec.migration_id, spec.registry_revision)
            rows_by_attempt.setdefault(row["attempt_id"], []).append(row)
        event_order = {"STARTED": 1, "FAILED": 2, "SUCCEEDED": 2, "ROLLED_BACK": 3, "ROLLBACK_FAILED": 3}
        for attempt_rows in rows_by_attempt.values():
            ordered = sorted(attempt_rows, key=lambda row: (row["event_at"], event_order.get(row["event_type"], 99), row["event_id"]))
            for sequence, row in enumerate(ordered, start=1):
                sequence_by_event_id[row["event_id"]] = sequence

        if isinstance(self, PostgresDatabaseManager):
            if "migration_id" not in existing_columns:
                conn.execute("ALTER TABLE schema_migration_events ADD COLUMN migration_id TEXT")
            if "registry_revision" not in existing_columns:
                conn.execute("ALTER TABLE schema_migration_events ADD COLUMN registry_revision TEXT")
            if "event_sequence" not in existing_columns:
                conn.execute("ALTER TABLE schema_migration_events ADD COLUMN event_sequence INTEGER")
            conn.execute("DROP TRIGGER IF EXISTS schema_migration_events_no_update_delete ON schema_migration_events")
            conn.execute("""CREATE OR REPLACE FUNCTION schema_migration_events_immutable() RETURNS trigger
                LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'schema_migration_events is append-only'; END; $$""")
            event_check = conn.execute("""SELECT conname FROM pg_constraint c
                JOIN pg_class t ON t.oid = c.conrelid JOIN pg_namespace n ON n.oid = t.relnamespace
                WHERE n.nspname = current_schema() AND t.relname = 'schema_migration_events'
                  AND c.contype = 'c' AND pg_get_constraintdef(c.oid) ILIKE '%EVENT_TYPE%'""").fetchall()
            for row in event_check:
                conn.execute(f"ALTER TABLE schema_migration_events DROP CONSTRAINT {_quote_postgres_identifier(row['conname'])}")
            conn.execute("""ALTER TABLE schema_migration_events ADD CONSTRAINT ck_schema_migration_event_type
                CHECK (event_type IN ('STARTED','SUCCEEDED','FAILED','ROLLED_BACK','ROLLBACK_FAILED','RECONCILIATION_REQUIRED','RECONCILIATION_RESOLVED'))""")
            for event_id, (migration_id, registry_revision) in identities.items():
                conn.execute("UPDATE schema_migration_events SET migration_id = ?, registry_revision = ?, event_sequence = ? WHERE event_id = ?", (migration_id, registry_revision, sequence_by_event_id[event_id], event_id))
            conn.execute("ALTER TABLE schema_migration_events ALTER COLUMN migration_id SET NOT NULL")
            conn.execute("ALTER TABLE schema_migration_events ALTER COLUMN registry_revision SET NOT NULL")
            conn.execute("ALTER TABLE schema_migration_events ALTER COLUMN event_sequence SET NOT NULL")
            if not self._migration_ledger_has_sequence_unique(conn):
                conn.execute("ALTER TABLE schema_migration_events ADD CONSTRAINT uq_schema_migration_attempt_sequence UNIQUE (attempt_id, event_sequence)")
            conn.execute("""CREATE TRIGGER schema_migration_events_no_update_delete
                BEFORE UPDATE OR DELETE ON schema_migration_events FOR EACH ROW
                EXECUTE FUNCTION schema_migration_events_immutable()""")
            return

        conn.execute("BEGIN IMMEDIATE")
        conn.execute("DROP TRIGGER IF EXISTS schema_migration_events_no_update")
        conn.execute("DROP TRIGGER IF EXISTS schema_migration_events_no_delete")
        conn.execute("ALTER TABLE schema_migration_events RENAME TO schema_migration_events_legacy_identity")
        conn.execute("""CREATE TABLE schema_migration_events (
            event_id TEXT PRIMARY KEY, attempt_id TEXT NOT NULL, migration_version INTEGER NOT NULL,
            migration_id TEXT NOT NULL, migration_name TEXT NOT NULL, registry_revision TEXT NOT NULL,
            event_sequence INTEGER NOT NULL, event_type TEXT NOT NULL CHECK (event_type IN ('STARTED','SUCCEEDED','FAILED','ROLLED_BACK','ROLLBACK_FAILED','RECONCILIATION_REQUIRED','RECONCILIATION_RESOLVED')),
            event_at TEXT NOT NULL, backend TEXT NOT NULL CHECK (backend IN ('SQLITE','POSTGRESQL')),
            schema_name TEXT NOT NULL, previous_schema_version INTEGER, target_schema_version INTEGER NOT NULL,
            migration_checksum TEXT NOT NULL, runner_identity TEXT NOT NULL, transaction_context_id TEXT NOT NULL,
            error_code TEXT, error_class TEXT, error_message TEXT, context_json TEXT NOT NULL DEFAULT '{}',
            rollback_status TEXT NOT NULL CHECK (rollback_status IN ('NOT_APPLICABLE','PENDING','CONFIRMED','FAILED','UNKNOWN')),
            UNIQUE (attempt_id, event_type), UNIQUE (attempt_id, event_sequence)
        )""")
        columns = ["event_id", "attempt_id", "migration_version", "migration_id", "migration_name", "registry_revision", "event_sequence", "event_type", "event_at", "backend", "schema_name", "previous_schema_version", "target_schema_version", "migration_checksum", "runner_identity", "transaction_context_id", "error_code", "error_class", "error_message", "context_json", "rollback_status"]
        placeholders = ",".join("?" for _ in columns)
        for row in rows:
            values = [row[name] for name in columns if name not in {"migration_id", "registry_revision", "event_sequence"}]
            migration_id, registry_revision = identities[row["event_id"]]
            values = values[:3] + [migration_id] + values[3:4] + [registry_revision, sequence_by_event_id[row["event_id"]]] + values[4:]
            conn.execute(f"INSERT INTO schema_migration_events ({','.join(columns)}) VALUES ({placeholders})", tuple(values))
        conn.execute("DROP TABLE schema_migration_events_legacy_identity")
        conn.execute("""CREATE TRIGGER schema_migration_events_no_update
            BEFORE UPDATE ON schema_migration_events BEGIN SELECT RAISE(ABORT, 'schema_migration_events is append-only'); END""")
        conn.execute("""CREATE TRIGGER schema_migration_events_no_delete
            BEFORE DELETE ON schema_migration_events BEGIN SELECT RAISE(ABORT, 'schema_migration_events is append-only'); END""")

    def _migration_ledger_has_sequence_unique(self, conn) -> bool:
        if isinstance(self, PostgresDatabaseManager):
            row = conn.execute("""SELECT 1 FROM pg_constraint c
                JOIN pg_class t ON t.oid = c.conrelid JOIN pg_namespace n ON n.oid = t.relnamespace
                WHERE n.nspname = current_schema() AND t.relname = 'schema_migration_events'
                  AND c.contype = 'u' AND pg_get_constraintdef(c.oid) ILIKE '%(attempt_id, event_sequence)%'""").fetchone()
            return row is not None
        for index in conn.execute("PRAGMA index_list(schema_migration_events)").fetchall():
            if index["unique"]:
                columns = conn.execute(f"PRAGMA index_info('{str(index['name']).replace(chr(39), chr(39) + chr(39))}')").fetchall()
                if [column["name"] for column in sorted(columns, key=lambda value: value["seqno"])] == ["attempt_id", "event_sequence"]:
                    return True
        return False

    def _migration_ledger_requires_integrity_upgrade(self, conn) -> bool:
        """Detect post-column ledger constraint drift requiring a schema upgrade."""
        if isinstance(self, PostgresDatabaseManager):
            checks = conn.execute("""SELECT pg_get_constraintdef(c.oid) AS definition
                FROM pg_constraint c JOIN pg_class t ON t.oid = c.conrelid
                JOIN pg_namespace n ON n.oid = t.relnamespace
                WHERE n.nspname = current_schema() AND t.relname = 'schema_migration_events' AND c.contype = 'c'""").fetchall()
            event_sql = " ".join(str(row["definition"]) for row in checks)
            event_check = "RECONCILIATION_REQUIRED" in event_sql and "RECONCILIATION_RESOLVED" in event_sql
            return not event_check or not self._migration_ledger_has_sequence_unique(conn)
        sql = str(conn.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='schema_migration_events'").fetchone()["sql"]).upper()
        return "RECONCILIATION_REQUIRED" not in sql or "RECONCILIATION_RESOLVED" not in sql or not self._migration_ledger_has_sequence_unique(conn)

    def _reconcile_orphaned_attempts(self, conn) -> None:
        """Persist an explicit terminal state for attempts left open by a crash."""
        rows = conn.execute("SELECT * FROM schema_migration_events ORDER BY attempt_id, event_sequence").fetchall()
        attempts = {}
        for row in rows:
            attempts.setdefault(row["attempt_id"], []).append(row)
        backend = "POSTGRESQL" if isinstance(self, PostgresDatabaseManager) else "SQLITE"
        for attempt_id, attempt_rows in attempts.items():
            event_types = {row["event_type"] for row in attempt_rows}
            if "STARTED" not in event_types or event_types & {"SUCCEEDED", "FAILED", "ROLLED_BACK", "ROLLBACK_FAILED", "RECONCILIATION_REQUIRED"}:
                continue
            started = next(row for row in attempt_rows if row["event_type"] == "STARTED")
            next_sequence = max(int(row["event_sequence"]) for row in attempt_rows) + 1
            conn.execute("""INSERT INTO schema_migration_events
                (event_id,attempt_id,migration_version,migration_id,migration_name,registry_revision,event_sequence,event_type,event_at,backend,schema_name,
                 previous_schema_version,target_schema_version,migration_checksum,runner_identity,transaction_context_id,
                 error_code,error_class,error_message,context_json,rollback_status)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (
                f"event-{uuid.uuid4().hex}", attempt_id, started["migration_version"], started["migration_id"],
                started["migration_name"], started["registry_revision"], next_sequence, "RECONCILIATION_REQUIRED",
                utc_now().isoformat(), backend, started["schema_name"], started["previous_schema_version"],
                started["target_schema_version"], started["migration_checksum"], "database-startup",
                started["transaction_context_id"], "MIGRATION_ATTEMPT_ORPHANED", "MigrationReconciliationRequired",
                "migration attempt was left without a terminal outcome", '{"action":"operator_reconciliation_required"}', "UNKNOWN"))

    def _begin_migration_attempt(self) -> None:
        with self._connection_scope() as conn:
            self._verify_resolved_reconciliation_artifacts(conn)
            unresolved = conn.execute("""SELECT 1 FROM schema_migration_events required
                WHERE required.event_type = 'RECONCILIATION_REQUIRED' AND required.rollback_status = 'UNKNOWN'
                  AND NOT EXISTS (
                    SELECT 1 FROM schema_migration_events resolved
                    WHERE resolved.attempt_id = required.attempt_id
                      AND resolved.event_type = 'RECONCILIATION_RESOLVED'
                  ) LIMIT 1""").fetchone()
            if unresolved and not getattr(self, "_allow_unresolved_reconciliation", False):
                raise RuntimeError("migration reconciliation required: unresolved migration attempt is blocking startup")
            version_row = conn.execute("SELECT MAX(version) AS version FROM schema_migrations").fetchone() if (conn.execute("SELECT 1 FROM information_schema.tables WHERE table_schema=current_schema() AND table_name='schema_migrations'").fetchone() if isinstance(self, PostgresDatabaseManager) else conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_migrations'").fetchone()) else None
            if version_row and version_row["version"] is not None and int(version_row["version"]) >= 8:
                terminal = conn.execute("SELECT 1 FROM schema_migration_events WHERE migration_version = ? AND event_type = 'SUCCEEDED' LIMIT 1", (int(version_row["version"]),)).fetchone()
                if not terminal:
                    raise RuntimeError("migration outcome reconciliation required: applied schema version has no durable SUCCEEDED event")
                self._migration_attempt_id = None
                self._migration_transaction_id = None
                return
        self._migration_attempt_id = f"mig-{uuid.uuid4().hex}"
        self._migration_transaction_id = f"tx-{uuid.uuid4().hex}"
        self._migration_schema_name = "public" if isinstance(self, PostgresDatabaseManager) else str(self.db_path)
        self._migration_spec = MIGRATION_REGISTRY[-1]
        now = utc_now().isoformat()
        with self._connection_scope() as conn:
            conn.execute("""INSERT INTO schema_migration_events
                (event_id,attempt_id,migration_version,migration_id,migration_name,registry_revision,event_sequence,event_type,event_at,backend,schema_name,
                 previous_schema_version,target_schema_version,migration_checksum,runner_identity,transaction_context_id,
                 context_json,rollback_status)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (
                f"event-{uuid.uuid4().hex}", self._migration_attempt_id, self._migration_spec.version,
                self._migration_spec.migration_id, self._migration_spec.name, self._migration_spec.registry_revision,
                1, "STARTED", now, "POSTGRESQL" if isinstance(self, PostgresDatabaseManager) else "SQLITE",
                self._migration_schema_name, self._migration_spec.previous_version, self._migration_spec.target_version,
                self._migration_spec.checksum, "database-startup", self._migration_transaction_id, "{}", "PENDING"))

    def resolve_migration_reconciliation(
        self,
        attempt_id: str,
        access_token: str,
        resolution: str,
        evidence: Dict[str, Any],
        correlation_id: str,
    ) -> None:
        """Append an authorized operator resolution for one blocked attempt.

        This method is available only on an explicitly opened reconciliation
        manager.  Normal application startup cannot bypass unresolved markers.
        The operator must record whether the migration was verified or aborted,
        together with non-secret evidence suitable for later review.
        """
        if not getattr(self, "_allow_unresolved_reconciliation", False):
            raise PermissionError("migration reconciliation requires explicit maintenance mode")
        from app.core.auth import decode_access_token
        try:
            authorization_context = decode_access_token(access_token, revocation_store=self)
        except Exception as exc:
            raise PermissionError("migration reconciliation requires a valid signed administrator session") from exc
        operator_id = str(authorization_context.get("sub", ""))
        session_jti = str(authorization_context.get("jti", ""))
        if (
            not operator_id.strip()
            or not session_jti.strip()
            or authorization_context.get("iss") != "CyberAssess-Control-Plane"
            or authorization_context.get("aud") != "CyberAssess-Platform"
            or int(authorization_context.get("exp", 0)) <= int(time.time())
            or int(authorization_context.get("nbf", 0)) > int(time.time())
        ):
            raise PermissionError("migration reconciliation requires an authenticated administrator session")
        if resolution != "VERIFIED":
            raise ValueError("migration reconciliation cannot unblock startup without independent verification")
        if not isinstance(evidence, dict) or not evidence or len(evidence) > 20:
            raise ValueError("migration reconciliation requires bounded structured evidence")
        if not correlation_id.strip() or len(correlation_id) > 128:
            raise ValueError("migration reconciliation requires a bounded correlation id")
        if not evidence.get("ticket_id") or evidence.get("schema_verification") != "PASSED":
            raise ValueError("verified reconciliation requires ticket_id and schema_verification=PASSED")
        if len(json.dumps(evidence, ensure_ascii=True)) > 8192:
            raise ValueError("migration reconciliation evidence exceeds the maximum size")
        with self._connection_scope() as conn:
            operator = conn.execute("SELECT role, is_active FROM users WHERE id = ?", (operator_id,)).fetchone()
            if operator is None or operator["role"] != "ADMIN" or not operator["is_active"]:
                raise PermissionError("migration reconciliation requires an active administrator")
            if conn.execute("SELECT 1 FROM revoked_tokens WHERE jti = ?", (session_jti,)).fetchone() is not None:
                raise PermissionError("migration reconciliation session is revoked")
            schema_digest = self._verify_authoritative_schema_state(conn)
            applied = [int(row["version"]) for row in conn.execute("SELECT version FROM schema_migrations ORDER BY version").fetchall()]
            if applied != list(range(1, len(MIGRATION_REGISTRY) + 1)):
                raise RuntimeError("migration reconciliation requires independently verified contiguous schema versions")
            required = conn.execute("""SELECT * FROM schema_migration_events
                WHERE attempt_id = ? AND event_type = 'RECONCILIATION_REQUIRED'
                  AND rollback_status = 'UNKNOWN'""", (attempt_id,)).fetchone()
            if required is None:
                raise ValueError("unresolved migration attempt was not found")
            resolved = conn.execute("""SELECT 1 FROM schema_migration_events
                WHERE attempt_id = ? AND event_type = 'RECONCILIATION_RESOLVED'""", (attempt_id,)).fetchone()
            if resolved is not None:
                raise ValueError("migration attempt has already been resolved")
            next_sequence = conn.execute("SELECT MAX(event_sequence) AS sequence FROM schema_migration_events WHERE attempt_id = ?", (attempt_id,)).fetchone()["sequence"] + 1
            context = json.dumps({"resolution": resolution, "correlation_id": correlation_id, "session_jti": session_jti, "attempt_id": attempt_id, "migration_version": required["migration_version"], "migration_id": required["migration_id"], "registry_revision": required["registry_revision"], "verifier_revision": MIGRATION_POSTCONDITION_REVISION, "schema_digest": schema_digest, "schema_version_vector": applied, "evidence": sanitize_sensitive_data(evidence)}, sort_keys=True, separators=(",", ":"))
            conn.execute("""INSERT INTO schema_migration_events
                (event_id,attempt_id,migration_version,migration_id,migration_name,registry_revision,event_sequence,event_type,event_at,backend,schema_name,
                 previous_schema_version,target_schema_version,migration_checksum,runner_identity,transaction_context_id,
                 error_code,error_class,error_message,context_json,rollback_status)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (
                f"event-{uuid.uuid4().hex}", attempt_id, required["migration_version"], required["migration_id"],
                required["migration_name"], required["registry_revision"], next_sequence, "RECONCILIATION_RESOLVED",
                utc_now().isoformat(), required["backend"], required["schema_name"], required["previous_schema_version"],
                required["target_schema_version"], required["migration_checksum"], operator_id, required["transaction_context_id"],
                f"MIGRATION_RECONCILIATION_{resolution}", "MigrationReconciliationResolved", "operator reconciliation recorded",
                context, "NOT_APPLICABLE"))

    def _verify_authoritative_schema_state(self, conn) -> str:
        """Verify required migration-owned structures before unblocking startup."""
        required_tables = {"schema_migrations", "schema_migration_events", "users", "organizations", "execution_requests", "execution_runs", "execution_decisions", "execution_dispatch_intents"}
        if isinstance(self, PostgresDatabaseManager):
            rows = conn.execute("SELECT table_name FROM information_schema.tables WHERE table_schema = current_schema()").fetchall()
            actual_tables = {row["table_name"] for row in rows}
        else:
            rows = conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall()
            actual_tables = {row["name"] for row in rows}
        if not required_tables.issubset(actual_tables):
            raise RuntimeError("migration reconciliation requires independently verified application schema structures")
        self._verify_migration_ledger(conn)
        for spec in MIGRATION_REGISTRY:
            if spec.verify is None:
                raise RuntimeError(f"migration registry verifier is missing for version {spec.version}")
            method_name = f"_verify_migration_v{spec.version}_postconditions"
            implementation = getattr(self, method_name, None)
            if implementation is None or "sha256:" + hashlib.sha256(inspect.getsource(implementation).encode("utf-8")).hexdigest() != POSTCONDITION_SOURCE_SHA256.get(method_name):
                raise RuntimeError(f"migration verifier artifact drifted for version {spec.version}")
            spec.verify(self, conn)
        return self._schema_postcondition_digest(conn)

    def _schema_postcondition_digest(self, conn) -> str:
        """Return a deterministic digest of the verified migration-owned schema."""
        if isinstance(self, PostgresDatabaseManager):
            rows = conn.execute("""SELECT table_name, column_name, data_type, is_nullable, column_default
                FROM information_schema.columns WHERE table_schema = current_schema()
                ORDER BY table_name, ordinal_position""").fetchall()
            objects = [tuple(row.values()) for row in rows]
            constraints = conn.execute("""SELECT t.relname, c.conname, c.contype, pg_get_constraintdef(c.oid)
                FROM pg_constraint c JOIN pg_class t ON t.oid = c.conrelid
                JOIN pg_namespace n ON n.oid = t.relnamespace
                WHERE n.nspname = current_schema() ORDER BY t.relname, c.conname""").fetchall()
            objects.extend(tuple(row.values()) for row in constraints)
            indexes = conn.execute("""SELECT tablename, indexname, indexdef FROM pg_indexes
                WHERE schemaname = current_schema() ORDER BY tablename, indexname, indexdef""").fetchall()
            objects.extend(tuple(row.values()) for row in indexes)
            triggers = conn.execute("""SELECT t.relname, tg.tgname, pg_get_triggerdef(tg.oid),
                    pg_get_functiondef(p.oid)
                FROM pg_trigger tg JOIN pg_class t ON t.oid = tg.tgrelid
                JOIN pg_namespace n ON n.oid = t.relnamespace
                JOIN pg_proc p ON p.oid = tg.tgfoid
                WHERE n.nspname = current_schema() AND NOT tg.tgisinternal
                ORDER BY t.relname, tg.tgname""").fetchall()
            objects.extend(tuple(row.values()) for row in triggers)
            sequences = conn.execute("""SELECT sequence_name, data_type, start_value, minimum_value,
                    maximum_value, increment FROM information_schema.sequences
                WHERE sequence_schema = current_schema() ORDER BY sequence_name""").fetchall()
            objects.extend(tuple(row.values()) for row in sequences)
        else:
            rows = conn.execute("SELECT type, name, tbl_name, sql FROM sqlite_master WHERE sql IS NOT NULL ORDER BY type, name").fetchall()
            objects = [tuple(row) for row in rows]
            for table in sorted({row["name"] for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall()}):
                escaped_table = table.replace("'", "''")
                table_info = conn.execute(f"PRAGMA table_info('{escaped_table}')").fetchall()
                objects.extend((table, "column", row["name"], row["type"], row["notnull"], row["dflt_value"], row["pk"]) for row in table_info)
        migration_rows = conn.execute("SELECT version, applied_at FROM schema_migrations ORDER BY version").fetchall()
        applied_versions = [tuple(row) if not isinstance(self, PostgresDatabaseManager) else tuple(row.values()) for row in migration_rows]
        ledger_rows = conn.execute("""SELECT event_id, attempt_id, migration_version, migration_id, migration_name,
                registry_revision, event_sequence, event_type, event_at, backend, schema_name,
                previous_schema_version, target_schema_version, migration_checksum, runner_identity,
                transaction_context_id, error_code, error_class, error_message, rollback_status
            FROM schema_migration_events
            WHERE event_type NOT IN ('RECONCILIATION_REQUIRED', 'RECONCILIATION_RESOLVED')
            ORDER BY attempt_id, event_sequence, event_id""").fetchall()
        historical_events = [tuple(row) if not isinstance(self, PostgresDatabaseManager) else tuple(row.values()) for row in ledger_rows]
        material = json.dumps({"revision": MIGRATION_POSTCONDITION_REVISION, "objects": objects, "applied_versions": applied_versions, "historical_events": historical_events}, sort_keys=True, default=str, separators=(",", ":"))
        return "sha256:" + hashlib.sha256(material.encode("utf-8")).hexdigest()

    def _verify_resolved_reconciliation_artifacts(self, conn) -> None:
        resolved = conn.execute("SELECT * FROM schema_migration_events WHERE event_type = 'RECONCILIATION_RESOLVED'").fetchall()
        for row in resolved:
            try:
                context = json.loads(row["context_json"])
            except (TypeError, ValueError) as exc:
                raise RuntimeError("migration reconciliation artifact context is invalid") from exc
            if context.get("verifier_revision") != MIGRATION_POSTCONDITION_REVISION or not isinstance(context.get("schema_digest"), str):
                raise RuntimeError("migration reconciliation artifact is missing verifier identity")
            if context.get("attempt_id") != row["attempt_id"] or context.get("migration_version") != row["migration_version"] or context.get("migration_id") != row["migration_id"] or context.get("registry_revision") != row["registry_revision"]:
                raise RuntimeError("migration reconciliation artifact identity does not match its ledger attempt")
            applied = [int(item["version"]) for item in conn.execute("SELECT version FROM schema_migrations ORDER BY version").fetchall()]
            if context.get("schema_version_vector") != applied:
                raise RuntimeError("migration reconciliation artifact schema version vector no longer matches")
            if context["schema_digest"] != self._schema_postcondition_digest(conn):
                raise RuntimeError("migration reconciliation schema digest no longer matches live schema")

    def _record_migration_failure(self, exc: Exception) -> None:
        if not getattr(self, "_migration_attempt_id", None) or not getattr(self, "_migration_started_durable", False):
            return
        now = utc_now().isoformat()
        with self._connection_scope() as conn:
            spec = self._migration_spec
            for event_type, rollback_status, sequence in (("FAILED", "FAILED", 2), ("ROLLBACK_FAILED", "FAILED", 3)):
                conn.execute("""INSERT INTO schema_migration_events
                    (event_id,attempt_id,migration_version,migration_id,migration_name,registry_revision,event_sequence,event_type,event_at,backend,schema_name,
                     previous_schema_version,target_schema_version,migration_checksum,runner_identity,transaction_context_id,
                     error_class,error_message,context_json,rollback_status)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (
                    f"event-{uuid.uuid4().hex}", self._migration_attempt_id, self._migration_spec.version,
                    self._migration_spec.migration_id, self._migration_spec.name, self._migration_spec.registry_revision,
                    sequence, event_type, now, "POSTGRESQL" if isinstance(self, PostgresDatabaseManager) else "SQLITE",
                    self._migration_schema_name, spec.previous_version, spec.target_version,
                    spec.checksum, "database-startup", self._migration_transaction_id,
                    type(exc).__name__, str(exc)[:500], '{"coordinator":"registry","rollback":"not independently confirmed"}', rollback_status))

    def _verify_migration_ledger(self, conn) -> None:
        """Reject any existing migration ledger that cannot be trusted."""
        required = {"event_id", "attempt_id", "migration_version", "migration_id", "migration_name", "registry_revision", "event_sequence", "event_type", "event_at", "backend", "schema_name", "previous_schema_version", "target_schema_version", "migration_checksum", "runner_identity", "transaction_context_id", "error_code", "error_class", "error_message", "context_json", "rollback_status"}
        if isinstance(self, PostgresDatabaseManager):
            rows = conn.execute("SELECT column_name, data_type, is_nullable, column_default FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='schema_migration_events'").fetchall()
            actual = {r["column_name"] for r in rows}
            if actual != required:
                raise RuntimeError("migration ledger schema drifted; operator reconciliation required")
            definitions = {r["column_name"]: (str(r["data_type"]).lower(), r["is_nullable"], r["column_default"]) for r in rows}
            required_not_null = {"event_id", "attempt_id", "migration_version", "migration_id", "migration_name", "registry_revision", "event_sequence", "event_type", "event_at", "backend", "schema_name", "target_schema_version", "migration_checksum", "runner_identity", "transaction_context_id", "context_json", "rollback_status"}
            for name in required:
                expected_type = "integer" if name in {"migration_version", "event_sequence", "previous_schema_version", "target_schema_version"} else "text"
                expected_default = "'{}'::text" if name == "context_json" else None
                if definitions[name][0] != expected_type or ("NO" if name in required_not_null else "YES") != definitions[name][1] or definitions[name][2] != expected_default:
                    raise RuntimeError("migration ledger column definitions drifted")
            constraints = conn.execute("SELECT contype, convalidated FROM pg_constraint c JOIN pg_class t ON t.oid=c.conrelid JOIN pg_namespace n ON n.oid=t.relnamespace WHERE n.nspname=current_schema() AND t.relname='schema_migration_events'").fetchall()
            if sum(1 for r in constraints if r["contype"] == "p") != 1 or sum(1 for r in constraints if r["contype"] == "u") != 2 or sum(1 for r in constraints if r["contype"] == "c") != 3 or any(not r["convalidated"] for r in constraints):
                raise RuntimeError("migration ledger constraints are not exact or validated")
            identity = conn.execute("""SELECT c.contype, c.conkey, c.confkey, pg_get_constraintdef(c.oid) AS definition
                FROM pg_constraint c JOIN pg_class t ON t.oid=c.conrelid JOIN pg_namespace n ON n.oid=t.relnamespace
                WHERE n.nspname=current_schema() AND t.relname='schema_migration_events'""").fetchall()
            pk = [r for r in identity if r["contype"] == "p"]
            uq = [r for r in identity if r["contype"] == "u"]
            checks = {str(r["definition"]).upper().replace(" ", "") for r in identity if r["contype"] == "c"}
            expected_checks = {
                "CHECK((EVENT_TYPE=ANY(ARRAY['STARTED'::TEXT,'SUCCEEDED'::TEXT,'FAILED'::TEXT,'ROLLED_BACK'::TEXT,'ROLLBACK_FAILED'::TEXT,'RECONCILIATION_REQUIRED'::TEXT,'RECONCILIATION_RESOLVED'::TEXT])))",
                "CHECK((BACKEND=ANY(ARRAY['SQLITE'::TEXT,'POSTGRESQL'::TEXT])))",
                "CHECK((ROLLBACK_STATUS=ANY(ARRAY['NOT_APPLICABLE'::TEXT,'PENDING'::TEXT,'CONFIRMED'::TEXT,'FAILED'::TEXT,'UNKNOWN'::TEXT])))",
            }
            if len(pk) != 1 or len(uq) != 2 or not any("PRIMARYKEY(EVENT_ID)" == str(r["definition"]).upper().replace(" ", "") for r in pk) or not any("UNIQUE(ATTEMPT_ID,EVENT_TYPE)" == str(r["definition"]).upper().replace(" ", "") for r in uq) or not any("UNIQUE(ATTEMPT_ID,EVENT_SEQUENCE)" == str(r["definition"]).upper().replace(" ", "") for r in uq) or checks != expected_checks:
                raise RuntimeError("migration ledger constraint identities drifted")
            trigger = conn.execute("""SELECT tg.tgenabled, pg_get_triggerdef(tg.oid) AS trigger_def,
                    pg_get_functiondef(p.oid) AS function_def
                FROM pg_trigger tg JOIN pg_class t ON t.oid=tg.tgrelid
                JOIN pg_proc p ON p.oid=tg.tgfoid JOIN pg_namespace n ON n.oid=t.relnamespace
                WHERE n.nspname=current_schema() AND t.relname='schema_migration_events'
                  AND NOT tg.tgisinternal AND tg.tgname='schema_migration_events_no_update_delete'""").fetchall()
            if len(trigger) != 1 or trigger[0]["tgenabled"] != "O":
                raise RuntimeError("migration ledger append-only trigger is absent or disabled")
            trigger_def = "".join(str(trigger[0]["trigger_def"]).upper().split())
            function_def = "".join(str(trigger[0]["function_def"]).upper().split())
            if "BEFOREDELETEORUPDATEON" not in trigger_def or "SCHEMA_MIGRATION_EVENTS" not in trigger_def or "FOREACHROW" not in trigger_def or "EXECUTEFUNCTION" not in trigger_def or "SCHEMA_MIGRATION_EVENTS_IMMUTABLE" not in trigger_def or "AS$FUNCTION$BEGINRAISEEXCEPTION" not in function_def or "APPEND-ONLY" not in function_def or "TG_OP" in function_def or "RETURNOLD" in function_def or "RETURNNEW" in function_def:
                raise RuntimeError("migration ledger append-only trigger definition drifted")
        else:
            rows = conn.execute("PRAGMA table_info(schema_migration_events)").fetchall()
            if {r["name"] for r in rows} != required:
                raise RuntimeError("migration ledger schema drifted; operator reconciliation required")
            expected = {"event_id": ("text", False, None), "attempt_id": ("text", True, None), "migration_version": ("integer", True, None), "migration_id": ("text", True, None), "migration_name": ("text", True, None), "registry_revision": ("text", True, None), "event_sequence": ("integer", True, None), "event_type": ("text", True, None), "event_at": ("text", True, None), "backend": ("text", True, None), "schema_name": ("text", True, None), "previous_schema_version": ("integer", False, None), "target_schema_version": ("integer", True, None), "migration_checksum": ("text", True, None), "runner_identity": ("text", True, None), "transaction_context_id": ("text", True, None), "error_code": ("text", False, None), "error_class": ("text", False, None), "error_message": ("text", False, None), "context_json": ("text", True, "'{}'"), "rollback_status": ("text", True, None)}
            actual = {r["name"]: (str(r["type"]).strip().lower(), bool(r["notnull"]), r["dflt_value"]) for r in rows}
            if any(actual[n] != expected[n] for n in required):
                raise RuntimeError("migration ledger column definitions drifted")
            if sum(1 for r in rows if r["pk"] == 1) != 1 or next((r["name"] for r in rows if r["pk"] == 1), None) != "event_id":
                raise RuntimeError("migration ledger primary key drifted")
            unique = []
            for index in conn.execute("PRAGMA index_list(schema_migration_events)").fetchall():
                if index["unique"]:
                    cols = conn.execute(f"PRAGMA index_info('{str(index['name']).replace(chr(39), chr(39) + chr(39))}')").fetchall()
                    unique.append([c["name"] for c in sorted(cols, key=lambda c: c["seqno"])])
            if unique.count(["attempt_id", "event_type"]) != 1 or unique.count(["attempt_id", "event_sequence"]) != 1 or unique.count(["event_id"]) != 1 or len(unique) != 3:
                raise RuntimeError("migration ledger attempt/event uniqueness drifted")
            sql = conn.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='schema_migration_events'").fetchone()["sql"].upper()
            allowed_values = ("'STARTED'", "'SUCCEEDED'", "'FAILED'", "'ROLLED_BACK'", "'ROLLBACK_FAILED'", "'RECONCILIATION_REQUIRED'", "'RECONCILIATION_RESOLVED'", "'SQLITE'", "'POSTGRESQL'", "'NOT_APPLICABLE'", "'PENDING'", "'CONFIRMED'", "'UNKNOWN'")
            if sql.count("CHECK (") != 3 or any(token not in sql for token in ("CHECK (EVENT_TYPE IN", "CHECK (BACKEND IN", "CHECK (ROLLBACK_STATUS IN")) or any(token not in sql for token in allowed_values):
                raise RuntimeError("migration ledger CHECK constraints drifted")
            triggers = {r["name"] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='schema_migration_events'").fetchall()}
            if triggers != {"schema_migration_events_no_update", "schema_migration_events_no_delete"}:
                raise RuntimeError("migration ledger append-only protection is absent")
            trigger_sql = {r["name"]: "".join(str(r["sql"]).upper().split()) for r in conn.execute("SELECT name, sql FROM sqlite_master WHERE type='trigger' AND tbl_name='schema_migration_events'").fetchall()}
            for name, operation in (("schema_migration_events_no_update", "UPDATE"), ("schema_migration_events_no_delete", "DELETE")):
                if trigger_sql.get(name) != f"CREATETRIGGER{name.upper()}BEFORE{operation}ONSCHEMA_MIGRATION_EVENTSBEGINSELECTRAISE(ABORT,'SCHEMA_MIGRATION_EVENTSISAPPEND-ONLY');END":
                    raise RuntimeError("migration ledger append-only trigger definition drifted")
        self._verify_migration_ledger_rows(conn)

    def _verify_migration_ledger_rows(self, conn) -> None:
        """Verify stored event identity and the allowable attempt state shape."""
        specs_by_version = {spec.version: spec for spec in MIGRATION_REGISTRY}
        expected_backend = "POSTGRESQL" if isinstance(self, PostgresDatabaseManager) else "SQLITE"
        rows = conn.execute("SELECT * FROM schema_migration_events ORDER BY event_at, event_id").fetchall()
        attempts = {}
        for row in rows:
            spec = specs_by_version.get(int(row["migration_version"]))
            if spec is None:
                raise RuntimeError("migration ledger contains an unknown migration version")
            if (
                row["migration_id"] != spec.migration_id
                or row["registry_revision"] != spec.registry_revision
                or row["migration_name"] != spec.name
                or row["migration_checksum"] != spec.checksum
                or row["previous_schema_version"] != spec.previous_version
                or row["target_schema_version"] != spec.target_version
                or row["backend"] != expected_backend
                or row["event_sequence"] is None
                or int(row["event_sequence"]) < 1
                or not row["attempt_id"]
                or not row["event_type"]
                or not row["event_at"]
                or not row["runner_identity"]
                or not row["transaction_context_id"]
            ):
                raise RuntimeError("migration ledger row identity or provenance drifted")
            attempts.setdefault(row["attempt_id"], []).append(row)

        for attempt_id, attempt_rows in attempts.items():
            ordered_rows = sorted(attempt_rows, key=lambda row: int(row["event_sequence"]))
            if [int(row["event_sequence"]) for row in ordered_rows] != list(range(1, len(ordered_rows) + 1)):
                raise RuntimeError(f"migration attempt {attempt_id} has a non-contiguous event sequence")
            first = ordered_rows[0]
            if any(
                row["migration_version"] != first["migration_version"]
                or row["migration_id"] != first["migration_id"]
                or row["registry_revision"] != first["registry_revision"]
                or row["migration_name"] != first["migration_name"]
                or row["migration_checksum"] != first["migration_checksum"]
                or row["previous_schema_version"] != first["previous_schema_version"]
                or row["target_schema_version"] != first["target_schema_version"]
                or row["backend"] != first["backend"]
                or row["schema_name"] != first["schema_name"]
                or row["transaction_context_id"] != first["transaction_context_id"]
                for row in ordered_rows[1:]
            ):
                raise RuntimeError(f"migration attempt {attempt_id} mixes migration identity or transaction context")
            event_types = [row["event_type"] for row in ordered_rows]
            if event_types.count("STARTED") != 1:
                raise RuntimeError(f"migration attempt {attempt_id} has an invalid STARTED event count")
            terminal_types = [event_type for event_type in event_types if event_type != "STARTED"]
            if not terminal_types:
                continue
            if terminal_types not in (["SUCCEEDED"], ["FAILED"], ["FAILED", "ROLLED_BACK"], ["FAILED", "ROLLBACK_FAILED"], ["RECONCILIATION_REQUIRED"], ["RECONCILIATION_REQUIRED", "RECONCILIATION_RESOLVED"]):
                raise RuntimeError(f"migration attempt {attempt_id} has an invalid terminal event sequence")
            started = next(row for row in ordered_rows if row["event_type"] == "STARTED")
            terminal = next(row for row in reversed(ordered_rows) if row["event_type"] != "STARTED")
            if started["rollback_status"] != "PENDING":
                raise RuntimeError(f"migration attempt {attempt_id} has an invalid STARTED rollback state")
            expected_rollback = "NOT_APPLICABLE" if terminal["event_type"] in {"SUCCEEDED", "RECONCILIATION_RESOLVED"} else "UNKNOWN" if terminal["event_type"] == "RECONCILIATION_REQUIRED" else "CONFIRMED" if terminal["event_type"] == "ROLLED_BACK" else "FAILED" if terminal["event_type"] == "ROLLBACK_FAILED" else "CONFIRMED"
            if terminal["rollback_status"] != expected_rollback:
                raise RuntimeError(f"migration attempt {attempt_id} has an invalid terminal rollback state")

    def _get_connection(self) -> sqlite3.Connection:
        try:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(str(self.db_path), check_same_thread=False, timeout=30)
            conn.row_factory = sqlite3.Row
            try:
                conn.execute("PRAGMA journal_mode=WAL;")
            except sqlite3.DatabaseError:
                try:
                    conn.execute("PRAGMA journal_mode=DELETE;")
                except sqlite3.DatabaseError:
                    conn.close()
                    raise
            try:
                conn.execute("PRAGMA foreign_keys=ON;")
            except sqlite3.DatabaseError:
                conn.close()
                raise
            return conn
        except Exception:
            # Never silently switch databases: doing so can mix tenants or
            # resurrect state from an unrelated persistence location.
            raise

    @contextmanager
    def _connection_scope(self):
        """Provide an explicit transaction scope that always closes SQLite handles."""
        conn = self._get_connection()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _verify_migration_v1_postconditions(self, conn) -> None:
        self._verify_execution_run_tenant_binding_schema(conn)

    def _verify_migration_v2_postconditions(self, conn) -> None:
        self._verify_execution_run_tenant_binding_schema(conn)

    def _verify_migration_v3_postconditions(self, conn) -> None:
        self._verify_execution_snapshot_schema(conn)

    def _verify_migration_v4_postconditions(self, conn) -> None:
        self._verify_execution_authority_binding_schema(conn)

    def _verify_migration_v5_postconditions(self, conn) -> None:
        self._verify_execution_run_tenant_binding_schema(conn)

    def _verify_migration_v6_postconditions(self, conn) -> None:
        self._verify_execution_compatibility_schema(conn)

    def _verify_migration_v7_postconditions(self, conn) -> None:
        self._verify_execution_dispatch_base_schema(conn)

    def _verify_migration_v8_postconditions(self, conn) -> None:
        self._verify_execution_dispatch_schema(conn)

    def _verify_execution_dispatch_base_schema(self, conn) -> None:
        """Verify only the pre-lease dispatch shape created by migration v7."""
        required = {"execution_id", "organization_id", "state", "attempt_count", "created_at",
                    "claimed_at", "completed_at", "last_error"}
        forbidden = {"claimed_by", "claim_token", "lease_expires_at", "correlation_id"}
        if isinstance(self, PostgresDatabaseManager):
            rows = conn.execute("""SELECT column_name, data_type, is_nullable, column_default
                FROM information_schema.columns
                WHERE table_schema=current_schema() AND table_name='execution_dispatch_intents'""").fetchall()
            expected = {
                "execution_id": ("text", "NO", None), "organization_id": ("text", "NO", None),
                "state": ("text", "NO", "'PENDING'::text"), "attempt_count": ("integer", "NO", "0"),
                "created_at": ("text", "NO", None), "claimed_at": ("text", "YES", None),
                "completed_at": ("text", "YES", None), "last_error": ("text", "YES", None),
            }
            actual = {row["column_name"]: (str(row["data_type"]).lower(), row["is_nullable"], row["column_default"]) for row in rows}
            if actual != expected:
                raise RuntimeError("execution dispatch v7 column definitions drifted")
            columns = set(actual)
        else:
            rows = conn.execute("PRAGMA table_info(execution_dispatch_intents)").fetchall()
            expected = {
                "execution_id": ("text", True, None), "organization_id": ("text", True, None),
                "state": ("text", True, "'PENDING'"), "attempt_count": ("integer", True, "0"),
                "created_at": ("text", True, None), "claimed_at": ("text", False, None),
                "completed_at": ("text", False, None), "last_error": ("text", False, None),
            }
            actual = {row["name"]: (str(row["type"]).strip().lower(), bool(row["notnull"]), row["dflt_value"]) for row in rows}
            if actual != expected:
                raise RuntimeError("execution dispatch v7 column definitions drifted")
            columns = set(actual)
        if columns != required or columns & forbidden:
            raise RuntimeError("execution dispatch v7 schema does not match its pre-lease target")
        self._verify_execution_dispatch_constraints(conn, include_lease_columns=False)

    def _verify_execution_dispatch_constraints(self, conn, include_lease_columns: bool) -> None:
        """Verify dispatch keys/checks shared by v7 and v8."""
        if isinstance(self, PostgresDatabaseManager):
            constraints = conn.execute("""SELECT contype, convalidated, pg_get_constraintdef(c.oid) AS definition
                FROM pg_constraint c JOIN pg_class t ON t.oid=c.conrelid JOIN pg_namespace n ON n.oid=t.relnamespace
                WHERE n.nspname=current_schema() AND t.relname='execution_dispatch_intents'""").fetchall()
            definitions = {str(row["definition"]).upper().replace(" ", "") for row in constraints}
            required_definitions = {
                "PRIMARYKEY(EXECUTION_ID)",
                "FOREIGNKEY(EXECUTION_ID,ORGANIZATION_ID)REFERENCESEXECUTION_RUNS(EXECUTION_ID,ORGANIZATION_ID)",
                "FOREIGNKEY(ORGANIZATION_ID)REFERENCESORGANIZATIONS(ID)",
                "CHECK((STATE=ANY(ARRAY['PENDING'::TEXT,'CLAIMED'::TEXT,'COMPLETED'::TEXT,'FAILED'::TEXT,'BLOCKED'::TEXT])))",
                "CHECK((ATTEMPT_COUNT>=0))",
            }
            if any(not row["convalidated"] for row in constraints) or not required_definitions.issubset(definitions):
                raise RuntimeError("execution dispatch schema contains an unvalidated constraint")
            if sum(1 for row in constraints if row["contype"] == "p") != 1 or sum(1 for row in constraints if row["contype"] == "f") != 2 or sum(1 for row in constraints if row["contype"] == "c") != 2:
                raise RuntimeError("execution dispatch schema constraint set drifted")
        else:
            sql = str(conn.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='execution_dispatch_intents'").fetchone()["sql"]).upper()
            foreign_keys = {}
            for row in conn.execute("PRAGMA foreign_key_list(execution_dispatch_intents)").fetchall():
                foreign_keys.setdefault(row["id"], []).append(row)
            exact_run = any(len(rows) == 2 and sorted((r["seq"], r["from"], r["to"]) for r in rows) == [(0, "execution_id", "execution_id"), (1, "organization_id", "organization_id")] and all(r["table"] == "execution_runs" for r in rows) for rows in foreign_keys.values())
            exact_org = any(len(rows) == 1 and rows[0]["table"] == "organizations" and rows[0]["from"] == "organization_id" and rows[0]["to"] == "id" for rows in foreign_keys.values())
            if sum(1 for row in conn.execute("PRAGMA table_info(execution_dispatch_intents)").fetchall() if row["pk"] == 1) != 1 or not exact_run or not exact_org or "CHECK (STATE IN" not in sql or "CHECK (ATTEMPT_COUNT >= 0)" not in sql:
                raise RuntimeError("execution dispatch v7 keys or checks drifted")

    def _verify_execution_run_tenant_binding_schema(self, conn) -> None:
        """Verify the v1/v2/v5 execution-run tenant binding postcondition."""
        required_tables = {"execution_runs", "execution_requests", "organizations"}
        if isinstance(self, PostgresDatabaseManager):
            actual = {row["table_name"] for row in conn.execute("SELECT table_name FROM information_schema.tables WHERE table_schema = current_schema()").fetchall()}
            if not required_tables.issubset(actual):
                raise RuntimeError("execution tenant-binding postcondition requires core tables")
            parent = conn.execute("""SELECT COUNT(*) AS count FROM pg_index i
                JOIN pg_class t ON t.oid = i.indrelid JOIN pg_namespace n ON n.oid = t.relnamespace
                JOIN unnest(i.indkey) WITH ORDINALITY k(attnum, ord) ON TRUE
                JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = k.attnum
                WHERE n.nspname = current_schema() AND t.relname = 'execution_requests'
                  AND i.indisunique AND i.indisvalid AND i.indisready AND i.indpred IS NULL
                GROUP BY i.indexrelid HAVING array_agg(a.attname::text ORDER BY k.ord) = ARRAY['id','organization_id']::text[]""").fetchall()
            binding = conn.execute("""SELECT COUNT(DISTINCT c.oid) AS count FROM pg_constraint c
                JOIN pg_class t ON t.oid = c.conrelid JOIN pg_class p ON p.oid = c.confrelid
                JOIN pg_namespace n ON n.oid = t.relnamespace JOIN pg_namespace pn ON pn.oid = p.relnamespace
                JOIN unnest(c.conkey) WITH ORDINALITY local_cols(attnum, ord) ON TRUE
                JOIN unnest(c.confkey) WITH ORDINALITY parent_cols(attnum, ord) ON parent_cols.ord = local_cols.ord
                JOIN pg_attribute la ON la.attrelid = t.oid AND la.attnum = local_cols.attnum
                JOIN pg_attribute pa ON pa.attrelid = p.oid AND pa.attnum = parent_cols.attnum
                WHERE n.nspname = current_schema() AND pn.nspname = current_schema()
                  AND t.relname = 'execution_runs' AND p.relname = 'execution_requests'
                  AND c.contype = 'f' AND c.convalidated
                GROUP BY c.oid HAVING array_agg(la.attname::text ORDER BY local_cols.ord) = ARRAY['request_id','organization_id']::text[]
                  AND array_agg(pa.attname::text ORDER BY parent_cols.ord) = ARRAY['id','organization_id']::text[]""").fetchone()
            run_unique = conn.execute("""SELECT COUNT(*) AS count FROM pg_index i
                JOIN pg_class t ON t.oid = i.indrelid JOIN pg_namespace n ON n.oid = t.relnamespace
                JOIN unnest(i.indkey) WITH ORDINALITY k(attnum, ord) ON TRUE
                JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = k.attnum
                WHERE n.nspname = current_schema() AND t.relname = 'execution_runs'
                  AND i.indisunique AND i.indisvalid AND i.indisready AND i.indpred IS NULL
                GROUP BY i.indexrelid HAVING array_agg(a.attname::text ORDER BY k.ord) = ARRAY['request_id','organization_id']::text[]""").fetchall()
            if len(parent) != 1 or len(run_unique) != 1 or not binding or int(binding["count"]) != 1:
                raise RuntimeError("execution tenant-binding postcondition is not exact")
            return
        parent = 0
        for index in conn.execute("PRAGMA index_list(execution_requests)").fetchall():
            if index["unique"]:
                cols = conn.execute(f"PRAGMA index_info('{str(index['name']).replace(chr(39), chr(39) + chr(39))}')").fetchall()
                parent += [c["name"] for c in sorted(cols, key=lambda c: c["seqno"])] == ["id", "organization_id"]
        run_unique = 0
        for index in conn.execute("PRAGMA index_list(execution_runs)").fetchall():
            if index["unique"]:
                cols = conn.execute(f"PRAGMA index_info('{str(index['name']).replace(chr(39), chr(39) + chr(39))}')").fetchall()
                run_unique += [c["name"] for c in sorted(cols, key=lambda c: c["seqno"])] == ["request_id", "organization_id"]
        groups = {}
        for row in conn.execute("PRAGMA foreign_key_list(execution_runs)").fetchall():
            groups.setdefault(row["id"], []).append(row)
        binding = any(len(rows) == 2 and sorted((row["seq"], row["from"], row["to"]) for row in rows) == [(0, "request_id", "id"), (1, "organization_id", "organization_id")] and all(row["table"] == "execution_requests" for row in rows) for rows in groups.values())
        if parent != 1 or run_unique != 1 or not binding:
            raise RuntimeError("execution tenant-binding postcondition is not exact")

    def _verify_execution_snapshot_schema(self, conn) -> None:
        """Verify the immutable execution snapshot schema on every startup.

        Migration history is evidence of an attempted change, not proof that
        the live database still has the required definitions.  This check is
        intentionally strict and fails closed when a column is missing or has
        drifted in type, nullability, or default value.
        """
        expected = {
            "approved_decision_id": ("text", False, None),
            "target_policy_version": ("text", False, None),
            "operation_policy_revision": ("text", False, None),
            "request_fingerprint": ("text", False, None),
            "operation_options_json": ("text", True, "'{}'"),
            "resource_budget_json": ("text", True, "'{}'"),
            "account_impact_budget_json": ("text", True, "'{}'"),
            "credential_scope_json": ("text", True, "'{}'"),
            "snapshot_completeness": ("text", True, "'LEGACY_SNAPSHOT_UNAVAILABLE'"),
        }

        if isinstance(self, PostgresDatabaseManager):
            rows = conn.execute(
                """
                SELECT a.attname AS column_name, format_type(a.atttypid, a.atttypmod) AS data_type,
                       a.attnotnull AS not_null,
                       pg_get_expr(d.adbin, d.adrelid) AS default_value
                FROM pg_attribute a
                JOIN pg_class t ON t.oid = a.attrelid
                JOIN pg_namespace n ON n.oid = t.relnamespace
                LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
                WHERE n.nspname = current_schema() AND t.relname = 'execution_runs'
                  AND a.attnum > 0 AND NOT a.attisdropped
                """
            ).fetchall()
            actual = {
                row["column_name"]: (
                    str(row["data_type"]).lower(),
                    bool(row["not_null"]),
                    str(row["default_value"]).strip() if row["default_value"] is not None else None,
                )
                for row in rows
            }
            normalized_expected = {
                name: (data_type, not_null, (f"{default}::text" if default else None))
                for name, (data_type, not_null, default) in expected.items()
            }
        else:
            rows = conn.execute("PRAGMA table_info('execution_runs')").fetchall()
            actual = {
                row["name"]: (
                    str(row["type"]).strip().lower(),
                    bool(row["notnull"]),
                    str(row["dflt_value"]).strip() if row["dflt_value"] is not None else None,
                )
                for row in rows
            }
            normalized_expected = expected

        missing = sorted(set(expected) - set(actual))
        mismatched = {
            name: {"expected": normalized_expected[name], "actual": actual.get(name)}
            for name in expected
            if name in actual and actual[name] != normalized_expected[name]
        }
        if missing or mismatched:
            raise RuntimeError(
                "execution_runs snapshot schema verification failed: "
                f"missing={missing!r}, mismatched={mismatched!r}"
            )

    def _verify_execution_authority_binding_schema(self, conn) -> None:
        """Require exactly one validated tenant-scoped decision relationship."""
        if isinstance(self, PostgresDatabaseManager):
            parent = conn.execute("""
                SELECT COUNT(*) AS count
                FROM pg_index i
                JOIN pg_class t ON t.oid = i.indrelid
                JOIN pg_namespace n ON n.oid = t.relnamespace
                JOIN LATERAL unnest(i.indkey) WITH ORDINALITY AS k(attnum, ordinality) ON TRUE
                JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = k.attnum
                WHERE t.relname = 'execution_decisions' AND n.nspname = current_schema()
                  AND i.indisunique AND i.indisvalid AND i.indisready AND i.indpred IS NULL
                GROUP BY i.indexrelid
                HAVING array_agg(a.attname::text ORDER BY k.ordinality) = ARRAY['id', 'organization_id']::text[]
            """).fetchall()
            binding = conn.execute("""
                SELECT COUNT(*) AS count
                FROM pg_constraint c
                JOIN pg_class t ON t.oid = c.conrelid
                JOIN pg_class pt ON pt.oid = c.confrelid
                JOIN pg_namespace n ON n.oid = t.relnamespace
                JOIN pg_namespace pn ON pn.oid = pt.relnamespace
                WHERE t.relname = 'execution_runs' AND pt.relname = 'execution_decisions'
                  AND n.nspname = current_schema() AND pn.nspname = current_schema()
                  AND c.contype = 'f' AND c.convalidated
                  AND c.conkey = ARRAY[
                      (SELECT attnum FROM pg_attribute WHERE attrelid = t.oid AND attname = 'approved_decision_id'),
                      (SELECT attnum FROM pg_attribute WHERE attrelid = t.oid AND attname = 'organization_id')]
                  AND c.confkey = ARRAY[
                      (SELECT attnum FROM pg_attribute WHERE attrelid = pt.oid AND attname = 'id'),
                      (SELECT attnum FROM pg_attribute WHERE attrelid = pt.oid AND attname = 'organization_id')]
            """).fetchall()
            parent_count = len(parent)
            binding_count = int(binding[0]["count"]) if binding else 0
        else:
            parent_count = 0
            for index in conn.execute("PRAGMA index_list(execution_decisions)").fetchall():
                if index["unique"] and not index["partial"]:
                    columns = conn.execute(f"PRAGMA index_info('{str(index['name']).replace(chr(39), chr(39) + chr(39))}')").fetchall()
                    if [row["name"] for row in sorted(columns, key=lambda value: value["seqno"])] == ["id", "organization_id"]:
                        parent_count += 1
            grouped = {}
            for row in conn.execute("PRAGMA foreign_key_list(execution_runs)").fetchall():
                grouped.setdefault(row["id"], []).append(row)
            binding_count = sum(
                1 for rows in grouped.values()
                if len(rows) == 2
                and sorted((row["seq"], row["from"], row["to"]) for row in rows)
                == [(0, "approved_decision_id", "id"), (1, "organization_id", "organization_id")]
                and all(row["table"] == "execution_decisions" for row in rows)
            )
        if parent_count != 1 or binding_count != 1:
            raise RuntimeError(
                "execution authority schema verification failed: "
                f"expected one parent key and one decision binding, got {parent_count} and {binding_count}"
            )

    def _verify_execution_compatibility_schema(self, conn) -> None:
        """Verify the v6 execution-plane columns on every startup."""
        expected = {
            "execution_decisions": {"consumed_at", "claim_owner", "claim_expires_at", "started_at", "claim_token"},
            "execution_requests": {"approval_idempotency_key"},
        }
        missing = []
        wrong_type = []
        if isinstance(self, PostgresDatabaseManager):
            rows = conn.execute(
                "SELECT table_name, column_name, data_type, is_nullable, column_default "
                "FROM information_schema.columns WHERE table_schema = current_schema() "
                "AND table_name IN ('execution_decisions', 'execution_requests')"
            ).fetchall()
            actual = {(row["table_name"], row["column_name"]): row for row in rows}
            for table, columns in expected.items():
                for column in columns:
                    row = actual.get((table, column))
                    if not row:
                        missing.append(f"{table}.{column}")
                    elif str(row["data_type"]).lower() != "text" or row["is_nullable"] != "YES" or row["column_default"] is not None:
                        wrong_type.append(f"{table}.{column}")
        else:
            for table, columns in expected.items():
                rows = conn.execute(f"PRAGMA table_info('{table}')").fetchall()
                actual = {row["name"]: row for row in rows}
                for column in columns:
                    row = actual.get(column)
                    if not row:
                        missing.append(f"{table}.{column}")
                    elif str(row["type"]).strip().lower() != "text" or bool(row["notnull"]) or row["dflt_value"] is not None:
                        wrong_type.append(f"{table}.{column}")
        if missing or wrong_type:
            raise RuntimeError(
                "execution compatibility schema verification failed: "
                f"missing={sorted(missing)!r}, mismatched={sorted(wrong_type)!r}"
            )

    def _verify_execution_dispatch_schema(self, conn) -> None:
        """Fail closed if dispatch intents are not tenant-bound and lease-capable."""
        required = {"execution_id", "organization_id", "state", "attempt_count", "created_at",
                    "claimed_at", "completed_at", "last_error", "claimed_by", "claim_token",
                    "lease_expires_at", "correlation_id"}
        if isinstance(self, PostgresDatabaseManager):
            rows = conn.execute("""SELECT column_name, data_type, is_nullable, column_default
                FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='execution_dispatch_intents'""").fetchall()
            actual = {r["column_name"]: (str(r["data_type"]).lower(), r["is_nullable"], r["column_default"]) for r in rows}
            expected = {name: ("integer" if name == "attempt_count" else "text", "NO" if name in {"execution_id", "organization_id", "state", "attempt_count", "created_at"} else "YES", "'PENDING'::text" if name == "state" else "0" if name == "attempt_count" else None) for name in required}
            if set(actual) != required or any(actual[n] != expected[n] for n in required):
                raise RuntimeError("execution dispatch schema columns drifted")
            fk = conn.execute("""SELECT COUNT(*) AS count FROM pg_constraint c
                JOIN pg_class t ON t.oid=c.conrelid JOIN pg_class p ON p.oid=c.confrelid
                JOIN pg_namespace n ON n.oid=t.relnamespace
                WHERE n.nspname=current_schema() AND t.relname='execution_dispatch_intents' AND p.relname='execution_runs'
                  AND c.contype='f' AND c.convalidated
                  AND c.conkey=ARRAY[(SELECT attnum FROM pg_attribute WHERE attrelid=t.oid AND attname='execution_id'),(SELECT attnum FROM pg_attribute WHERE attrelid=t.oid AND attname='organization_id')]
                  AND c.confkey=ARRAY[(SELECT attnum FROM pg_attribute WHERE attrelid=p.oid AND attname='execution_id'),(SELECT attnum FROM pg_attribute WHERE attrelid=p.oid AND attname='organization_id')]""").fetchone()
            if not fk or int(fk["count"]) != 1:
                raise RuntimeError("execution dispatch schema requires exactly one tenant-bound foreign key")
            legacy = conn.execute("""SELECT COUNT(*) AS count FROM pg_constraint c
                JOIN pg_class t ON t.oid=c.conrelid JOIN pg_class p ON p.oid=c.confrelid
                JOIN pg_namespace n ON n.oid=t.relnamespace
                WHERE n.nspname=current_schema() AND t.relname='execution_dispatch_intents' AND p.relname='execution_runs'
                  AND c.contype='f' AND c.conkey=ARRAY[(SELECT attnum FROM pg_attribute WHERE attrelid=t.oid AND attname='execution_id')]""").fetchone()
            if legacy and int(legacy["count"]) != 0:
                raise RuntimeError("execution dispatch schema contains a legacy single-column run foreign key")
            parent = conn.execute("""SELECT COUNT(*) AS count FROM pg_index i JOIN pg_class t ON t.oid=i.indrelid
                JOIN pg_namespace n ON n.oid=t.relnamespace JOIN unnest(i.indkey) WITH ORDINALITY k(attnum,ord) ON TRUE
                JOIN pg_attribute a ON a.attrelid=t.oid AND a.attnum=k.attnum
                WHERE n.nspname=current_schema() AND t.relname='execution_runs' AND i.indisunique AND i.indisvalid AND i.indisready AND i.indpred IS NULL
                GROUP BY i.indexrelid HAVING array_agg(a.attname::text ORDER BY k.ord)=ARRAY['execution_id','organization_id']::text[]""").fetchall()
            if len(parent) != 1:
                raise RuntimeError("execution dispatch schema lacks exact parent execution key")
            constraints = conn.execute("""SELECT c.contype, c.convalidated, pg_get_constraintdef(c.oid) AS definition
                FROM pg_constraint c JOIN pg_class t ON t.oid=c.conrelid JOIN pg_namespace n ON n.oid=t.relnamespace
                WHERE n.nspname=current_schema() AND t.relname='execution_dispatch_intents'""").fetchall()
            if any(not r["definition"] or not r["contype"] for r in constraints):
                raise RuntimeError("execution dispatch schema contains unreadable constraints")
            if any(r["contype"] in {"p", "f", "c"} and not r["convalidated"] for r in constraints):
                raise RuntimeError("execution dispatch schema contains an unvalidated constraint")
            if sum(1 for r in constraints if r["contype"] == "p") != 1 or sum(1 for r in constraints if r["contype"] == "f") != 2 or sum(1 for r in constraints if r["contype"] == "c") != 2:
                raise RuntimeError("execution dispatch schema constraint set drifted")
            org_fk = conn.execute("""SELECT COUNT(*) AS count FROM pg_constraint c
                JOIN pg_class t ON t.oid=c.conrelid JOIN pg_class p ON p.oid=c.confrelid
                JOIN pg_namespace n ON n.oid=t.relnamespace JOIN pg_namespace pn ON pn.oid=p.relnamespace
                WHERE n.nspname=current_schema() AND pn.nspname=current_schema()
                  AND t.relname='execution_dispatch_intents' AND p.relname='organizations'
                  AND c.contype='f' AND c.convalidated
                  AND c.conkey=ARRAY[(SELECT attnum FROM pg_attribute WHERE attrelid=t.oid AND attname='organization_id')]
                  AND c.confkey=ARRAY[(SELECT attnum FROM pg_attribute WHERE attrelid=p.oid AND attname='id')]""").fetchone()
            if not org_fk or int(org_fk["count"]) != 1:
                raise RuntimeError("execution dispatch schema lacks exact organization foreign key")
            defs = [str(r["definition"]).upper().replace(' ', '') for r in constraints]
            if sum(1 for r in constraints if r["contype"] == "p") != 1 or not any("PRIMARYKEY(EXECUTION_ID)" in d for d in defs):
                raise RuntimeError("execution dispatch schema primary key drifted")
            state_check = "CHECK((STATE=ANY(ARRAY['PENDING'::TEXT,'CLAIMED'::TEXT,'COMPLETED'::TEXT,'FAILED'::TEXT,'BLOCKED'::TEXT])))"
            if sum(1 for d in defs if d == state_check) != 1:
                raise RuntimeError("execution dispatch schema state constraint drifted")
            if sum(1 for d in defs if d == "CHECK((ATTEMPT_COUNT>=0))") != 1:
                raise RuntimeError("execution dispatch schema attempt constraint drifted")
        else:
            rows = conn.execute("PRAGMA table_info(execution_dispatch_intents)").fetchall()
            expected = {
                "execution_id": ("text", False, None), "organization_id": ("text", True, None),
                "state": ("text", True, "'PENDING'"), "attempt_count": ("integer", True, "0"),
                "created_at": ("text", True, None), "claimed_at": ("text", False, None),
                "completed_at": ("text", False, None), "last_error": ("text", False, None),
                "claimed_by": ("text", False, None), "claim_token": ("text", False, None),
                "lease_expires_at": ("text", False, None), "correlation_id": ("text", False, None),
            }
            actual = {r["name"]: (str(r["type"]).strip().lower(), bool(r["notnull"]), r["dflt_value"]) for r in rows}
            if set(actual) != required or any(actual[name] != expected[name] for name in required):
                raise RuntimeError("execution dispatch schema columns drifted")
            if sum(1 for r in rows if r["pk"] == 1) != 1 or next((r["name"] for r in rows if r["pk"] == 1), None) != "execution_id":
                raise RuntimeError("execution dispatch schema primary key drifted")
            sql = conn.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='execution_dispatch_intents'").fetchone()["sql"].upper()
            if "CHECK (STATE IN" not in sql or "CHECK (ATTEMPT_COUNT >= 0)" not in sql or " OR " in sql:
                raise RuntimeError("execution dispatch schema lacks state/attempt constraints")
            parent_keys = []
            for index in conn.execute("PRAGMA index_list(execution_runs)").fetchall():
                if index["unique"] and not index["partial"]:
                    cols = conn.execute(f"PRAGMA index_info('{str(index['name']).replace(chr(39), chr(39) + chr(39))}')").fetchall()
                    if [c["name"] for c in sorted(cols, key=lambda c: c["seqno"])] == ["execution_id", "organization_id"]:
                        parent_keys.append(index)
            if len(parent_keys) != 1:
                raise RuntimeError("execution dispatch schema lacks exact parent execution key")
        grouped = {}
        for row in conn.execute("PRAGMA foreign_key_list(execution_dispatch_intents)").fetchall() if not isinstance(self, PostgresDatabaseManager) else []:
            grouped.setdefault(row["id"], []).append(row)
        if not isinstance(self, PostgresDatabaseManager):
            valid = any(len(v) == 2 and sorted((x["seq"], x["from"], x["to"]) for x in v) == [(0, "execution_id", "execution_id"), (1, "organization_id", "organization_id")] and all(x["table"] == "execution_runs" for x in v) for v in grouped.values())
            org = any(len(v) == 1 and v[0]["from"] == "organization_id" and v[0]["to"] == "id" and v[0]["table"] == "organizations" for v in grouped.values())
            if not valid or not org or len(grouped) != 2:
                raise RuntimeError("execution dispatch schema contains unexpected foreign keys")

    def _apply_migration_version(self, version: int) -> None:
        if version not in {spec.version for spec in MIGRATION_REGISTRY}:
            raise ValueError(f"unknown registered migration version {version}")
        self._init_db(max_migration_version=version)

    def _init_db(self, max_migration_version: Optional[int] = None) -> None:
        """Initializes database schema, relational constraints, and performance indexes."""
        with self._connection_scope() as conn:
            # 1. Ensure all tables exist
            conn.executescript("""
            -- Organizations Table
            CREATE TABLE IF NOT EXISTS organizations (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                slug TEXT UNIQUE NOT NULL,
                created_at TEXT NOT NULL,
                is_active INTEGER NOT NULL DEFAULT 1
            );

            -- Projects Table
            CREATE TABLE IF NOT EXISTS projects (
                id TEXT PRIMARY KEY,
                organization_id TEXT NOT NULL,
                name TEXT NOT NULL,
                description TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE
            );

            -- Workspaces Table
            CREATE TABLE IF NOT EXISTS workspaces (
                id TEXT PRIMARY KEY,
                organization_id TEXT NOT NULL,
                project_id TEXT,
                name TEXT NOT NULL,
                filesystem_root TEXT NOT NULL,
                is_sandboxed INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE
            );

            -- Users Table
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                email TEXT NOT NULL,
                hashed_password TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'VIEWER',
                organization_id TEXT NOT NULL DEFAULT 'org-default',
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                last_login_at TEXT
            );

            -- API Keys Table (Stored as Cryptographic Hashes)
            CREATE TABLE IF NOT EXISTS api_keys (
                key_id TEXT PRIMARY KEY,
                key_hash TEXT UNIQUE NOT NULL,
                organization_id TEXT NOT NULL DEFAULT 'org-default',
                user_id TEXT,
                name TEXT NOT NULL,
                scopes_json TEXT NOT NULL DEFAULT '[]',
                status TEXT NOT NULL DEFAULT 'ACTIVE',
                created_at TEXT NOT NULL,
                expires_at TEXT,
                revoked_at TEXT,
                last_used_at TEXT
            );

            -- Revoked JWT Tokens Table
            CREATE TABLE IF NOT EXISTS revoked_tokens (
                jti TEXT PRIMARY KEY,
                token_hash TEXT,
                revoked_at TEXT NOT NULL,
                expires_at TEXT
            );

            -- Durable execution authorization decisions. Credential material
            -- is never stored here; only its approved scope is recorded.
            CREATE TABLE IF NOT EXISTS execution_decisions (
                id TEXT PRIMARY KEY,
                organization_id TEXT NOT NULL,
                project_id TEXT,
                asset_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                authorization_decision_id TEXT NOT NULL,
                target_policy_version TEXT NOT NULL,
                tool_id TEXT NOT NULL,
                operation_family TEXT NOT NULL,
                operation_options_json TEXT NOT NULL DEFAULT '{}',
                operation_policy_revision TEXT NOT NULL,
                approval_state TEXT NOT NULL,
                approver_user_id TEXT NOT NULL,
                session_jti TEXT NOT NULL,
                worker_identity TEXT NOT NULL,
                resource_budget_json TEXT NOT NULL DEFAULT '{}',
                account_impact_budget_json TEXT NOT NULL DEFAULT '{}',
                credential_scope_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                revoked_at TEXT,
                consumed_at TEXT,
                claim_owner TEXT,
                claim_expires_at TEXT,
                started_at TEXT,
                claim_token TEXT,
                FOREIGN KEY (organization_id) REFERENCES organizations(id),
                FOREIGN KEY (asset_id, organization_id) REFERENCES assets(id, organization_id),
                FOREIGN KEY (project_id, organization_id) REFERENCES projects(id, organization_id),
                FOREIGN KEY (approver_user_id, organization_id) REFERENCES users(id, organization_id),
                UNIQUE (id, organization_id)
            );

            -- Immutable request recorded before administrator approval.
            CREATE TABLE IF NOT EXISTS execution_requests (
                id TEXT PRIMARY KEY,
                idempotency_key TEXT NOT NULL,
                request_fingerprint TEXT NOT NULL,
                organization_id TEXT NOT NULL,
                project_id TEXT,
                asset_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                authorization_decision_id TEXT NOT NULL,
                target_policy_version TEXT NOT NULL,
                tool_id TEXT NOT NULL,
                operation_family TEXT NOT NULL,
                operation_options_json TEXT NOT NULL DEFAULT '{}',
                operation_policy_revision TEXT NOT NULL,
                resource_budget_json TEXT NOT NULL DEFAULT '{}',
                account_impact_budget_json TEXT NOT NULL DEFAULT '{}',
                credential_scope_json TEXT NOT NULL DEFAULT '{}',
                requested_by_user_id TEXT NOT NULL,
                state TEXT NOT NULL DEFAULT 'REQUESTED',
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                approved_decision_id TEXT,
                approval_idempotency_key TEXT,
                UNIQUE (organization_id, idempotency_key),
                UNIQUE (id, organization_id),
                FOREIGN KEY (organization_id) REFERENCES organizations(id),
                FOREIGN KEY (asset_id, organization_id) REFERENCES assets(id, organization_id),
                FOREIGN KEY (project_id, organization_id) REFERENCES projects(id, organization_id),
                FOREIGN KEY (requested_by_user_id, organization_id) REFERENCES users(id, organization_id)
            );

            CREATE TABLE IF NOT EXISTS execution_runs (
                execution_id TEXT NOT NULL PRIMARY KEY,
                request_id TEXT NOT NULL,
                organization_id TEXT NOT NULL,
                approved_decision_id TEXT,
                target_policy_version TEXT,
                operation_policy_revision TEXT,
                request_fingerprint TEXT,
                operation_options_json TEXT NOT NULL DEFAULT '{}',
                resource_budget_json TEXT NOT NULL DEFAULT '{}',
                account_impact_budget_json TEXT NOT NULL DEFAULT '{}',
                credential_scope_json TEXT NOT NULL DEFAULT '{}',
                snapshot_completeness TEXT NOT NULL DEFAULT 'LEGACY_SNAPSHOT_UNAVAILABLE',
                state TEXT NOT NULL,
                worker_identity TEXT,
                process_id INTEGER,
                process_group_id TEXT,
                assurance_state TEXT NOT NULL,
                coverage_state TEXT NOT NULL,
                reason_code TEXT,
                evidence_ref TEXT,
                correlation_id TEXT,
                created_at TEXT NOT NULL,
                started_at TEXT,
                finished_at TEXT,
                UNIQUE (execution_id, organization_id),
                FOREIGN KEY (request_id, organization_id) REFERENCES execution_requests(id, organization_id),
                FOREIGN KEY (approved_decision_id, organization_id) REFERENCES execution_decisions(id, organization_id),
                FOREIGN KEY (organization_id) REFERENCES organizations(id)
            );

            CREATE TABLE IF NOT EXISTS execution_dispatch_intents (
                execution_id TEXT NOT NULL PRIMARY KEY,
                organization_id TEXT NOT NULL,
                state TEXT NOT NULL DEFAULT 'PENDING' CHECK (state IN ('PENDING', 'CLAIMED', 'COMPLETED', 'FAILED', 'BLOCKED')),
                attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
                created_at TEXT NOT NULL,
                claimed_at TEXT,
                completed_at TEXT,
                last_error TEXT,
                FOREIGN KEY (execution_id, organization_id) REFERENCES execution_runs(execution_id, organization_id),
                FOREIGN KEY (organization_id) REFERENCES organizations(id)
            );

            -- Attack Surface Assets Inventory Table
            CREATE TABLE IF NOT EXISTS assets (
                id TEXT PRIMARY KEY,
                organization_id TEXT NOT NULL DEFAULT 'org-default',
                project_id TEXT,
                name TEXT NOT NULL,
                type TEXT NOT NULL,
                target_value TEXT NOT NULL,
                criticality TEXT NOT NULL DEFAULT 'MEDIUM',
                internet_exposed INTEGER NOT NULL DEFAULT 1,
                active_probing_granted INTEGER NOT NULL DEFAULT 0,
                live_secret_verification_granted INTEGER NOT NULL DEFAULT 0,
                owner TEXT,
                lifecycle_status TEXT NOT NULL DEFAULT 'MONITORED',
                tags_json TEXT NOT NULL DEFAULT '[]',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                last_scanned_at TEXT,
                last_verified_at TEXT,
                active_findings_count INTEGER NOT NULL DEFAULT 0
            );

            -- Scans Table
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                organization_id TEXT NOT NULL DEFAULT 'org-default',
                project_id TEXT,
                asset_id TEXT,
                target_name TEXT NOT NULL,
                target_type TEXT NOT NULL,
                target_value TEXT NOT NULL,
                profile TEXT NOT NULL,
                status TEXT NOT NULL,
                progress_percent INTEGER NOT NULL DEFAULT 0,
                grade TEXT,
                score REAL,
                total_findings INTEGER NOT NULL DEFAULT 0,
                started_at TEXT,
                completed_at TEXT,
                cancelled_at TEXT,
                failure_reason TEXT,
                summary_json TEXT,
                data_json TEXT NOT NULL
            );

            -- Canonical Findings Table
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                organization_id TEXT NOT NULL DEFAULT 'org-default',
                project_id TEXT,
                asset_id TEXT,
                scan_id TEXT NOT NULL,
                check_id TEXT NOT NULL,
                category TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                cvss_score REAL NOT NULL,
                cvss_vector TEXT,
                contextual_risk_score REAL NOT NULL DEFAULT 0.0,
                cwe_id TEXT,
                owasp_category TEXT,
                nist_control TEXT,
                status TEXT NOT NULL DEFAULT 'OPEN',
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                times_observed INTEGER NOT NULL DEFAULT 1,
                assigned_to TEXT,
                contributing_tools_json TEXT NOT NULL DEFAULT '[]',
                correlation_type TEXT,
                description TEXT NOT NULL DEFAULT '',
                impact TEXT NOT NULL DEFAULT '',
                remediation TEXT NOT NULL DEFAULT '',
                evidence_hash TEXT NOT NULL DEFAULT '',
                sla_json TEXT,
                fingerprint TEXT NOT NULL,
                data_json TEXT NOT NULL
            );

            -- Finding Occurrences Table
            CREATE TABLE IF NOT EXISTS finding_occurrences (
                id TEXT PRIMARY KEY,
                organization_id TEXT NOT NULL DEFAULT 'org-default',
                canonical_finding_id TEXT NOT NULL,
                scan_id TEXT NOT NULL,
                asset_id TEXT,
                source_tool TEXT NOT NULL,
                check_id TEXT NOT NULL,
                raw_evidence_json TEXT NOT NULL,
                reproduction_curl TEXT,
                taint_trace_json TEXT,
                detected_at TEXT NOT NULL,
                FOREIGN KEY (canonical_finding_id) REFERENCES findings(id) ON DELETE CASCADE
            );

            -- Finding Collaboration Comments Table
            CREATE TABLE IF NOT EXISTS finding_comments (
                id TEXT PRIMARY KEY,
                finding_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                username TEXT NOT NULL,
                comment TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE CASCADE
            );

            -- Immutable Append-Only Audit Trail Table with Chained Hashes
            CREATE TABLE IF NOT EXISTS audit_events (
                id TEXT PRIMARY KEY,
                sequence_number INTEGER,
                timestamp TEXT NOT NULL,
                actor TEXT NOT NULL,
                organization_id TEXT NOT NULL DEFAULT 'org-default',
                action TEXT NOT NULL,
                object_type TEXT NOT NULL,
                object_id TEXT NOT NULL,
                result TEXT NOT NULL,
                source_ip TEXT,
                correlation_id TEXT,
                details_json TEXT NOT NULL DEFAULT '{}',
                previous_event_hash TEXT,
                event_hash TEXT
            );

            -- Performance and Multi-Tenant Query Indexes
            CREATE INDEX IF NOT EXISTS idx_users_org ON users(organization_id);
            CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
            CREATE INDEX IF NOT EXISTS idx_assets_org ON assets(organization_id);
            CREATE INDEX IF NOT EXISTS idx_scans_org_time ON scans(organization_id, started_at DESC);
            CREATE INDEX IF NOT EXISTS idx_findings_org_status ON findings(organization_id, status);
            CREATE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings(fingerprint);
            CREATE INDEX IF NOT EXISTS idx_occurrences_canonical ON finding_occurrences(canonical_finding_id);
            CREATE INDEX IF NOT EXISTS idx_audit_org_time ON audit_events(organization_id, timestamp DESC);
            CREATE INDEX IF NOT EXISTS idx_execution_decisions_scope ON execution_decisions(organization_id, asset_id, tool_id, operation_family);
            CREATE INDEX IF NOT EXISTS idx_execution_decisions_session ON execution_decisions(session_jti, revoked_at, expires_at);
            CREATE INDEX IF NOT EXISTS idx_execution_requests_scope ON execution_requests(organization_id, state, created_at);
            CREATE INDEX IF NOT EXISTS idx_execution_runs_scope ON execution_runs(organization_id, state, created_at);
            CREATE UNIQUE INDEX IF NOT EXISTS uq_assets_id_org ON assets(id, organization_id);
            CREATE UNIQUE INDEX IF NOT EXISTS uq_projects_id_org ON projects(id, organization_id);
            CREATE UNIQUE INDEX IF NOT EXISTS uq_users_id_org ON users(id, organization_id);
            """)

            # 2. Automated Non-Destructive Column Migrations for Existing Tables
            migrations = [
                "ALTER TABLE audit_events ADD COLUMN previous_event_hash TEXT;",
                "ALTER TABLE audit_events ADD COLUMN event_hash TEXT;",
                "ALTER TABLE api_keys ADD COLUMN status TEXT NOT NULL DEFAULT 'ACTIVE';",
                "ALTER TABLE users ADD COLUMN principal_type TEXT NOT NULL DEFAULT 'TENANT_PRINCIPAL';",
                "ALTER TABLE finding_occurrences ADD COLUMN organization_id TEXT NOT NULL DEFAULT 'org-default';",
                "ALTER TABLE audit_events ADD COLUMN sequence_number INTEGER;",
                "ALTER TABLE assets ADD COLUMN active_probing_granted INTEGER NOT NULL DEFAULT 0;",
                "ALTER TABLE assets ADD COLUMN live_secret_verification_granted INTEGER NOT NULL DEFAULT 0;",
            ]
            for migration_index, mig in enumerate(migrations):
                savepoint = f"schema_migration_{migration_index}"
                try:
                    conn.execute(f"SAVEPOINT {savepoint}")
                    conn.execute(mig)
                    conn.execute(f"RELEASE SAVEPOINT {savepoint}")
                except Exception as exc:
                    # PostgreSQL aborts a transaction after a duplicate-column
                    # error; rollback to a savepoint before continuing.
                    try:
                        conn.execute(f"ROLLBACK TO SAVEPOINT {savepoint}")
                        conn.execute(f"RELEASE SAVEPOINT {savepoint}")
                    except Exception:
                        raise
                    if "duplicate column name" not in str(exc).lower() and "already exists" not in str(exc).lower():
                        raise

            # Versioned execution-run migration.  The execution plane uses one
            # authorized request for one run; retries require a new request and
            # approval.  Legacy SQLite tables are rebuilt only after a
            # duplicate/orphan preflight so an upgrade cannot silently choose a
            # winner or weaken tenant referential integrity.
            conn.execute("CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)")
            migration_version = 1
            already_applied = conn.execute("SELECT 1 FROM schema_migrations WHERE version = ?", (migration_version,)).fetchone()
            if not already_applied:
                duplicate = conn.execute("SELECT request_id, organization_id, COUNT(*) AS count FROM execution_runs GROUP BY request_id, organization_id HAVING COUNT(*) > 1 LIMIT 1").fetchone()
                if duplicate:
                    raise ValueError("execution_runs migration blocked: duplicate runs for one request require audited reconciliation before upgrade")
                inconsistent = conn.execute("""
                    SELECT r.execution_id
                    FROM execution_runs r
                    LEFT JOIN execution_requests q
                      ON q.id = r.request_id AND q.organization_id = r.organization_id
                    WHERE q.id IS NULL
                    LIMIT 1
                """).fetchone()
                if inconsistent:
                    raise ValueError("execution_runs migration blocked: orphaned or cross-tenant request reference requires audited reconciliation before upgrade")
                if isinstance(self, PostgresDatabaseManager):
                    duplicate = conn.execute("SELECT request_id, organization_id, COUNT(*) AS count FROM execution_runs GROUP BY request_id, organization_id HAVING COUNT(*) > 1 LIMIT 1").fetchone()
                    if duplicate:
                        raise ValueError("execution_runs PostgreSQL migration blocked: duplicate runs require audited reconciliation before upgrade")
                    inconsistent = conn.execute("""
                        SELECT r.execution_id
                        FROM execution_runs r
                        LEFT JOIN execution_requests q
                          ON q.id = r.request_id AND q.organization_id = r.organization_id
                        LEFT JOIN organizations o ON o.id = r.organization_id
                        WHERE q.id IS NULL OR o.id IS NULL
                        LIMIT 1
                    """).fetchone()
                    if inconsistent:
                        raise ValueError("execution_runs PostgreSQL migration blocked: orphaned or cross-tenant reference requires audited reconciliation before upgrade")
                    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS uq_execution_runs_request ON execution_runs(request_id, organization_id)")
                    constraints = conn.execute("""
                        SELECT c.conname,
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
                        WHERE t.relname = 'execution_runs'
                          AND pt.relname = 'execution_requests'
                          AND n.nspname = current_schema()
                          AND pn.nspname = current_schema()
                          AND c.contype = 'f'
                        GROUP BY c.conname
                    """).fetchall()
                    desired_columns = ["request_id", "organization_id"]
                    desired_parent_columns = ["id", "organization_id"]
                    has_desired = False
                    for constraint in constraints:
                        local_columns = list(constraint["local_columns"] or [])
                        parent_columns = list(constraint["parent_columns"] or [])
                        if local_columns == desired_columns and parent_columns == desired_parent_columns:
                            has_desired = True
                        elif local_columns == ["request_id"] and parent_columns == ["id"]:
                            safe_name = '"' + str(constraint["conname"]).replace('"', '""') + '"'
                            conn.execute(f"ALTER TABLE execution_runs DROP CONSTRAINT IF EXISTS {safe_name}")
                    if not has_desired:
                        conn.execute("ALTER TABLE execution_runs ADD CONSTRAINT execution_runs_request_tenant_fk FOREIGN KEY (request_id, organization_id) REFERENCES execution_requests(id, organization_id)")
                else:
                    parent_indexes = conn.execute("PRAGMA index_list(execution_requests)").fetchall()
                    has_parent_unique = False
                    for index in parent_indexes:
                        if not index["unique"]:
                            continue
                        columns = conn.execute(f"PRAGMA index_info('{str(index['name']).replace(chr(39), chr(39) + chr(39))}')").fetchall()
                        if [column["name"] for column in sorted(columns, key=lambda value: value["seqno"])] == ["id", "organization_id"]:
                            has_parent_unique = True
                            break
                    if not has_parent_unique:
                        duplicate_parent = conn.execute("SELECT id, organization_id, COUNT(*) AS count FROM execution_requests GROUP BY id, organization_id HAVING COUNT(*) > 1 LIMIT 1").fetchone()
                        if duplicate_parent:
                            raise ValueError("execution_runs migration blocked: execution_requests lacks a unique tenant parent key and contains duplicates")
                    foreign_key_rows = conn.execute("PRAGMA foreign_key_list(execution_runs)").fetchall()
                    grouped_foreign_keys = {}
                    for row in foreign_key_rows:
                        grouped_foreign_keys.setdefault(row["id"], []).append(row)
                    has_composite_fk = any(
                        len(rows) == 2
                        and sorted((row["seq"], row["from"], row["to"]) for row in rows)
                        == [(0, "request_id", "id"), (1, "organization_id", "organization_id")]
                        and all(row["table"] == "execution_requests" for row in rows)
                        for rows in grouped_foreign_keys.values()
                    )
                if not isinstance(self, PostgresDatabaseManager) and not has_composite_fk:
                    conn.execute("ALTER TABLE execution_runs RENAME TO execution_runs_legacy")
                    conn.execute("""
                        CREATE TABLE execution_runs (
                            execution_id TEXT PRIMARY KEY,
                            request_id TEXT NOT NULL,
                            organization_id TEXT NOT NULL,
                            approved_decision_id TEXT,
                            target_policy_version TEXT,
                            operation_policy_revision TEXT,
                            request_fingerprint TEXT,
                            operation_options_json TEXT NOT NULL DEFAULT '{}',
                            resource_budget_json TEXT NOT NULL DEFAULT '{}',
                            account_impact_budget_json TEXT NOT NULL DEFAULT '{}',
                            credential_scope_json TEXT NOT NULL DEFAULT '{}',
                            snapshot_completeness TEXT NOT NULL DEFAULT 'LEGACY_SNAPSHOT_UNAVAILABLE',
                            state TEXT NOT NULL,
                            worker_identity TEXT,
                            process_id INTEGER,
                            process_group_id TEXT,
                            assurance_state TEXT NOT NULL,
                            coverage_state TEXT NOT NULL,
                            reason_code TEXT,
                            evidence_ref TEXT,
                            correlation_id TEXT,
                            created_at TEXT NOT NULL,
                            started_at TEXT,
                            finished_at TEXT,
                            FOREIGN KEY (request_id, organization_id) REFERENCES execution_requests(id, organization_id),
                            FOREIGN KEY (organization_id) REFERENCES organizations(id)
                        )
                    """)
                    conn.execute("""
                        INSERT INTO execution_runs (
                            execution_id, request_id, organization_id, approved_decision_id,
                            target_policy_version, operation_policy_revision, request_fingerprint,
                            operation_options_json, resource_budget_json, account_impact_budget_json,
                            credential_scope_json, snapshot_completeness, state,
                            worker_identity, process_id, process_group_id,
                            assurance_state, coverage_state, reason_code,
                            evidence_ref, correlation_id, created_at, started_at,
                            finished_at
                        )
                        SELECT execution_id, request_id, organization_id, NULL, NULL, NULL, NULL,
                               '{}', '{}', '{}', '{}', 'LEGACY_SNAPSHOT_UNAVAILABLE', state,
                               worker_identity, process_id, process_group_id,
                               assurance_state, coverage_state, reason_code,
                               evidence_ref, correlation_id, created_at, started_at,
                               finished_at
                        FROM execution_runs_legacy
                    """)
                    conn.execute("DROP TABLE execution_runs_legacy")
                if not isinstance(self, PostgresDatabaseManager):
                    postcondition_rows = conn.execute("PRAGMA foreign_key_list(execution_runs)").fetchall()
                    postcondition_groups = {}
                    for row in postcondition_rows:
                        postcondition_groups.setdefault(row["id"], []).append(row)
                    if not any(
                        len(rows) == 2
                        and sorted((row["seq"], row["from"], row["to"]) for row in rows)
                        == [(0, "request_id", "id"), (1, "organization_id", "organization_id")]
                        and all(row["table"] == "execution_requests" for row in rows)
                        for rows in postcondition_groups.values()
                    ):
                        raise ValueError("execution_runs migration failed postcondition: composite tenant foreign key is absent")
                conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS uq_execution_runs_request ON execution_runs(request_id, organization_id)")
                conn.execute("INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)", (migration_version, utc_now().isoformat()))
            if max_migration_version == migration_version:
                return

            # Version 2 is an immutable remediation for databases that already
            # recorded version 1 before PostgreSQL constraint reconciliation was
            # idempotent.  It is intentionally separate from version 1 so an
            # applied migration definition is never changed in place.
            remediation_version = 2
            remediation_applied = conn.execute("SELECT 1 FROM schema_migrations WHERE version = ?", (remediation_version,)).fetchone()
            if not remediation_applied:
                if isinstance(self, PostgresDatabaseManager):
                    duplicate_parent = conn.execute("SELECT id, organization_id, COUNT(*) AS count FROM execution_requests GROUP BY id, organization_id HAVING COUNT(*) > 1 LIMIT 1").fetchone()
                    if duplicate_parent:
                        raise ValueError("execution_runs remediation blocked: duplicate execution request parent keys require audited reconciliation")
                    constraints = conn.execute("""
                        SELECT c.conname,
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
                        WHERE t.relname = 'execution_runs'
                          AND pt.relname = 'execution_requests'
                          AND n.nspname = current_schema()
                          AND pn.nspname = current_schema()
                          AND c.contype = 'f'
                        GROUP BY c.conname
                    """).fetchall()
                    desired = []
                    for constraint in constraints:
                        local_columns = list(constraint["local_columns"] or [])
                        parent_columns = list(constraint["parent_columns"] or [])
                        if local_columns == ["request_id", "organization_id"] and parent_columns == ["id", "organization_id"]:
                            desired.append(constraint)
                        elif local_columns == ["request_id"] and parent_columns == ["id"]:
                            safe_name = '"' + str(constraint["conname"]).replace('"', '""') + '"'
                            conn.execute(f"ALTER TABLE execution_runs DROP CONSTRAINT IF EXISTS {safe_name}")
                    for duplicate_constraint in desired[1:]:
                        safe_name = '"' + str(duplicate_constraint["conname"]).replace('"', '""') + '"'
                        conn.execute(f"ALTER TABLE execution_runs DROP CONSTRAINT IF EXISTS {safe_name}")
                    if not desired:
                        conn.execute("ALTER TABLE execution_runs ADD CONSTRAINT execution_runs_request_tenant_fk FOREIGN KEY (request_id, organization_id) REFERENCES execution_requests(id, organization_id)")
                    final_count = conn.execute("""
                        SELECT COUNT(*) AS count
                        FROM pg_constraint c
                        JOIN pg_class t ON t.oid = c.conrelid
                        JOIN pg_class pt ON pt.oid = c.confrelid
                        JOIN pg_namespace n ON n.oid = t.relnamespace
                        JOIN pg_namespace pn ON pn.oid = pt.relnamespace
                        WHERE t.relname = 'execution_runs' AND pt.relname = 'execution_requests'
                          AND n.nspname = current_schema() AND pn.nspname = current_schema()
                          AND c.contype = 'f'
                          AND pg_get_constraintdef(c.oid) LIKE 'FOREIGN KEY (request_id, organization_id)%'
                    """).fetchone()
                    if not final_count or final_count["count"] != 1:
                        raise ValueError("execution_runs remediation failed postcondition: expected exactly one composite tenant foreign key")
                else:
                    foreign_key_rows = conn.execute("PRAGMA foreign_key_list(execution_runs)").fetchall()
                    grouped_foreign_keys = {}
                    for row in foreign_key_rows:
                        grouped_foreign_keys.setdefault(row["id"], []).append(row)
                    if not any(
                        len(rows) == 2
                        and sorted((row["seq"], row["from"], row["to"]) for row in rows)
                        == [(0, "request_id", "id"), (1, "organization_id", "organization_id")]
                        and all(row["table"] == "execution_requests" for row in rows)
                        for rows in grouped_foreign_keys.values()
                    ):
                        raise ValueError("execution_runs remediation failed postcondition: version-1 schema has no exact composite tenant foreign key")
                    parent_indexes = conn.execute("PRAGMA index_list(execution_requests)").fetchall()
                    has_parent_unique = False
                    for index in parent_indexes:
                        if not index["unique"]:
                            continue
                        index_name = str(index["name"]).replace("'", "''")
                        columns = conn.execute(f"PRAGMA index_info('{index_name}')").fetchall()
                        if [column["name"] for column in sorted(columns, key=lambda value: value["seqno"])] == ["id", "organization_id"]:
                            has_parent_unique = True
                            break
                    if not has_parent_unique:
                        raise ValueError("execution_runs remediation failed postcondition: tenant parent key is not unique")
                conn.execute("INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)", (remediation_version, utc_now().isoformat()))
            if max_migration_version == remediation_version:
                return

            # Version 3 binds each execution run to an immutable authority
            # snapshot.  These fields are deliberately versioned with the
            # execution schema; they are not part of the generic compatibility
            # column loop above.
            snapshot_migration_version = 3
            snapshot_applied = conn.execute(
                "SELECT 1 FROM schema_migrations WHERE version = ?",
                (snapshot_migration_version,),
            ).fetchone()
            if not snapshot_applied:
                snapshot_columns = [
                    ("approved_decision_id", "TEXT"),
                    ("target_policy_version", "TEXT"),
                    ("operation_policy_revision", "TEXT"),
                    ("request_fingerprint", "TEXT"),
                    ("operation_options_json", "TEXT NOT NULL DEFAULT '{}'"),
                    ("resource_budget_json", "TEXT NOT NULL DEFAULT '{}'"),
                    ("account_impact_budget_json", "TEXT NOT NULL DEFAULT '{}'"),
                    ("credential_scope_json", "TEXT NOT NULL DEFAULT '{}'"),
                    ("snapshot_completeness", "TEXT NOT NULL DEFAULT 'LEGACY_SNAPSHOT_UNAVAILABLE'"),
                ]
                for column, definition in snapshot_columns:
                    savepoint = f"execution_snapshot_{column}"
                    try:
                        conn.execute(f"SAVEPOINT {savepoint}")
                        conn.execute(f"ALTER TABLE execution_runs ADD COLUMN {column} {definition}")
                        conn.execute(f"RELEASE SAVEPOINT {savepoint}")
                    except Exception as exc:
                        conn.execute(f"ROLLBACK TO SAVEPOINT {savepoint}")
                        conn.execute(f"RELEASE SAVEPOINT {savepoint}")
                        if "duplicate column name" not in str(exc).lower() and "already exists" not in str(exc).lower():
                            raise ValueError(f"execution snapshot migration failed for {column}") from exc
                if isinstance(self, PostgresDatabaseManager):
                    snapshot_count = conn.execute(
                        "SELECT COUNT(*) AS count FROM information_schema.columns "
                        "WHERE table_schema = current_schema() AND table_name = 'execution_runs' "
                        "AND column_name IN ('approved_decision_id', 'target_policy_version', 'operation_policy_revision', 'request_fingerprint', 'operation_options_json', 'resource_budget_json', 'account_impact_budget_json', 'credential_scope_json', 'snapshot_completeness')"
                    ).fetchone()
                else:
                    snapshot_count = conn.execute(
                        "SELECT COUNT(*) AS count FROM pragma_table_info('execution_runs') "
                        "WHERE name IN ('approved_decision_id', 'target_policy_version', 'operation_policy_revision', 'request_fingerprint', 'operation_options_json', 'resource_budget_json', 'account_impact_budget_json', 'credential_scope_json', 'snapshot_completeness')"
                    ).fetchone()
                if not snapshot_count or snapshot_count["count"] != len(snapshot_columns):
                    raise ValueError("execution snapshot migration failed postcondition: required columns are absent")
                conn.execute(
                    "INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)",
                    (snapshot_migration_version, utc_now().isoformat()),
                )
            if max_migration_version == snapshot_migration_version:
                return

            # Version 4 binds an execution run's approved decision to the
            # same tenant.  A nullable decision reference is retained for
            # historical runs, but any populated reference must be valid.
            authority_binding_version = 4
            if not conn.execute(
                "SELECT 1 FROM schema_migrations WHERE version = ?",
                (authority_binding_version,),
            ).fetchone():
                orphan = conn.execute(
                    """
                    SELECT r.execution_id
                    FROM execution_runs r
                    LEFT JOIN execution_decisions d
                      ON d.id = r.approved_decision_id
                     AND d.organization_id = r.organization_id
                    WHERE r.approved_decision_id IS NOT NULL AND d.id IS NULL
                    LIMIT 1
                    """
                ).fetchone()
                if orphan:
                    raise ValueError("execution authority migration blocked: orphaned or cross-tenant approved decision reference")
                if not isinstance(self, PostgresDatabaseManager):
                    interrupted = conn.execute(
                        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'execution_runs_legacy_binding'"
                    ).fetchone()
                    if interrupted:
                        replacement = conn.execute(
                            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'execution_runs'"
                        ).fetchone()
                        if not replacement:
                            raise ValueError("execution authority migration recovery blocked: replacement execution_runs table is absent")
                        self._verify_execution_snapshot_schema(conn)
                        recovery_columns = (
                            "execution_id", "request_id", "organization_id", "approved_decision_id",
                            "target_policy_version", "operation_policy_revision", "request_fingerprint",
                            "operation_options_json", "resource_budget_json", "account_impact_budget_json",
                            "credential_scope_json", "snapshot_completeness", "state", "worker_identity",
                            "process_id", "process_group_id", "assurance_state", "coverage_state", "reason_code",
                            "evidence_ref", "correlation_id", "created_at", "started_at", "finished_at",
                        )
                        column_sql = ", ".join(recovery_columns)
                        replacement_rows = conn.execute(
                            f"SELECT {column_sql} FROM execution_runs ORDER BY execution_id"
                        ).fetchall()
                        backup_rows = conn.execute(
                            f"SELECT {column_sql} FROM execution_runs_legacy_binding ORDER BY execution_id"
                        ).fetchall()
                        if [tuple(row) for row in replacement_rows] != [tuple(row) for row in backup_rows]:
                            raise ValueError("execution authority migration recovery blocked: replacement rows differ from backup")
                        conn.execute("DROP INDEX IF EXISTS uq_execution_runs_request")
                        conn.execute("DROP INDEX IF EXISTS idx_execution_runs_scope")
                        conn.execute("DROP TABLE execution_runs_legacy_binding")
                if isinstance(self, PostgresDatabaseManager):
                    parent_keys = conn.execute("""
                        SELECT i.indexrelid
                        FROM pg_index i
                        JOIN pg_class t ON t.oid = i.indrelid
                        JOIN pg_namespace n ON n.oid = t.relnamespace
                        JOIN LATERAL unnest(i.indkey) WITH ORDINALITY AS k(attnum, ordinality) ON TRUE
                        JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = k.attnum
                        WHERE t.relname = 'execution_decisions' AND n.nspname = current_schema()
                          AND i.indisunique AND i.indisvalid AND i.indisready AND i.indpred IS NULL
                        GROUP BY i.indexrelid
                        HAVING array_agg(a.attname::text ORDER BY k.ordinality) = ARRAY['id', 'organization_id']::text[]
                    """).fetchall()
                    if not parent_keys:
                        duplicate = conn.execute("SELECT id, organization_id, COUNT(*) AS count FROM execution_decisions GROUP BY id, organization_id HAVING COUNT(*) > 1 LIMIT 1").fetchone()
                        if duplicate:
                            raise ValueError("execution authority migration blocked: duplicate decision parent tuples require audited reconciliation")
                        conn.execute("CREATE UNIQUE INDEX uq_execution_decisions_id_org ON execution_decisions(id, organization_id)")
                    elif len(parent_keys) > 1:
                        raise ValueError("execution authority migration blocked: duplicate decision parent keys require audited reconciliation")
                else:
                    parent_keys = []
                    for index in conn.execute("PRAGMA index_list(execution_decisions)").fetchall():
                        if index["unique"] and not index["partial"]:
                            columns = conn.execute(f"PRAGMA index_info('{str(index['name']).replace(chr(39), chr(39) + chr(39))}')").fetchall()
                            if [row["name"] for row in sorted(columns, key=lambda value: value["seqno"])] == ["id", "organization_id"]:
                                parent_keys.append(index["name"])
                    if len(parent_keys) > 1 and "uq_execution_decisions_id_org" in parent_keys:
                        conn.execute("DROP INDEX uq_execution_decisions_id_org")
                        parent_keys.remove("uq_execution_decisions_id_org")
                    if not parent_keys:
                        duplicate = conn.execute("SELECT id, organization_id, COUNT(*) AS count FROM execution_decisions GROUP BY id, organization_id HAVING COUNT(*) > 1 LIMIT 1").fetchone()
                        if duplicate:
                            raise ValueError("execution authority migration blocked: duplicate decision parent tuples require audited reconciliation")
                        conn.execute("CREATE UNIQUE INDEX uq_execution_decisions_id_org ON execution_decisions(id, organization_id)")
                    elif len(parent_keys) > 1:
                        raise ValueError("execution authority migration blocked: duplicate decision parent keys require audited reconciliation")
                conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS uq_execution_runs_request ON execution_runs(request_id, organization_id)")
                if isinstance(self, PostgresDatabaseManager):
                    existing = conn.execute("""
                        SELECT COUNT(*) AS count
                        FROM pg_constraint c
                        JOIN pg_class t ON t.oid = c.conrelid
                        JOIN pg_class pt ON pt.oid = c.confrelid
                        JOIN pg_namespace n ON n.oid = t.relnamespace
                        JOIN pg_namespace pn ON pn.oid = pt.relnamespace
                        WHERE t.relname = 'execution_runs' AND pt.relname = 'execution_decisions'
                          AND n.nspname = current_schema() AND pn.nspname = current_schema()
                          AND c.contype = 'f' AND c.convalidated
                          AND c.conkey = ARRAY[
                              (SELECT attnum FROM pg_attribute WHERE attrelid = t.oid AND attname = 'approved_decision_id'),
                              (SELECT attnum FROM pg_attribute WHERE attrelid = t.oid AND attname = 'organization_id')]
                          AND c.confkey = ARRAY[
                              (SELECT attnum FROM pg_attribute WHERE attrelid = pt.oid AND attname = 'id'),
                              (SELECT attnum FROM pg_attribute WHERE attrelid = pt.oid AND attname = 'organization_id')]
                    """).fetchone()
                    if not existing or existing["count"] == 0:
                        conn.execute(
                            "ALTER TABLE execution_runs ADD CONSTRAINT execution_runs_decision_tenant_fk "
                            "FOREIGN KEY (approved_decision_id, organization_id) "
                            "REFERENCES execution_decisions(id, organization_id)"
                        )
                    elif existing["count"] != 1:
                        raise ValueError("execution authority migration blocked: duplicate decision tenant foreign keys")
                else:
                    foreign_keys = conn.execute("PRAGMA foreign_key_list(execution_runs)").fetchall()
                    grouped = {}
                    for row in foreign_keys:
                        grouped.setdefault(row["id"], []).append(row)
                    has_binding = any(
                        len(rows) == 2
                        and sorted((row["seq"], row["from"], row["to"]) for row in rows)
                        == [(0, "approved_decision_id", "id"), (1, "organization_id", "organization_id")]
                        and all(row["table"] == "execution_decisions" for row in rows)
                        for rows in grouped.values()
                    )
                    if not has_binding:
                        conn.execute("ALTER TABLE execution_runs RENAME TO execution_runs_legacy_binding")
                        conn.execute("""
                            CREATE TABLE execution_runs (
                                execution_id TEXT PRIMARY KEY, request_id TEXT NOT NULL,
                                organization_id TEXT NOT NULL, approved_decision_id TEXT,
                                target_policy_version TEXT, operation_policy_revision TEXT,
                                request_fingerprint TEXT, operation_options_json TEXT NOT NULL DEFAULT '{}',
                                resource_budget_json TEXT NOT NULL DEFAULT '{}',
                                account_impact_budget_json TEXT NOT NULL DEFAULT '{}',
                                credential_scope_json TEXT NOT NULL DEFAULT '{}',
                                snapshot_completeness TEXT NOT NULL DEFAULT 'LEGACY_SNAPSHOT_UNAVAILABLE',
                                state TEXT NOT NULL, worker_identity TEXT, process_id INTEGER,
                                process_group_id TEXT, assurance_state TEXT NOT NULL,
                                coverage_state TEXT NOT NULL, reason_code TEXT, evidence_ref TEXT,
                                correlation_id TEXT, created_at TEXT NOT NULL, started_at TEXT,
                                finished_at TEXT,
                                FOREIGN KEY (request_id, organization_id) REFERENCES execution_requests(id, organization_id),
                                FOREIGN KEY (approved_decision_id, organization_id) REFERENCES execution_decisions(id, organization_id),
                                FOREIGN KEY (organization_id) REFERENCES organizations(id)
                            )
                        """)
                        recovery_columns = (
                            "execution_id", "request_id", "organization_id", "approved_decision_id",
                            "target_policy_version", "operation_policy_revision", "request_fingerprint",
                            "operation_options_json", "resource_budget_json", "account_impact_budget_json",
                            "credential_scope_json", "snapshot_completeness", "state", "worker_identity",
                            "process_id", "process_group_id", "assurance_state", "coverage_state", "reason_code",
                            "evidence_ref", "correlation_id", "created_at", "started_at", "finished_at",
                        )
                        copy_columns = ", ".join(recovery_columns)
                        conn.execute(
                            f"INSERT INTO execution_runs ({copy_columns}) SELECT {copy_columns} FROM execution_runs_legacy_binding"
                        )
                        conn.execute("DROP TABLE execution_runs_legacy_binding")
                        conn.execute("CREATE UNIQUE INDEX uq_execution_runs_request ON execution_runs(request_id, organization_id)")
                        conn.execute("CREATE INDEX idx_execution_runs_scope ON execution_runs(organization_id, state, created_at)")
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_execution_runs_scope ON execution_runs(organization_id, state, created_at)"
                )
                conn.execute(
                    "INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)",
                    (authority_binding_version, utc_now().isoformat()),
                )
            if max_migration_version == authority_binding_version:
                return

            # Version 5 removes only migration-owned objects from the
            # superseded duplicate-producing v4 implementation.
            cleanup_version = 5
            if not conn.execute("SELECT 1 FROM schema_migrations WHERE version = ?", (cleanup_version,)).fetchone():
                if isinstance(self, PostgresDatabaseManager):
                    # The parent key is defined by the canonical table
                    # constraint.  Remove only the migration-owned duplicate
                    # index; never remove the constraint-backed key.
                    conn.execute("DROP INDEX IF EXISTS uq_execution_requests_id_org")
                    duplicate_parent = conn.execute("""
                        SELECT COUNT(*) AS count FROM pg_index i
                        JOIN pg_class t ON t.oid = i.indrelid
                        JOIN pg_namespace n ON n.oid = t.relnamespace
                        JOIN LATERAL unnest(i.indkey) WITH ORDINALITY AS k(attnum, ordinality) ON TRUE
                        JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = k.attnum
                        WHERE t.relname = 'execution_decisions' AND n.nspname = current_schema()
                          AND i.indisunique AND i.indisvalid AND i.indisready AND i.indpred IS NULL
                        GROUP BY i.indexrelid
                        HAVING array_agg(a.attname::text ORDER BY k.ordinality) = ARRAY['id', 'organization_id']::text[]
                    """).fetchall()
                    if len(duplicate_parent) > 1:
                        conn.execute("DROP INDEX IF EXISTS uq_execution_decisions_id_org")
                    duplicate_fk = conn.execute("SELECT COUNT(*) AS count FROM pg_constraint WHERE conrelid = 'execution_runs'::regclass AND confrelid = 'execution_decisions'::regclass AND conname = 'execution_runs_decision_tenant_fk'").fetchone()
                    if duplicate_fk and duplicate_fk["count"] and len(duplicate_parent) > 1:
                        conn.execute("ALTER TABLE execution_runs DROP CONSTRAINT execution_runs_decision_tenant_fk")
                else:
                    legacy_request_index = conn.execute("SELECT 1 FROM pragma_index_list('execution_requests') WHERE name = 'uq_execution_requests_id_org'").fetchone()
                    if legacy_request_index:
                        metadata = conn.execute("PRAGMA index_list(execution_requests)").fetchall()
                        known = next(row for row in metadata if row["name"] == "uq_execution_requests_id_org")
                        columns = conn.execute("PRAGMA index_info('uq_execution_requests_id_org')").fetchall()
                        if not known["unique"] or known["partial"] or [row["name"] for row in sorted(columns, key=lambda value: value["seqno"])] != ["id", "organization_id"]:
                            raise ValueError("execution request parent index cleanup found an ambiguous migration-owned artifact")
                        conn.execute("DROP INDEX uq_execution_requests_id_org")
                    parent_keys = []
                    for index in conn.execute("PRAGMA index_list(execution_decisions)").fetchall():
                        if index["unique"] and not index["partial"]:
                            columns = conn.execute(f"PRAGMA index_info('{str(index['name']).replace(chr(39), chr(39) + chr(39))}')").fetchall()
                            if [row["name"] for row in sorted(columns, key=lambda value: value["seqno"])] == ["id", "organization_id"]:
                                parent_keys.append(index["name"])
                    if len(parent_keys) > 1 and "uq_execution_decisions_id_org" in parent_keys:
                        conn.execute("DROP INDEX uq_execution_decisions_id_org")
                        parent_keys.remove("uq_execution_decisions_id_org")
                    if not parent_keys:
                        conn.execute("CREATE UNIQUE INDEX uq_execution_decisions_id_org ON execution_decisions(id, organization_id)")
                    elif len(parent_keys) > 1:
                        raise ValueError("execution authority cleanup blocked: unknown duplicate decision parent keys require audited reconciliation")
                conn.execute("INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)", (cleanup_version, utc_now().isoformat()))
            if max_migration_version == cleanup_version:
                return

            # Version 6 records the formerly generic execution-plane column
            # upgrades as one auditable, idempotent migration.
            execution_columns_version = 6
            execution_columns = {
                "execution_decisions": {
                    "consumed_at": "TEXT",
                    "claim_owner": "TEXT",
                    "claim_expires_at": "TEXT",
                    "started_at": "TEXT",
                    "claim_token": "TEXT",
                },
                "execution_requests": {"approval_idempotency_key": "TEXT"},
            }
            if not conn.execute("SELECT 1 FROM schema_migrations WHERE version = ?", (execution_columns_version,)).fetchone():
                for table, columns in execution_columns.items():
                    for column, definition in columns.items():
                        if isinstance(self, PostgresDatabaseManager):
                            exists = conn.execute(
                                "SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = ? AND column_name = ?",
                                (table, column),
                            ).fetchone()
                        else:
                            exists = conn.execute(
                                f"SELECT 1 FROM pragma_table_info('{table}') WHERE name = ?", (column,)
                            ).fetchone()
                        if not exists:
                            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
                        if isinstance(self, PostgresDatabaseManager):
                            verified = conn.execute(
                                "SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = ? AND column_name = ?",
                                (table, column),
                            ).fetchone()
                        else:
                            verified = conn.execute(
                                f"SELECT 1 FROM pragma_table_info('{table}') WHERE name = ?", (column,)
                            ).fetchone()
                        if not verified:
                            raise RuntimeError(f"execution schema migration v6 failed postcondition for {table}.{column}")
                conn.execute("INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)", (execution_columns_version, utc_now().isoformat()))
            if max_migration_version == execution_columns_version:
                return

            dispatch_version = 7
            if not conn.execute("SELECT 1 FROM schema_migrations WHERE version = ?", (dispatch_version,)).fetchone():
                exists = conn.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'execution_dispatch_intents'").fetchone() if not isinstance(self, PostgresDatabaseManager) else conn.execute("SELECT 1 FROM information_schema.tables WHERE table_schema = current_schema() AND table_name = 'execution_dispatch_intents'").fetchone()
                if not exists:
                    conn.execute("""CREATE TABLE execution_dispatch_intents (
                        execution_id TEXT NOT NULL PRIMARY KEY, organization_id TEXT NOT NULL,
                        state TEXT NOT NULL DEFAULT 'PENDING' CHECK (state IN ('PENDING', 'CLAIMED', 'COMPLETED', 'FAILED', 'BLOCKED')),
                        attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
                        created_at TEXT NOT NULL, claimed_at TEXT, completed_at TEXT, last_error TEXT,
                        FOREIGN KEY (execution_id, organization_id) REFERENCES execution_runs(execution_id, organization_id),
                        FOREIGN KEY (organization_id) REFERENCES organizations(id)
                    )""")
                conn.execute("INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)", (dispatch_version, utc_now().isoformat()))
            if max_migration_version == dispatch_version:
                return

            dispatch_binding_version = 8
            if not conn.execute("SELECT 1 FROM schema_migrations WHERE version = ?", (dispatch_binding_version,)).fetchone():
                # The composite parent key is required before SQLite will validate
                # the tenant-bound foreign key during the compatibility rebuild.
                if isinstance(self, PostgresDatabaseManager):
                    parent_key = conn.execute("""SELECT COUNT(*) AS count FROM pg_index i JOIN pg_class t ON t.oid=i.indrelid
                        JOIN pg_namespace n ON n.oid=t.relnamespace JOIN unnest(i.indkey) WITH ORDINALITY k(attnum,ord) ON TRUE
                        JOIN pg_attribute a ON a.attrelid=t.oid AND a.attnum=k.attnum
                        WHERE n.nspname=current_schema() AND t.relname='execution_runs' AND i.indisunique AND i.indpred IS NULL AND i.indisvalid AND i.indisready
                        GROUP BY i.indexrelid HAVING array_agg(a.attname::text ORDER BY k.ord)=ARRAY['execution_id','organization_id']::text[]""").fetchall()
                    if not parent_key:
                        conn.execute("CREATE UNIQUE INDEX execution_runs_execution_org_uq ON execution_runs(execution_id, organization_id)")
                else:
                    parent_key = []
                    for index in conn.execute("PRAGMA index_list(execution_runs)").fetchall():
                        if index["unique"] and not index["partial"]:
                            columns = conn.execute(f"PRAGMA index_info('{str(index['name']).replace(chr(39), chr(39) + chr(39))}')").fetchall()
                            if [row["name"] for row in sorted(columns, key=lambda value: value["seqno"])] == ["execution_id", "organization_id"]:
                                parent_key.append(index)
                    if not parent_key:
                        conn.execute("CREATE UNIQUE INDEX execution_runs_execution_org_uq ON execution_runs(execution_id, organization_id)")
                bad = conn.execute("""SELECT i.execution_id FROM execution_dispatch_intents i
                    LEFT JOIN execution_runs r ON r.execution_id=i.execution_id AND r.organization_id=i.organization_id
                    WHERE r.execution_id IS NULL LIMIT 1""").fetchone()
                if bad:
                    raise RuntimeError("dispatch migration v8 refused orphan or cross-tenant intent")
                if isinstance(self, PostgresDatabaseManager):
                    for column in ("claimed_by", "claim_token", "lease_expires_at", "correlation_id"):
                        if not conn.execute("SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='execution_dispatch_intents' AND column_name=?", (column,)).fetchone():
                            conn.execute(f"ALTER TABLE execution_dispatch_intents ADD COLUMN {column} TEXT")
                    fk_count = conn.execute("""SELECT COUNT(DISTINCT c.oid) AS count FROM pg_constraint c
                        JOIN pg_class t ON t.oid=c.conrelid JOIN pg_class p ON p.oid=c.confrelid
                        JOIN pg_namespace n ON n.oid=t.relnamespace
                        WHERE n.nspname=current_schema() AND t.relname='execution_dispatch_intents' AND p.relname='execution_runs'
                        AND c.contype='f' AND c.convalidated AND c.conkey=ARRAY[(SELECT attnum FROM pg_attribute WHERE attrelid=t.oid AND attname='execution_id'),(SELECT attnum FROM pg_attribute WHERE attrelid=t.oid AND attname='organization_id')]
                        AND c.confkey=ARRAY[(SELECT attnum FROM pg_attribute WHERE attrelid=p.oid AND attname='execution_id'),(SELECT attnum FROM pg_attribute WHERE attrelid=p.oid AND attname='organization_id')]""").fetchone()
                    if int(fk_count["count"]) == 0:
                        conn.execute("ALTER TABLE execution_dispatch_intents ADD CONSTRAINT execution_dispatch_intents_run_org_fkey FOREIGN KEY (execution_id, organization_id) REFERENCES execution_runs(execution_id, organization_id)")
                    elif int(fk_count["count"]) > 1:
                        raise RuntimeError("dispatch migration v8 found duplicate tenant-bound foreign keys")
                else:
                    # Never delete an ambiguous recovery artifact.  A prior
                    # interrupted migration must be reconciled explicitly.
                    if conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='execution_dispatch_intents_v8'").fetchone():
                        raise RuntimeError("dispatch migration v8 found an existing recovery artifact; manual reconciliation required")
                    existing_columns = {row["name"] for row in conn.execute("PRAGMA table_info(execution_dispatch_intents)").fetchall()}
                    partial_columns = existing_columns & {"claimed_by", "claim_token", "lease_expires_at", "correlation_id"}
                    if partial_columns:
                        raise RuntimeError(f"dispatch migration v8 found partial lease columns: {sorted(partial_columns)!r}")
                    conn.execute("""CREATE TABLE execution_dispatch_intents_v8 (
                        execution_id TEXT NOT NULL PRIMARY KEY, organization_id TEXT NOT NULL,
                        state TEXT NOT NULL DEFAULT 'PENDING' CHECK (state IN ('PENDING','CLAIMED','COMPLETED','FAILED','BLOCKED')),
                        attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
                        created_at TEXT NOT NULL, claimed_at TEXT, completed_at TEXT, last_error TEXT,
                        claimed_by TEXT, claim_token TEXT, lease_expires_at TEXT, correlation_id TEXT,
                        FOREIGN KEY (execution_id, organization_id) REFERENCES execution_runs(execution_id, organization_id),
                        FOREIGN KEY (organization_id) REFERENCES organizations(id)
                    )""")
                    conn.execute("""INSERT INTO execution_dispatch_intents_v8
                        (execution_id,organization_id,state,attempt_count,created_at,claimed_at,completed_at,last_error)
                        SELECT execution_id,organization_id,state,attempt_count,created_at,claimed_at,completed_at,last_error
                        FROM execution_dispatch_intents""")
                    conn.execute("DROP TABLE execution_dispatch_intents")
                    conn.execute("ALTER TABLE execution_dispatch_intents_v8 RENAME TO execution_dispatch_intents")
                conn.execute("INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)", (dispatch_binding_version, utc_now().isoformat()))
            if max_migration_version == dispatch_binding_version:
                return

            self._verify_execution_snapshot_schema(conn)
            self._verify_execution_authority_binding_schema(conn)
            self._verify_execution_compatibility_schema(conn)
            self._verify_execution_dispatch_schema(conn)

            # Migration rows prove history, not present-day schema integrity.
            # Recheck the safety-critical execution invariants on every startup
            # so post-migration drift fails closed instead of being accepted.
            if isinstance(self, PostgresDatabaseManager):
                run_index = conn.execute("""
                    SELECT array_agg(a.attname ORDER BY key_cols.ordinality) AS columns,
                           am.amname AS access_method,
                           x.indnkeyatts,
                           x.indnatts
                    FROM pg_class i
                    JOIN pg_index x ON x.indexrelid = i.oid
                    JOIN pg_class t ON t.oid = x.indrelid
                    JOIN pg_am am ON am.oid = i.relam
                    JOIN pg_namespace n ON n.oid = t.relnamespace
                    JOIN unnest(x.indkey) WITH ORDINALITY AS key_cols(attnum, ordinality) ON TRUE
                    JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = key_cols.attnum
                    WHERE i.relname = 'uq_execution_runs_request'
                      AND t.relname = 'execution_runs' AND n.nspname = current_schema()
                      AND x.indisunique AND x.indpred IS NULL AND x.indisvalid AND x.indisready
                    GROUP BY i.oid, am.amname, x.indnkeyatts, x.indnatts
                """).fetchall()
                if not any(
                    list(row["columns"] or []) == ["request_id", "organization_id"]
                    and row["access_method"] == "btree"
                    and row["indnkeyatts"] == 2
                    and row["indnatts"] == 2
                    for row in run_index
                ):
                    raise ValueError("execution schema health check failed: unique execution-run request index is absent")
                parent_index = conn.execute("""
                    SELECT array_agg(a.attname ORDER BY key_cols.ordinality) AS columns,
                           am.amname AS access_method,
                           x.indnkeyatts,
                           x.indnatts
                    FROM pg_class i
                    JOIN pg_index x ON x.indexrelid = i.oid
                    JOIN pg_class t ON t.oid = x.indrelid
                    JOIN pg_am am ON am.oid = i.relam
                    JOIN pg_namespace n ON n.oid = t.relnamespace
                    JOIN unnest(x.indkey) WITH ORDINALITY AS key_cols(attnum, ordinality) ON TRUE
                    JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = key_cols.attnum
                    WHERE t.relname = 'execution_requests' AND n.nspname = current_schema()
                      AND x.indisunique AND x.indpred IS NULL AND x.indisvalid AND x.indisready
                    GROUP BY i.oid, am.amname, x.indnkeyatts, x.indnatts
                """).fetchall()
                if not any(
                    list(row["columns"] or []) == ["id", "organization_id"]
                    and row["access_method"] == "btree"
                    and row["indnkeyatts"] == 2
                    and row["indnatts"] == 2
                    for row in parent_index
                ):
                    raise ValueError("execution schema health check failed: tenant parent unique key is absent")
                final_constraints = conn.execute("""
                    SELECT array_agg(a.attname ORDER BY local_cols.ordinality) AS local_columns,
                           array_agg(pa.attname ORDER BY local_cols.ordinality) AS parent_columns,
                           c.convalidated
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
                    GROUP BY c.conname, c.convalidated
                """).fetchall()
                exact = [
                    row for row in final_constraints
                    if list(row["local_columns"] or []) == ["request_id", "organization_id"]
                    and list(row["parent_columns"] or []) == ["id", "organization_id"]
                    and row["convalidated"]
                ]
                if len(exact) != 1:
                    raise ValueError("execution schema health check failed: expected exactly one composite tenant foreign key")
                legacy_constraints = conn.execute("""
                    SELECT COUNT(*) AS count
                    FROM pg_constraint c
                    JOIN pg_class t ON t.oid = c.conrelid
                    JOIN pg_class pt ON pt.oid = c.confrelid
                    JOIN pg_namespace n ON n.oid = t.relnamespace
                    JOIN pg_namespace pn ON pn.oid = pt.relnamespace
                    JOIN unnest(c.conkey) AS local_cols(attnum) ON TRUE
                    JOIN unnest(c.confkey) AS parent_cols(attnum) ON TRUE
                    WHERE t.relname = 'execution_runs' AND pt.relname = 'execution_requests'
                      AND n.nspname = current_schema() AND pn.nspname = current_schema()
                      AND c.contype = 'f'
                      AND array_length(c.conkey, 1) = 1 AND array_length(c.confkey, 1) = 1
                      AND (SELECT attname FROM pg_attribute WHERE attrelid = t.oid AND attnum = local_cols.attnum) = 'request_id'
                      AND (SELECT attname FROM pg_attribute WHERE attrelid = pt.oid AND attnum = parent_cols.attnum) = 'id'
                """).fetchone()
                if legacy_constraints and legacy_constraints["count"]:
                    raise ValueError("execution schema health check failed: legacy request-only foreign key remains")
            else:
                run_indexes = conn.execute("PRAGMA index_list(execution_runs)").fetchall()
                run_index_valid = False
                for index in run_indexes:
                    if index["unique"] and index["name"] == "uq_execution_runs_request" and not index["partial"]:
                        index_name = str(index["name"]).replace("'", "''")
                        columns = conn.execute(f"PRAGMA index_info('{index_name}')").fetchall()
                        run_index_valid = [column["name"] for column in sorted(columns, key=lambda value: value["seqno"])] == ["request_id", "organization_id"]
                        break
                if not run_index_valid:
                    raise ValueError("execution schema health check failed: unique execution-run request index is absent")
                parent_index_valid = False
                for index in conn.execute("PRAGMA index_list(execution_requests)").fetchall():
                    if index["unique"] and not index["partial"]:
                        index_name = str(index["name"]).replace("'", "''")
                        columns = conn.execute(f"PRAGMA index_info('{index_name}')").fetchall()
                        if [column["name"] for column in sorted(columns, key=lambda value: value["seqno"])] == ["id", "organization_id"]:
                            parent_index_valid = True
                            break
                if not parent_index_valid:
                    raise ValueError("execution schema health check failed: tenant parent unique key is absent")
                health_rows = conn.execute("PRAGMA foreign_key_list(execution_runs)").fetchall()
                health_groups = {}
                for row in health_rows:
                    health_groups.setdefault(row["id"], []).append(row)
                if not any(
                    len(rows) == 2
                    and sorted((row["seq"], row["from"], row["to"]) for row in rows)
                    == [(0, "request_id", "id"), (1, "organization_id", "organization_id")]
                    and all(row["table"] == "execution_requests" for row in rows)
                    for rows in health_groups.values()
                ):
                    raise ValueError("execution schema health check failed: composite tenant foreign key is absent")

            if getattr(self, "_migration_attempt_id", None) and not getattr(self, "_migration_coordinator_active", False):
                conn.execute("""INSERT INTO schema_migration_events
                (event_id,attempt_id,migration_version,migration_id,migration_name,registry_revision,event_sequence,event_type,event_at,backend,schema_name,
                 previous_schema_version,target_schema_version,migration_checksum,runner_identity,transaction_context_id,
                 context_json,rollback_status)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (
                f"event-{uuid.uuid4().hex}", self._migration_attempt_id, self._migration_spec.version,
                self._migration_spec.migration_id, self._migration_spec.name, self._migration_spec.registry_revision,
                2, "SUCCEEDED", utc_now().isoformat(), "POSTGRESQL" if isinstance(self, PostgresDatabaseManager) else "SQLITE",
                self._migration_schema_name, 7, 8,
                self._migration_spec.checksum, "database-startup", self._migration_transaction_id, "{}", "NOT_APPLICABLE"))

    # ========================================================================
    # 1. System Bootstrap & Authentication Operations
    # ========================================================================

    def is_initialized(self) -> bool:
        """Returns True if the system already contains at least one administrator user."""
        with self._connection_scope() as conn:
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) as cnt FROM users WHERE role = 'ADMIN'")
            row = cur.fetchone()
            return bool(row and row["cnt"] > 0)

    def bootstrap_system(
        self,
        admin_username: str,
        admin_email: str,
        hashed_password: str,
        org_name: str = "Default Organization",
    ) -> Tuple[UserProfile, Organization]:
        """
        Executes one-time first-run setup.
        Creates initial Organization and Administrator account.
        Raises ValueError if already initialized.
        """
        org_id = f"org-{uuid.uuid4().hex[:8]}"
        user_id = f"usr-{uuid.uuid4().hex[:8]}"
        now_str = utc_now().isoformat()

        with self._connection_scope() as conn:
            # Serialize the check and the first writes in one transaction.
            # The API-level status check is only an optimization; this lock is
            # the authoritative one-time-bootstrap boundary across threads,
            # processes, and pooled PostgreSQL connections.
            if isinstance(conn, sqlite3.Connection):
                conn.execute("BEGIN IMMEDIATE")
            elif isinstance(conn, _PostgresConnection):
                conn.execute(
                    "SELECT pg_advisory_xact_lock(hashtext(?))",
                    ("cyberassess:bootstrap",),
                )
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) AS cnt FROM users WHERE role = 'ADMIN'")
            row = cur.fetchone()
            if row and row["cnt"] > 0:
                raise ValueError("System has already been initialized with an administrator.")

            # 1. Create Default Organization
            conn.execute(
                "INSERT INTO organizations (id, name, slug, created_at, is_active) VALUES (?, ?, ?, ?, 1)",
                (org_id, org_name, "default", now_str),
            )

            # 2. Create Administrator User
            conn.execute(
                "INSERT INTO users (id, username, email, hashed_password, role, organization_id, is_active, created_at) VALUES (?, ?, ?, ?, 'ADMIN', ?, 1, ?)",
                (user_id, admin_username, admin_email, hashed_password, org_id, now_str),
            )

            # 3. Record the bootstrap event through the same chained audit
            # writer used by every later privileged operation.  Raw insertion
            # would omit sequence/hash fields and bypass request correlation.
            self._insert_audit_event_conn(
                conn,
                AuditEvent(
                    id=f"aud-{uuid.uuid4().hex[:12]}",
                    timestamp=utc_now(),
                    actor=admin_username,
                    organization_id=org_id,
                    action=AuditAction.BOOTSTRAP_COMPLETE,
                    object_type="system",
                    object_id=user_id,
                    result="SUCCESS",
                    details={"initial_admin": admin_username, "org_name": org_name},
                ),
            )

        user = UserProfile(
            id=user_id,
            username=admin_username,
            email=admin_email,
            role=UserRole.ADMIN,
            organization_id=org_id,
            created_at=utc_now(),
        )
        org = Organization(id=org_id, name=org_name, slug="default", created_at=utc_now())
        return user, org

    def verify_api_key_hash(self, key_hash: str) -> Tuple[Optional[APIKeyRecord], Optional[UserProfile]]:
        """Verifies an incoming API Key hash against the database and returns the bound UserProfile."""
        with self._connection_scope() as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM api_keys WHERE key_hash = ? AND (revoked_at IS NULL) AND (status = 'ACTIVE')", (key_hash,))
            row = cur.fetchone()
            if not row:
                return None, None

            # Check expiration
            if row["expires_at"]:
                exp_dt = datetime.fromisoformat(row["expires_at"])
                if utc_now() >= exp_dt:
                    return None, None

            key_record = APIKeyRecord(
                key_id=row["key_id"],
                key_hash=row["key_hash"],
                organization_id=row["organization_id"],
                user_id=row["user_id"],
                name=row["name"],
                scopes=json.loads(row["scopes_json"]),
                status=row["status"] if "status" in row.keys() else "ACTIVE",
                created_at=datetime.fromisoformat(row["created_at"]),
                expires_at=datetime.fromisoformat(row["expires_at"]) if row["expires_at"] else None,
                revoked_at=datetime.fromisoformat(row["revoked_at"]) if row["revoked_at"] else None,
                last_used_at=datetime.fromisoformat(row["last_used_at"]) if row["last_used_at"] else None,
            )

            # Update last_used_at
            conn.execute("UPDATE api_keys SET last_used_at = ? WHERE key_id = ?", (utc_now().isoformat(), row["key_id"]))

            # A user-bound key must remain bound to the current authoritative
            # identity. Never let a stale key preserve access after the user
            # is deactivated or moved to another organization.
            if row["user_id"]:
                cur.execute("SELECT * FROM users WHERE id = ?", (row["user_id"],))
                bound_user = cur.fetchone()
                if (
                    not bound_user
                    or not bool(bound_user["is_active"])
                    or bound_user["organization_id"] != row["organization_id"]
                ):
                    return None, None
                principal_type = PrincipalType.TENANT_PRINCIPAL
                if "principal_type" in bound_user.keys():
                    try:
                        principal_type = PrincipalType(bound_user["principal_type"])
                    except ValueError:
                        return None, None
                user_profile = UserProfile(
                    id=bound_user["id"],
                    username=bound_user["username"],
                    email=bound_user["email"],
                    role=UserRole(bound_user["role"]),
                    principal_type=principal_type,
                    organization_id=bound_user["organization_id"],
                    is_active=True,
                    created_at=datetime.fromisoformat(bound_user["created_at"]),
                )
            else:
                user_profile = UserProfile(
                    id=f"usr-key-{row['key_id']}",
                    username=f"apikey-{row['name']}",
                    email=f"apikey-{row['name']}@cyberassess.local",
                    role=UserRole.SECURITY_ANALYST,
                    organization_id=row["organization_id"],
                )
            return key_record, user_profile

    def get_user_by_id(self, user_id: str) -> Optional[UserProfile]:
        """Load the current authoritative identity state for a bearer-token subject."""
        with self._connection_scope() as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
            row = cur.fetchone()
            if not row:
                return None
            return UserProfile(
                id=row["id"],
                username=row["username"],
                email=row["email"],
                role=UserRole(row["role"]),
                principal_type=PrincipalType(row["principal_type"])
                if "principal_type" in row.keys() and row["principal_type"]
                else PrincipalType.TENANT_PRINCIPAL,
                organization_id=row["organization_id"],
                is_active=bool(row["is_active"]),
                created_at=datetime.fromisoformat(row["created_at"]),
            )

    def revoke_api_key(self, key_id: str, organization_id: Optional[str] = None) -> bool:
        """Revokes an API Key and updates its status to REVOKED."""
        with self._connection_scope() as conn:
            query = "UPDATE api_keys SET revoked_at = ?, status = 'REVOKED' WHERE key_id = ?"
            params = [utc_now().isoformat(), key_id]
            if organization_id:
                query += " AND organization_id = ?"
                params.append(organization_id)
            cur = conn.execute(query, params)
            return cur.rowcount > 0

    def revoke_token(self, jti: str, token_hash: Optional[str] = None, expires_at: Optional[str] = None) -> None:
        """Revokes a JWT token by jti identifier."""
        with self._connection_scope() as conn:
            conn.execute(
                """
                INSERT INTO revoked_tokens (jti, token_hash, revoked_at, expires_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(jti) DO UPDATE SET
                    token_hash = excluded.token_hash,
                    revoked_at = excluded.revoked_at,
                    expires_at = excluded.expires_at
                """,
                (jti, token_hash, utc_now().isoformat(), expires_at),
            )

    def is_token_revoked(self, jti: str) -> bool:
        """Checks if a JWT token has been revoked in the database."""
        with self._connection_scope() as conn:
            cur = conn.cursor()
            cur.execute("SELECT 1 FROM revoked_tokens WHERE jti = ?", (jti,))
            return bool(cur.fetchone())

    def create_execution_request(self, request: ExecutionRequestRecord) -> Optional[ExecutionRequestRecord]:
        """Persist an idempotent REQUESTED execution record with tenant checks."""
        with self._connection_scope() as conn:
            cur = conn.cursor()
            cur.execute("SELECT id FROM execution_requests WHERE organization_id = ? AND idempotency_key = ?", (request.organization_id, request.idempotency_key))
            existing_row = cur.fetchone()
            existing = self.get_execution_request(existing_row["id"], organization_id=request.organization_id) if existing_row else None
            if existing:
                if existing.idempotency_key == request.idempotency_key and existing.request_fingerprint == request.request_fingerprint:
                    return existing
                raise ValueError("execution request idempotency conflict")
            if request.state != "REQUESTED" or not is_canonical_operation_policy_revision(request.operation_policy_revision):
                raise ValueError("execution request state or policy revision is invalid")
            policy = get_operation_policy(request.tool_id, request.operation_family)
            if policy is None or any(request.operation_options.get(k) != v for k, v in policy.get("required_options", {}).items()):
                raise ValueError("execution request does not conform to the canonical policy row")
            if any(not isinstance(value, int) or value <= 0 for value in request.resource_budget.values()):
                raise ValueError("execution request resource budget is invalid")
            if any(not isinstance(value, int) or value < 0 for value in request.account_impact_budget.values()):
                raise ValueError("execution request account-impact budget is invalid")
            if request.credential_scope.get("provider") != request.operation_options.get("provider"):
                raise ValueError("execution request credential scope is not policy-bound")
            cur = conn.cursor()
            cur.execute("SELECT id FROM organizations WHERE id = ? AND is_active = 1", (request.organization_id,))
            if not cur.fetchone():
                raise ValueError("execution request organization is invalid")
            cur.execute("SELECT id FROM assets WHERE id = ? AND organization_id = ? AND (project_id = ? OR (project_id IS NULL AND ? IS NULL))", (request.asset_id, request.organization_id, request.project_id, request.project_id))
            if not cur.fetchone():
                raise ValueError("execution request asset is not tenant-bound")
            cur.execute("SELECT id FROM users WHERE id = ? AND organization_id = ? AND is_active = 1", (request.requested_by_user_id, request.organization_id))
            if not cur.fetchone():
                raise ValueError("execution request principal is invalid")
            conn.execute(
                """INSERT INTO execution_requests (
                    id, idempotency_key, request_fingerprint, organization_id, project_id,
                    asset_id, target_id, authorization_decision_id, target_policy_version,
                    tool_id, operation_family, operation_options_json, operation_policy_revision,
                    resource_budget_json, account_impact_budget_json, credential_scope_json,
                    requested_by_user_id, state, created_at, expires_at, approved_decision_id, approval_idempotency_key
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (request.id, request.idempotency_key, request.request_fingerprint, request.organization_id, request.project_id,
                 request.asset_id, request.target_id, request.authorization_decision_id, request.target_policy_version,
                 request.tool_id, request.operation_family, json.dumps(request.operation_options, sort_keys=True, separators=(",", ":")),
                 request.operation_policy_revision, json.dumps(request.resource_budget, sort_keys=True, separators=(",", ":")),
                 json.dumps(request.account_impact_budget, sort_keys=True, separators=(",", ":")), json.dumps(request.credential_scope, sort_keys=True, separators=(",", ":")),
                 request.requested_by_user_id, request.state, request.created_at.isoformat(), request.expires_at.isoformat(), None, None),
            )
            self._insert_audit_event_conn(conn, AuditEvent(
                id=f"aud-{uuid.uuid4().hex[:12]}", actor=request.requested_by_user_id,
                organization_id=request.organization_id, action=AuditAction.EXECUTION_REQUESTED,
                object_type="execution_request", object_id=request.id, result="SUCCESS",
                details={"tool_id": request.tool_id, "operation_family": request.operation_family, "request_fingerprint": request.request_fingerprint},
            ))
            return request

    def get_execution_request(self, request_id: str, organization_id: Optional[str] = None) -> Optional[ExecutionRequestRecord]:
        with self._connection_scope() as conn:
            query = "SELECT * FROM execution_requests WHERE id = ?"
            params: List[Any] = [request_id]
            if organization_id is not None:
                query += " AND organization_id = ?"
                params.append(organization_id)
            cur = conn.cursor(); cur.execute(query, params); row = cur.fetchone()
            if not row:
                return None
            return ExecutionRequestRecord(
                id=row["id"], idempotency_key=row["idempotency_key"], request_fingerprint=row["request_fingerprint"],
                organization_id=row["organization_id"], project_id=row["project_id"], asset_id=row["asset_id"],
                target_id=row["target_id"], authorization_decision_id=row["authorization_decision_id"],
                target_policy_version=row["target_policy_version"], tool_id=row["tool_id"], operation_family=row["operation_family"],
                operation_options=json.loads(row["operation_options_json"]), operation_policy_revision=row["operation_policy_revision"],
                resource_budget=json.loads(row["resource_budget_json"]), account_impact_budget=json.loads(row["account_impact_budget_json"]),
                credential_scope=json.loads(row["credential_scope_json"]), requested_by_user_id=row["requested_by_user_id"],
                state=row["state"], created_at=datetime.fromisoformat(row["created_at"]), expires_at=datetime.fromisoformat(row["expires_at"]),
                approved_decision_id=row["approved_decision_id"],
                approval_idempotency_key=row["approval_idempotency_key"] if "approval_idempotency_key" in row.keys() else None,
            )

    def approve_execution_request(
        self, request_id: str, organization_id: str, request_fingerprint: str, approval_idempotency_key: str,
        approver_user_id: str, session_jti: str, worker_identity: str,
    ) -> tuple[str, Optional[str], Optional[str]]:
        """Atomically authorize a request or return an idempotent/conflict result."""
        correlation_id = get_correlation_id()
        if not correlation_id:
            # This is an infrastructure precondition failure, not evidence
            # that the supplied approver identity was authenticated.  The
            # fixed system actor deliberately preserves that distinction.
            rejection_correlation_id = f"corr-{uuid.uuid4().hex}"
            with self._connection_scope() as conn:
                request_row = conn.execute(
                    "SELECT id FROM execution_requests WHERE id = ? AND organization_id = ?",
                    (request_id, organization_id),
                ).fetchone()
                if request_row:
                    self._insert_audit_event_conn(conn, AuditEvent(
                        id=f"aud-{uuid.uuid4().hex[:12]}", actor="system",
                        organization_id=organization_id,
                        action=AuditAction.EXECUTION_AUTHORITY_INVARIANT_FAILED,
                        object_type="execution_request", object_id=request_id, result="FAILURE",
                        correlation_id=rejection_correlation_id,
                        details={"reason_code": "CORRELATION_REQUIRED"},
                    ))
            return "CORRELATION_REQUIRED", None, None
        with self._connection_scope() as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM execution_requests WHERE id = ? AND organization_id = ?", (request_id, organization_id))
            row = cur.fetchone()
            if not row:
                return "NOT_FOUND", None, None
            if row["request_fingerprint"] != request_fingerprint:
                return "CONFLICT", None, None
            if row["state"] == "AUTHORIZED":
                if row["approval_idempotency_key"] != approval_idempotency_key:
                    return "CONFLICT", None, None
                run = cur.execute(
                    "SELECT execution_id FROM execution_runs WHERE request_id = ? AND organization_id = ?",
                    (request_id, organization_id),
                ).fetchone()
                if not run:
                    raise ValueError("authorized execution request has no durable execution run")
                return "REPLAY", row["approved_decision_id"], run["execution_id"]
            if row["state"] != "REQUESTED":
                return "CONFLICT", None, None
            now = utc_now()
            if datetime.fromisoformat(row["expires_at"]) <= now:
                return "EXPIRED", None, None
            cur.execute(
                """SELECT id FROM assets WHERE id = ? AND organization_id = ?
                   AND (project_id = ? OR (project_id IS NULL AND ? IS NULL))
                   AND active_probing_granted = 1""",
                (row["asset_id"], organization_id, row["project_id"], row["project_id"]),
            )
            if not cur.fetchone():
                return "DENIED", None, None
            cur.execute("SELECT id FROM users WHERE id = ? AND organization_id = ? AND role = 'ADMIN' AND is_active = 1", (approver_user_id, organization_id))
            if not cur.fetchone() or not session_jti or not worker_identity:
                return "DENIED", None, None
            decision_id = f"dec-{uuid.uuid4().hex[:16]}"
            cur.execute(
                """UPDATE execution_requests SET state = 'AUTHORIZED', approved_decision_id = ?, approval_idempotency_key = ?
                   WHERE id = ? AND organization_id = ? AND state = 'REQUESTED'""",
                (decision_id, approval_idempotency_key, request_id, organization_id),
            )
            if cur.rowcount != 1:
                return "CONFLICT", None, None
            conn.execute(
                """INSERT INTO execution_decisions (
                    id, organization_id, project_id, asset_id, target_id, authorization_decision_id,
                    target_policy_version, tool_id, operation_family, operation_options_json,
                    operation_policy_revision, approval_state, approver_user_id, session_jti,
                    worker_identity, resource_budget_json, account_impact_budget_json,
                    credential_scope_json, created_at, expires_at, revoked_at, consumed_at
                ) SELECT ?, organization_id, project_id, asset_id, target_id, authorization_decision_id,
                    target_policy_version, tool_id, operation_family, operation_options_json,
                    operation_policy_revision, 'APPROVED', ?, ?, ?, resource_budget_json,
                    account_impact_budget_json, credential_scope_json, ?, expires_at, NULL, NULL
                    FROM execution_requests WHERE id = ? AND organization_id = ?""",
                (decision_id, approver_user_id, session_jti, worker_identity, now.isoformat(), request_id, organization_id),
            )
            execution_id = f"run-{uuid.uuid4().hex[:16]}"
            conn.execute(
                """INSERT INTO execution_runs (
                    execution_id, request_id, organization_id, approved_decision_id,
                    target_policy_version, operation_policy_revision, request_fingerprint,
                    operation_options_json, resource_budget_json, account_impact_budget_json,
                    credential_scope_json, snapshot_completeness, state, worker_identity, assurance_state,
                    coverage_state, correlation_id, created_at
                ) SELECT ?, id, organization_id, ?, target_policy_version,
                    operation_policy_revision, request_fingerprint, operation_options_json,
                    resource_budget_json, account_impact_budget_json, credential_scope_json,
                    'COMPLETE', 'REQUESTED', ?, 'UNVERIFIED', 'UNAVAILABLE', ?, ?
                    FROM execution_requests WHERE id = ? AND organization_id = ?""",
                    (execution_id, decision_id, worker_identity, correlation_id, now.isoformat(), request_id, organization_id),
            )
            conn.execute(
                "INSERT INTO execution_dispatch_intents (execution_id, organization_id, state, attempt_count, created_at) VALUES (?, ?, 'PENDING', 0, ?)",
                (execution_id, organization_id, now.isoformat()),
            )
            self._insert_audit_event_conn(conn, AuditEvent(
                id=f"aud-{uuid.uuid4().hex[:12]}", actor=approver_user_id,
                organization_id=organization_id, action=AuditAction.EXECUTION_AUTHORIZED,
                object_type="execution_request", object_id=request_id, result="SUCCESS",
                details={"decision_id": decision_id, "request_fingerprint": request_fingerprint},
            ))
            self._insert_audit_event_conn(conn, AuditEvent(
                id=f"aud-{uuid.uuid4().hex[:12]}", actor=approver_user_id,
                organization_id=organization_id, action=AuditAction.EXECUTION_RUN_CREATED,
                object_type="execution_run", object_id=execution_id, result="SUCCESS",
                correlation_id=correlation_id,
                details={"request_id": request_id, "state": "REQUESTED"},
            ))
            return "AUTHORIZED", decision_id, execution_id

    def get_execution_run_for_request(self, request_id: str, organization_id: str) -> Optional[dict[str, Any]]:
        """Return one tenant-scoped durable run snapshot for an execution request."""
        with self._connection_scope() as conn:
            row = conn.execute(
                "SELECT execution_id, request_id, organization_id, state, worker_identity, process_id, "
                "process_group_id, assurance_state, coverage_state, reason_code, evidence_ref, "
                "approved_decision_id, target_policy_version, operation_policy_revision, request_fingerprint, "
                "operation_options_json, resource_budget_json, account_impact_budget_json, credential_scope_json, "
                "snapshot_completeness, correlation_id, created_at, started_at, finished_at FROM execution_runs "
                "WHERE request_id = ? AND organization_id = ?",
                (request_id, organization_id),
            ).fetchone()
            if not row:
                return None
            result = dict(row)
            for field in ("operation_options_json", "resource_budget_json", "account_impact_budget_json", "credential_scope_json"):
                result[field.removesuffix("_json")] = json.loads(result.pop(field) or "{}")
            return result

    def create_execution_decision(self, decision: ExecutionDecisionRecord) -> None:
        """Persist one immutable authorization decision transactionally."""
        with self._connection_scope() as conn:
            if decision.approval_state != "APPROVED":
                raise ValueError("only an approved execution decision may be persisted")
            if not is_canonical_operation_policy_revision(decision.operation_policy_revision):
                raise ValueError("execution decision policy revision is not canonical")
            policy = get_operation_policy(decision.tool_id, decision.operation_family)
            if policy is None or any(
                decision.operation_options.get(key) != value
                for key, value in policy.get("required_options", {}).items()
            ):
                raise ValueError("execution decision does not conform to the canonical policy row")
            if any(not isinstance(value, int) or value <= 0 for value in decision.resource_budget.values()):
                raise ValueError("execution decision resource budget is invalid")
            if any(not isinstance(value, int) or value < 0 for value in decision.account_impact_budget.values()):
                raise ValueError("execution decision account-impact budget is invalid")
            if decision.credential_scope.get("provider") != decision.operation_options.get("provider"):
                raise ValueError("execution decision credential scope is not policy-bound")
            cur = conn.cursor()
            cur.execute("SELECT id FROM organizations WHERE id = ? AND is_active = 1", (decision.organization_id,))
            if not cur.fetchone():
                raise ValueError("execution decision organization does not exist or is inactive")
            cur.execute(
                "SELECT id FROM assets WHERE id = ? AND organization_id = ? AND (project_id = ? OR (project_id IS NULL AND ? IS NULL))",
                (decision.asset_id, decision.organization_id, decision.project_id, decision.project_id),
            )
            if not cur.fetchone():
                raise ValueError("execution decision asset is not bound to the authorized tenant/project")
            cur.execute(
                "SELECT id FROM users WHERE id = ? AND organization_id = ? AND role = 'ADMIN' AND is_active = 1",
                (decision.approver_user_id, decision.organization_id),
            )
            if not cur.fetchone():
                raise ValueError("execution decision approver is not an active tenant administrator")
            conn.execute(
                """
                INSERT INTO execution_decisions (
                    id, organization_id, project_id, asset_id, target_id,
                    authorization_decision_id, target_policy_version, tool_id,
                    operation_family, operation_options_json, operation_policy_revision,
                    approval_state, approver_user_id, session_jti, worker_identity,
                    resource_budget_json, account_impact_budget_json, credential_scope_json,
                    created_at, expires_at, revoked_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    decision.id,
                    decision.organization_id,
                    decision.project_id,
                    decision.asset_id,
                    decision.target_id,
                    decision.authorization_decision_id,
                    decision.target_policy_version,
                    decision.tool_id,
                    decision.operation_family,
                    json.dumps(decision.operation_options, sort_keys=True, separators=(",", ":")),
                    decision.operation_policy_revision,
                    decision.approval_state,
                    decision.approver_user_id,
                    decision.session_jti,
                    decision.worker_identity,
                    json.dumps(decision.resource_budget, sort_keys=True, separators=(",", ":")),
                    json.dumps(decision.account_impact_budget, sort_keys=True, separators=(",", ":")),
                    json.dumps(decision.credential_scope, sort_keys=True, separators=(",", ":")),
                    decision.created_at.isoformat(),
                    decision.expires_at.isoformat(),
                    decision.revoked_at.isoformat() if decision.revoked_at else None,
                ),
            )
            self._insert_audit_event_conn(
                conn,
                AuditEvent(
                    id=f"aud-{uuid.uuid4().hex[:12]}", actor=decision.approver_user_id,
                    organization_id=decision.organization_id,
                    action=AuditAction.EXECUTION_DECISION_CREATED,
                    object_type="execution_decision", object_id=decision.id,
                    result="SUCCESS",
                    details={"tool_id": decision.tool_id, "operation_family": decision.operation_family,
                             "asset_id": decision.asset_id, "approval_state": decision.approval_state},
                ),
            )

    def get_execution_decision(self, decision_id: str, organization_id: Optional[str] = None) -> Optional[ExecutionDecisionRecord]:
        """Load an execution decision with an optional mandatory tenant filter."""
        with self._connection_scope() as conn:
            query = "SELECT * FROM execution_decisions WHERE id = ?"
            params: List[Any] = [decision_id]
            if organization_id is not None:
                query += " AND organization_id = ?"
                params.append(organization_id)
            cur = conn.cursor()
            cur.execute(query, params)
            row = cur.fetchone()
            if not row:
                return None
            return ExecutionDecisionRecord(
                id=row["id"], organization_id=row["organization_id"], project_id=row["project_id"],
                asset_id=row["asset_id"], target_id=row["target_id"],
                authorization_decision_id=row["authorization_decision_id"],
                target_policy_version=row["target_policy_version"], tool_id=row["tool_id"],
                operation_family=row["operation_family"], operation_options=json.loads(row["operation_options_json"]),
                operation_policy_revision=row["operation_policy_revision"], approval_state=row["approval_state"],
                approver_user_id=row["approver_user_id"], session_jti=row["session_jti"],
                worker_identity=row["worker_identity"], resource_budget=json.loads(row["resource_budget_json"]),
                account_impact_budget=json.loads(row["account_impact_budget_json"]),
                credential_scope=json.loads(row["credential_scope_json"]),
                created_at=datetime.fromisoformat(row["created_at"]),
                expires_at=datetime.fromisoformat(row["expires_at"]),
                revoked_at=datetime.fromisoformat(row["revoked_at"]) if row["revoked_at"] else None,
                consumed_at=datetime.fromisoformat(row["consumed_at"]) if row["consumed_at"] else None,
                claim_owner=row["claim_owner"] if "claim_owner" in row.keys() else None,
                claim_expires_at=datetime.fromisoformat(row["claim_expires_at"]) if "claim_expires_at" in row.keys() and row["claim_expires_at"] else None,
                started_at=datetime.fromisoformat(row["started_at"]) if "started_at" in row.keys() and row["started_at"] else None,
                claim_token=row["claim_token"] if "claim_token" in row.keys() else None,
            )

    def claim_execution_decision(
        self,
        decision_id: str,
        organization_id: str,
        session_jti: str,
        worker_identity: str,
        policy_revision: str,
        now: Optional[datetime] = None,
    ) -> Optional[ExecutionLeaseClaim]:
        """Atomically reserve one approved decision and return its typed fence."""
        now = now or utc_now()
        with self._connection_scope() as conn:
            cur = conn.execute(
                """
                UPDATE execution_decisions
                SET claim_owner = ?, claim_expires_at = ?, claim_token = ?
                WHERE id = ? AND organization_id = ? AND session_jti = ?
                  AND worker_identity = ? AND operation_policy_revision = ?
                  AND approval_state = 'APPROVED'
                  AND revoked_at IS NULL AND consumed_at IS NULL
                  AND (claim_expires_at IS NULL OR claim_expires_at <= ?)
                  AND expires_at > ?
                """,
                (worker_identity, (now + timedelta(seconds=30)).isoformat(), uuid.uuid4().hex, decision_id, organization_id, session_jti, worker_identity, policy_revision, now.isoformat(), now.isoformat()),
            )
            if cur.rowcount != 1:
                return None
            self._insert_audit_event_conn(
                conn,
                AuditEvent(
                    id=f"aud-{uuid.uuid4().hex[:12]}", actor=worker_identity,
                    organization_id=organization_id,
                    action=AuditAction.EXECUTION_DECISION_CLAIMED,
                    object_type="execution_decision", object_id=decision_id,
                    result="SUCCESS", details={"worker_identity": worker_identity},
                ),
            )
            claim_row = cur.connection.execute("SELECT claim_token, claim_expires_at FROM execution_decisions WHERE id = ? AND organization_id = ?", (decision_id, organization_id)).fetchone()
            return ExecutionLeaseClaim(token=claim_row[0], owner=worker_identity, expires_at=datetime.fromisoformat(claim_row[1])) if claim_row else None

    def mark_execution_decision_started(self, decision_id: str, organization_id: str, worker_identity: str, claim_token: str, now: Optional[datetime] = None) -> bool:
        now = now or utc_now()
        with self._connection_scope() as conn:
            cur = conn.execute(
                "UPDATE execution_decisions SET started_at = ?, consumed_at = ?, claim_expires_at = NULL WHERE id = ? AND organization_id = ? AND claim_owner = ? AND claim_token = ? AND consumed_at IS NULL AND revoked_at IS NULL AND expires_at > ? AND claim_expires_at > ?",
                (now.isoformat(), now.isoformat(), decision_id, organization_id, worker_identity, claim_token, now.isoformat(), now.isoformat()),
            )
            if cur.rowcount == 1:
                self._insert_audit_event_conn(conn, AuditEvent(id=f"aud-{uuid.uuid4().hex[:12]}", actor=worker_identity, organization_id=organization_id, action=AuditAction.EXECUTION_DECISION_STARTED, object_type="execution_decision", object_id=decision_id, result="SUCCESS", details={"claim_token": claim_token}))
                self._insert_audit_event_conn(conn, AuditEvent(id=f"aud-{uuid.uuid4().hex[:12]}", actor=worker_identity, organization_id=organization_id, action=AuditAction.EXECUTION_DECISION_CONSUMED, object_type="execution_decision", object_id=decision_id, result="SUCCESS", details={"claim_token": claim_token}))
            return cur.rowcount == 1

    def release_execution_decision_claim(self, decision_id: str, organization_id: str, worker_identity: str, claim_token: str) -> bool:
        with self._connection_scope() as conn:
            cur = conn.execute(
                "UPDATE execution_decisions SET claim_owner = NULL, claim_expires_at = NULL, claim_token = NULL WHERE id = ? AND organization_id = ? AND claim_owner = ? AND claim_token = ? AND consumed_at IS NULL",
                (decision_id, organization_id, worker_identity, claim_token),
            )
            if cur.rowcount == 1:
                self._insert_audit_event_conn(conn, AuditEvent(id=f"aud-{uuid.uuid4().hex[:12]}", actor=worker_identity, organization_id=organization_id, action=AuditAction.EXECUTION_DECISION_LEASE_RELEASED, object_type="execution_decision", object_id=decision_id, result="SUCCESS", details={"claim_token": claim_token}))
            return cur.rowcount == 1

    def revoke_execution_decision(self, decision_id: str, organization_id: str, actor: str) -> bool:
        """Revoke a decision without deleting its audit-relevant record."""
        with self._connection_scope() as conn:
            if not organization_id or not actor:
                raise ValueError("tenant scope and revoking actor are required")
            query = "UPDATE execution_decisions SET revoked_at = ? WHERE id = ? AND organization_id = ? AND revoked_at IS NULL"
            params: List[Any] = [utc_now().isoformat(), decision_id, organization_id]
            cur = conn.execute(query, params)
            changed = cur.rowcount > 0
            if changed:
                self._insert_audit_event_conn(
                    conn,
                    AuditEvent(
                        id=f"aud-{uuid.uuid4().hex[:12]}", actor=actor,
                        organization_id=organization_id,
                        action=AuditAction.EXECUTION_DECISION_REVOKED,
                        object_type="execution_decision", object_id=decision_id,
                        result="SUCCESS", details={"decision_id": decision_id},
                    ),
                )
            return changed

    # ========================================================================
    # 2. Immutable Audit Logging with Cryptographic Chained Hashes
    # ========================================================================

    def _insert_audit_event_conn(self, conn: sqlite3.Connection, event: "AuditEvent") -> None:
        """Inserts an audit event using an already-open connection. Use this when the caller
        already holds a write transaction to avoid a second-connection deadlock on SQLite."""
        if event.correlation_id is None:
            from app.core.correlation import get_correlation_id
            event.correlation_id = get_correlation_id()

        # The chain predecessor and sequence number must be read and written
        # as one serialized operation.  SQLite needs an immediate write lock
        # when this is the outermost transaction; PostgreSQL needs a
        # transaction-scoped advisory lock because its default isolation level
        # otherwise permits concurrent readers to observe the same predecessor.
        if isinstance(conn, sqlite3.Connection) and not conn.in_transaction:
            conn.execute("BEGIN IMMEDIATE")
        elif isinstance(conn, _PostgresConnection):
            conn.execute(
                "SELECT pg_advisory_xact_lock(hashtext(?))",
                ("cyberassess:audit-chain",),
            )
        cur = conn.cursor()
        cur.execute(
            "SELECT event_hash, sequence_number FROM audit_events "
            "ORDER BY sequence_number DESC NULLS LAST, timestamp DESC, id DESC LIMIT 1"
        )
        last_row = cur.fetchone()
        prev_hash = last_row["event_hash"] if (last_row and last_row["event_hash"]) else None
        sequence_number = (last_row["sequence_number"] if last_row else None) or 0
        sequence_number += 1

        ts_str = event.timestamp.isoformat() if event.timestamp else utc_now().isoformat()
        act_str = event.action.value if hasattr(event.action, "value") else str(event.action)
        event.details = sanitize_sensitive_data(event.details)
        details_str = json.dumps(event.details, sort_keys=True)
        canonical_payload = f"{event.id}|{ts_str}|{event.actor}|{event.organization_id}|{act_str}|{event.object_type}|{event.object_id}|{event.result}|{details_str}|{prev_hash or ''}"
        event_hash = hashlib.sha256(canonical_payload.encode("utf-8")).hexdigest()
        event.previous_event_hash = prev_hash
        event.event_hash = event_hash

        conn.execute(
            """
            INSERT INTO audit_events (
                id, sequence_number, timestamp, actor, organization_id, action, object_type,
                object_id, result, source_ip, correlation_id, details_json,
                previous_event_hash, event_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event.id, sequence_number, ts_str, event.actor, event.organization_id, act_str,
                event.object_type, event.object_id, event.result, event.source_ip,
                event.correlation_id, details_str, prev_hash, event_hash,
            ),
        )

    def record_audit_event(self, event: "AuditEvent") -> None:
        """Appends an immutable security audit event to the relational audit log with chained cryptographic hash."""
        if event.correlation_id is None:
            from app.core.correlation import get_correlation_id
            event.correlation_id = get_correlation_id()
        with self._connection_scope() as conn:
            self._insert_audit_event_conn(conn, event)


    def list_audit_events(
        self,
        organization_id: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[AuditEvent], int]:
        with self._connection_scope() as conn:
            cur = conn.cursor()
            query = "SELECT * FROM audit_events WHERE 1=1"
            params: List[Any] = []
            if organization_id:
                query += " AND organization_id = ?"
                params.append(organization_id)

            cur.execute(query.replace("SELECT *", "SELECT COUNT(*) as total", 1), params)
            total = cur.fetchone()["total"]

            query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])

            cur.execute(query, params)
            rows = cur.fetchall()

            events = [
                AuditEvent(
                    id=r["id"],
                    timestamp=datetime.fromisoformat(r["timestamp"]),
                    actor=r["actor"],
                    organization_id=r["organization_id"],
                    action=AuditAction(r["action"]),
                    object_type=r["object_type"],
                    object_id=r["object_id"],
                    result=r["result"],
                    source_ip=r["source_ip"],
                    correlation_id=r["correlation_id"],
                    details=json.loads(r["details_json"]),
                    previous_event_hash=r["previous_event_hash"] if "previous_event_hash" in r.keys() else None,
                    event_hash=r["event_hash"] if "event_hash" in r.keys() else None,
                )
                for r in rows
            ]
            return events, total

    def verify_audit_log_integrity(self, organization_id: Optional[str] = None) -> Tuple[bool, Optional[str]]:
        """
        Cryptographically verifies the immutable SHA-256 hash chain of the audit log.
        Returns (True, None) if the hash chain is completely intact, or (False, broken_event_id)
        if any record was modified, reordered, deleted, or tampered with.
        """
        with self._connection_scope() as conn:
            cur = conn.cursor()
            query = "SELECT * FROM audit_events"
            params: List[Any] = []
            if organization_id:
                query += " WHERE organization_id = ?"
                params.append(organization_id)
            query += " ORDER BY sequence_number ASC NULLS LAST, timestamp ASC, id ASC"
            cur.execute(query, params)
            rows = cur.fetchall()

            prev_hash: Optional[str] = None
            for row in rows:
                row_id = row["id"]
                ts_str = row["timestamp"]
                actor = row["actor"]
                org_id = row["organization_id"]
                action = row["action"]
                obj_type = row["object_type"]
                obj_id = row["object_id"]
                result = row["result"]
                details_json = row["details_json"]
                stored_prev = row["previous_event_hash"]
                stored_hash = row["event_hash"]

                # Verify previous event hash pointer
                if stored_prev != prev_hash:
                    return False, row_id

                # Recompute canonical payload and SHA-256 hash
                canonical_payload = f"{row_id}|{ts_str}|{actor}|{org_id}|{action}|{obj_type}|{obj_id}|{result}|{details_json}|{prev_hash or ''}"
                expected_hash = hashlib.sha256(canonical_payload.encode("utf-8")).hexdigest()

                if stored_hash != expected_hash:
                    return False, row_id

                prev_hash = stored_hash

            return True, None

    # ========================================================================
    # 3. Asset Management Operations
    # ========================================================================

    def create_asset(self, asset: Asset) -> Asset:
        with self._connection_scope() as conn:
            conn.execute(
                """
                INSERT INTO assets (
                    id, organization_id, project_id, name, type, target_value,
                    criticality, internet_exposed, active_probing_granted, live_secret_verification_granted, owner, lifecycle_status, tags_json,
                    created_at, updated_at, last_scanned_at, last_verified_at, active_findings_count
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    organization_id = excluded.organization_id,
                    project_id = excluded.project_id,
                    name = excluded.name,
                    type = excluded.type,
                    target_value = excluded.target_value,
                    criticality = excluded.criticality,
                    internet_exposed = excluded.internet_exposed,
                    active_probing_granted = excluded.active_probing_granted,
                    live_secret_verification_granted = excluded.live_secret_verification_granted,
                    owner = excluded.owner,
                    lifecycle_status = excluded.lifecycle_status,
                    tags_json = excluded.tags_json,
                    updated_at = excluded.updated_at,
                    last_scanned_at = excluded.last_scanned_at,
                    last_verified_at = excluded.last_verified_at,
                    active_findings_count = excluded.active_findings_count
                """,
                (
                    asset.id,
                    asset.organization_id,
                    asset.project_id,
                    asset.name,
                    asset.type.value if hasattr(asset.type, "value") else str(asset.type),
                    asset.target_value,
                    asset.criticality.value if hasattr(asset.criticality, "value") else str(asset.criticality),
                    1 if asset.internet_exposed else 0,
                    1 if asset.active_probing_granted else 0,
                    1 if asset.live_secret_verification_granted else 0,
                    asset.owner,
                    asset.lifecycle_status.value if hasattr(asset.lifecycle_status, "value") else str(asset.lifecycle_status),
                    json.dumps(asset.tags),
                    asset.created_at.isoformat() if asset.created_at else utc_now().isoformat(),
                    asset.updated_at.isoformat() if asset.updated_at else utc_now().isoformat(),
                    asset.last_scanned_at.isoformat() if asset.last_scanned_at else None,
                    asset.last_verified_at.isoformat() if asset.last_verified_at else None,
                    asset.active_findings_count,
                ),
            )
        return asset

    def get_asset(self, asset_id: str, organization_id: Optional[str] = None) -> Optional[Asset]:
        with self._connection_scope() as conn:
            cur = conn.cursor()
            if organization_id:
                cur.execute("SELECT * FROM assets WHERE id = ? AND organization_id = ?", (asset_id, organization_id))
            else:
                cur.execute("SELECT * FROM assets WHERE id = ?", (asset_id,))
            row = cur.fetchone()
            if not row:
                return None
            return self._row_to_asset(row)

    def list_assets(
        self,
        organization_id: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[Asset], int]:
        with self._connection_scope() as conn:
            cur = conn.cursor()
            query = "SELECT * FROM assets WHERE 1=1"
            params: List[Any] = []
            if organization_id:
                query += " AND organization_id = ?"
                params.append(organization_id)

            cur.execute(query.replace("SELECT *", "SELECT COUNT(*) as total", 1), params)
            total = cur.fetchone()["total"]

            query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])

            cur.execute(query, params)
            rows = cur.fetchall()
            return [self._row_to_asset(r) for r in rows], total

    def delete_asset(self, asset_id: str, organization_id: Optional[str] = None) -> bool:
        with self._connection_scope() as conn:
            cur = conn.cursor()
            if organization_id:
                cur.execute("DELETE FROM assets WHERE id = ? AND organization_id = ?", (asset_id, organization_id))
            else:
                cur.execute("DELETE FROM assets WHERE id = ?", (asset_id,))
            return cur.rowcount > 0

    def revoke_execution_request(self, request_id: str, organization_id: str, actor: str) -> bool:
        """Atomically revoke a tenant-scoped request and its linked decision."""
        if not organization_id or not actor:
            return False
        with self._connection_scope() as conn:
            cur = conn.cursor()
            authority_lock = " FOR UPDATE" if isinstance(self, PostgresDatabaseManager) else ""
            # Keep request -> decision lock order identical to run creation.
            cur.execute(f"SELECT state, approved_decision_id FROM execution_requests WHERE id = ? AND organization_id = ?{authority_lock}", (request_id, organization_id))
            row = cur.fetchone()
            if not row:
                return False
            if row["approved_decision_id"]:
                # Acquire the decision lock before any audit-chain lock or
                # mutation, preserving the global request -> decision order.
                cur.execute(f"SELECT id FROM execution_decisions WHERE id = ? AND organization_id = ?{authority_lock}", (row["approved_decision_id"], organization_id))
                decision_row = cur.fetchone()
                if not decision_row:
                    # Roll back the state transaction before recording the
                    # invariant failure.  The connection scope will commit
                    # this sanitized event while leaving request state intact.
                    conn.rollback()
                    self._insert_audit_event_conn(conn, AuditEvent(
                        id=f"aud-{uuid.uuid4().hex[:12]}", actor=actor, organization_id=organization_id,
                        action=AuditAction.EXECUTION_AUTHORITY_INVARIANT_FAILED, object_type="execution_request", object_id=request_id,
                        result="FAILURE", details={"reason_code": "APPROVED_DECISION_REFERENCE_MISSING"},
                    ))
                    conn.commit()
                    raise ValueError("execution request has an invalid approved decision reference")
            now = utc_now().isoformat()
            self._insert_audit_event_conn(conn, AuditEvent(
                id=f"aud-{uuid.uuid4().hex[:12]}", actor=actor, organization_id=organization_id,
                action=AuditAction.EXECUTION_CANCEL_REQUESTED, object_type="execution_request", object_id=request_id,
                result="SUCCESS", details={"decision_id": row["approved_decision_id"]},
            ))
            if row["approved_decision_id"]:
                cur.execute("UPDATE execution_decisions SET revoked_at = ? WHERE id = ? AND organization_id = ? AND revoked_at IS NULL", (now, row["approved_decision_id"], organization_id))
            cur.execute("UPDATE execution_requests SET state = 'REVOKED' WHERE id = ? AND organization_id = ? AND state != 'REVOKED'", (request_id, organization_id))
            changed = cur.rowcount > 0
            self._insert_audit_event_conn(conn, AuditEvent(
                id=f"aud-{uuid.uuid4().hex[:12]}", actor=actor, organization_id=organization_id,
                action=AuditAction.EXECUTION_DECISION_REVOKED, object_type="execution_request", object_id=request_id,
                result="SUCCESS" if changed else "REPLAY", details={"decision_id": row["approved_decision_id"]},
            ))
            return changed or row["state"] == "REVOKED"

    def create_execution_run(self, run: ExecutionRunRecord) -> ExecutionRunRecord:
        with self._connection_scope() as conn:
            if run.state not in EXECUTION_RUN_STATES or not run.request_id or not run.organization_id:
                raise ValueError("execution run state or identity is invalid")
            if run.state != "REQUESTED":
                raise ValueError("execution run must be created in REQUESTED state")
            # Lock authority rows for the entire request-to-run transaction on
            # PostgreSQL so revoke/expiry cannot race validation and insertion.
            authority_lock = " FOR UPDATE" if isinstance(self, PostgresDatabaseManager) else ""
            request_row = conn.execute(f"SELECT state, approved_decision_id, expires_at FROM execution_requests WHERE id = ? AND organization_id = ?{authority_lock}", (run.request_id, run.organization_id)).fetchone()
            if not request_row or request_row["state"] != "AUTHORIZED" or not request_row["approved_decision_id"]:
                raise ValueError("execution run request is not tenant-bound")
            decision_row = conn.execute(f"SELECT * FROM execution_decisions WHERE id = ? AND organization_id = ? AND approval_state = 'APPROVED' AND revoked_at IS NULL{authority_lock}", (request_row["approved_decision_id"], run.organization_id)).fetchone()
            if not decision_row:
                raise ValueError("execution run has no current approved decision")
            # Capture time only after both row locks have been acquired; a
            # blocked lock wait must not make expired authority appear valid.
            now = utc_now()
            if datetime.fromisoformat(request_row["expires_at"]) <= now or datetime.fromisoformat(decision_row["expires_at"]) <= now:
                raise ValueError("execution run request is expired")
            request_full = conn.execute("SELECT * FROM execution_requests WHERE id = ? AND organization_id = ?", (run.request_id, run.organization_id)).fetchone()
            if any([
                request_full["project_id"] != decision_row["project_id"], request_full["asset_id"] != decision_row["asset_id"],
                request_full["target_id"] != decision_row["target_id"], request_full["authorization_decision_id"] != decision_row["authorization_decision_id"],
                request_full["target_policy_version"] != decision_row["target_policy_version"], request_full["tool_id"] != decision_row["tool_id"],
                request_full["operation_family"] != decision_row["operation_family"], request_full["operation_options_json"] != decision_row["operation_options_json"],
                request_full["operation_policy_revision"] != decision_row["operation_policy_revision"], request_full["resource_budget_json"] != decision_row["resource_budget_json"],
                request_full["account_impact_budget_json"] != decision_row["account_impact_budget_json"], request_full["credential_scope_json"] != decision_row["credential_scope_json"],
            ]):
                raise ValueError("execution request and approved decision authority binding does not match")
            conn.execute(
                """INSERT INTO execution_runs (
                    execution_id, request_id, organization_id, approved_decision_id,
                    target_policy_version, operation_policy_revision, request_fingerprint,
                    operation_options_json, resource_budget_json, account_impact_budget_json,
                    credential_scope_json, snapshot_completeness, state, worker_identity, process_id, process_group_id,
                    assurance_state, coverage_state, reason_code, evidence_ref, correlation_id,
                    created_at, started_at, finished_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (run.execution_id, run.request_id, run.organization_id, decision_row["id"],
                 decision_row["target_policy_version"], decision_row["operation_policy_revision"],
                 request_full["request_fingerprint"], decision_row["operation_options_json"],
                 decision_row["resource_budget_json"], decision_row["account_impact_budget_json"],
                 decision_row["credential_scope_json"], "COMPLETE", run.state, run.worker_identity,
                 run.process_id, run.process_group_id, run.assurance_state, run.coverage_state,
                 run.reason_code, run.evidence_ref, run.correlation_id,
                 run.created_at.isoformat(), run.started_at.isoformat() if run.started_at else None,
                 run.finished_at.isoformat() if run.finished_at else None),
            )
            self._insert_audit_event_conn(conn, AuditEvent(id=f"aud-{uuid.uuid4().hex[:12]}", actor=run.worker_identity or "system", organization_id=run.organization_id, action=AuditAction.EXECUTION_RUN_CREATED, object_type="execution_run", object_id=run.execution_id, result="SUCCESS", details={"request_id": run.request_id, "state": run.state}))
            return run

    def transition_execution_run(self, execution_id: str, organization_id: str, expected_state: str, new_state: str, *, reason_code: Optional[str] = None, process_id: Optional[int] = None, worker_identity: Optional[str] = None) -> bool:
        with self._connection_scope() as conn:
            if expected_state not in EXECUTION_RUN_STATES or new_state not in EXECUTION_RUN_STATES or new_state not in EXECUTION_RUN_TRANSITIONS.get(expected_state, frozenset()):
                return False
            now = utc_now().isoformat()
            cur = conn.execute(
                "UPDATE execution_runs SET state = ?, reason_code = COALESCE(?, reason_code), process_id = COALESCE(?, process_id), worker_identity = COALESCE(?, worker_identity), started_at = CASE WHEN ? = 'RUNNING' THEN COALESCE(started_at, ?) ELSE started_at END, finished_at = CASE WHEN ? IN ('SUCCEEDED','PARTIAL_RESULTS_WITH_WARNING','FAILED','TIMED_OUT','CANCELLED','EXECUTION_BLOCKED') THEN COALESCE(finished_at, ?) ELSE finished_at END WHERE execution_id = ? AND organization_id = ? AND state = ?",
                (new_state, reason_code, process_id, worker_identity, new_state, now, new_state, now, execution_id, organization_id, expected_state),
            )
            if cur.rowcount == 1:
                self._insert_audit_event_conn(conn, AuditEvent(id=f"aud-{uuid.uuid4().hex[:12]}", actor=worker_identity or "system", organization_id=organization_id, action=AuditAction.EXECUTION_RUN_TRANSITIONED, object_type="execution_run", object_id=execution_id, result="SUCCESS", details={"from": expected_state, "to": new_state, "reason_code": reason_code}))
                return True
            return False

    def _row_to_asset(self, row: sqlite3.Row) -> Asset:
        return Asset(
            id=row["id"],
            organization_id=row["organization_id"],
            project_id=row["project_id"],
            name=row["name"],
            type=AssetType(row["type"]),
            target_value=row["target_value"],
            criticality=AssetCriticality(row["criticality"]),
            internet_exposed=bool(row["internet_exposed"]),
            active_probing_granted=bool(row["active_probing_granted"]) if "active_probing_granted" in row.keys() else False,
            live_secret_verification_granted=bool(row["live_secret_verification_granted"]) if "live_secret_verification_granted" in row.keys() else False,
            owner=row["owner"],
            lifecycle_status=AssetLifecycleStatus(row["lifecycle_status"]) if "lifecycle_status" in row.keys() else AssetLifecycleStatus.MONITORED,
            tags=json.loads(row["tags_json"]) if row["tags_json"] else [],
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]) if "updated_at" in row.keys() and row["updated_at"] else datetime.fromisoformat(row["created_at"]),
            last_scanned_at=datetime.fromisoformat(row["last_scanned_at"]) if row["last_scanned_at"] else None,
            active_findings_count=row["active_findings_count"],
        )

    # ========================================================================
    # 4. Scan & Finding Persistence Operations
    # ========================================================================

    def save_scan_record(self, scan_job: ScanJob) -> None:
        """
        Atomically persists or updates a ScanJob entity, correlates raw findings into
        CanonicalFinding entities with SLA tracking, and stores all FindingOccurrence records.
        """
        with self._connection_scope() as conn:
            target = scan_job.target
            summary = scan_job.summary
            data_json = json.dumps(
                sanitize_sensitive_data(scan_job.model_dump(mode="json")),
                separators=(",", ":"),
                ensure_ascii=False,
            )
            org_id = getattr(scan_job, "organization_id", None) or "org-default"
            proj_id = getattr(scan_job, "project_id", None)
            asset_id = getattr(scan_job, "asset_id", None)

            conn.execute(
                """
                INSERT INTO scans (
                    id, organization_id, project_id, asset_id, target_name, target_type, target_value,
                    profile, status, progress_percent, grade, score, total_findings,
                    started_at, completed_at, summary_json, data_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    organization_id = excluded.organization_id,
                    project_id = excluded.project_id,
                    asset_id = excluded.asset_id,
                    target_name = excluded.target_name,
                    target_type = excluded.target_type,
                    target_value = excluded.target_value,
                    profile = excluded.profile,
                    status = excluded.status,
                    progress_percent = excluded.progress_percent,
                    grade = excluded.grade,
                    score = excluded.score,
                    total_findings = excluded.total_findings,
                    started_at = excluded.started_at,
                    completed_at = excluded.completed_at,
                    summary_json = excluded.summary_json,
                    data_json = excluded.data_json
                """,
                (
                    scan_job.id,
                    org_id,
                    proj_id,
                    asset_id,
                    target.name,
                    target.type.value if hasattr(target.type, "value") else str(target.type),
                    target.value,
                    scan_job.profile.value if hasattr(scan_job.profile, "value") else str(scan_job.profile),
                    scan_job.status.value if hasattr(scan_job.status, "value") else str(scan_job.status),
                    scan_job.progress_percent,
                    summary.overall_security_grade if summary else None,
                    summary.weighted_score if summary else 0.0,
                    summary.total_findings if summary else len(scan_job.findings),
                    scan_job.started_at.isoformat() if scan_job.started_at else None,
                    scan_job.completed_at.isoformat() if scan_job.completed_at else None,
                    summary.model_dump_json() if summary else None,
                    data_json,
                ),
            )

            # Correlate findings into canonical clusters and occurrences
            from app.core.correlator import FindingCorrelator
            correlator = FindingCorrelator()
            canonical_findings, occurrences = correlator.correlate_findings(
                findings=scan_job.findings,
                asset_id=asset_id,
                organization_id=org_id,
                project_id=proj_id,
            )

            # Persist canonical findings
            for cf in canonical_findings:
                now_str = utc_now().isoformat()
                cf_data = sanitize_sensitive_data(cf.model_dump(mode="json"))
                first_seen_str = cf.first_seen.isoformat() if cf.first_seen else now_str
                last_seen_str = cf.last_seen.isoformat() if cf.last_seen else now_str
                sla_json = cf.sla.model_dump_json() if cf.sla else None
                tools_json = json.dumps(cf.contributing_tools or [getattr(cf, "source_tool", "native")])
                corr_type = cf.correlation_type.value if hasattr(cf.correlation_type, "value") else (str(cf.correlation_type) if cf.correlation_type else None)
                
                # Resolve check_id from occurrences or default
                matching_check_id = next((o.check_id for o in occurrences if o.canonical_finding_id == cf.id), cf.cwe_id or "SEC-CHECK-001")

                conn.execute(
                    """
                    INSERT INTO findings (
                        id, organization_id, project_id, asset_id, scan_id, check_id, category, title, severity,
                        cvss_score, cvss_vector, contextual_risk_score, cwe_id, owasp_category, nist_control,
                        status, first_seen, last_seen, times_observed, assigned_to, contributing_tools_json,
                        correlation_type, description, impact, remediation, evidence_hash, sla_json, fingerprint, data_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                        last_seen = excluded.last_seen,
                        times_observed = times_observed + 1,
                        contextual_risk_score = excluded.contextual_risk_score,
                        contributing_tools_json = excluded.contributing_tools_json,
                        data_json = excluded.data_json
                    """,
                    (
                        cf.id,
                        org_id,
                        proj_id,
                        asset_id,
                        scan_job.id,
                        matching_check_id,
                        cf.category,
                        cf.title,
                        cf.severity.value if hasattr(cf.severity, "value") else str(cf.severity),
                        cf.cvss_score,
                        cf.cvss_vector or "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                        cf.contextual_risk_score,
                        cf.cwe_id,
                        cf.owasp_category,
                        cf.nist_control,
                        cf.status.value if hasattr(cf.status, "value") else str(cf.status),
                        first_seen_str,
                        last_seen_str,
                        cf.times_observed,
                        cf.assigned_to,
                        tools_json,
                        corr_type,
                        sanitize_sensitive_data(cf.description) or "",
                        sanitize_sensitive_data(cf.impact) or "",
                        sanitize_sensitive_data(cf.remediation) or "",
                        cf.evidence_hash or "",
                        sla_json,
                        cf.evidence_hash or cf.id,
                        json.dumps(cf_data, ensure_ascii=False),
                    ),
                )

            # Persist individual finding occurrences
            for occ in occurrences:
                conn.execute(
                    """
                    INSERT INTO finding_occurrences (
                        id, organization_id, canonical_finding_id, scan_id, asset_id, source_tool, check_id,
                        raw_evidence_json, reproduction_curl, taint_trace_json, detected_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                        organization_id = excluded.organization_id,
                        canonical_finding_id = excluded.canonical_finding_id,
                        scan_id = excluded.scan_id,
                        asset_id = excluded.asset_id,
                        source_tool = excluded.source_tool,
                        check_id = excluded.check_id,
                        raw_evidence_json = excluded.raw_evidence_json,
                        reproduction_curl = excluded.reproduction_curl,
                        taint_trace_json = excluded.taint_trace_json,
                        detected_at = excluded.detected_at
                    """,
                    (
                        occ.id,
                        occ.organization_id,
                        occ.canonical_finding_id,
                        occ.scan_id,
                        occ.asset_id or asset_id,
                        occ.source_tool,
                        occ.check_id,
                        json.dumps(
                            sanitize_sensitive_data(occ.raw_evidence.model_dump(mode="json")),
                            ensure_ascii=False,
                        ) if hasattr(occ.raw_evidence, "model_dump") else json.dumps(
                            sanitize_sensitive_data(occ.raw_evidence), ensure_ascii=False
                        ),
                        sanitize_sensitive_data(occ.reproduction_curl),
                        json.dumps(occ.taint_trace or []),
                        occ.detected_at.isoformat() if occ.detected_at else utc_now().isoformat(),
                    ),
                )

    def get_scan_record(self, scan_id: str, organization_id: Optional[str] = None) -> Optional[ScanJob]:
        """Retrieves a ScanJob entity directly from relational persistence."""
        with self._connection_scope() as conn:
            cur = conn.cursor()
            if organization_id:
                cur.execute("SELECT data_json FROM scans WHERE id = ? AND organization_id = ?", (scan_id, organization_id))
            else:
                cur.execute("SELECT data_json FROM scans WHERE id = ?", (scan_id,))
            row = cur.fetchone()
            if not row:
                return None
            try:
                data = json.loads(row["data_json"])
                return ScanJob.model_validate(data)
            except (json.JSONDecodeError, TypeError, ValueError) as exc:
                raise RuntimeError(f"Authoritative scan record '{scan_id}' is corrupt.") from exc

    def list_scans_records(
        self,
        organization_id: Optional[str] = None,
        limit: int = 50,
        offset: int = 0
    ) -> Tuple[List[ScanJob], int]:
        """Returns paginated scan jobs scoped to the caller's organization."""
        with self._connection_scope() as conn:
            cur = conn.cursor()
            if organization_id:
                cur.execute("SELECT COUNT(*) FROM scans WHERE organization_id = ?", (organization_id,))
                total = cur.fetchone()[0]
                cur.execute(
                    "SELECT data_json FROM scans WHERE organization_id = ? ORDER BY started_at DESC LIMIT ? OFFSET ?",
                    (organization_id, limit, offset),
                )
            else:
                cur.execute("SELECT COUNT(*) FROM scans")
                total = cur.fetchone()[0]
                cur.execute(
                    "SELECT data_json FROM scans ORDER BY started_at DESC LIMIT ? OFFSET ?",
                    (limit, offset),
                )
            rows = cur.fetchall()
            scans: List[ScanJob] = []
            for r in rows:
                try:
                    data = json.loads(r["data_json"])
                    scans.append(ScanJob.model_validate(data))
                except (json.JSONDecodeError, TypeError, ValueError) as exc:
                    raise RuntimeError("Authoritative scan listing contains a corrupt record.") from exc
            return scans, total

    def delete_scan_record(self, scan_id: str, organization_id: Optional[str] = None) -> bool:
        """Deletes a scan job and cascades removal of child finding records."""
        with self._connection_scope() as conn:
            cur = conn.cursor()
            if organization_id:
                cur.execute("DELETE FROM scans WHERE id = ? AND organization_id = ?", (scan_id, organization_id))
            else:
                cur.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
            return cur.rowcount > 0


db_manager = DatabaseManager.get_instance()
