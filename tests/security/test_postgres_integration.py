"""Opt-in real PostgreSQL schema assurance tests.

These tests deliberately require an explicitly supplied, isolated database URL.
They never discover or mutate an ambient application database.
"""

import os
import uuid
from contextlib import contextmanager
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import pytest
import psycopg

from app.core.db import PostgresDatabaseManager


POSTGRES_TEST_URL = os.getenv("CYBERASSESS_POSTGRES_TEST_URL", "").strip()


pytestmark = pytest.mark.skipif(
    not POSTGRES_TEST_URL,
    reason="CYBERASSESS_POSTGRES_TEST_URL is required for the isolated PostgreSQL integration suite",
)


def _disposable_database_url() -> str:
    """Require the caller to identify a local, disposable test database."""
    parts = urlsplit(POSTGRES_TEST_URL)
    if parts.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise RuntimeError("PostgreSQL integration tests require a loopback host")
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


def test_postgres_bootstrap_health_and_rerun_are_real_backend_operations():
    with _isolated_manager() as manager:
        with manager._connection_scope() as conn:
            versions = [row["version"] for row in conn.execute(
                "SELECT version FROM schema_migrations ORDER BY version"
            ).fetchall()]
            assert versions == [1, 2]

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

            # A second manager initialization exercises migration idempotency and
            # the startup health path against the real PostgreSQL service.
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
