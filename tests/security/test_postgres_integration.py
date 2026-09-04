"""Opt-in real PostgreSQL schema assurance tests.

These tests deliberately require an explicitly supplied, isolated database URL.
They never discover or mutate an ambient application database.
"""

import os

import pytest

from app.core.db import PostgresDatabaseManager


POSTGRES_TEST_URL = os.getenv("CYBERASSESS_POSTGRES_TEST_URL", "").strip()


pytestmark = pytest.mark.skipif(
    not POSTGRES_TEST_URL,
    reason="CYBERASSESS_POSTGRES_TEST_URL is required for the isolated PostgreSQL integration suite",
)


def test_postgres_bootstrap_health_and_rerun_are_real_backend_operations():
    manager = PostgresDatabaseManager(POSTGRES_TEST_URL)
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

    # A second manager initialization exercises migration idempotency and the
    # startup health path against the real PostgreSQL service.
    PostgresDatabaseManager(POSTGRES_TEST_URL)
