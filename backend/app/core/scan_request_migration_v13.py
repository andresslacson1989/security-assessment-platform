"""Version 13 scan persistence DDL, isolated from frozen legacy migrations.

The migration coordinator owns the transaction and migration ledger. This module
never commits, changes FK enforcement, or invents missing historical authority.
Its complete source must be fingerprinted when registered, including SQL values.
"""

import sqlite3
import inspect
import hashlib
import re


OPERATION_COLUMNS = (
    "operation_id", "scan_request_id", "organization_id", "tool_id", "engine_id",
    "operation_family", "classification", "operation_options_json",
    "operation_policy_revision", "target_id", "authorization_decision_id",
    "resource_budget_json", "account_impact_budget_json", "credential_scope_json",
    "capability_state", "selection_state", "exclusion_reason", "child_request_id",
    "child_decision_id", "child_execution_id",
)

OPERATION_TABLE_SQL = """CREATE TABLE scan_authorization_operations_v13 (
    operation_id TEXT NOT NULL,
    scan_request_id TEXT NOT NULL,
    organization_id TEXT NOT NULL,
    tool_id TEXT NOT NULL,
    engine_id TEXT NOT NULL,
    operation_family TEXT NOT NULL,
    classification TEXT NOT NULL,
    operation_options_json TEXT NOT NULL,
    operation_policy_revision TEXT NOT NULL,
    target_id TEXT NOT NULL,
    authorization_decision_id TEXT NOT NULL,
    resource_budget_json TEXT NOT NULL,
    account_impact_budget_json TEXT NOT NULL,
    credential_scope_json TEXT NOT NULL,
    capability_state TEXT NOT NULL,
    selection_state TEXT NOT NULL,
    exclusion_reason TEXT,
    child_request_id TEXT,
    child_decision_id TEXT,
    child_execution_id TEXT,
    PRIMARY KEY (scan_request_id, organization_id, operation_id),
    UNIQUE (child_request_id, organization_id),
    UNIQUE (child_decision_id, organization_id),
    UNIQUE (child_execution_id, organization_id),
    FOREIGN KEY (scan_request_id, organization_id)
        REFERENCES scan_authorization_requests(scan_request_id, organization_id),
    FOREIGN KEY (organization_id) REFERENCES organizations(id),
    FOREIGN KEY (child_request_id, organization_id)
        REFERENCES execution_requests(id, organization_id),
    FOREIGN KEY (child_decision_id, organization_id)
        REFERENCES execution_decisions(id, organization_id),
    FOREIGN KEY (child_execution_id, organization_id)
        REFERENCES execution_runs(execution_id, organization_id),
    CHECK ((child_request_id IS NULL AND child_decision_id IS NULL AND child_execution_id IS NULL)
        OR (child_request_id IS NOT NULL AND child_decision_id IS NOT NULL AND child_execution_id IS NOT NULL))
)"""
APPLY_ARTIFACT_REVISION = "scan-request-v13-apply-v1"


def apply_artifact_digest(manager, *, backend: str, manifest: dict) -> str:
    """Fingerprint the callable and every migration-owned SQL dependency."""
    verification_helpers = (
        _normalized_sql,
        _sqlite_check_expressions,
        _require_tables,
        _sqlite_index_columns,
        _sqlite_indexes,
        _require_sqlite_unique_index,
        _sqlite_foreign_keys,
        _require_sqlite_foreign_key,
        _verify_sqlite_schema,
        _postgres_indexes,
        _require_postgres_unique_index,
        _postgres_foreign_keys,
        _require_postgres_foreign_key,
        _verify_postgres_schema,
        verify_schema,
    )
    material = "\n".join((
        inspect.getsource(apply_schema),
        *(inspect.getsource(helper) for helper in verification_helpers),
        OPERATION_TABLE_SQL, APPLY_ARTIFACT_REVISION,
        repr((
            _REQUIRED_OPERATION_PRIMARY_KEY,
            _REQUIRED_OPERATION_UNIQUE_KEYS,
            _REQUIRED_OPERATION_FOREIGN_KEYS,
            _REQUIRED_REQUEST_FOREIGN_KEYS,
            _REQUIRED_REQUEST_COLUMNS,
            _CHILD_LINK_CHECK,
        )),
        inspect.getsource(manager._apply_scan_request_v13),
        repr(sorted(manifest.items())), backend,
    )).encode("utf-8")
    return "sha256:" + hashlib.sha256(material).hexdigest()


_REQUIRED_OPERATION_PRIMARY_KEY = ("scan_request_id", "organization_id", "operation_id")
_REQUIRED_OPERATION_UNIQUE_KEYS = (
    ("child_request_id", "organization_id"),
    ("child_decision_id", "organization_id"),
    ("child_execution_id", "organization_id"),
)
_REQUIRED_OPERATION_FOREIGN_KEYS = (
    (
        ("scan_request_id", "organization_id"),
        "scan_authorization_requests",
        ("scan_request_id", "organization_id"),
    ),
    (("organization_id",), "organizations", ("id",)),
    (("child_request_id", "organization_id"), "execution_requests", ("id", "organization_id")),
    (("child_decision_id", "organization_id"), "execution_decisions", ("id", "organization_id")),
    (("child_execution_id", "organization_id"), "execution_runs", ("execution_id", "organization_id")),
)
_REQUIRED_REQUEST_FOREIGN_KEYS = (
    (("organization_id",), "organizations", ("id",)),
)
_REQUIRED_REQUEST_COLUMNS = ("manifest_json", "creation_idempotency_key", "creation_fingerprint")
_CHILD_LINK_CHECK = (
    "CHECK ((child_request_id IS NULL AND child_decision_id IS NULL AND child_execution_id IS NULL) "
    "OR (child_request_id IS NOT NULL AND child_decision_id IS NOT NULL AND child_execution_id IS NOT NULL))"
)


def _normalized_sql(value: object) -> str:
    """Normalize catalog SQL enough to compare the required v13 expression."""
    return re.sub(r"[\s()\"`]+", "", str(value or "")).upper()


def _sqlite_check_expressions(table_sql: str) -> list[str]:
    """Extract balanced SQLite CHECK expressions from a CREATE TABLE statement."""
    expressions = []
    for match in re.finditer(r"\bCHECK\s*\(", table_sql, re.IGNORECASE):
        opening = table_sql.find("(", match.start())
        depth = 0
        quote = None
        index = opening
        while index < len(table_sql):
            character = table_sql[index]
            if quote is not None:
                if character == quote:
                    if index + 1 < len(table_sql) and table_sql[index + 1] == quote:
                        index += 1
                    else:
                        quote = None
            elif character in {"'", '"'}:
                quote = character
            elif character == "(":
                depth += 1
            elif character == ")":
                depth -= 1
                if depth == 0:
                    expressions.append(table_sql[match.start():index + 1])
                    break
            index += 1
    return expressions


def _require_tables(conn, *, backend: str) -> None:
    required = {
        "scan_authorization_requests",
        "scan_authorization_operations",
        "organizations",
        "execution_requests",
        "execution_decisions",
        "execution_runs",
    }
    if backend == "sqlite":
        actual = {
            row["name"] for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
    else:
        actual = {
            row["table_name"] for row in conn.execute(
                "SELECT table_name FROM information_schema.tables "
                "WHERE table_schema=current_schema()"
            ).fetchall()
        }
    missing = required - actual
    if missing:
        raise RuntimeError(f"scan request v13 schema is missing required tables: {sorted(missing)!r}")


def _sqlite_index_columns(conn, index_name: str) -> list[str | None]:
    escaped = index_name.replace("'", "''")
    rows = conn.execute(f"PRAGMA index_info('{escaped}')").fetchall()
    return [row["name"] for row in sorted(rows, key=lambda row: row["seqno"])]


def _sqlite_indexes(conn, table: str) -> list[dict]:
    indexes = []
    for row in conn.execute(f"PRAGMA index_list({table})").fetchall():
        index = dict(row)
        index["columns"] = _sqlite_index_columns(conn, str(row["name"]))
        indexes.append(index)
    return indexes


def _require_sqlite_unique_index(conn, table: str, columns: tuple[str, ...], label: str) -> None:
    matches = [
        index for index in _sqlite_indexes(conn, table)
        if bool(index.get("unique"))
        and not bool(index.get("partial"))
        and index["columns"] == list(columns)
    ]
    if len(matches) != 1:
        raise RuntimeError(
            f"scan request v13 {label} unique index is missing, duplicate, or malformed"
        )


def _sqlite_foreign_keys(conn, table: str) -> list[tuple[tuple[str, ...], str, tuple[str, ...]]]:
    rows = conn.execute(f"PRAGMA foreign_key_list({table})").fetchall()
    grouped: dict[int, list] = {}
    for row in rows:
        grouped.setdefault(int(row["id"]), []).append(row)
    return [
        (
            tuple(row["from"] for row in sorted(items, key=lambda item: item["seq"])),
            str(items[0]["table"]),
            tuple(row["to"] for row in sorted(items, key=lambda item: item["seq"])),
        )
        for items in grouped.values()
    ]


def _require_sqlite_foreign_key(
    conn,
    table: str,
    expected: tuple[tuple[str, ...], str, tuple[str, ...]],
    label: str,
) -> None:
    matches = [foreign_key for foreign_key in _sqlite_foreign_keys(conn, table) if foreign_key == expected]
    if len(matches) != 1:
        raise RuntimeError(
            f"scan request v13 {label} foreign key is missing, duplicate, or malformed"
        )


def _verify_sqlite_schema(conn) -> None:
    request_columns = {
        row["name"]: row for row in conn.execute(
            "PRAGMA table_info(scan_authorization_requests)"
        ).fetchall()
    }
    for column in _REQUIRED_REQUEST_COLUMNS:
        definition = request_columns.get(column)
        if definition is None or str(definition["type"]).strip().lower() != "text" or not bool(definition["notnull"]):
            raise RuntimeError(f"scan request v13 required request column {column!r} is missing or malformed")

    operation_columns = conn.execute("PRAGMA table_info(scan_authorization_operations)").fetchall()
    operation_primary_key = [
        row["name"] for row in sorted(operation_columns, key=lambda row: row["pk"]) if row["pk"]
    ]
    if operation_primary_key != list(_REQUIRED_OPERATION_PRIMARY_KEY):
        raise RuntimeError("scan authorization migration v13 operation key is not parent-scoped")

    _require_sqlite_unique_index(
        conn,
        "scan_authorization_requests",
        ("scan_request_id", "organization_id"),
        "parent identity",
    )
    _require_sqlite_unique_index(
        conn,
        "scan_authorization_requests",
        ("organization_id", "creation_idempotency_key"),
        "tenant idempotency",
    )
    for columns in _REQUIRED_OPERATION_UNIQUE_KEYS:
        _require_sqlite_unique_index(conn, "scan_authorization_operations", columns, f"{columns!r}")

    for local_columns, parent_table, parent_columns in _REQUIRED_OPERATION_FOREIGN_KEYS:
        _require_sqlite_foreign_key(
            conn,
            "scan_authorization_operations",
            (local_columns, parent_table, parent_columns),
            f"operation {local_columns!r}->{parent_table!r}",
        )
    for local_columns, parent_table, parent_columns in _REQUIRED_REQUEST_FOREIGN_KEYS:
        _require_sqlite_foreign_key(
            conn,
            "scan_authorization_requests",
            (local_columns, parent_table, parent_columns),
            f"request {local_columns!r}->{parent_table!r}",
        )

    table_sql = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='scan_authorization_operations'"
    ).fetchone()
    checks = [] if table_sql is None else _sqlite_check_expressions(str(table_sql["sql"] or ""))
    matches = [
        check for check in checks
        if _normalized_sql(check) == _normalized_sql(_CHILD_LINK_CHECK)
    ]
    if len(matches) != 1:
        raise RuntimeError("scan request v13 child-link all-or-none CHECK constraint is missing or malformed")
    if conn.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
        raise RuntimeError("scan request v13 requires SQLite foreign-key enforcement")
    if conn.execute("PRAGMA foreign_key_check").fetchall():
        raise RuntimeError("scan request v13 contains an orphaned foreign-key row")


def _postgres_indexes(conn, table: str) -> list[dict]:
    return [
        dict(row) for row in conn.execute(
            """
            SELECT i.relname AS index_name, am.amname AS access_method,
                   x.indisprimary, x.indisunique, x.indpred,
                   x.indisvalid, x.indisready, x.indnkeyatts, x.indnatts,
                   array_agg(a.attname ORDER BY key_cols.ordinality) AS columns
            FROM pg_class i
            JOIN pg_index x ON x.indexrelid=i.oid
            JOIN pg_class t ON t.oid=x.indrelid
            JOIN pg_namespace n ON n.oid=t.relnamespace
            JOIN pg_am am ON am.oid=i.relam
            JOIN unnest(x.indkey) WITH ORDINALITY AS key_cols(attnum, ordinality)
              ON key_cols.ordinality <= x.indnkeyatts
            JOIN pg_attribute a ON a.attrelid=t.oid AND a.attnum=key_cols.attnum
            WHERE t.relname=? AND n.nspname=current_schema()
            GROUP BY i.oid, i.relname, am.amname, x.indisprimary,
                     x.indisunique, x.indpred, x.indisvalid, x.indisready,
                     x.indnkeyatts, x.indnatts
            """,
            (table,),
        ).fetchall()
    ]


def _require_postgres_unique_index(conn, table: str, columns: tuple[str, ...], label: str) -> None:
    matches = [
        index for index in _postgres_indexes(conn, table)
        if bool(index["indisunique"])
        and index["indpred"] is None
        and list(index["columns"] or []) == list(columns)
        and int(index["indnkeyatts"]) == int(index["indnatts"]) == len(columns)
    ]
    if len(matches) != 1:
        raise RuntimeError(
            f"scan request v13 {label} unique index is missing, duplicate, or malformed"
        )
    index = matches[0]
    if index["access_method"] != "btree" or not index["indisvalid"] or not index["indisready"]:
        raise RuntimeError(f"scan request v13 {label} unique index is not ready and valid")


def _postgres_foreign_keys(conn, table: str) -> list[tuple[tuple[str, ...], str, tuple[str, ...], bool]]:
    rows = conn.execute(
        """
        SELECT pt.relname AS parent_table, c.convalidated,
               array_agg(a.attname ORDER BY local_cols.ordinality) AS local_columns,
               array_agg(pa.attname ORDER BY local_cols.ordinality) AS parent_columns
        FROM pg_constraint c
        JOIN pg_class t ON t.oid=c.conrelid
        JOIN pg_class pt ON pt.oid=c.confrelid
        JOIN pg_namespace n ON n.oid=t.relnamespace
        JOIN pg_namespace pn ON pn.oid=pt.relnamespace
        JOIN unnest(c.conkey) WITH ORDINALITY AS local_cols(attnum, ordinality) ON TRUE
        JOIN pg_attribute a ON a.attrelid=t.oid AND a.attnum=local_cols.attnum
        JOIN unnest(c.confkey) WITH ORDINALITY AS parent_cols(attnum, ordinality)
          ON parent_cols.ordinality=local_cols.ordinality
        JOIN pg_attribute pa ON pa.attrelid=pt.oid AND pa.attnum=parent_cols.attnum
        WHERE t.relname=? AND n.nspname=current_schema() AND pn.nspname=current_schema()
          AND c.contype='f'
        GROUP BY c.oid, pt.relname, c.convalidated
        """,
        (table,),
    ).fetchall()
    return [
        (
            tuple(row["local_columns"] or []),
            str(row["parent_table"]),
            tuple(row["parent_columns"] or []),
            bool(row["convalidated"]),
        )
        for row in rows
    ]


def _require_postgres_foreign_key(
    conn,
    table: str,
    expected: tuple[tuple[str, ...], str, tuple[str, ...]],
    label: str,
) -> None:
    matches = [
        foreign_key for foreign_key in _postgres_foreign_keys(conn, table)
        if foreign_key[:3] == expected
    ]
    if len(matches) != 1 or not matches[0][3]:
        raise RuntimeError(
            f"scan request v13 {label} foreign key is missing, duplicate, or unvalidated"
        )


def _verify_postgres_schema(conn) -> None:
    request_columns = {
        row["column_name"]: row for row in conn.execute(
            """
            SELECT column_name, data_type, is_nullable
            FROM information_schema.columns
            WHERE table_schema=current_schema() AND table_name='scan_authorization_requests'
            """
        ).fetchall()
    }
    for column in _REQUIRED_REQUEST_COLUMNS:
        definition = request_columns.get(column)
        if definition is None or str(definition["data_type"]).lower() != "text" or definition["is_nullable"] != "NO":
            raise RuntimeError(f"scan request v13 required request column {column!r} is missing or malformed")

    operation_primary_keys = [
        index for index in _postgres_indexes(conn, "scan_authorization_operations")
        if index["indisprimary"]
    ]
    if len(operation_primary_keys) != 1:
        raise RuntimeError("scan authorization migration v13 operation primary key is missing or duplicated")
    primary_key = operation_primary_keys[0]
    if (
        list(primary_key["columns"] or []) != list(_REQUIRED_OPERATION_PRIMARY_KEY)
        or int(primary_key["indnkeyatts"]) != len(_REQUIRED_OPERATION_PRIMARY_KEY)
        or int(primary_key["indnatts"]) != len(_REQUIRED_OPERATION_PRIMARY_KEY)
    ):
        raise RuntimeError("scan authorization migration v13 operation key is not parent-scoped")
    if not primary_key["indisvalid"] or not primary_key["indisready"]:
        raise RuntimeError("scan request v13 operation primary key is not ready and valid")

    _require_postgres_unique_index(
        conn,
        "scan_authorization_requests",
        ("scan_request_id", "organization_id"),
        "parent identity",
    )
    _require_postgres_unique_index(
        conn,
        "scan_authorization_requests",
        ("organization_id", "creation_idempotency_key"),
        "tenant idempotency",
    )
    for columns in _REQUIRED_OPERATION_UNIQUE_KEYS:
        _require_postgres_unique_index(conn, "scan_authorization_operations", columns, f"{columns!r}")

    for local_columns, parent_table, parent_columns in _REQUIRED_OPERATION_FOREIGN_KEYS:
        _require_postgres_foreign_key(
            conn,
            "scan_authorization_operations",
            (local_columns, parent_table, parent_columns),
            f"operation {local_columns!r}->{parent_table!r}",
        )
    for local_columns, parent_table, parent_columns in _REQUIRED_REQUEST_FOREIGN_KEYS:
        _require_postgres_foreign_key(
            conn,
            "scan_authorization_requests",
            (local_columns, parent_table, parent_columns),
            f"request {local_columns!r}->{parent_table!r}",
        )

    checks = conn.execute(
        """
        SELECT c.convalidated, pg_get_constraintdef(c.oid) AS definition
        FROM pg_constraint c
        JOIN pg_class t ON t.oid=c.conrelid
        JOIN pg_namespace n ON n.oid=t.relnamespace
        WHERE t.relname='scan_authorization_operations'
          AND n.nspname=current_schema() AND c.contype='c'
        """
    ).fetchall()
    matches = [
        check for check in checks
        if _normalized_sql(check["definition"]) == _normalized_sql(_CHILD_LINK_CHECK)
    ]
    if len(matches) != 1 or not matches[0]["convalidated"]:
        raise RuntimeError("scan request v13 child-link all-or-none CHECK constraint is missing, duplicate, or unvalidated")


def verify_schema(conn, *, backend: str) -> None:
    """Verify every v13-owned identity, tenant binding, and readiness invariant."""
    if backend not in {"sqlite", "postgresql"}:
        raise RuntimeError("scan request v13: unsupported database backend")
    _require_tables(conn, backend=backend)
    if backend == "sqlite":
        _verify_sqlite_schema(conn)
    else:
        _verify_postgres_schema(conn)


def apply_schema(conn, *, backend: str) -> None:
    """Apply only inside the coordinator transaction; reject unresolved legacy data."""
    if backend not in {"sqlite", "postgresql"}:
        raise RuntimeError("scan request v13: unsupported database backend")
    if backend == "sqlite":
        if not isinstance(conn, sqlite3.Connection) or not conn.in_transaction:
            raise RuntimeError("scan request v13 requires an active SQLite transaction")
        if conn.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
            raise RuntimeError("scan request v13 requires SQLite foreign-key enforcement")
    else:
        # Serialize parent and operation changes while checking and rebuilding.
        conn.execute("LOCK TABLE scan_authorization_requests, scan_authorization_operations IN ACCESS EXCLUSIVE MODE")

    if backend == "sqlite":
        request_columns = {row["name"] for row in conn.execute("PRAGMA table_info(scan_authorization_requests)").fetchall()}
        operation_columns = conn.execute("PRAGMA table_info(scan_authorization_operations)").fetchall()
        operation_key = [row["name"] for row in sorted(operation_columns, key=lambda row: row["pk"]) if row["pk"]]
        if {"manifest_json", "creation_idempotency_key", "creation_fingerprint"}.issubset(request_columns) and operation_key == ["scan_request_id", "organization_id", "operation_id"]:
            verify_schema(conn, backend=backend)
            return
    else:
        request_columns = {
            row["column_name"] for row in conn.execute(
                """SELECT column_name FROM information_schema.columns
                   WHERE table_schema=current_schema() AND table_name='scan_authorization_requests'"""
            ).fetchall()
        }
        operation_key = [
            row["column_name"] for row in conn.execute("""
                SELECT a.attname AS column_name
                FROM pg_class t
                JOIN pg_index i ON i.indrelid=t.oid AND i.indisprimary
                JOIN pg_namespace n ON n.oid=t.relnamespace
                JOIN unnest(i.indkey) WITH ORDINALITY AS key_cols(attnum, ordinality) ON TRUE
                JOIN pg_attribute a ON a.attrelid=t.oid AND a.attnum=key_cols.attnum
                WHERE t.relname='scan_authorization_operations'
                  AND n.nspname=current_schema()
                ORDER BY key_cols.ordinality
            """).fetchall()
        ]
        if {"manifest_json", "creation_idempotency_key", "creation_fingerprint"}.issubset(request_columns) and operation_key == list(_REQUIRED_OPERATION_PRIMARY_KEY):
            verify_schema(conn, backend=backend)
            return

    orphan = conn.execute("""SELECT o.operation_id FROM scan_authorization_operations o
        LEFT JOIN scan_authorization_requests p
          ON p.scan_request_id=o.scan_request_id AND p.organization_id=o.organization_id
        WHERE p.scan_request_id IS NULL LIMIT 1""").fetchone()
    if orphan:
        raise RuntimeError("scan request v13: orphaned or cross-tenant operation; reconciliation required")
    duplicate = conn.execute("""SELECT scan_request_id FROM scan_authorization_operations
        GROUP BY scan_request_id, organization_id, operation_id
        HAVING COUNT(*) > 1 LIMIT 1""").fetchone()
    if duplicate:
        raise RuntimeError("scan request v13: duplicate operation identity; reconciliation required")
    # v12 never persisted sufficient canonical manifest material or a creation
    # idempotency key. Even an apparently complete child cannot recover them.
    if conn.execute("SELECT scan_request_id FROM scan_authorization_requests LIMIT 1").fetchone():
        raise RuntimeError(
            "scan request v13: legacy manifest/idempotency material is missing; "
            "preserve requests and obtain operator reconciliation before upgrading"
        )

    conn.execute(OPERATION_TABLE_SQL)
    columns = ", ".join(OPERATION_COLUMNS)
    conn.execute(f"INSERT INTO scan_authorization_operations_v13 ({columns}) SELECT {columns} FROM scan_authorization_operations")
    conn.execute("DROP TABLE scan_authorization_operations")
    conn.execute("ALTER TABLE scan_authorization_operations_v13 RENAME TO scan_authorization_operations")
    for column in ("manifest_json", "creation_idempotency_key", "creation_fingerprint"):
        conn.execute(f"ALTER TABLE scan_authorization_requests ADD COLUMN {column} TEXT NOT NULL")
    conn.execute("CREATE UNIQUE INDEX scan_request_creation_idempotency_uq ON scan_authorization_requests(organization_id, creation_idempotency_key)")
    verify_schema(conn, backend=backend)
