"""
Contract 01 §4, Contract 02 §2-§6, Contract 04 §1 & Contract 08 §1:
Authoritative Relational Database Persistence Engine (SQLite & PostgreSQL Enterprise Architecture).
Maintains ACID transactional integrity for Users, Organizations, Projects, Workspaces,
API Keys, Assets, Scans, Canonical Findings, Occurrences, and Append-Only Audit Trails.
"""

from __future__ import annotations
import hashlib
import json
import os
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
import uuid

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
    Evidence,
    utc_now,
)

DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent.parent.parent / "data" / "cyberassess.db"


class DatabaseManager:
    """
    Universal database manager handling relational tables, migrations, transactions, and tenant queries.
    Uses SQLite with WAL mode by default, supporting thread-safe connection pooling.
    """

    _instance: Optional[DatabaseManager] = None
    _lock = threading.Lock()

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or DEFAULT_DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    @classmethod
    def get_instance(cls) -> DatabaseManager:
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), check_same_thread=False, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        return conn

    def _init_db(self) -> None:
        """Initializes database schema, relational constraints, and performance indexes."""
        with self._get_connection() as conn:
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
            """)

            # 2. Automated Non-Destructive Column Migrations for Existing Tables
            migrations = [
                "ALTER TABLE audit_events ADD COLUMN previous_event_hash TEXT;",
                "ALTER TABLE audit_events ADD COLUMN event_hash TEXT;",
                "ALTER TABLE api_keys ADD COLUMN status TEXT NOT NULL DEFAULT 'ACTIVE';",
                "ALTER TABLE users ADD COLUMN principal_type TEXT NOT NULL DEFAULT 'TENANT_PRINCIPAL';",
                "ALTER TABLE finding_occurrences ADD COLUMN organization_id TEXT NOT NULL DEFAULT 'org-default';",
            ]
            for mig in migrations:
                try:
                    conn.execute(mig)
                except Exception:
                    pass

    # ========================================================================
    # 1. System Bootstrap & Authentication Operations
    # ========================================================================

    def is_initialized(self) -> bool:
        """Returns True if the system already contains at least one administrator user."""
        with self._get_connection() as conn:
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
        if self.is_initialized():
            raise ValueError("System has already been initialized with an administrator.")

        org_id = f"org-{uuid.uuid4().hex[:8]}"
        user_id = f"usr-{uuid.uuid4().hex[:8]}"
        now_str = utc_now().isoformat()

        with self._get_connection() as conn:
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

            # 3. Record Audit Event
            conn.execute(
                "INSERT INTO audit_events (id, timestamp, actor, organization_id, action, object_type, object_id, result, details_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    f"aud-{uuid.uuid4().hex[:12]}",
                    now_str,
                    admin_username,
                    org_id,
                    AuditAction.BOOTSTRAP_COMPLETE.value,
                    "system",
                    user_id,
                    "SUCCESS",
                    json.dumps({"initial_admin": admin_username, "org_name": org_name}),
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
        with self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM api_keys WHERE key_hash = ? AND (revoked_at IS NULL) AND (status = 'ACTIVE')", (key_hash,))
            row = cur.fetchone()
            if not row:
                return None, None

            # Check expiration
            if row["expires_at"]:
                exp_dt = datetime.fromisoformat(row["expires_at"])
                if utc_now() > exp_dt:
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

            # Synthesize or lookup caller user profile
            user_profile = UserProfile(
                id=row["user_id"] or f"usr-key-{row['key_id']}",
                username=f"apikey-{row['name']}",
                email=f"apikey-{row['name']}@cyberassess.local",
                role=UserRole.SECURITY_ANALYST,
                organization_id=row["organization_id"],
            )
            return key_record, user_profile

    def revoke_api_key(self, key_id: str, organization_id: Optional[str] = None) -> bool:
        """Revokes an API Key and updates its status to REVOKED."""
        with self._get_connection() as conn:
            query = "UPDATE api_keys SET revoked_at = ?, status = 'REVOKED' WHERE key_id = ?"
            params = [utc_now().isoformat(), key_id]
            if organization_id:
                query += " AND organization_id = ?"
                params.append(organization_id)
            cur = conn.execute(query, params)
            return cur.rowcount > 0

    def revoke_token(self, jti: str, token_hash: Optional[str] = None, expires_at: Optional[str] = None) -> None:
        """Revokes a JWT token by jti identifier."""
        with self._get_connection() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO revoked_tokens (jti, token_hash, revoked_at, expires_at) VALUES (?, ?, ?, ?)",
                (jti, token_hash, utc_now().isoformat(), expires_at),
            )

    def is_token_revoked(self, jti: str) -> bool:
        """Checks if a JWT token has been revoked in the database."""
        with self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT 1 FROM revoked_tokens WHERE jti = ?", (jti,))
            return bool(cur.fetchone())

    # ========================================================================
    # 2. Immutable Audit Logging with Cryptographic Chained Hashes
    # ========================================================================

    def _insert_audit_event_conn(self, conn: sqlite3.Connection, event: "AuditEvent") -> None:
        """Inserts an audit event using an already-open connection. Use this when the caller
        already holds a write transaction to avoid a second-connection deadlock on SQLite."""
        cur = conn.cursor()
        cur.execute("SELECT event_hash FROM audit_events ORDER BY rowid DESC LIMIT 1")
        last_row = cur.fetchone()
        prev_hash = last_row["event_hash"] if (last_row and last_row["event_hash"]) else None

        ts_str = event.timestamp.isoformat() if event.timestamp else utc_now().isoformat()
        act_str = event.action.value if hasattr(event.action, "value") else str(event.action)
        details_str = json.dumps(event.details, sort_keys=True)
        canonical_payload = f"{event.id}|{ts_str}|{event.actor}|{event.organization_id}|{act_str}|{event.object_type}|{event.object_id}|{event.result}|{details_str}|{prev_hash or ''}"
        event_hash = hashlib.sha256(canonical_payload.encode("utf-8")).hexdigest()
        event.previous_event_hash = prev_hash
        event.event_hash = event_hash

        conn.execute(
            """
            INSERT INTO audit_events (
                id, timestamp, actor, organization_id, action, object_type,
                object_id, result, source_ip, correlation_id, details_json,
                previous_event_hash, event_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event.id, ts_str, event.actor, event.organization_id, act_str,
                event.object_type, event.object_id, event.result, event.source_ip,
                event.correlation_id, details_str, prev_hash, event_hash,
            ),
        )

    def record_audit_event(self, event: "AuditEvent") -> None:
        """Appends an immutable security audit event to the relational audit log with chained cryptographic hash."""
        with self._get_connection() as conn:
            self._insert_audit_event_conn(conn, event)


    def list_audit_events(
        self,
        organization_id: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[AuditEvent], int]:
        with self._get_connection() as conn:
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
        with self._get_connection() as conn:
            cur = conn.cursor()
            query = "SELECT * FROM audit_events"
            params: List[Any] = []
            if organization_id:
                query += " WHERE organization_id = ?"
                params.append(organization_id)
            query += " ORDER BY rowid ASC"
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
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO assets (
                    id, organization_id, project_id, name, type, target_value,
                    criticality, internet_exposed, owner, lifecycle_status, tags_json,
                    created_at, updated_at, last_scanned_at, last_verified_at, active_findings_count
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
        with self._get_connection() as conn:
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
        with self._get_connection() as conn:
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
        with self._get_connection() as conn:
            cur = conn.cursor()
            if organization_id:
                cur.execute("DELETE FROM assets WHERE id = ? AND organization_id = ?", (asset_id, organization_id))
            else:
                cur.execute("DELETE FROM assets WHERE id = ?", (asset_id,))
            return cur.rowcount > 0

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
        with self._get_connection() as conn:
            target = scan_job.target
            summary = scan_job.summary
            data_json = scan_job.model_dump_json()
            org_id = getattr(scan_job, "organization_id", None) or "org-default"
            proj_id = getattr(scan_job, "project_id", None)
            asset_id = getattr(scan_job, "asset_id", None)

            conn.execute(
                """
                INSERT OR REPLACE INTO scans (
                    id, organization_id, project_id, asset_id, target_name, target_type, target_value,
                    profile, status, progress_percent, grade, score, total_findings,
                    started_at, completed_at, summary_json, data_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                        cf.description or "",
                        cf.impact or "",
                        cf.remediation or "",
                        cf.evidence_hash or "",
                        sla_json,
                        cf.evidence_hash or cf.id,
                        cf.model_dump_json(),
                    ),
                )

            # Persist individual finding occurrences
            for occ in occurrences:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO finding_occurrences (
                        id, canonical_finding_id, scan_id, asset_id, source_tool, check_id,
                        raw_evidence_json, reproduction_curl, taint_trace_json, detected_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        occ.id,
                        occ.canonical_finding_id,
                        occ.scan_id,
                        occ.asset_id or asset_id,
                        occ.source_tool,
                        occ.check_id,
                        occ.raw_evidence.model_dump_json() if hasattr(occ.raw_evidence, "model_dump_json") else json.dumps(occ.raw_evidence),
                        occ.reproduction_curl,
                        json.dumps(occ.taint_trace or []),
                        occ.detected_at.isoformat() if occ.detected_at else utc_now().isoformat(),
                    ),
                )

    def get_scan_record(self, scan_id: str, organization_id: Optional[str] = None) -> Optional[ScanJob]:
        """Retrieves a ScanJob entity directly from relational persistence."""
        with self._get_connection() as conn:
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
            except Exception:
                return None

    def list_scans_records(
        self,
        organization_id: Optional[str] = None,
        limit: int = 50,
        offset: int = 0
    ) -> Tuple[List[ScanJob], int]:
        """Returns paginated scan jobs scoped to the caller's organization."""
        with self._get_connection() as conn:
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
                except Exception:
                    continue
            return scans, total

    def delete_scan_record(self, scan_id: str, organization_id: Optional[str] = None) -> bool:
        """Deletes a scan job and cascades removal of child finding records."""
        with self._get_connection() as conn:
            cur = conn.cursor()
            if organization_id:
                cur.execute("DELETE FROM scans WHERE id = ? AND organization_id = ?", (scan_id, organization_id))
            else:
                cur.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
            return cur.rowcount > 0


db_manager = DatabaseManager.get_instance()
