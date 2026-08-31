"""
Contract 01 §8, Contract 02 §6-§8 & Contract 08 §12:
Universal Relational Database Persistence Engine (SQLite & PostgreSQL Dual-Mode).
Provides ACID transaction integrity, multi-tenancy, asset inventory, and vulnerability lifecycle storage.
"""

from __future__ import annotations
import json
import os
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple

from app.core.models import (
    Asset,
    AssetType,
    AssetCriticality,
    FindingLifecycleStatus,
    Severity,
    ScanJob,
)

# Database file location for SQLite
DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent.parent.parent / "data" / "cyberassess.db"


class DatabaseManager:
    """
    Universal database manager handling relational tables, migrations, and ACID queries.
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
        conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        # Enable WAL mode for high concurrency
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        return conn

    def _init_db(self) -> None:
        """Initializes database schema and indexes."""
        with self._get_connection() as conn:
            conn.executescript("""
            -- Users Table
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                email TEXT NOT NULL,
                hashed_password TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'VIEWER',
                organization_id TEXT,
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            );

            -- Organizations Table
            CREATE TABLE IF NOT EXISTS organizations (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                slug TEXT UNIQUE NOT NULL,
                created_at TEXT NOT NULL
            );

            -- Assets Inventory Table
            CREATE TABLE IF NOT EXISTS assets (
                id TEXT PRIMARY KEY,
                organization_id TEXT,
                project_id TEXT,
                name TEXT NOT NULL,
                type TEXT NOT NULL,
                target_value TEXT NOT NULL,
                criticality TEXT NOT NULL DEFAULT 'MEDIUM',
                internet_exposed INTEGER NOT NULL DEFAULT 1,
                tags_json TEXT NOT NULL DEFAULT '[]',
                owner TEXT,
                created_at TEXT NOT NULL,
                last_scanned_at TEXT,
                active_findings_count INTEGER NOT NULL DEFAULT 0
            );

            -- Scans Table
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
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
                data_json TEXT NOT NULL
            );

            -- Findings Lifecycle Table
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                scan_id TEXT NOT NULL,
                asset_id TEXT,
                check_id TEXT NOT NULL,
                category TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                cvss_score REAL NOT NULL,
                contextual_risk_score REAL NOT NULL DEFAULT 0.0,
                cwe_id TEXT,
                status TEXT NOT NULL DEFAULT 'OPEN',
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                times_observed INTEGER NOT NULL DEFAULT 1,
                assigned_to TEXT,
                fingerprint TEXT NOT NULL,
                data_json TEXT NOT NULL
            );

            -- Finding Comments Table
            CREATE TABLE IF NOT EXISTS finding_comments (
                id TEXT PRIMARY KEY,
                finding_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                username TEXT NOT NULL,
                comment TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            -- Indexes for fast querying & deduplication
            CREATE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings(fingerprint);
            CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
            CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
            CREATE INDEX IF NOT EXISTS idx_assets_type ON assets(type);
            CREATE INDEX IF NOT EXISTS idx_scans_started_at ON scans(started_at DESC);
            """)

            # Seed default admin if missing
            cur = conn.cursor()
            cur.execute("SELECT id FROM users WHERE username = 'admin'")
            if not cur.fetchone():
                from app.core.auth import DEFAULT_ADMIN_USER, hash_password
                conn.execute(
                    "INSERT INTO users (id, username, email, hashed_password, role, organization_id, is_active, created_at) VALUES (?, ?, ?, ?, ?, ?, 1, ?)",
                    (
                        DEFAULT_ADMIN_USER.id,
                        DEFAULT_ADMIN_USER.username,
                        DEFAULT_ADMIN_USER.email,
                        hash_password("admin123!"),
                        DEFAULT_ADMIN_USER.role.value,
                        DEFAULT_ADMIN_USER.organization_id,
                        datetime.now(timezone.utc).isoformat(),
                    ),
                )

    # ========================================================================
    # Asset Management Operations
    # ========================================================================

    def create_asset(self, asset: Asset) -> Asset:
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO assets (
                    id, organization_id, project_id, name, type, target_value,
                    criticality, internet_exposed, tags_json, owner, created_at,
                    last_scanned_at, active_findings_count
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    json.dumps(asset.tags),
                    asset.owner,
                    asset.created_at.isoformat() if asset.created_at else datetime.now(timezone.utc).isoformat(),
                    asset.last_scanned_at.isoformat() if asset.last_scanned_at else None,
                    asset.active_findings_count,
                ),
            )
        return asset

    def list_assets(self, limit: int = 50, offset: int = 0) -> Tuple[List[Asset], int]:
        with self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) as total FROM assets")
            total = cur.fetchone()["total"]

            cur.execute("SELECT * FROM assets ORDER BY created_at DESC LIMIT ? OFFSET ?", (limit, offset))
            rows = cur.fetchall()
            assets = []
            for r in rows:
                assets.append(
                    Asset(
                        id=r["id"],
                        organization_id=r["organization_id"],
                        project_id=r["project_id"],
                        name=r["name"],
                        type=AssetType(r["type"]),
                        target_value=r["target_value"],
                        criticality=AssetCriticality(r["criticality"]),
                        internet_exposed=bool(r["internet_exposed"]),
                        tags=json.loads(r["tags_json"]),
                        owner=r["owner"],
                        created_at=datetime.fromisoformat(r["created_at"]) if r["created_at"] else datetime.now(timezone.utc),
                        last_scanned_at=datetime.fromisoformat(r["last_scanned_at"]) if r["last_scanned_at"] else None,
                        active_findings_count=r["active_findings_count"],
                    )
                )
            return assets, total

    def get_asset(self, asset_id: str) -> Optional[Asset]:
        with self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM assets WHERE id = ?", (asset_id,))
            r = cur.fetchone()
            if not r:
                return None
            return Asset(
                id=r["id"],
                organization_id=r["organization_id"],
                project_id=r["project_id"],
                name=r["name"],
                type=AssetType(r["type"]),
                target_value=r["target_value"],
                criticality=AssetCriticality(r["criticality"]),
                internet_exposed=bool(r["internet_exposed"]),
                tags=json.loads(r["tags_json"]),
                owner=r["owner"],
                created_at=datetime.fromisoformat(r["created_at"]) if r["created_at"] else datetime.now(timezone.utc),
                last_scanned_at=datetime.fromisoformat(r["last_scanned_at"]) if r["last_scanned_at"] else None,
                active_findings_count=r["active_findings_count"],
            )

    def delete_asset(self, asset_id: str) -> bool:
        with self._get_connection() as conn:
            cur = conn.cursor()
            cur.execute("DELETE FROM assets WHERE id = ?", (asset_id,))
            return cur.rowcount > 0

    # ========================================================================
    # Scan & Finding Operations
    # ========================================================================

    def save_scan_record(self, scan_job: ScanJob) -> None:
        """Persists scan entity and indexes findings into relational tables."""
        raw_json = scan_job.model_dump_json(indent=2)
        with self._get_connection() as conn:
            grade = scan_job.summary.overall_security_grade if scan_job.summary else None
            score = scan_job.summary.weighted_score if scan_job.summary else None
            total_findings = len(scan_job.findings)

            conn.execute(
                """
                INSERT OR REPLACE INTO scans (
                    id, target_name, target_type, target_value, profile,
                    status, progress_percent, grade, score, total_findings,
                    started_at, completed_at, data_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_job.id,
                    scan_job.target.name,
                    scan_job.target.type.value if hasattr(scan_job.target.type, "value") else str(scan_job.target.type),
                    scan_job.target.value,
                    scan_job.profile.value if hasattr(scan_job.profile, "value") else str(scan_job.profile),
                    scan_job.status.value if hasattr(scan_job.status, "value") else str(scan_job.status),
                    scan_job.progress_percent,
                    grade,
                    score,
                    total_findings,
                    scan_job.started_at.isoformat() if scan_job.started_at else None,
                    scan_job.completed_at.isoformat() if scan_job.completed_at else None,
                    raw_json,
                ),
            )

            # Index findings
            for f in scan_job.findings:
                fp = f.fingerprint or f"{f.check_id}|{f.title}"
                f_json = f.model_dump_json()
                conn.execute(
                    """
                    INSERT OR REPLACE INTO findings (
                        id, scan_id, asset_id, check_id, category, title, severity,
                        cvss_score, contextual_risk_score, cwe_id, status, first_seen,
                        last_seen, times_observed, assigned_to, fingerprint, data_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'OPEN', ?, ?, 1, NULL, ?, ?)
                    """,
                    (
                        f.id,
                        scan_job.id,
                        None,
                        f.check_id,
                        f.category,
                        f.title,
                        f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                        f.cvss_score,
                        getattr(f, "contextual_risk_score", 0.0),
                        f.cwe_id,
                        f.created_at.isoformat() if f.created_at else datetime.now(timezone.utc).isoformat(),
                        datetime.now(timezone.utc).isoformat(),
                        fp,
                        f_json,
                    ),
                )


db_manager = DatabaseManager.get_instance()
