"""
Contract 02 & 04 Local File Storage Persistence Layer.
"""

from __future__ import annotations
import json
import logging
from pathlib import Path
from typing import Optional, List, Tuple
from app.core.models import ScanJob
from app.core.db import db_manager

logger = logging.getLogger("cyberassess.storage")

# Default storage directory under project root: data/scans/
DEFAULT_STORAGE_DIR = Path(__file__).resolve().parent.parent.parent.parent / "data" / "scans"


def get_storage_dir(custom_path: Optional[Path] = None) -> Path:
    """
    Returns the resolved storage path and ensures the directory exists.
    """
    storage_path = custom_path or DEFAULT_STORAGE_DIR
    storage_path.mkdir(parents=True, exist_ok=True)
    return storage_path


def save_scan(scan_job: ScanJob, storage_dir: Optional[Path] = None) -> None:
    """
    Authoritatively persists ScanJob and correlated findings to relational database,
    and caches a formatted JSON snapshot to disk for export convenience.
    """
    # 1. Authoritative persistence in Relational Database
    db_manager.save_scan_record(scan_job)

    # 2. Cache JSON artifact to disk
    try:
        target_dir = get_storage_dir(storage_dir)
        file_path = target_dir / f"{scan_job.id}.json"
        json_data = scan_job.model_dump_json(indent=2)
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(json_data)
    except OSError as exc:
        # The database write above is authoritative.  The JSON file is only
        # an export/cache artifact, so a cache failure must be observable but
        # must never cause a second persistence source or silent data loss.
        logger.warning(
            "Scan JSON cache write failed for scan_id=%s error_type=%s",
            scan_job.id,
            type(exc).__name__,
        )


def get_scan(
    scan_id: str,
    storage_dir: Optional[Path] = None,
    organization_id: Optional[str] = None,
) -> Optional[ScanJob]:
    """
    Retrieves a ScanJob entity from authoritative database persistence. JSON files
    are export caches and are never used to resurrect authoritative state.
    """
    # JSON snapshots are export/cache artifacts only.  They must never
    # resurrect authoritative state when the relational record is absent.
    return db_manager.get_scan_record(scan_id, organization_id=organization_id)


def list_scans(
    limit: int = 50,
    offset: int = 0,
    storage_dir: Optional[Path] = None,
    organization_id: Optional[str] = None,
) -> Tuple[List[ScanJob], int]:
    """
    Returns a paginated list of all stored ScanJobs sorted by creation/start time descending.
    """
    # JSON snapshots are not a query source.  Listing is always backed by the
    # relational database, regardless of where export/cache files are stored.
    return db_manager.list_scans_records(limit=limit, offset=offset, organization_id=organization_id)


def delete_scan(
    scan_id: str,
    storage_dir: Optional[Path] = None,
    organization_id: Optional[str] = None,
) -> bool:
    """
    Deletes the scan record from authoritative database and removes cached JSON file.
    """
    db_deleted = db_manager.delete_scan_record(scan_id, organization_id=organization_id)
    target_dir = get_storage_dir(storage_dir)
    file_path = target_dir / f"{scan_id}.json"
    if file_path.exists() and file_path.is_file():
        try:
            file_path.unlink()
        except OSError as exc:
            logger.warning(
                "Scan JSON cache removal failed for scan_id=%s error_type=%s",
                scan_id,
                type(exc).__name__,
            )
    # Only the relational deletion is authoritative.  A stale cache file
    # must never turn a missing database row into a reported deletion.
    return db_deleted
