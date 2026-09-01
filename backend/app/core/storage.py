"""
Contract 02 & 04 Local File Storage Persistence Layer.
"""

from __future__ import annotations
import json
import os
from pathlib import Path
from typing import Optional, List, Tuple
from app.core.models import ScanJob
from app.core.db import db_manager

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
    except OSError:
        pass


def get_scan(scan_id: str, storage_dir: Optional[Path] = None) -> Optional[ScanJob]:
    """
    Retrieves a ScanJob entity from authoritative database persistence. JSON files
    are export caches and are never used to resurrect authoritative state.
    """
    if storage_dir is None:
        return db_manager.get_scan_record(scan_id)

    # 2. Fallback to cached JSON file
    target_dir = get_storage_dir(storage_dir)
    file_path = target_dir / f"{scan_id}.json"
    if not file_path.exists() or not file_path.is_file():
        return None

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return ScanJob.model_validate(data)
    except Exception:
        return None


def list_scans(
    limit: int = 50,
    offset: int = 0,
    storage_dir: Optional[Path] = None
) -> Tuple[List[ScanJob], int]:
    """
    Returns a paginated list of all stored ScanJobs sorted by creation/start time descending.
    """
    if storage_dir is None:
        return db_manager.list_scans_records(limit=limit, offset=offset)

    # Fallback / explicit custom directory scan
    target_dir = get_storage_dir(storage_dir)
    scan_files = list(target_dir.glob("*.json"))
    disk_scans: List[ScanJob] = []
    for file_path in scan_files:
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            job = ScanJob.model_validate(data)
            disk_scans.append(job)
        except Exception:
            continue

    disk_scans.sort(
        key=lambda s: s.started_at or s.target.created_at,
        reverse=True
    )
    return disk_scans[offset : offset + limit], len(disk_scans)


def delete_scan(scan_id: str, storage_dir: Optional[Path] = None) -> bool:
    """
    Deletes the scan record from authoritative database and removes cached JSON file.
    """
    db_deleted = db_manager.delete_scan_record(scan_id)
    target_dir = get_storage_dir(storage_dir)
    file_path = target_dir / f"{scan_id}.json"
    file_deleted = False
    if file_path.exists() and file_path.is_file():
        file_path.unlink()
        file_deleted = True
    return db_deleted or file_deleted
