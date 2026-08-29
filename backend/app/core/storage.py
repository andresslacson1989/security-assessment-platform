"""
Contract 02 & 04 Local File Storage Persistence Layer.
"""

from __future__ import annotations
import json
import os
from pathlib import Path
from typing import Optional, List, Tuple
from app.core.models import ScanJob

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
    Persists a ScanJob entity as formatted JSON to disk.
    """
    target_dir = get_storage_dir(storage_dir)
    file_path = target_dir / f"{scan_job.id}.json"
    
    # Dump Pydantic model to JSON string with indentation
    json_data = scan_job.model_dump_json(indent=2)
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(json_data)


def get_scan(scan_id: str, storage_dir: Optional[Path] = None) -> Optional[ScanJob]:
    """
    Retrieves and parses a ScanJob JSON record from disk by UUID.
    """
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
    target_dir = get_storage_dir(storage_dir)
    scan_files = list(target_dir.glob("*.json"))
    
    scans: List[ScanJob] = []
    for file_path in scan_files:
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            job = ScanJob.model_validate(data)
            scans.append(job)
        except Exception:
            continue

    # Sort descending by started_at or target created_at
    scans.sort(
        key=lambda s: s.started_at or s.target.created_at,
        reverse=True
    )
    
    total_count = len(scans)
    paginated_scans = scans[offset : offset + limit]
    return paginated_scans, total_count


def delete_scan(scan_id: str, storage_dir: Optional[Path] = None) -> bool:
    """
    Deletes the JSON record for the specified scan ID.
    Returns True if deleted, False if file did not exist.
    """
    target_dir = get_storage_dir(storage_dir)
    file_path = target_dir / f"{scan_id}.json"
    
    if file_path.exists() and file_path.is_file():
        file_path.unlink()
        return True
    return False
