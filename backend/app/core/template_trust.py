"""Integrity verification for the managed Nuclei template set."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


NUCLEI_TEMPLATES_COMMIT = "83234ce456da3e90dda86dfbc5e605e64a846df3"
NUCLEI_TEMPLATES_ARCHIVE_SHA256 = "5b22a097bf0b828377574a82b98b4ed0d1227b4aae3ff6e3bedf97272e70ccc6"


def _tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            raise ValueError("managed Nuclei template tree contains a non-regular file")
        if path.is_dir():
            continue
        if not path.is_file():
            raise ValueError("managed Nuclei template tree contains a non-regular file")
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(path.read_bytes()).digest())
        digest.update(b"\0")
    return digest.hexdigest()


def verify_managed_nuclei_templates(root: str | Path, trust_record: str | Path) -> bool:
    """Verify the pinned source identity and every managed template file."""
    template_root = Path(root).resolve()
    record_path = Path(trust_record).resolve()
    try:
        if not template_root.is_dir() or not record_path.is_file():
            return False
        record = json.loads(record_path.read_text(encoding="utf-8"))
        if not isinstance(record, dict):
            return False
        return (
            record.get("source_commit") == NUCLEI_TEMPLATES_COMMIT
            and record.get("archive_sha256") == NUCLEI_TEMPLATES_ARCHIVE_SHA256
            and record.get("trust_status") == "VALID"
            and record.get("template_tree_sha256") == _tree_digest(template_root)
        )
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
        return False
