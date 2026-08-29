"""
Contract 04 & 05 JSON Raw Audit Report Exporter.
"""

from __future__ import annotations
import json
from app.core.models import ScanJob


def export_scan_to_json(scan_job: ScanJob) -> str:
    """
    Serializes complete ScanJob model into an indented JSON string.
    """
    return scan_job.model_dump_json(indent=2)
