"""
Contract 04, 05 & 06 JSON Raw Audit Report Exporter with Mandatory Secret Masking.
"""

from __future__ import annotations
import json
from app.core.models import ScanJob, mask_secret


def export_scan_to_json(scan_job: ScanJob) -> str:
    """
    Serializes complete ScanJob model into an indented JSON string,
    applying mandatory secret masking to sensitive credentials.
    """
    data = json.loads(scan_job.model_dump_json())
    if "findings" in data:
        for f in data["findings"]:
            cat = str(f.get("category", "")).lower()
            chk = str(f.get("check_id", "")).lower()
            if "secret" in cat or "secret" in chk or "key" in cat:
                if "evidence" in f and isinstance(f["evidence"], dict) and "observed_value" in f["evidence"]:
                    f["evidence"]["observed_value"] = mask_secret(f["evidence"]["observed_value"])
    return json.dumps(data, indent=2)
