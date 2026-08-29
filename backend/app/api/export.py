"""
Contract 04 & 08 Multi-Format Export Endpoints (HTML, SARIF, JSON).
"""

from __future__ import annotations
from fastapi import APIRouter, HTTPException, Response
from fastapi.responses import JSONResponse

from app.core.storage import get_scan
from app.core.orchestrator import orchestrator
from app.exporters.html_exporter import export_scan_to_html
from app.exporters.sarif_exporter import export_scan_to_sarif
from app.exporters.json_exporter import export_scan_to_json

router = APIRouter()


@router.get("/{scan_id}/export/html", summary="Export Standalone Interactive HTML Report")
async def export_html_report(scan_id: str):
    """
    Downloads a self-contained, standalone single-file HTML report with zero external dependencies.
    """
    job = orchestrator.get_active_job(scan_id) or get_scan(scan_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Scan job '{scan_id}' not found.")

    html_content = export_scan_to_html(job)
    filename = f"security-report-{scan_id[:8]}.html"

    return Response(
        content=html_content,
        media_type="text/html; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"'
        },
    )


@router.get("/{scan_id}/export/sarif", summary="Export OASIS SARIF v2.1.0 JSON Report")
async def export_sarif_report(scan_id: str):
    """
    Downloads an OASIS SARIF v2.1.0 standardized security report for GitHub/GitLab Code Scanning.
    """
    job = orchestrator.get_active_job(scan_id) or get_scan(scan_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Scan job '{scan_id}' not found.")

    sarif_data = export_scan_to_sarif(job)
    filename = f"security-report-{scan_id[:8]}.sarif.json"

    return JSONResponse(
        content=sarif_data,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"'
        },
    )


@router.get("/{scan_id}/export/json", summary="Export Raw Scan JSON")
async def export_raw_json_report(scan_id: str):
    """
    Downloads the complete serialized ScanJob data model in JSON format.
    """
    job = orchestrator.get_active_job(scan_id) or get_scan(scan_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Scan job '{scan_id}' not found.")

    json_str = export_scan_to_json(job)
    filename = f"security-report-{scan_id[:8]}.json"

    return Response(
        content=json_str,
        media_type="application/json; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"'
        },
    )
