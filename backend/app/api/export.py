"""
Contract 04 §1.6 & Contract 08 §1:
Multi-Format Export Endpoints (HTML, SARIF, JSON, CycloneDX, SPDX).
Enforces multi-tenant authorization, evidence masking, and audit logging.
"""

from __future__ import annotations
from fastapi import APIRouter, HTTPException, Depends, Response
from fastapi.responses import JSONResponse

from app.core.storage import get_scan
from app.core.orchestrator import orchestrator
from app.core.auth import require_permission, UserProfile, authorize_scan_access
from app.core.models import AuditEvent, AuditAction, PrincipalType
from app.core.db import db_manager
from app.exporters.html_exporter import export_scan_to_html
from app.exporters.sarif_exporter import export_scan_to_sarif
from app.exporters.json_exporter import export_scan_to_json
from app.exporters.sbom_cyclonedx import export_cyclonedx_sbom
from app.exporters.sbom_spdx import export_spdx_sbom

router = APIRouter()


def _organization_scope(user: UserProfile) -> str | None:
    if user.principal_type == PrincipalType.SYSTEM_PRINCIPAL and user.role.value == "ADMIN":
        return None
    return user.organization_id


@router.get("/{scan_id}/export/html", summary="Export Standalone Interactive HTML Report")
async def export_html_report(
    scan_id: str,
    current_user: UserProfile = Depends(require_permission(required_scope="report:read")),
):
    """
    Downloads a self-contained, standalone single-file HTML report with zero external dependencies.
    Enforces tenant authorization.
    """
    job = orchestrator.get_active_job(scan_id, organization_id=_organization_scope(current_user))
    if not job or not authorize_scan_access(current_user, job, action="read"):
        raise HTTPException(status_code=404, detail=f"Scan job '{scan_id}' not found.")

    html_content = export_scan_to_html(job)
    filename = f"security-report-{scan_id[:8]}.html"

    db_manager.record_audit_event(
        AuditEvent(
            actor=current_user.username,
            organization_id=current_user.organization_id,
            action=AuditAction.REPORT_GENERATED,
            object_type="scan",
            object_id=scan_id,
            result="SUCCESS",
            details={"format": "html"},
        )
    )

    return Response(
        content=html_content,
        media_type="text/html; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"'
        },
    )


@router.get("/{scan_id}/export/sarif", summary="Export OASIS SARIF v2.1.0 JSON Report")
async def export_sarif_report(
    scan_id: str,
    current_user: UserProfile = Depends(require_permission(required_scope="report:read")),
):
    """
    Downloads an OASIS SARIF v2.1.0 standardized security report for GitHub/GitLab Code Scanning.
    Enforces tenant authorization.
    """
    job = orchestrator.get_active_job(scan_id, organization_id=_organization_scope(current_user))
    if not job or not authorize_scan_access(current_user, job, action="read"):
        raise HTTPException(status_code=404, detail=f"Scan job '{scan_id}' not found.")

    sarif_data = export_scan_to_sarif(job)
    filename = f"security-report-{scan_id[:8]}.sarif.json"

    db_manager.record_audit_event(
        AuditEvent(
            actor=current_user.username,
            organization_id=current_user.organization_id,
            action=AuditAction.REPORT_GENERATED,
            object_type="scan",
            object_id=scan_id,
            result="SUCCESS",
            details={"format": "sarif"},
        )
    )

    return JSONResponse(
        content=sarif_data,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"'
        },
    )


@router.get("/{scan_id}/export/json", summary="Export Raw Scan JSON")
async def export_raw_json_report(
    scan_id: str,
    current_user: UserProfile = Depends(require_permission(required_scope="report:read")),
):
    """
    Downloads the complete serialized ScanJob data model in JSON format.
    Enforces tenant authorization.
    """
    job = orchestrator.get_active_job(scan_id, organization_id=_organization_scope(current_user))
    if not job or not authorize_scan_access(current_user, job, action="read"):
        raise HTTPException(status_code=404, detail=f"Scan job '{scan_id}' not found.")

    json_str = export_scan_to_json(job)
    filename = f"security-report-{scan_id[:8]}.json"

    db_manager.record_audit_event(
        AuditEvent(
            actor=current_user.username,
            organization_id=current_user.organization_id,
            action=AuditAction.REPORT_GENERATED,
            object_type="scan",
            object_id=scan_id,
            result="SUCCESS",
            details={"format": "json"},
        )
    )

    return Response(
        content=json_str,
        media_type="application/json; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"'
        },
    )


@router.get("/{scan_id}/export/sbom/cyclonedx", summary="Export CycloneDX 1.5 JSON SBOM")
async def export_cyclonedx_sbom_report(
    scan_id: str,
    current_user: UserProfile = Depends(require_permission(required_scope="report:read")),
):
    """
    Downloads a CycloneDX 1.5 standardized Software Bill of Materials (SBOM) JSON.
    Enforces tenant authorization.
    """
    job = orchestrator.get_active_job(scan_id, organization_id=_organization_scope(current_user))
    if not job or not authorize_scan_access(current_user, job, action="read"):
        raise HTTPException(status_code=404, detail=f"Scan job '{scan_id}' not found.")

    sbom_json = export_cyclonedx_sbom(job)
    filename = f"sbom-cyclonedx-{scan_id[:8]}.json"

    db_manager.record_audit_event(
        AuditEvent(
            actor=current_user.username,
            organization_id=current_user.organization_id,
            action=AuditAction.REPORT_GENERATED,
            object_type="scan",
            object_id=scan_id,
            result="SUCCESS",
            details={"format": "cyclonedx"},
        )
    )

    return Response(
        content=sbom_json,
        media_type="application/vnd.cyclonedx+json; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"'
        },
    )
