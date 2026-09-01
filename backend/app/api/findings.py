"""
Contract 04 §1.4 & Contract 08 §1:
Canonical Finding Lifecycle, Multi-Tenant Triage & Occurrence History Router.
"""

from __future__ import annotations
import json
import uuid
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, Depends, Query, status
from pydantic import BaseModel, Field

from app.core.models import (
    FindingLifecycleStatus,
    Severity,
    FindingTriageUpdate,
    FindingComment,
    AuditEvent,
    AuditAction,
    PrincipalType,
    utc_now,
)
from app.core.auth import get_current_user, require_dev_or_higher, require_permission, UserProfile, UserRole
from app.core.db import db_manager

router = APIRouter()


def _organization_scope(user: UserProfile) -> Optional[str]:
    if user.principal_type == PrincipalType.SYSTEM_PRINCIPAL and user.role == UserRole.ADMIN:
        return None
    return user.organization_id


class AddCommentRequest(BaseModel):
    comment: str = Field(..., min_length=1, max_length=2000)


@router.get("", summary="Query Canonical Findings Across Tenant Fleet")
@router.get("/", summary="Query Canonical Findings Across Tenant Fleet", include_in_schema=False)
async def list_findings(
    severity: Optional[Severity] = None,
    status_filter: Optional[FindingLifecycleStatus] = Query(None, alias="status"),
    category: Optional[str] = None,
    scan_id: Optional[str] = None,
    asset_id: Optional[str] = None,
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    current_user: UserProfile = Depends(require_permission(required_scope="finding:read")),
) -> Dict[str, Any]:
    """
    Returns filtered canonical finding records scoped strictly to caller's organization.
    """
    with db_manager._connection_scope() as conn:
        cur = conn.cursor()
        query = "SELECT * FROM findings WHERE 1=1"
        params: List[Any] = []

        is_system_admin = (
            current_user.principal_type == PrincipalType.SYSTEM_PRINCIPAL
            and current_user.role == UserRole.ADMIN
        )
        if not is_system_admin:
            query += " AND organization_id = ?"
            params.append(current_user.organization_id)
        if severity:
            query += " AND severity = ?"
            params.append(severity.value)
        if status_filter:
            query += " AND status = ?"
            params.append(status_filter.value)
        if category:
            query += " AND category = ?"
            params.append(category)
        if scan_id:
            query += " AND scan_id = ?"
            params.append(scan_id)
        if asset_id:
            query += " AND asset_id = ?"
            params.append(asset_id)

        # Count total
        count_query = query.replace("SELECT *", "SELECT COUNT(*) as total", 1)
        cur.execute(count_query, params)
        total = cur.fetchone()["total"]

        query += " ORDER BY cvss_score DESC, first_seen DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        cur.execute(query, params)
        rows = cur.fetchall()

        items = []
        for r in rows:
            f_data = json.loads(r["data_json"])
            f_data["lifecycle_status"] = r["status"]
            f_data["status"] = r["status"]
            f_data["times_observed"] = r["times_observed"]
            f_data["assigned_to"] = r["assigned_to"]
            items.append(f_data)

        return {
            "total": total,
            "limit": limit,
            "offset": offset,
            "items": items,
        }


@router.get("/{finding_id}", summary="Get Canonical Finding Details")
async def get_finding_detail(
    finding_id: str,
    current_user: UserProfile = Depends(require_permission(required_scope="finding:read")),
) -> Dict[str, Any]:
    """Retrieves full finding details. Enforces strict tenant ownership (IDOR denial)."""
    with db_manager._connection_scope() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT * FROM findings WHERE id = ? AND (? IS NULL OR organization_id = ?)",
            (finding_id, _organization_scope(current_user), _organization_scope(current_user)),
        )
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail=f"Finding '{finding_id}' not found.")

        f_data = json.loads(row["data_json"])
        f_data["lifecycle_status"] = row["status"]
        f_data["status"] = row["status"]
        f_data["times_observed"] = row["times_observed"]
        f_data["assigned_to"] = row["assigned_to"]
        return f_data


@router.get("/{finding_id}/occurrences", summary="Get Finding Occurrence History")
async def list_finding_occurrences(
    finding_id: str,
    current_user: UserProfile = Depends(require_permission(required_scope="finding:read")),
) -> Dict[str, Any]:
    """Return historical detections for a finding within the caller's tenant."""
    organization_id = _organization_scope(current_user)
    with db_manager._connection_scope() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT id FROM findings WHERE id = ? AND (? IS NULL OR organization_id = ?)",
            (finding_id, organization_id, organization_id),
        )
        if not cur.fetchone():
            raise HTTPException(status_code=404, detail=f"Finding '{finding_id}' not found.")

        cur.execute(
            """
            SELECT id, organization_id, canonical_finding_id, scan_id, asset_id,
                   source_tool, check_id, raw_evidence_json, reproduction_curl,
                   taint_trace_json, detected_at
            FROM finding_occurrences
            WHERE canonical_finding_id = ?
              AND (? IS NULL OR organization_id = ?)
            ORDER BY detected_at DESC, id DESC
            """,
            (finding_id, organization_id, organization_id),
        )
        rows = cur.fetchall()

    items: List[Dict[str, Any]] = []
    for row in rows:
        try:
            raw_evidence = json.loads(row["raw_evidence_json"])
        except (TypeError, json.JSONDecodeError):
            raw_evidence = {}
        try:
            taint_trace = json.loads(row["taint_trace_json"] or "[]")
        except (TypeError, json.JSONDecodeError):
            taint_trace = []
        items.append({
            "id": row["id"],
            "organization_id": row["organization_id"],
            "canonical_finding_id": row["canonical_finding_id"],
            "scan_id": row["scan_id"],
            "asset_id": row["asset_id"],
            "source_tool": row["source_tool"],
            "check_id": row["check_id"],
            "raw_evidence": raw_evidence,
            "reproduction_curl": row["reproduction_curl"],
            "taint_trace": taint_trace,
            "detected_at": row["detected_at"],
        })
    return {"finding_id": finding_id, "total": len(items), "items": items}


@router.patch("/{finding_id}/status", summary="Update Finding Lifecycle State & SLA Assignment")
async def update_finding_status(
    finding_id: str,
    payload: FindingTriageUpdate,
    current_user: UserProfile = Depends(require_permission(allowed_roles=[UserRole.ADMIN, UserRole.SECURITY_ANALYST, UserRole.DEVELOPER])),
) -> Dict[str, Any]:
    """
    Updates the lifecycle triage status of a vulnerability finding (OPEN, IN_PROGRESS, FIXED, RISK_ACCEPTED).
    Enforces tenant ownership.
    """
    required_scope = "finding:risk_accept" if payload.status == FindingLifecycleStatus.RISK_ACCEPTED else "finding:triage"
    if "*" not in (current_user.scopes or []) and required_scope not in (current_user.scopes or []):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access forbidden: Credentials lack required scope '{required_scope}'.",
        )
    with db_manager._connection_scope() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT * FROM findings WHERE id = ? AND (? IS NULL OR organization_id = ?)",
            (finding_id, _organization_scope(current_user), _organization_scope(current_user)),
        )
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail=f"Finding '{finding_id}' not found.")

        now_str = utc_now().isoformat()
        conn.execute(
            "UPDATE findings SET status = ?, assigned_to = ?, last_seen = ? WHERE id = ? AND (? IS NULL OR organization_id = ?)",
            (payload.status.value, payload.assigned_to, now_str, finding_id, _organization_scope(current_user), _organization_scope(current_user)),
        )

        if payload.comment:
            conn.execute(
                "INSERT INTO finding_comments (id, finding_id, user_id, username, comment, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (f"cmt-{uuid.uuid4().hex[:12]}", finding_id, current_user.id, current_user.username, payload.comment, now_str),
            )

    # Audit Action
    audit_act = AuditAction.RISK_ACCEPTED if payload.status == FindingLifecycleStatus.RISK_ACCEPTED else AuditAction.FINDING_STATUS_CHANGED
    db_manager.record_audit_event(
        AuditEvent(
            actor=current_user.username,
            organization_id=current_user.organization_id,
            action=audit_act,
            object_type="finding",
            object_id=finding_id,
            result="SUCCESS",
            details={"new_status": payload.status.value, "assigned_to": payload.assigned_to},
        )
    )

    return {
        "finding_id": finding_id,
        "status": payload.status.value,
        "assigned_to": payload.assigned_to,
        "message": f"Finding status updated to '{payload.status.value}'.",
    }


@router.post("/{finding_id}/comments", summary="Add Remediation Note / Triage Comment")
async def add_finding_comment(
    finding_id: str,
    payload: AddCommentRequest,
    current_user: UserProfile = Depends(require_permission(required_scope="finding:write", allowed_roles=[UserRole.ADMIN, UserRole.SECURITY_ANALYST, UserRole.DEVELOPER])),
) -> FindingComment:
    """
    Appends a collaboration or verification comment to a finding record. Enforces tenant ownership.
    """
    with db_manager._connection_scope() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT * FROM findings WHERE id = ? AND (? IS NULL OR organization_id = ?)",
            (finding_id, _organization_scope(current_user), _organization_scope(current_user)),
        )
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail=f"Finding '{finding_id}' not found.")

        comment_id = f"cmt-{uuid.uuid4().hex[:12]}"
        now = utc_now()
        conn.execute(
            "INSERT INTO finding_comments (id, finding_id, user_id, username, comment, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (comment_id, finding_id, current_user.id, current_user.username, payload.comment, now.isoformat()),
        )

    db_manager.record_audit_event(
        AuditEvent(
            actor=current_user.username,
            organization_id=current_user.organization_id,
            action=AuditAction.FINDING_COMMENTED,
            object_type="finding",
            object_id=finding_id,
            result="SUCCESS",
        )
    )

    return FindingComment(
        id=comment_id,
        user_id=current_user.id,
        username=current_user.username,
        comment=payload.comment,
        created_at=now,
    )
