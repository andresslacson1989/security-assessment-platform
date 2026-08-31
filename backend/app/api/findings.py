"""
Contract 04 §3.3:
Unified Vulnerability Lifecycle, Triage, SLA & Correlation Management Router.
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
)
from app.core.auth import get_current_user, require_dev_or_higher, UserProfile
from app.core.db import db_manager

router = APIRouter()


class AddCommentRequest(BaseModel):
    comment: str = Field(..., min_length=1, max_length=2000)


@router.get("", summary="Query Unified Findings Across Fleet")
@router.get("/", summary="Query Unified Findings Across Fleet", include_in_schema=False)
async def list_findings(
    severity: Optional[Severity] = None,
    status_filter: Optional[FindingLifecycleStatus] = Query(None, alias="status"),
    category: Optional[str] = None,
    scan_id: Optional[str] = None,
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    current_user: UserProfile = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Returns filtered finding records with lifecycle status and correlation metadata.
    """
    with db_manager._get_connection() as conn:
        cur = conn.cursor()
        query = "SELECT * FROM findings WHERE 1=1"
        params: List[Any] = []

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
            f_data["times_observed"] = r["times_observed"]
            f_data["assigned_to"] = r["assigned_to"]
            items.append(f_data)

        return {
            "total": total,
            "limit": limit,
            "offset": offset,
            "items": items,
        }


@router.patch("/{finding_id}/status", summary="Update Finding Lifecycle State & SLA Assignment")
async def update_finding_status(
    finding_id: str,
    payload: FindingTriageUpdate,
    current_user: UserProfile = Depends(require_dev_or_higher),
) -> Dict[str, Any]:
    """
    Updates the lifecycle triage status of a vulnerability finding (OPEN, IN_PROGRESS, FIXED, etc.).
    """
    with db_manager._get_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM findings WHERE id = ?", (finding_id,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail=f"Finding '{finding_id}' not found.")

        conn.execute(
            "UPDATE findings SET status = ?, assigned_to = ?, last_seen = datetime('now') WHERE id = ?",
            (payload.status.value, payload.assigned_to, finding_id),
        )

        if payload.comment:
            conn.execute(
                "INSERT INTO finding_comments (id, finding_id, user_id, username, comment, created_at) VALUES (?, ?, ?, ?, ?, datetime('now'))",
                (str(uuid.uuid4()), finding_id, current_user.id, current_user.username, payload.comment),
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
    current_user: UserProfile = Depends(require_dev_or_higher),
) -> FindingComment:
    """
    Appends a collaboration or verification comment to a finding record.
    """
    with db_manager._get_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id FROM findings WHERE id = ?", (finding_id,))
        if not cur.fetchone():
            raise HTTPException(status_code=404, detail=f"Finding '{finding_id}' not found.")

        comment_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        conn.execute(
            "INSERT INTO finding_comments (id, finding_id, user_id, username, comment, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (comment_id, finding_id, current_user.id, current_user.username, payload.comment, now.isoformat()),
        )

    return FindingComment(
        id=comment_id,
        user_id=current_user.id,
        username=current_user.username,
        comment=payload.comment,
        created_at=now,
    )
