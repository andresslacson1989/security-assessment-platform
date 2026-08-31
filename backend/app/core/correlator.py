"""
Contract 02 §9 & Contract 08 §12.5:
Cross-Scanner Finding Correlation, Deduplication & Root-Cause Analysis Engine.
Synthesizes disparate findings from SAST, DAST, SCA, and Network tools into high-confidence Unified Findings.
"""

from __future__ import annotations
import urllib.parse
from typing import List, Dict, Tuple, Optional
from datetime import datetime, timezone

from app.core.models import (
    Finding,
    UnifiedFinding,
    CorrelationType,
    FindingLifecycleStatus,
    Severity,
    SLAInfo,
)


def compute_sla_info(severity: Severity) -> SLAInfo:
    """Computes prescriptive remediation SLA window based on vulnerability severity."""
    sla_map = {
        Severity.CRITICAL: 7,
        Severity.HIGH: 14,
        Severity.MEDIUM: 30,
        Severity.LOW: 90,
        Severity.INFO: 180,
    }
    days = sla_map.get(severity, 30)
    now = datetime.now(timezone.utc)
    due = datetime.fromtimestamp(now.timestamp() + (days * 86400), tz=timezone.utc)
    return SLAInfo(severity=severity, sla_days=days, due_date=due, is_breached=False)


class FindingCorrelator:
    """
    Consolidates multi-engine findings into actionable root-cause clusters.
    """

    def correlate_findings(
        self,
        findings: List[Finding],
        asset_id: Optional[str] = None,
        exposure_multiplier: float = 1.0,
        asset_criticality_factor: float = 1.0,
    ) -> List[UnifiedFinding]:
        """
        Processes a list of raw scanner findings and outputs correlated UnifiedFinding instances.
        """
        if not findings:
            return []

        unified_findings: List[UnifiedFinding] = []
        visited_ids = set()

        # 1. Look for SAST + DAST Cross-Engine Correlation (e.g. SQLi / XSS)
        sast_findings = [f for f in findings if f.engine == "code_sast" or "sast" in f.check_id.lower()]
        dast_findings = [f for f in findings if f.engine == "web_dast" or "dast" in f.check_id.lower() or "nuclei" in f.source_tool]

        for df in dast_findings:
            matched_sast = None
            for sf in sast_findings:
                if sf.id in visited_ids:
                    continue
                # Match common vulnerability categories (e.g. Injection, XSS, SSRF)
                if sf.category and df.category and sf.category.lower() == df.category.lower():
                    matched_sast = sf
                    break

            if matched_sast:
                visited_ids.add(df.id)
                visited_ids.add(matched_sast.id)

                base_cvss = max(df.cvss_score, matched_sast.cvss_score)
                # SAST + DAST verification applies 1.3x confidence multiplier
                conf_mult = 1.3
                risk_score = round(min(10.0, base_cvss * asset_criticality_factor * exposure_multiplier * conf_mult), 1)

                unified = UnifiedFinding(
                    asset_id=asset_id,
                    correlation_type=CorrelationType.SAST_DAST_VERIFIED,
                    title=f"[DAST + SAST Verified] {df.title}",
                    category=df.category,
                    severity=df.severity,
                    cvss_score=base_cvss,
                    contextual_risk_score=risk_score,
                    cwe_id=df.cwe_id or matched_sast.cwe_id,
                    contributing_tools=list(set([df.source_tool, matched_sast.source_tool])),
                    raw_finding_ids=[df.id, matched_sast.id],
                    lifecycle_status=FindingLifecycleStatus.OPEN,
                    times_observed=2,
                    sla=compute_sla_info(df.severity),
                    remediation=f"Source flaw detected in code ({matched_sast.check_id}) and live endpoint verified ({df.check_id}). {df.remediation}",
                )
                unified_findings.append(unified)

        # 2. Multi-Tool Confirmation & Clustering for remaining findings
        remaining = [f for f in findings if f.id not in visited_ids]
        grouped_by_key: Dict[str, List[Finding]] = {}

        for f in remaining:
            # Group by normalized check_id or category
            key = f"{f.category}|{f.cwe_id or f.check_id}"
            grouped_by_key.setdefault(key, []).append(f)

        for key, group in grouped_by_key.items():
            primary = group[0]
            tools = list(dict.fromkeys(f.source_tool for f in group))
            raw_ids = [f.id for f in group]

            corr_type = CorrelationType.MULTI_TOOL_CONFIRMED if len(tools) > 1 else None
            conf_mult = 1.15 if corr_type else 1.0
            risk_score = round(min(10.0, primary.cvss_score * asset_criticality_factor * exposure_multiplier * conf_mult), 1)

            title_prefix = f"[{len(tools)} Tools Confirmed] " if len(tools) > 1 else ""

            unified = UnifiedFinding(
                asset_id=asset_id,
                correlation_type=corr_type,
                title=f"{title_prefix}{primary.title}",
                category=primary.category,
                severity=primary.severity,
                cvss_score=primary.cvss_score,
                contextual_risk_score=risk_score,
                cwe_id=primary.cwe_id,
                contributing_tools=tools,
                raw_finding_ids=raw_ids,
                lifecycle_status=FindingLifecycleStatus.OPEN,
                times_observed=len(group),
                sla=compute_sla_info(primary.severity),
                remediation=primary.remediation,
            )
            unified_findings.append(unified)

        return unified_findings


correlator = FindingCorrelator()
