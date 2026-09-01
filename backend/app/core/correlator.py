"""
Contract 02 §4, §5 & Contract 08 §12.5:
Cross-Scanner Finding Correlation, Multi-Dimensional Deduplication & Contextual Risk Engine.
Synthesizes findings from SAST, DAST, SCA, and Network tools into high-confidence Canonical Findings,
preserving occurrence provenance and SLA clocks.
"""

from __future__ import annotations
import urllib.parse
from typing import List, Dict, Tuple, Optional
from datetime import datetime, timezone

from app.core.models import (
    Finding,
    CanonicalFinding,
    UnifiedFinding,
    FindingOccurrence,
    CorrelationType,
    FindingLifecycleStatus,
    Severity,
    SLAInfo,
    calculate_evidence_hash,
    utc_now,
)
from app.core.version import RISK_MODEL_VERSION


def compute_sla_info(severity: Severity, started_at: Optional[datetime] = None) -> SLAInfo:
    """
    Computes prescriptive remediation SLA window based on vulnerability severity.
    Preserves original starting clock if started_at is provided.
    """
    sla_map = {
        Severity.CRITICAL: 7,
        Severity.HIGH: 14,
        Severity.MEDIUM: 30,
        Severity.LOW: 90,
        Severity.INFO: 180,
    }
    days = sla_map.get(severity, 30)
    start = started_at or utc_now()
    due = datetime.fromtimestamp(start.timestamp() + (days * 86400), tz=timezone.utc)
    is_breached = utc_now() > due
    return SLAInfo(
        severity=severity,
        sla_days=days,
        sla_started_at=start,
        sla_due_at=due,
        is_breached=is_breached,
        sla_breached_at=due if is_breached else None,
    )


class FindingCorrelator:
    """
    Consolidates multi-engine findings into actionable root-cause clusters while preserving raw occurrences.
    """

    def correlate_findings(
        self,
        findings: List[Finding],
        asset_id: Optional[str] = None,
        organization_id: Optional[str] = None,
        project_id: Optional[str] = None,
        exposure_multiplier: float = 1.0,
        asset_criticality_factor: float = 1.0,
        existing_canonical_findings: Optional[List[CanonicalFinding]] = None,
    ) -> Tuple[List[CanonicalFinding], List[FindingOccurrence]]:
        """
        Processes raw scanner findings and outputs correlated CanonicalFinding and FindingOccurrence instances.
        """
        if not findings:
            return [], []

        org_id = organization_id or "org-default"
        canonical_findings: List[CanonicalFinding] = []
        occurrences: List[FindingOccurrence] = []
        visited_ids = set()

        existing_by_fp = {c.evidence_hash: c for c in (existing_canonical_findings or []) if c.evidence_hash}

        # 1. Look for SAST + DAST Cross-Engine Correlation (e.g. SQLi / XSS)
        sast_findings = [f for f in findings if f.engine == "code_sast" or "sast" in f.check_id.lower()]
        dast_findings = [f for f in findings if f.engine == "web_dast" or "dast" in f.check_id.lower() or "nuclei" in f.source_tool]

        for df in dast_findings:
            matched_sast = None
            for sf in sast_findings:
                if sf.id in visited_ids:
                    continue
                # Match common vulnerability categories & CWEs
                if (sf.cwe_id and df.cwe_id and sf.cwe_id == df.cwe_id) or (
                    sf.category and df.category and sf.category.lower() == df.category.lower()
                ):
                    matched_sast = sf
                    break

            if matched_sast:
                visited_ids.add(df.id)
                visited_ids.add(matched_sast.id)

                base_cvss = max(df.cvss_score, matched_sast.cvss_score)
                conf_mult = 1.3  # SAST + DAST verified multiplier
                risk_score = round(min(10.0, base_cvss * asset_criticality_factor * exposure_multiplier * conf_mult), 1)

                ev_hash = calculate_evidence_hash(df.evidence.location, df.evidence.observed_value)
                orig_start = existing_by_fp[ev_hash].sla.sla_started_at if ev_hash in existing_by_fp and existing_by_fp[ev_hash].sla else utc_now()

                canonical = CanonicalFinding(
                    organization_id=org_id,
                    project_id=project_id,
                    asset_id=asset_id,
                    correlation_type=CorrelationType.SAST_DAST_VERIFIED,
                    title=f"[DAST + SAST Verified] {df.title}",
                    category=df.category,
                    severity=df.severity,
                    cvss_score=base_cvss,
                    cvss_vector=df.cvss_vector,
                    contextual_risk_score=risk_score,
                    cwe_id=df.cwe_id or matched_sast.cwe_id,
                    owasp_category=df.owasp_category or matched_sast.owasp_category,
                    nist_control=df.nist_control or matched_sast.nist_control,
                    contributing_tools=list(set([df.source_tool, matched_sast.source_tool])),
                    status=FindingLifecycleStatus.OPEN,
                    times_observed=2,
                    first_seen=orig_start,
                    last_seen=utc_now(),
                    sla=compute_sla_info(df.severity, started_at=orig_start),
                    description=f"DAST live probe and SAST static analysis both detected this vulnerability.\n\nDAST: {df.description}\nSAST: {matched_sast.description}",
                    impact=df.impact or matched_sast.impact,
                    remediation=f"Source flaw detected in code ({matched_sast.check_id}) and live endpoint verified ({df.check_id}). {df.remediation}",
                    evidence_hash=ev_hash,
                )
                canonical_findings.append(canonical)

                # Append occurrences
                occurrences.append(FindingOccurrence(
                    organization_id=org_id,
                    canonical_finding_id=canonical.id,
                    scan_id=df.scan_id,
                    asset_id=asset_id,
                    source_tool=df.source_tool,
                    check_id=df.check_id,
                    raw_evidence=df.evidence,
                    reproduction_curl=df.reproduction_curl,
                ))
                occurrences.append(FindingOccurrence(
                    organization_id=org_id,
                    canonical_finding_id=canonical.id,
                    scan_id=matched_sast.scan_id,
                    asset_id=asset_id,
                    source_tool=matched_sast.source_tool,
                    check_id=matched_sast.check_id,
                    raw_evidence=matched_sast.evidence,
                    taint_trace=matched_sast.taint_trace,
                ))

        # 2. Multi-Tool Confirmation & Clustering for remaining findings
        remaining = [f for f in findings if f.id not in visited_ids]
        grouped_by_key: Dict[str, List[Finding]] = {}

        for f in remaining:
            # High-precision grouping key includes location to avoid false merges across endpoints
            loc_key = (f.evidence.location or "").strip().lower()
            key = f"{f.category}|{f.cwe_id or f.check_id}|{loc_key}"
            grouped_by_key.setdefault(key, []).append(f)

        for key, group in grouped_by_key.items():
            primary = group[0]
            tools = list(dict.fromkeys(f.source_tool for f in group))

            corr_type = CorrelationType.MULTI_TOOL_CONFIRMED if len(tools) > 1 else None
            conf_mult = 1.15 if corr_type else 1.0
            risk_score = round(min(10.0, primary.cvss_score * asset_criticality_factor * exposure_multiplier * conf_mult), 1)

            title_prefix = f"[{len(tools)} Tools Confirmed] " if len(tools) > 1 else ""
            ev_hash = calculate_evidence_hash(primary.evidence.location, primary.evidence.observed_value)
            orig_start = existing_by_fp[ev_hash].sla.sla_started_at if ev_hash in existing_by_fp and existing_by_fp[ev_hash].sla else utc_now()

            canonical = CanonicalFinding(
                organization_id=org_id,
                project_id=project_id,
                asset_id=asset_id,
                correlation_type=corr_type,
                title=f"{title_prefix}{primary.title}",
                category=primary.category,
                severity=primary.severity,
                cvss_score=primary.cvss_score,
                cvss_vector=primary.cvss_vector,
                contextual_risk_score=risk_score,
                cwe_id=primary.cwe_id,
                owasp_category=primary.owasp_category,
                nist_control=primary.nist_control,
                contributing_tools=tools,
                status=FindingLifecycleStatus.OPEN,
                times_observed=len(group),
                first_seen=orig_start,
                last_seen=utc_now(),
                sla=compute_sla_info(primary.severity, started_at=orig_start),
                description=primary.description,
                impact=primary.impact,
                remediation=primary.remediation,
                evidence_hash=ev_hash,
            )
            canonical_findings.append(canonical)

            for gf in group:
                occurrences.append(FindingOccurrence(
                    organization_id=org_id,
                    canonical_finding_id=canonical.id,
                    scan_id=gf.scan_id,
                    asset_id=asset_id,
                    source_tool=gf.source_tool,
                    check_id=gf.check_id,
                    raw_evidence=gf.evidence,
                    reproduction_curl=gf.reproduction_curl,
                    taint_trace=gf.taint_trace,
                ))

        return canonical_findings, occurrences


correlator = FindingCorrelator()
