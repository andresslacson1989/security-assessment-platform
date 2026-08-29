"""
Contract 02 & 08 Deterministic Security Scoring & Grading Engine.
"""

from typing import List, Dict
from app.core.models import Finding, Severity, ScanJobSummary


# Exact penalty weights per Contract 02 & Contract 08
PENALTY_WEIGHTS: Dict[Severity, float] = {
    Severity.CRITICAL: 35.0,
    Severity.HIGH: 15.0,
    Severity.MEDIUM: 5.0,
    Severity.LOW: 1.0,
    Severity.INFO: 0.0,
}


def calculate_scan_grade(
    findings: List[Finding],
    total_checks_evaluated: int = 0,
    passed_checks: int = 0,
    duration_seconds: float = 0.0,
) -> ScanJobSummary:
    """
    Computes a deterministic security score (0.0 to 100.0) and letter grade (A+, A, B, C, D, F)
    based on the findings distribution and exact contract constraints.
    """
    critical_count = sum(1 for f in findings if f.severity == Severity.CRITICAL)
    high_count = sum(1 for f in findings if f.severity == Severity.HIGH)
    medium_count = sum(1 for f in findings if f.severity == Severity.MEDIUM)
    low_count = sum(1 for f in findings if f.severity == Severity.LOW)
    info_count = sum(1 for f in findings if f.severity == Severity.INFO)
    total_findings = len(findings)

    # Engine breakdown map
    engine_breakdown: Dict[str, int] = {}
    for f in findings:
        engine_breakdown[f.engine] = engine_breakdown.get(f.engine, 0) + 1

    # Base score deduction formula: S_raw = 100.0 - (N_crit * 35 + N_high * 15 + N_med * 5 + N_low * 1)
    total_deductions = (
        critical_count * PENALTY_WEIGHTS[Severity.CRITICAL]
        + high_count * PENALTY_WEIGHTS[Severity.HIGH]
        + medium_count * PENALTY_WEIGHTS[Severity.MEDIUM]
        + low_count * PENALTY_WEIGHTS[Severity.LOW]
    )
    raw_score = 100.0 - total_deductions
    weighted_score = max(0.0, min(100.0, raw_score))
    weighted_score = round(weighted_score, 1)

    # Deterministic Letter Grade Assignment with Hard Constraints
    if critical_count > 0:
        # Any CRITICAL finding always forces an 'F' grade
        overall_security_grade = "F"
    elif high_count >= 1:
        # High findings present without critical force at least a 'D' or 'F' depending on score
        if weighted_score < 50.0:
            overall_security_grade = "F"
        else:
            overall_security_grade = "D"
    elif weighted_score >= 96.0 and critical_count == 0 and high_count == 0 and medium_count == 0 and low_count == 0:
        overall_security_grade = "A+"
    elif weighted_score >= 90.0 and critical_count == 0 and high_count == 0 and medium_count == 0 and low_count <= 2:
        overall_security_grade = "A"
    elif weighted_score >= 80.0 and critical_count == 0 and high_count == 0 and medium_count <= 2:
        overall_security_grade = "B"
    elif weighted_score >= 65.0 and critical_count == 0 and high_count == 0:
        overall_security_grade = "C"
    elif weighted_score >= 50.0 and critical_count == 0:
        overall_security_grade = "D"
    else:
        overall_security_grade = "F"

    # Adjust evaluated check counts if default zero was provided
    if total_checks_evaluated == 0:
        total_checks_evaluated = max(total_findings, passed_checks + total_findings)

    return ScanJobSummary(
        critical_count=critical_count,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
        info_count=info_count,
        total_findings=total_findings,
        passed_checks=passed_checks,
        total_checks_evaluated=total_checks_evaluated,
        weighted_score=weighted_score,
        overall_security_grade=overall_security_grade,
        duration_seconds=round(duration_seconds, 2),
        engine_breakdown=engine_breakdown,
    )
