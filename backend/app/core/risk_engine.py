"""
Contract 02 §10 & Contract 08 §12.6:
Contextual Risk Engine & Calibrated Posture Grading Algorithm.
Replaces naive arithmetic point deductions with multi-dimensional risk modeling:
Risk = min(10.0, CVSS * AssetCriticality * InternetExposure * ConfidenceFactor)
"""

from __future__ import annotations
from typing import List, Tuple
from app.core.models import (
    Finding,
    UnifiedFinding,
    AssetCriticality,
    Severity,
    SecurityGrade,
)


def get_criticality_factor(criticality: AssetCriticality) -> float:
    """Maps asset business criticality tier to numerical risk multiplier."""
    mapping = {
        AssetCriticality.CRITICAL: 1.5,
        AssetCriticality.HIGH: 1.2,
        AssetCriticality.MEDIUM: 1.0,
        AssetCriticality.LOW: 0.7,
    }
    return mapping.get(criticality, 1.0)


def calculate_finding_contextual_risk(
    base_cvss: float,
    criticality: AssetCriticality = AssetCriticality.MEDIUM,
    internet_exposed: bool = True,
    confidence_multiplier: float = 1.0,
) -> float:
    """
    Computes a contextual 0.0 - 10.0 risk score for an individual vulnerability finding.
    """
    c_factor = get_criticality_factor(criticality)
    e_factor = 1.0 if internet_exposed else 0.7
    raw_risk = base_cvss * c_factor * e_factor * confidence_multiplier
    return round(min(10.0, max(0.0, raw_risk)), 1)


def calculate_contextual_posture_grade(
    findings: List[Finding],
    criticality: AssetCriticality = AssetCriticality.MEDIUM,
    internet_exposed: bool = True,
) -> Tuple[float, SecurityGrade]:
    """
    Calculates overall weighted score (0-100) and letter grade (A+ through F)
    based on calibrated contextual risk and severity constraints.
    """
    crit_count = sum(1 for f in findings if f.severity == Severity.CRITICAL)
    high_count = sum(1 for f in findings if f.severity == Severity.HIGH)
    med_count = sum(1 for f in findings if f.severity == Severity.MEDIUM)
    low_count = sum(1 for f in findings if f.severity == Severity.LOW)

    c_factor = get_criticality_factor(criticality)
    e_factor = 1.0 if internet_exposed else 0.7
    scope_multiplier = c_factor * e_factor

    deduction = (
        (crit_count * 35.0 * scope_multiplier)
        + (high_count * 15.0 * scope_multiplier)
        + (med_count * 5.0 * scope_multiplier)
        + (low_count * 1.0 * scope_multiplier)
    )

    final_score = round(max(0.0, min(100.0, 100.0 - deduction)), 1)

    # Mandatory Hard Constraints
    if crit_count > 0:
        grade = SecurityGrade.F
    elif high_count > 0 or final_score < 65.0:
        if final_score < 50.0:
            grade = SecurityGrade.F
        elif final_score < 65.0 or high_count > 0:
            grade = SecurityGrade.D
        else:
            grade = SecurityGrade.C
    elif med_count > 2 or final_score < 80.0:
        grade = SecurityGrade.C
    elif med_count > 0 or final_score < 90.0:
        grade = SecurityGrade.B
    elif low_count > 0 or final_score < 96.0:
        grade = SecurityGrade.A
    else:
        grade = SecurityGrade.A_PLUS

    return final_score, grade
