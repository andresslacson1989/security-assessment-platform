"""Native, observation-only cloud posture fallback.

This fallback never contacts a provider and never treats absent observations as
compliant. It exists to preserve limited coverage when the assured Prowler
process is unavailable or produces an unusable report.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from app.core.models import Evidence, Finding, Severity, calculate_fingerprint, sanitize_sensitive_text


def evaluate_cloud_posture_observations(
    observations: Any,
    *,
    scan_id: str,
    organization_id: str,
    primary_tool_failed: str = "prowler",
) -> List[Finding]:
    """Convert explicit worker-side observations into reduced-coverage findings."""
    if not isinstance(observations, dict) or not isinstance(organization_id, str) or not organization_id.strip():
        return []

    findings: List[Finding] = []
    checks = (
        ("root_mfa_disabled", "CLOUD-MFA-001", "Root account MFA is disabled", Severity.CRITICAL, "Enable MFA for the root account."),
        ("public_storage_buckets", "CLOUD-STORAGE-001", "Public cloud storage exposure observed", Severity.HIGH, "Remove public access and enforce a least-privilege bucket policy."),
        ("overly_permissive_iam", "CLOUD-IAM-001", "Overly permissive IAM policy observed", Severity.HIGH, "Restrict IAM actions and resources to the minimum required scope."),
        ("unencrypted_databases", "CLOUD-DATA-001", "Unencrypted cloud database observed", Severity.HIGH, "Enable encryption at rest using an approved key-management policy."),
        ("unlogged_api_gateways", "CLOUD-LOGGING-001", "Cloud API gateway lacks audit logging", Severity.MEDIUM, "Enable provider audit logging and retain logs according to policy."),
    )
    for key, check_id, title, severity, remediation in checks:
        raw = observations.get(key)
        if not raw:
            continue
        values = [True] if raw is True else raw if isinstance(raw, list) else [raw]
        for value in values:
            location = sanitize_sensitive_text(str(value)) if value is not True else key
            observed = sanitize_sensitive_text(f"Observation key: {key}; resource: {location}")
            finding = Finding(
                scan_id=scan_id,
                organization_id=organization_id,
                engine="infra_iac",
                source_tool="native",
                check_id=check_id,
                category="Cloud Compliance",
                title=title,
                severity=severity,
                cvss_score=9.0 if severity == Severity.CRITICAL else 7.5 if severity == Severity.HIGH else 5.0,
                description="A server-supplied cloud posture observation indicates a potential compliance weakness.",
                impact="The observed cloud configuration may increase the risk of unauthorized access or data exposure.",
                remediation=remediation,
                evidence=Evidence(
                    location=location,
                    observed_value=observed,
                    expected_value="The cloud control is configured according to the approved posture policy.",
                    raw_response_snippet=observed,
                ),
                fingerprint=calculate_fingerprint(check_id, location, observed),
                is_fallback=True,
                primary_tool_failed=primary_tool_failed,
            )
            findings.append(finding)
    return findings
