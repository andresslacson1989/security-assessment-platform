"""
Contract 04 & 05 OASIS SARIF v2.1.0 Exporter for GitHub Code Scanning & CI/CD Security Dashboards.
"""

from __future__ import annotations
from typing import Dict, Any, List
from app.core.models import ScanJob, Severity


def severity_to_sarif_level(severity: Severity) -> str:
    """
    Maps platform Severity enum to OASIS SARIF v2.1.0 reporting levels:
    - CRITICAL / HIGH -> 'error'
    - MEDIUM -> 'warning'
    - LOW / INFO -> 'note'
    """
    if severity in (Severity.CRITICAL, Severity.HIGH):
        return "error"
    elif severity == Severity.MEDIUM:
        return "warning"
    return "note"


def export_scan_to_sarif(scan_job: ScanJob) -> Dict[str, Any]:
    """
    Serializes a completed ScanJob into standard OASIS SARIF v2.1.0 JSON format.
    """
    rules_map: Dict[str, Dict[str, Any]] = {}
    results_list: List[Dict[str, Any]] = []

    for f in scan_job.findings:
        sarif_level = severity_to_sarif_level(f.severity)

        # 1. Register Rule in Driver Rules Catalog
        if f.check_id not in rules_map:
            help_md = f"### Remediation\n\n{f.remediation}\n"
            if f.remediation_code_snippet:
                help_md += f"\n```\n{f.remediation_code_snippet}\n```\n"

            rules_map[f.check_id] = {
                "id": f.check_id,
                "name": f.title,
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.description},
                "defaultConfiguration": {
                    "level": sarif_level
                },
                "help": {
                    "text": f"{f.remediation}",
                    "markdown": help_md,
                },
                "properties": {
                    "tags": list(filter(None, [f.cwe_id, f.owasp_category, f.nist_control, f.category])),
                    "cvss_score": f.cvss_score,
                    "cvss_vector": f.cvss_vector,
                    "cwe": f.cwe_id,
                    "owasp": f.owasp_category,
                    "nist": f.nist_control,
                }
            }

        # 2. Build Location Object
        uri_str = f.evidence.location
        line_num = f.evidence.line_number or 1

        # Extract file path if location is in 'path:line' format
        if ":" in uri_str and not uri_str.startswith("http"):
            parts = uri_str.split(":")
            uri_str = parts[0]
            if len(parts) > 1 and parts[1].isdigit():
                line_num = int(parts[1])

        # 3. Create Result Entry
        result_entry: Dict[str, Any] = {
            "ruleId": f.check_id,
            "level": sarif_level,
            "message": {
                "text": f"{f.title}: {f.description} (Observed: {f.evidence.observed_value})"
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": uri_str,
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": line_num,
                            "startColumn": 1,
                        }
                    }
                }
            ],
            "properties": {
                "cvss_score": f.cvss_score,
                "severity": f.severity.value,
                "category": f.category,
                "engine": f.engine,
                "fingerprint": f.fingerprint,
            }
        }
        results_list.append(result_entry)

    sarif_doc: Dict[str, Any] = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CyberAssess Security Scanner",
                        "version": "6.0.0",
                        "informationUri": "https://github.com/andresslacson1989/security-assessment-platform",
                        "rules": list(rules_map.values()),
                    }
                },
                "results": results_list,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "startTimeUtc": scan_job.started_at.isoformat() if scan_job.started_at else None,
                        "endTimeUtc": scan_job.completed_at.isoformat() if scan_job.completed_at else None,
                    }
                ]
            }
        ]
    }

    return sarif_doc
