"""
CycloneDX 1.5 JSON Software Bill of Materials (SBOM) Exporter.
Authoritative Reference: contracts/04_API_AND_STREAMING_EVENTS_CONTRACT.md (Section 1.3)
"""

from __future__ import annotations
from datetime import datetime, timezone
import json
import logging
import uuid
from typing import Dict, Any

from app.core.models import ScanJob, SBOMReport
from app.core.version import APP_VERSION

logger = logging.getLogger("cyberassess.exporters.cyclonedx")


def export_cyclonedx_sbom(scan: ScanJob) -> str:
    """
    Serializes scan dependency inventory and findings into CycloneDX 1.5 JSON.
    """
    # If a pre-generated raw CycloneDX document exists, return it
    if scan.sbom_report and scan.sbom_report.raw_document and scan.sbom_report.raw_document.strip().startswith("{"):
        try:
            parsed = json.loads(scan.sbom_report.raw_document)
            if parsed.get("bomFormat") == "CycloneDX":
                return json.dumps(parsed, indent=2)
        except Exception as exc:
            logger.warning("Stored CycloneDX document was invalid; synthesizing a replacement: error_type=%s", type(exc).__name__)

    # Otherwise synthesize CycloneDX 1.5 structure from SBOM components and findings
    components_list = []
    if scan.sbom_report and scan.sbom_report.components:
        for comp in scan.sbom_report.components:
            comp_obj: Dict[str, Any] = {
                "type": comp.type or "library",
                "name": comp.name,
                "version": comp.version,
            }
            if comp.purl:
                comp_obj["purl"] = comp.purl
            if comp.cpe:
                comp_obj["cpe"] = comp.cpe
            if comp.license:
                comp_obj["licenses"] = [{"license": {"id": comp.license}}]
            components_list.append(comp_obj)
    else:
        # Fallback synthesis from SAST-DEP / SCA findings
        seen = set()
        for f in scan.findings:
            if f.check_id.startswith("SCA-") or f.check_id.startswith("SAST-DEP"):
                pkg_info = f.evidence.location.split()[0] if f.evidence.location else f.title
                if "@" in pkg_info:
                    name, ver = pkg_info.split("@", 1)
                else:
                    name, ver = pkg_info, "1.0.0"
                if name not in seen:
                    seen.add(name)
                    components_list.append({
                        "type": "library",
                        "name": name,
                        "version": ver,
                        "purl": f"pkg:generic/{name}@{ver}",
                    })

    # Add scan target as root component
    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{scan.id}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [
                {
                    "vendor": "CyberAssess",
                    "name": "Security Assessment Platform",
                    "version": APP_VERSION,
                }
            ],
            "component": {
                "type": "application",
                "name": scan.target.name or scan.target.value,
                "version": "1.0.0",
            },
        },
        "components": components_list,
    }

    # Include vulnerability matches if available
    vulnerabilities = []
    for f in scan.findings:
        if f.cwe_id or "CVE-" in f.title or "SCA-" in f.check_id:
            cve_match = [w for w in f.title.split() if w.startswith("CVE-")]
            vuln_id = cve_match[0] if cve_match else f.check_id
            vulnerabilities.append({
                "id": vuln_id,
                "source": {"name": f.source_tool},
                "ratings": [
                    {
                        "score": f.cvss_score,
                        "severity": f.severity.value.lower(),
                        "method": "CVSSv31",
                    }
                ],
                "description": f.description,
                "recommendation": f.remediation,
            })

    if vulnerabilities:
        doc["vulnerabilities"] = vulnerabilities

    return json.dumps(doc, indent=2)
