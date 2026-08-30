"""
SPDX 2.3 JSON Software Bill of Materials (SBOM) Exporter.
Authoritative Reference: contracts/04_API_AND_STREAMING_EVENTS_CONTRACT.md (Section 1.3)
"""

from __future__ import annotations
from datetime import datetime, timezone
import json
import uuid
from typing import Dict, Any

from app.core.models import ScanJob, SBOMReport


def export_spdx_sbom(scan: ScanJob) -> str:
    """
    Serializes scan dependency inventory and findings into SPDX 2.3 JSON.
    """
    packages_list = []
    relationships = []
    root_spdx_id = "SPDXRef-RootPackage"

    # Root application package
    packages_list.append({
        "SPDXID": root_spdx_id,
        "name": scan.target.name or scan.target.value,
        "versionInfo": "1.0.0",
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "NOASSERTION",
        "copyrightText": "NOASSERTION",
    })

    if scan.sbom_report and scan.sbom_report.components:
        for idx, comp in enumerate(scan.sbom_report.components):
            pkg_spdx_id = f"SPDXRef-Package-{idx+1}"
            pkg_obj = {
                "SPDXID": pkg_spdx_id,
                "name": comp.name,
                "versionInfo": comp.version,
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": comp.license or "NOASSERTION",
                "licenseDeclared": comp.license or "NOASSERTION",
                "copyrightText": "NOASSERTION",
            }
            if comp.purl:
                pkg_obj["externalRefs"] = [
                    {
                        "referenceCategory": "PACKAGE_MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": comp.purl,
                    }
                ]
            packages_list.append(pkg_obj)
            relationships.append({
                "spdxElementId": root_spdx_id,
                "relatedSpdxElement": pkg_spdx_id,
                "relationshipType": "DEPENDS_ON",
            })
    else:
        seen = set()
        for idx, f in enumerate(scan.findings):
            if f.check_id.startswith("SCA-") or f.check_id.startswith("SAST-DEP"):
                pkg_info = f.evidence.location.split()[0] if f.evidence.location else f.title
                if "@" in pkg_info:
                    name, ver = pkg_info.split("@", 1)
                else:
                    name, ver = pkg_info, "1.0.0"
                if name not in seen:
                    seen.add(name)
                    pkg_spdx_id = f"SPDXRef-Package-{len(seen)}"
                    packages_list.append({
                        "SPDXID": pkg_spdx_id,
                        "name": name,
                        "versionInfo": ver,
                        "downloadLocation": "NOASSERTION",
                        "filesAnalyzed": False,
                        "licenseConcluded": "NOASSERTION",
                        "licenseDeclared": "NOASSERTION",
                        "copyrightText": "NOASSERTION",
                    })
                    relationships.append({
                        "spdxElementId": root_spdx_id,
                        "relatedSpdxElement": pkg_spdx_id,
                        "relationshipType": "DEPENDS_ON",
                    })

    doc = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"SBOM-{scan.target.name or scan.id}",
        "documentNamespace": f"https://spdx.org/spdxdocs/{scan.id}",
        "creationInfo": {
            "created": datetime.now(timezone.utc).isoformat(),
            "creators": ["Tool: CyberAssess-8.0.0", "Organization: Security Assessment Platform"],
        },
        "packages": packages_list,
        "relationships": relationships,
    }

    return json.dumps(doc, indent=2)
