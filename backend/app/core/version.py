"""
Contract 02 §1: Single Authoritative Version & Metadata Authority.
All platform components, API responses, exporters, and UI templates MUST derive from here.
"""

APP_NAME = "CyberAssess"
APP_TITLE = "CyberAssess Security Assessment & Vulnerability Management Platform"
APP_VERSION = "14.3.0"             # Authoritative Platform Release Version
API_VERSION = "v1"
SCHEMA_VERSION = "4.1.0"           # Data Schema Model Specification (Contract 02 v4.1.0)
CONTRACT_VERSION = "14.3.0"         # Authoritative Contract Specification Suite (Contract 09 v14.3.0)
RULESET_VERSION = "14.3.0"          # Security Check Catalog Ruleset (Contract 06 v14.3.0)
RISK_MODEL_VERSION = "14.3.0"       # Contextual Risk Scoring Model (Contract 07 v14.3.0)

STANDARDS_BASELINE = {
    "owasp_asvs": "v5.0.0",
    "nist_ssdf": "SP 800-218 v1.1",
    "nist_sp800_53": "Rev. 5",
    "rfc_jwt": "RFC 8725",
    "cyclonedx_sbom": "v1.5",
    "sarif": "v2.1.0",
}
