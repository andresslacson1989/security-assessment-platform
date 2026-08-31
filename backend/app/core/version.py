"""
Contract 02 §1: Single Authoritative Version & Metadata Authority.
All platform components, API responses, exporters, and UI templates MUST derive from here.
"""

APP_NAME = "CyberAssess"
APP_TITLE = "CyberAssess Security Assessment & Vulnerability Management Platform"
APP_VERSION = "12.0.0"
API_VERSION = "v1"
SCHEMA_VERSION = "12.0.0"
CONTRACT_VERSION = "12.0.0"
RULESET_VERSION = "2026.08.31"
RISK_MODEL_VERSION = "contextual_risk_model_v2"
STANDARDS_BASELINE = {
    "owasp_asvs": "v5.0.0",
    "nist_ssdf": "SP 800-218 v1.1",
    "nist_sp800_53": "Rev. 5",
    "rfc_jwt": "RFC 8725",
    "cyclonedx_sbom": "v1.5",
    "sarif": "v2.1.0",
}
