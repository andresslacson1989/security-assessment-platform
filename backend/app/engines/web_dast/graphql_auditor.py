"""
Contract 03, 06 & 08 GraphQL Introspection Auditor.
"""

from __future__ import annotations
import logging
from typing import List, Optional
import httpx

from app.core.models import Finding, Evidence, Severity, calculate_fingerprint, LogLevel
from app.engines.base import LogCallback

logger = logging.getLogger("cyberassess.engines.graphql")


def normalize_target_url(target_value: str) -> str:
    if not target_value.startswith("http://") and not target_value.startswith("https://"):
        return f"https://{target_value}"
    return target_value


async def audit_graphql_endpoints(
    target_value: str,
    client: httpx.AsyncClient,
    emit_log: Optional[LogCallback] = None,
) -> List[Finding]:
    """
    Sends safe GraphQL introspection queries to check if the schema is publicly exposed.
    """
    findings: List[Finding] = []
    base_url = normalize_target_url(target_value).rstrip("/")

    graphql_paths = ["/graphql", "/api/graphql", "/v1/graphql"]
    introspection_query = {"query": "{ __schema { types { name } } }"}

    for path in graphql_paths:
        gql_url = f"{base_url}{path}"
        try:
            resp = await client.post(
                gql_url,
                json=introspection_query,
                headers={"Content-Type": "application/json"},
                timeout=5.0,
            )
            if resp.status_code == 200:
                data = resp.json()
                if "data" in data and "__schema" in data["data"]:
                    type_names = [t.get("name") for t in data["data"]["__schema"].get("types", [])[:5]]
                    findings.append(Finding(
                        scan_id="auto",
                        engine="web_dast",
                        check_id="DAST-GQL-001",
                        category="API Security",
                        title=f"Public GraphQL Introspection Enabled ({path})",
                        severity=Severity.MEDIUM,
                        cvss_score=5.3,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                        cwe_id="CWE-200",
                        owasp_category="A05:2021-Security Misconfiguration",
                        nist_control="AC-3",
                        description=f"The GraphQL endpoint at '{gql_url}' permits unauthenticated full introspection queries.",
                        impact="Attackers can map out the entire GraphQL database schema, all queryable models, private mutations, and hidden fields.",
                        remediation="Disable GraphQL introspection in production environments.",
                        remediation_code_snippet=(
                            "# Apollo Server (Node.js):\n"
                            "const server = new ApolloServer({\n"
                            "  typeDefs,\n"
                            "  resolvers,\n"
                            "  introspection: process.env.NODE_ENV !== 'production'\n"
                            "});"
                        ),
                        references=["https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html"],
                        evidence=Evidence(
                            location=gql_url,
                            observed_value=f"GraphQL schema types discovered: {', '.join(filter(None, type_names))}",
                            expected_value="Introspection disabled in production",
                            request_details={"method": "POST", "url": gql_url, "json": introspection_query},
                            response_details={"status_code": resp.status_code},
                        ),
                        fingerprint=calculate_fingerprint("DAST-GQL-001", gql_url, "introspection_open"),
                    ))
                    break
        except Exception as exc:
            logger.debug("GraphQL introspection probe failed: error_type=%s", type(exc).__name__)

    return findings
