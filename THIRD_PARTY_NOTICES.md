# Third-Party Notices

This document identifies third-party software referenced by or integrated with
CyberAssess. It is informational and is not a replacement for the license,
copyright notice, attribution, or source-availability terms supplied by each
third-party project. Versions and transitive dependencies may change; review
the exact dependency set used for each build.

Third-party components are not owned by Andress Lacson or CyberAssess. They
remain subject to their respective licenses. The CyberAssess Proprietary
Personal-Use License does not relicense, restrict, or supersede those licenses,
and it does not grant rights in upstream source code or external tools.

## Python dependencies

The direct Python dependencies declared in `backend/requirements.txt` are:

- FastAPI
- Uvicorn
- Pydantic
- HTTPX
- dnspython
- cryptography
- Beautiful Soup 4
- PyYAML
- pytest
- pytest-asyncio
- PyJWT
- Schemathesis

These packages and their transitive dependencies are separate works. Consult
their installed distribution metadata and upstream repositories for the exact
license and notice applicable to the version used.

## External security tools and integrations

CyberAssess contains adapters or integrations for tools including Nmap, Nuclei,
FFuf, Katana, Schemathesis, SSLyze, ProjectDiscovery tools, Semgrep, Trivy,
TruffleHog, Syft, Grype, Gitleaks, Dockle, Checkov, kube-bench, Prowler,
OSV-Scanner, Retire.js, and httpx. Tool names and integrations do not convey
ownership, endorsement, or trademark permission.

Some tools may be optional and may be installed separately rather than bundled
with CyberAssess. Their licenses, terms of use, output restrictions, and
installation requirements apply independently. In particular, review each
tool's license before redistribution, embedding, or any commercial activity.

## Redistribution review

Before distributing CyberAssess or a build containing or invoking third-party
components, identify the exact versions, retain required notices, comply with
source-distribution and attribution requirements, and verify compatibility
with the intended distribution. Nothing in this document should be read as a
representation that every dependency or tool permits the same personal-use
terms as CyberAssess.
