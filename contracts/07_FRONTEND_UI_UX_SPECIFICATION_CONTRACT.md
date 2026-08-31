# Contract 07: Frontend UI/UX, Real-Time Telemetry & Enterprise Workflow Contract

**Project Name:** CyberAssess Automated Security Assessment & Vulnerability Management Platform  
**Document Version:** 13.2.0 (Enterprise ASPM Dashboard, Per-Link Assessment Dossiers, Active Subdomain IP Resolution & Real-Time Telemetry Hub)  
**Status:** APPROVED / AUTHORITATIVE SPECIFICATION  
**Scope Authority:** Single Page Application (SPA), HUD Components, Real-Time SSE Streams & Client Security Controls  

---

## 1. UI Security Principles

1. **Backend Authorization as Single Source of Truth:** The UI reflects backend authorization state but is never treated as a security boundary. Denied actions from the API are gracefully caught and presented as permission notices.
2. **No Sensitive Data in Plain LocalStorage:** Secrets, private keys, and passwords are never cached in unencrypted browser storage.
3. **Correlation ID Visibility:** Requests and scan sessions visibly reference the active `X-Correlation-ID` for traceability with backend audit logs.

---

## 2. Core UI Workspaces & Modals

1. **Authentication & Session Status:**
   - Real-time indicator displaying authenticated user, organization context, and role badge (`ADMIN`, `SECURITY_ANALYST`, `DEVELOPER`, `VIEWER`).
   - One-time bootstrap prompt when platform is uninitialized.
2. **Attack Surface & Asset Inventory Modal (`#assets-modal`):**
   - Manage registered assets across all asset types (`Web Application`, `API Endpoint`, `Domain`, `IP Address`, `Git Repository`, `Container Image`) with criticality tier filters, owner tagging, and direct 1-click audit launching.
3. **Vulnerability Lifecycle & Triage HUD:**
   - View canonical findings with SLA countdown timers, correlation tags, contributing tools, and inline status modification (`OPEN`, `IN_PROGRESS`, `FIXED`, `RISK_ACCEPTED`).
4. **Pentester Workbench (HTTP Repeater):**
   - Safe interactive HTTP repeater enforcing SSRF controls, size limits, and formatted request/response inspection.
5. **Toolbox Manager:**
   - Real-time tool capabilities fleet status (21 tools) with 1-click installation telemetry stream.
6. **Assessment Intelligence & Telemetry Hub (`#telemetry-hub-modal`):**
   - Viewport Ergonomics: Uses responsive 92vh viewport with unified modal-body vertical scrolling to eliminate inner nested scroll traps and prevent content clipping on expanded dossiers.
   - **Tested Links & Endpoints (Per-Link Grouped Matrix)**: Each crawled link renders as an expandable card displaying:
     - Header: HTTP method badge, URL, HTTP status badge, depth level, auth badge, total tests evaluated chip, and findings count badge.
     - Body (on click/expand with smooth scroll alignment):
       - *Tools Run on Link*: Executed tool badges (`Katana`, `Nuclei`, `FFuF`, `Native DAST`).
       - *Security Checks & Tests Evaluated*: Table of tests (SQL Injection, Reflected XSS, Security Headers, CORS, CSRF) with green `SAFE / PASS` or red `FAIL` indicators and detailed probe logs.
       - *Correlated Findings*: Full unclipped vulnerability cards detected specifically on that URL with title, CWE badge, severity badge, description, and remediation snippet.
       - *Actions*: 1-click `⚡ Send to HTTP Repeater` and `📋 Copy URL` buttons.
   - **Attack Surface & OSINT**: Discovered subdomains table with actively resolved IPv4/IPv6 addresses, CNAME targets, takeover risk, and discovery source (`crt.sh`, `Certspotter`, `Subfinder`).
