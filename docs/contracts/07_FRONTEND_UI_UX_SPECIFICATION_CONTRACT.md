# Contract 07: Frontend UI/UX, Real-Time Telemetry & Enterprise Workflow Contract

**Project Name:** CyberAssess Automated Security Assessment & Vulnerability Management Platform  
**Document Version:** 14.0.0 (Enterprise ASPM Dashboard, 26-Tool Fleet, Per-Link Assessment Dossiers, Active Subdomain IP Resolution & Real-Time Telemetry Hub)  
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
   - Login is an authentication-only interaction. After the authenticated response is accepted, the UI MUST establish session state and return control without awaiting toolbox, capability, scan-history, installer, telemetry, or external-tool work. Observational data may load independently after login and MUST fail independently.
2. **Attack Surface & Asset Inventory Modal (`#assets-modal`):**
   - Manage registered assets across all asset types (`Web Application`, `API Endpoint`, `Domain`, `IP Address`, `Git Repository`, `Container Image`) with criticality tier filters, owner tagging, and direct 1-click audit launching.
3. **Vulnerability Lifecycle & Triage HUD:**
   - View canonical findings with SLA countdown timers, correlation tags, contributing tools, and inline status modification (`OPEN`, `IN_PROGRESS`, `FIXED`, `RISK_ACCEPTED`).
4. **Pentester Workbench (HTTP Repeater):**
   - Safe interactive HTTP repeater enforcing SSRF controls, size limits, and formatted request/response inspection.
5. **Toolbox Manager (`#toolbox-modal`):**
   - Tool capabilities fleet status (26 tools) with 1-click installation telemetry stream. The toolbox requests backend-owned installation/status and capability snapshots by default, including live-versus-cached metadata where exposed, and supports deliberate backend live refresh after installation or user request. `ADAPTER_ACTIVE` and `NATIVE_ENGINE_READY` render green; `NATIVE_FALLBACK` renders yellow; manual-only and disabled states render gray. The frontend does not perform tool detection. This observational status never authorizes execution and is not persisted in the browser or database.
   - The toolbox is a read-only view of backend observations. Normal page refresh, opening the toolbox, login, logout, and token renewal MUST NOT cause browser-side detection or force a live refresh. A deliberate refresh action may request `refresh=true`; loading state, source (`LIVE`/`CACHE`), age, and failure state MUST be visible without presenting stale data as current.
   - **Viewport Ergonomics & Geometry:**
     - Modal Card (`.modal-card--toolbox`): Responsive viewport bounds capped at `width: 95vw` (max `1280px`) and `height: 92vh` (max `94vh`) in a flex-column layout to fit modern desktop and widescreen SOC displays without overflow clipping.
     - Actions Bar (`.toolbox-actions-bar`): Fixed header region (`flex-shrink: 0`) hosting summary telemetry chips and batch action controls.
     - Scrollable Fleet Table (`.toolbox-table-container`): Responsive height with `min-height: 200px` and `max-height: calc(100% - 240px)`, auto vertical and horizontal overflow scrolling.
     - Sticky Header (`.toolbox-table thead th`): Positioned `sticky; top: 0; z-index: 10` with solid background (`#1e293b`) preserving column identifiers during deep fleet navigation.
     - Installation Terminal Viewport (`.toolbox-terminal-log`): Fixed bounded scrolling height of `180px` (`min-height: 160px`), `overflow-y: auto`, `white-space: pre-wrap`, `word-break: break-word` with dark terminal styling (`#020617`), eliminating log clipping and inner nested scroll traps.
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

7. **Historical Scan and Test Records:**
   - History views MUST read the authenticated backend's canonical `items` collection and preserve tenant-scoped records across refresh, logout/login, and service restart. The UI MUST never clear history as a side effect of session state or capability loading.
   - Any destructive deletion control MUST be clearly labeled as a privileged purge, require the backend authorization and audit response, and be separate from ordinary history navigation. If retention policy requires preservation, the UI MUST offer archive/retention states rather than hard deletion.
