# Contract 07: Frontend UI/UX, Real-Time Telemetry & Enterprise Workflow Contract

**Project Name:** CyberAssess Automated Security Assessment & Vulnerability Management Platform  
**Document Version:** 10.0.0 (Enterprise ASPM Dashboard, Real Auth State Synchronization, Asset Management HUD & Secure Token Handling)  
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
   - Manage registered assets with criticality tier filters, owner tagging, and direct 1-click audit launching.
3. **Vulnerability Lifecycle & Triage HUD:**
   - View canonical findings with SLA countdown timers, correlation tags, contributing tools, and inline status modification (`OPEN`, `IN_PROGRESS`, `FIXED`, `RISK_ACCEPTED`).
4. **Pentester Workbench (HTTP Repeater):**
   - Safe interactive HTTP repeater enforcing SSRF controls, size limits, and formatted request/response inspection.
5. **Toolbox Manager:**
   - Real-time tool capabilities fleet status (21 tools) with 1-click installation telemetry stream.
