# Contract 07: Frontend UI/UX Architecture, Design System & Telemetry Contract

**Project Name:** Full-Stack Automated Security Assessment & Vulnerability Management Platform  
**Document Version:** 4.0.0 (Enterprise Penetration Testing & Advanced Threat Auditing Specification)  
**Status:** APPROVED / AUTHORITATIVE SPECIFICATION  
**Scope Authority:** Frontend Architecture, Design Tokens, HUD Layout & User Interactions  

---

## 1. Design System & Cyber SOC HUD Tokens

The dashboard is structured as a **Cyber-Security Operations Center (SOC) Command HUD** with deep obsidian backgrounds, high-contrast typography, and neon status accents.

### 1.1 Color Tokens & CSS Variables
```css
:root {
  /* Surfaces & Backgrounds */
  --bg-primary: #07090e;          /* Deep space black */
  --bg-surface: #0e131f;          /* Card & panel background */
  --bg-surface-elevated: #161d2f;   /* Interactive hover & modal background */
  --bg-terminal: #05070a;         /* Monospace log console background */
  
  /* Borders & Accents */
  --border-subtle: #1e293b;
  --border-active: #334155;
  --border-glow: rgba(56, 189, 248, 0.3);

  /* Cyber Neon Accents */
  --accent-cyan: #06b6d4;
  --accent-emerald: #10b981;
  --accent-blue: #3b82f6;
  --accent-purple: #8b5cf6;

  /* Severity Hierarchy Colors */
  --color-critical: #ef4444;      /* Crimson Red */
  --color-high: #f97316;          /* Bright Orange */
  --color-medium: #eab308;        /* Amber Yellow */
  --color-low: #3b82f6;           /* Dodger Blue */
  --color-info: #10b981;          /* Emerald Green */

  /* Typography */
  --font-sans: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  --font-mono: 'JetBrains Mono', 'Fira Code', 'Cascadia Code', Consolas, monospace;
}
```

---

## 2. Dashboard Component Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ 🛡️ CYBERASSESS HUD  [Target Input: URL / IP / Repo / Docker]  [🚀 LAUNCH SCAN]│
├─────────────────────────────────────────────────────────────────────────────┤
│ 🟢 SCAN STATUS: RUNNING (65%) | Stage: Active Parameter Fuzzing & DAST      │
│ [█████████████████████████████████████████████░░░░░░░░░░░░░░░░░░░░░░░░░░]   │
├─────────────────────────────────────────────────────────────────────────────┤
│ ┌───────────────────────┐ ┌───────────────────────────────────────────────┐ │
│ │  SECURITY SCORECARD   │ │         REAL-TIME TERMINAL STREAM             │ │
│ │   GRADE: [ C ] (76.0) │ │ 21:45:02 [INFO] (network) Discovered 8 subdoms│ │
│ │  Crit: 0 | High: 1    │ │ 21:45:05 [WARN] (dast) Injected XSS Canary OK │ │
│ │  Med:  3 | Low:  4    │ │ 21:45:07 [INFO] (sast) AST Taint Traces Mapped│ │
│ └───────────────────────┘ └───────────────────────────────────────────────┘ │
├─────────────────────────────────────────────────────────────────────────────┤
│ 📡 ATTACK SURFACE & RECON: [Discovered Endpoints (14)] [OSINT Subdomains (8)]│
│ ┌─────────────────────────────────────────────────────────────────────────┐ │
│ │ api.example.com -> AWS S3 [CNAME Takeover Vulnerable: NO]               │ │
│ │ dev.example.com -> Unregistered Bucket [TAKEOVER DETECTED!]            │ │
│ └─────────────────────────────────────────────────────────────────────────┘ │
├─────────────────────────────────────────────────────────────────────────────┤
│ 🛠️ PENTESTER WORKBENCH: [Vulnerability Findings] [HTTP Repeater Tool]       │
│ Engine Filter: [All] [Network] [DAST] [SAST] [IaC/Docker] [CI/CD]           │
│ Severity Tabs: [All (10)] [Critical (0)] [High (1)] [Med (3)] [Low (4)]     │
│ [🔍 Search findings...] [Export: 📄 HTML | ⚡ SARIF | 💾 JSON]              │
│ ┌─────────────────────────────────────────────────────────────────────────┐ │
│ │ 🔴 [CRIT] CVSS 9.8 - SQL Injection Detected via Timing (SLEEP 2s)       │ │
│ │   [Copy cURL PoC] [View Taint Trace] [Inspect Response Diff]            │ │
│ │ 🟠 [HIGH] CVSS 8.1 - Insecure CORS Origin Reflection with Credentials   │ │
│ │ 🟡 [MED]  CVSS 5.0 - Missing Content-Security-Policy (CSP) Header       │ │
│ └─────────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Interactive Component Workflows

1. **Target Launch Bar & Advanced Config Drawers:**
   - Auto-detects input type (`URL`, `DOMAIN`, `IP`, `LOCAL_PATH`, `DOCKERFILE`, `IAC_MANIFEST`).
   - **Authentication Controls:** Radio pills for `No Auth`, `Custom Header/Bearer`, `Session Cookie`, `Form Login` (fields for Login URL, Username, Password, CSRF Field, and Logged-In Indicator).
   - **Crawler Controls:** Depth ($1-5$), Max Pages ($10-200$), Exclude Patterns (`*logout*`, `*delete*`).
   - **Active Fuzzing Controls:** Toggles for SQLi probes, Canary XSS tokens, Path Traversal, SSTI evaluation, and Open Redirect.
   - **OSINT Recon Controls:** Toggles for Certificate Transparency (crt.sh) subdomain harvesting and Dangling CNAME takeover checks.

2. **Attack Surface Reconnaissance Tables:**
   - **Discovered Endpoints HUD:** Real-time table displaying crawled URLs, HTTP status, crawl depth, form discovery count, and auth posture.
   - **Discovered Subdomains HUD:** Real-time table displaying subdomain names, resolved IPs, CNAME aliases, and Takeover Vulnerability status badges.

3. **Interactive Findings Explorer:**
   - Filterable by engine, severity, and text search.
   - Expandable finding cards with CVSS badges, CWE/OWASP tags, evidence diffs, and remediation code blocks.
   - **One-Click "Copy cURL PoC":** Copies exact, standalone reproduction cURL command with test payloads and headers to clipboard.
   - **AST Taint Trace Viewer:** Visual step-by-step ladder showing untrusted user source variable down to database/command execution sink.

4. **Interactive HTTP Repeater Tab:**
   - Manual penetration testing workbench.
   - Method selector (GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD).
   - URL input bar with query parameter editor.
   - Headers and Request Body editor with syntax assistance.
   - Live "Send Request" trigger returning response status, latency, TLS ciphersuite, response headers, and formatted body viewer.

5. **Multi-Format Export Bar:** Direct download triggers for Standalone HTML, SARIF v2.1.0, and JSON.

6. **Scan History Archive:** Instant reload of past scans with timestamps, targets, grades, and findings.

---

## 4. SSE Stream Lifecycle Management

```javascript
class ScanStreamManager {
  connect(scanId) {
    if (this.eventSource) this.eventSource.close();
    
    this.eventSource = new EventSource(`/api/scans/${scanId}/events`);
    
    this.eventSource.addEventListener('progress', (e) => {
      const data = JSON.parse(e.data);
      this.updateProgressBar(data.percent, data.stage);
    });

    this.eventSource.addEventListener('log', (e) => {
      const data = JSON.parse(e.data);
      this.appendTerminalLog(data);
    });

    this.eventSource.addEventListener('auth_status', (e) => {
      const data = JSON.parse(e.data);
      this.updateAuthStatusBadge(data);
    });

    this.eventSource.addEventListener('crawl_discovered', (e) => {
      const endpoint = JSON.parse(e.data);
      this.addDiscoveredEndpointRow(endpoint);
    });

    this.eventSource.addEventListener('subdomain_discovered', (e) => {
      const subdomain = JSON.parse(e.data);
      this.addDiscoveredSubdomainRow(subdomain);
    });

    this.eventSource.addEventListener('finding', (e) => {
      const finding = JSON.parse(e.data);
      this.addFindingCard(finding);
      this.recalculateSummaryScore();
    });

    this.eventSource.addEventListener('completed', (e) => {
      const data = JSON.parse(e.data);
      this.finalizeScanState(data);
      this.eventSource.close();
    });

    this.eventSource.onerror = () => {
      this.startPollingFallback(scanId);
    };
  }
}
```

---

## 5. Zero-Build Lightweight Frontend Contract

- All frontend assets run directly in any standard browser without Node.js, Webpack, or npm build steps at runtime.
- FastAPI serves pure static HTML5, CSS3, and ES6 JavaScript directly at `/`.

