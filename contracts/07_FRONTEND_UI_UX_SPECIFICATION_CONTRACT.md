# Contract 07: Frontend UI/UX Architecture, Design System & Telemetry Contract

**Project Name:** Full-Stack Automated Security Assessment & Vulnerability Management Platform  
**Document Version:** 3.0.0 (Comprehensive Production Specification)  
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
│ 🟢 SCAN STATUS: RUNNING (65%) | Stage: Web DAST & Browser Security Audit    │
│ [█████████████████████████████████████████████░░░░░░░░░░░░░░░░░░░░░░░░░░]   │
├─────────────────────────────────────────────────────────────────────────────┤
│ ┌───────────────────────┐ ┌───────────────────────────────────────────────┐ │
│ │  SECURITY SCORECARD   │ │         REAL-TIME TERMINAL STREAM             │ │
│ │   GRADE: [ C ] (76.0) │ │ 21:45:02 [INFO] (network) TLS 1.3 Active      │ │
│ │  Crit: 0 | High: 1    │ │ 21:45:05 [WARN] (dast) Missing CSP Header     │ │
│ │  Med:  3 | Low:  4    │ │ 21:45:07 [WARN] (dast) Missing SRI on CDN     │ │
│ └───────────────────────┘ └───────────────────────────────────────────────┘ │
├─────────────────────────────────────────────────────────────────────────────┤
│ 📋 VULNERABILITY FINDINGS EXPLORER                                          │
│ Engine Filter: [All] [Network] [DAST] [SAST] [IaC/Docker] [CI/CD]           │
│ Severity Tabs: [All (10)] [Critical (0)] [High (1)] [Med (3)] [Low (4)]     │
│ [🔍 Search findings...] [Export: 📄 HTML | ⚡ SARIF | 💾 JSON]              │
│ ┌─────────────────────────────────────────────────────────────────────────┐ │
│ │ 🟠 [HIGH] CVSS 8.1 - Insecure CORS Origin Reflection with Credentials   │ │
│ │ 🟡 [MED]  CVSS 5.0 - Missing Content-Security-Policy (CSP) Header       │ │
│ │ 🟡 [MED]  CVSS 5.3 - Public GraphQL Introspection Enabled               │ │
│ └─────────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Interactive Component Workflows

1. **Target Launch Bar & Advanced Config:** Auto-detects input type (`URL`, `DOMAIN`, `IP`, `LOCAL_PATH`, `DOCKERFILE`, `IAC_MANIFEST`), preset profile selection (`Full Stack`, `Quick`, `DAST`, `SAST`, `Network`, `IaC`), and instantaneous launch.
   - **Authentication Config Modal/Drawer:** Radio buttons for `No Auth`, `Custom Header/Bearer`, `Session Cookie`, `Form Login` (fields for Login URL, Username, Password, and Logged-In Indicator).
   - **Crawler Scope Controls:** Sliders/inputs for Crawl Depth ($1-5$), Max Pages ($10-200$), and Exclude Path Patterns (`*logout*`, `*delete*`).
2. **Real-Time Telemetry & Monospace Terminal:** Real-time animated progress bar with glowing stage notifications; auto-scrolling terminal log feed with severity level color chips (`INFO`, `WARN`, `ERROR`).
3. **Security Grade Scorecard:** Giant grade hexagon badge (`A+` to `F`), numerical score meter (0-100), and clickable severity count tiles that immediately filter the findings table.
4. **Discovered Endpoints HUD:** Live updating table displaying crawled URLs, crawl depth, observed HTTP response code, and authentication status badges.
5. **Findings Explorer & Inspection Drawer:** Filterable by engine, severity, and text search. Clicking any finding row expands an inspection drawer with:
   - CVSS score badge and vector string
   - CWE ID & OWASP (2021) tags with external reference links
   - Detailed Description & Business Impact
   - Observed vs Expected Evidence Diff Box
   - Formatted Code Remediation Box with one-click "Copy Snippet" action.
6. **Multi-Format Export Bar:** Direct download triggers for Standalone HTML, SARIF v2.1.0, and JSON.
7. **Scan History Archive:** Instant reload of past scans with timestamps, targets, and grades.

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
