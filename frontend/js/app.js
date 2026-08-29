/**
 * CyberAssess Security Platform - Frontend HUD Controller
 * Pure Vanilla Zero-Build Architecture (Contract 07 & Contract 04 v3.1.0)
 */

class ScanStreamManager {
  constructor() {
    this.currentScanId = null;
    this.eventSource = null;
    this.allFindings = [];
    this.discoveredEndpoints = [];
    this.activeFilter = "ALL";
    this.searchQuery = "";

    this.initElements();
    this.attachEventListeners();
    this.checkSystemHealth();
    this.detectTargetType();
  }

  initElements() {
    // Form elements
    this.scanForm = document.getElementById("scan-form");
    this.targetInput = document.getElementById("target-input");
    this.targetName = document.getElementById("target-name");
    this.typeBadge = document.getElementById("type-detected-badge");
    this.scanProfile = document.getElementById("scan-profile");
    this.engineChips = document.querySelectorAll(".engine-chip");
    this.btnLaunch = document.getElementById("btn-launch");
    this.btnCancel = document.getElementById("btn-cancel");
    this.btnToggleAdvanced = document.getElementById("btn-toggle-advanced");
    this.advancedPanel = document.getElementById("advanced-config-panel");

    // Header Auth Indicator
    this.authStatusBadge = document.getElementById("auth-status-badge");

    // Crawler Config Controls
    this.cfgCrawlerEnabled = document.getElementById("cfg-crawler-enabled");
    this.cfgCrawlerDepth = document.getElementById("cfg-crawler-depth");
    this.valCrawlerDepth = document.getElementById("val-crawler-depth");
    this.cfgCrawlerPages = document.getElementById("cfg-crawler-pages");
    this.cfgCrawlerExclude = document.getElementById("cfg-crawler-exclude");

    // Auth Pills & Subforms
    this.authPills = document.querySelectorAll(".auth-pill");
    this.subformAuthHeader = document.getElementById("subform-auth-header");
    this.subformAuthCookie = document.getElementById("subform-auth-cookie");
    this.subformAuthForm = document.getElementById("subform-auth-form");

    // Discovered Endpoints HUD
    this.endpointsHud = document.getElementById("endpoints-hud");
    this.endpointsCountBadge = document.getElementById("endpoints-count-badge");
    this.endpointsTableBody = document.getElementById("endpoints-table-body");
    this.btnToggleEndpoints = document.getElementById("btn-toggle-endpoints");
    this.endpointsTableContainer = document.getElementById("endpoints-table-container");

    // Progress HUD
    this.progressHud = document.getElementById("progress-hud");
    this.progressBar = document.getElementById("progress-bar-fill");
    this.progressPercent = document.getElementById("progress-percent");
    this.stageText = document.getElementById("stage-text");

    // Terminal
    this.terminalWindow = document.getElementById("terminal-window");
    this.chkAutoscroll = document.getElementById("chk-autoscroll");
    this.btnClearTerminal = document.getElementById("btn-clear-terminal");

    // Scorecard & Dashboard
    this.resultsDashboard = document.getElementById("results-dashboard");
    this.gradeLetter = document.getElementById("grade-letter");
    this.gradeCircle = document.getElementById("grade-circle");
    this.scoreVal = document.getElementById("score-val");
    this.countCritical = document.getElementById("count-critical");
    this.countHigh = document.getElementById("count-high");
    this.countMedium = document.getElementById("count-medium");
    this.countLow = document.getElementById("count-low");
    this.countInfo = document.getElementById("count-info");

    // Export Buttons
    this.btnExportHtml = document.getElementById("btn-export-html");
    this.btnExportSarif = document.getElementById("btn-export-sarif");
    this.btnExportJson = document.getElementById("btn-export-json");

    // Findings
    this.findingsList = document.getElementById("findings-list-container");
    this.filterTabs = document.querySelectorAll(".filter-tab");
    this.searchInput = document.getElementById("findings-search");

    // History Modal
    this.btnOpenHistory = document.getElementById("btn-open-history");
    this.btnCloseHistory = document.getElementById("btn-close-history");
    this.historyModal = document.getElementById("history-modal");
    this.historyTableBody = document.getElementById("history-table-body");
  }

  attachEventListeners() {
    // Target Input Type Detection
    this.targetInput.addEventListener("input", () => this.detectTargetType());

    // Profile Presets Selection
    this.scanProfile.addEventListener("change", (e) => this.applyProfilePreset(e.target.value));

    // Engine Chips Toggle
    this.engineChips.forEach((chip) => {
      const checkbox = chip.querySelector('input[type="checkbox"]');
      checkbox.addEventListener("change", () => {
        chip.classList.toggle("active", checkbox.checked);
      });
    });

    // Advanced Panel Toggle
    this.btnToggleAdvanced.addEventListener("click", (e) => {
      e.preventDefault();
      const isVisible = this.advancedPanel.style.display !== "none";
      this.advancedPanel.style.display = isVisible ? "none" : "block";
    });

    // Crawler Depth Slider
    if (this.cfgCrawlerDepth) {
      this.cfgCrawlerDepth.addEventListener("input", (e) => {
        if (this.valCrawlerDepth) this.valCrawlerDepth.innerText = e.target.value;
      });
    }

    // Auth Pill Selection
    this.authPills.forEach((pill) => {
      const radio = pill.querySelector('input[type="radio"]');
      pill.addEventListener("click", () => {
        this.authPills.forEach((p) => p.classList.remove("active"));
        pill.classList.add("active");
        radio.checked = true;
        this.toggleAuthSubforms(radio.value);
      });
    });

    // Toggle Endpoints HUD Table
    if (this.btnToggleEndpoints) {
      this.btnToggleEndpoints.addEventListener("click", () => {
        const isHidden = this.endpointsTableContainer.style.display === "none";
        this.endpointsTableContainer.style.display = isHidden ? "block" : "none";
        this.btnToggleEndpoints.innerText = isHidden ? "Collapse" : "Expand";
      });
    }

    // Form Submission (Launch Scan)
    this.scanForm.addEventListener("submit", (e) => this.handleStartScan(e));

    // Cancel Scan
    this.btnCancel.addEventListener("click", () => this.handleCancelScan());

    // Terminal Clear
    this.btnClearTerminal.addEventListener("click", () => {
      this.terminalWindow.innerHTML = "";
    });

    // Filter Tabs
    this.filterTabs.forEach((tab) => {
      tab.addEventListener("click", () => {
        this.filterTabs.forEach((t) => t.classList.remove("active"));
        tab.classList.add("active");
        this.activeFilter = tab.dataset.filter;
        this.renderFindings();
      });
    });

    // Live Search Input
    this.searchInput.addEventListener("input", (e) => {
      this.searchQuery = e.target.value.toLowerCase();
      this.renderFindings();
    });

    // History Modal
    this.btnOpenHistory.addEventListener("click", () => this.openHistoryModal());
    this.btnCloseHistory.addEventListener("click", () => this.closeHistoryModal());
    this.historyModal.addEventListener("click", (e) => {
      if (e.target === this.historyModal) this.closeHistoryModal();
    });
  }

  toggleAuthSubforms(authType) {
    if (this.subformAuthHeader) this.subformAuthHeader.style.display = authType === "HEADER" ? "block" : "none";
    if (this.subformAuthCookie) this.subformAuthCookie.style.display = authType === "COOKIE" ? "block" : "none";
    if (this.subformAuthForm) this.subformAuthForm.style.display = authType === "FORM_LOGIN" ? "block" : "none";

    this.updateAuthStatusBadge(authType, false);
  }

  updateAuthStatusBadge(authType, isActive = false) {
    if (!this.authStatusBadge) return;
    this.authStatusBadge.className = "auth-status-badge";
    if (authType === "NONE") {
      this.authStatusBadge.classList.add("badge-none");
      this.authStatusBadge.innerText = "AUTH: NONE";
    } else if (isActive) {
      this.authStatusBadge.classList.add("badge-auth-active");
      this.authStatusBadge.innerText = `AUTH: ${authType} (ACTIVE)`;
    } else {
      this.authStatusBadge.classList.add("badge-none");
      this.authStatusBadge.innerText = `AUTH: ${authType}`;
    }
  }

  async checkSystemHealth() {
    try {
      const res = await fetch("/api/system/health");
      if (res.ok) {
        document.getElementById("system-status-text").innerText = "SYSTEM ONLINE";
        document.getElementById("system-status-indicator").style.borderColor = "var(--border-subtle)";
      }
    } catch (e) {
      document.getElementById("system-status-text").innerText = "DISCONNECTED";
      document.getElementById("system-status-indicator").style.borderColor = "var(--color-critical)";
    }
  }

  detectTargetType() {
    const val = this.targetInput.value.trim();
    let type = "URL";

    if (val.startsWith("/") || val.startsWith("./") || val.includes(":\\") || val.startsWith("..")) {
      if (val.toLowerCase().endsWith("dockerfile")) {
        type = "DOCKERFILE";
      } else if (val.endsWith(".yaml") || val.endsWith(".yml") || val.endsWith(".tf")) {
        type = "IAC_MANIFEST";
      } else {
        type = "LOCAL_PATH";
      }
    } else if (val.startsWith("http://") || val.startsWith("https://")) {
      type = "URL";
    } else if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(val)) {
      type = "IP";
    } else if (/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/.test(val)) {
      type = "DOMAIN";
    }

    this.typeBadge.innerText = type;
    return type;
  }

  applyProfilePreset(profile) {
    const chipMap = {
      FULL_STACK: ["network", "web_dast", "code_sast", "infra_iac", "cicd_audit"],
      QUICK_AUDIT: ["network", "web_dast"],
      DAST_ONLY: ["web_dast"],
      SAST_ONLY: ["code_sast"],
      NETWORK_TLS: ["network"],
      INFRA_ONLY: ["infra_iac"],
      CUSTOM: null,
    };

    const targetEngines = chipMap[profile];
    if (!targetEngines) return;

    this.engineChips.forEach((chip) => {
      const engineName = chip.dataset.engine;
      const checkbox = chip.querySelector('input[type="checkbox"]');
      const isEnabled = targetEngines.includes(engineName);
      checkbox.checked = isEnabled;
      chip.classList.toggle("active", isEnabled);
    });
  }

  getSelectedEngines() {
    const selected = [];
    this.engineChips.forEach((chip) => {
      const checkbox = chip.querySelector('input[type="checkbox"]');
      if (checkbox.checked) selected.push(checkbox.value);
    });
    return selected;
  }

  getAuthConfig() {
    const checkedRadio = document.querySelector('input[name="auth_type"]:checked');
    const authType = checkedRadio ? checkedRadio.value : "NONE";

    const authConfig = { auth_type: authType };

    if (authType === "HEADER") {
      const hdrName = document.getElementById("cfg-auth-hdr-name").value.trim() || "Authorization";
      const hdrVal = document.getElementById("cfg-auth-hdr-val").value.trim();
      authConfig.headers = hdrVal ? { [hdrName]: hdrVal } : {};
    } else if (authType === "COOKIE") {
      const cookieName = document.getElementById("cfg-auth-cookie-name").value.trim() || "sessionid";
      const cookieVal = document.getElementById("cfg-auth-cookie-val").value.trim();
      authConfig.cookies = cookieVal ? { [cookieName]: cookieVal } : {};
    } else if (authType === "FORM_LOGIN") {
      authConfig.login_url = document.getElementById("cfg-auth-login-url").value.trim() || null;
      authConfig.username_field = document.getElementById("cfg-auth-user-field").value.trim() || "username";
      authConfig.username = document.getElementById("cfg-auth-username").value.trim() || null;
      authConfig.password_field = document.getElementById("cfg-auth-pass-field").value.trim() || "password";
      authConfig.password = document.getElementById("cfg-auth-password").value || null;
      authConfig.logged_in_indicator = document.getElementById("cfg-auth-indicator").value.trim() || null;
    }

    return authConfig;
  }

  getCrawlerConfig() {
    const enabled = this.cfgCrawlerEnabled ? this.cfgCrawlerEnabled.checked : true;
    const maxDepth = parseInt(this.cfgCrawlerDepth?.value || "3");
    const maxPages = parseInt(this.cfgCrawlerPages?.value || "50");
    const excludeRaw = this.cfgCrawlerExclude?.value || "";
    const excludePatterns = excludeRaw
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);

    return {
      enabled: enabled,
      max_depth: maxDepth,
      max_pages: maxPages,
      exclude_patterns: excludePatterns,
      follow_redirects: true,
      parse_sitemap: true,
    };
  }

  async handleStartScan(e) {
    e.preventDefault();
    const targetVal = this.targetInput.value.trim();
    if (!targetVal) return;

    const targetType = this.detectTargetType();
    const targetName = this.targetName.value.trim() || targetVal;
    const profile = this.scanProfile.value;
    const enabledEngines = this.getSelectedEngines();

    const rateLimit = parseFloat(document.getElementById("cfg-rate-limit").value) || 5.0;
    const timeoutSec = parseInt(document.getElementById("cfg-timeout").value) || 10;
    const customUa = document.getElementById("cfg-user-agent").value.trim();

    const crawlerConfig = this.getCrawlerConfig();
    const authConfig = this.getAuthConfig();

    const payload = {
      target_type: targetType,
      target_value: targetVal,
      target_name: targetName,
      profile: profile,
      enabled_engines: enabledEngines,
      config: {
        rate_limit_rps: rateLimit,
        timeout_seconds: timeoutSec,
        custom_headers: customUa ? { "User-Agent": customUa } : {},
        crawler: crawlerConfig,
        auth: authConfig,
      },
    };

    this.btnLaunch.style.display = "none";
    this.btnCancel.style.display = "inline-flex";
    this.progressHud.style.display = "block";
    this.resultsDashboard.style.display = "block";

    this.allFindings = [];
    this.discoveredEndpoints = [];
    this.renderScorecard(null);
    this.renderFindings();
    this.renderDiscoveredEndpoints();

    this.appendLog("orchestrator", "INFO", `Launching scan on target: ${targetVal}`);

    try {
      const res = await fetch("/api/scans/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      if (!res.ok) {
        const errData = await res.json();
        throw new Error(errData.detail || "Failed to start scan");
      }

      const data = await res.json();
      this.currentScanId = data.scan_id;
      this.updateExportLinks(this.currentScanId);
      this.connectEventStream(this.currentScanId);
    } catch (err) {
      this.appendLog("orchestrator", "ERROR", `Scan launch failed: ${err.message}`);
      this.btnLaunch.style.display = "inline-flex";
      this.btnCancel.style.display = "none";
    }
  }

  async handleCancelScan() {
    if (!this.currentScanId) return;
    try {
      await fetch(`/api/scans/${this.currentScanId}/cancel`, { method: "POST" });
      this.appendLog("orchestrator", "WARNING", "Scan cancellation requested by user.");
    } catch (e) {
      console.error(e);
    }
  }

  connectEventStream(scanId) {
    if (this.eventSource) {
      this.eventSource.close();
    }

    this.eventSource = new EventSource(`/api/scans/${scanId}/events`);

    this.eventSource.addEventListener("progress", (e) => {
      const data = JSON.parse(e.data);
      this.updateProgress(data.percent, data.stage);
    });

    this.eventSource.addEventListener("log", (e) => {
      const data = JSON.parse(e.data);
      this.appendLog(data.engine, data.level, data.message, data.timestamp);
    });

    this.eventSource.addEventListener("finding", (e) => {
      const finding = JSON.parse(e.data);
      this.allFindings.push(finding);
      this.renderFindings();
      this.updateLiveSummaryCounts();
    });

    this.eventSource.addEventListener("auth_status", (e) => {
      const data = JSON.parse(e.data);
      this.updateAuthStatusBadge(data.auth_type, data.session_active);
      this.appendLog("auth_session", data.authenticated ? "INFO" : "WARNING", data.message || "Auth status updated.");
    });

    this.eventSource.addEventListener("crawl_discovered", (e) => {
      const ep = JSON.parse(e.data);
      this.addDiscoveredEndpoint(ep);
    });

    this.eventSource.addEventListener("tool_status", (e) => {
      const data = JSON.parse(e.data);
      this.updateToolPill(data.tool, data.available, data.mode, data.version);
    });

    this.eventSource.addEventListener("completed", (e) => {
      const summary = JSON.parse(e.data);
      this.renderScorecard(summary);
      this.updateProgress(100, "Assessment complete.");
      this.btnLaunch.style.display = "inline-flex";
      this.btnCancel.style.display = "none";
      if (summary.authenticated_session_active) {
        this.updateAuthStatusBadge("ACTIVE", true);
      }
      this.eventSource.close();
    });

    this.eventSource.addEventListener("error", (e) => {
      if (this.eventSource.readyState === EventSource.CLOSED) {
        this.btnLaunch.style.display = "inline-flex";
        this.btnCancel.style.display = "none";
      }
    });
  }

  addDiscoveredEndpoint(endpoint) {
    if (!this.discoveredEndpoints.some((e) => e.url === endpoint.url)) {
      this.discoveredEndpoints.push(endpoint);
      this.renderDiscoveredEndpoints();
    }
  }

  // Contract 07 v4.1.0: Tool Adapter Pill Bar Update
  updateToolPill(toolName, available, mode, version) {
    const pill = document.getElementById(`tool-pill-${toolName}`);
    if (!pill) return;

    const iconEl = pill.querySelector(".tool-pill-icon");
    const modeEl = pill.querySelector(".tool-pill-mode");
    const nameEl = pill.querySelector(".tool-pill-name");

    // Remove all state classes
    pill.classList.remove("tool-pill--active", "tool-pill--fallback", "tool-pill--disabled");

    if (mode === "ADAPTER_ACTIVE") {
      pill.classList.add("tool-pill--active");
      if (iconEl) iconEl.textContent = "🟢";
      if (modeEl) modeEl.textContent = version ? `v${version}` : "ACTIVE";
    } else if (mode === "DISABLED") {
      pill.classList.add("tool-pill--disabled");
      if (iconEl) iconEl.textContent = "⚫";
      if (modeEl) modeEl.textContent = "DISABLED";
    } else {
      // NATIVE_FALLBACK (default)
      pill.classList.add("tool-pill--fallback");
      if (iconEl) iconEl.textContent = "🟡";
      if (modeEl) modeEl.textContent = "NATIVE FALLBACK";
    }
  }

  // Contract 04 v4.1.0: Probe GET /api/system/capabilities on page load
  async loadSystemCapabilities() {
    try {
      const resp = await fetch("/api/system/capabilities");
      if (!resp.ok) return;
      const data = await resp.json();
      const tools = data.tools || [];
      tools.forEach((t) => {
        this.updateToolPill(t.name, t.available, t.execution_mode, t.version);
      });
    } catch (_) {
      // Non-fatal: pill bar defaults remain (NATIVE FALLBACK)
    }
  }

  renderDiscoveredEndpoints() {
    if (!this.endpointsHud) return;

    if (this.discoveredEndpoints.length === 0) {
      this.endpointsHud.style.display = "none";
      return;
    }

    this.endpointsHud.style.display = "block";
    if (this.endpointsCountBadge) {
      this.endpointsCountBadge.innerText = `${this.discoveredEndpoints.length} Endpoint${this.discoveredEndpoints.length === 1 ? "" : "s"}`;
    }

    this.endpointsTableBody.innerHTML = this.discoveredEndpoints
      .map((ep) => {
        let statusClass = "status-badge-2xx";
        if (ep.status_code >= 500) statusClass = "status-badge-5xx";
        else if (ep.status_code >= 400) statusClass = "status-badge-4xx";
        else if (ep.status_code >= 300) statusClass = "status-badge-3xx";

        return `
        <tr>
          <td><span style="color: var(--text-dim);">D${ep.depth}</span></td>
          <td><span style="color: var(--accent-cyan); font-weight: 700;">${this.escapeHtml(ep.method || "GET")}</span></td>
          <td><code style="word-break: break-all;">${this.escapeHtml(ep.url)}</code></td>
          <td><span class="${statusClass}">${ep.status_code || 200}</span></td>
          <td>${ep.has_forms ? '<span class="tag-form">FORM</span>' : '<span style="color: var(--text-dim);">-</span>'}</td>
          <td>${ep.is_authenticated ? '<span class="tag-auth">AUTH</span>' : '<span style="color: var(--text-dim);">PUBLIC</span>'}</td>
        </tr>
      `;
      })
      .join("");
  }

  updateProgress(percent, stage) {
    const pct = Math.min(100, Math.max(0, percent || 0));
    this.progressBar.style.width = `${pct}%`;
    this.progressPercent.innerText = `${pct}%`;
    if (stage) this.stageText.innerText = stage;
  }

  appendLog(engine, level, message, timestamp) {
    const timeStr = timestamp ? new Date(timestamp).toLocaleTimeString() : new Date().toLocaleTimeString();
    const line = document.createElement("div");
    line.className = `log-line ${(level || "info").toLowerCase()}`;
    line.innerHTML = `
      <span class="log-time">[${timeStr}]</span>
      <span class="log-engine">[${engine || "sys"}]</span>
      <span class="log-msg">${this.escapeHtml(message)}</span>
    `;
    this.terminalWindow.appendChild(line);

    if (this.chkAutoscroll.checked) {
      this.terminalWindow.scrollTop = this.terminalWindow.scrollHeight;
    }
  }

  updateLiveSummaryCounts() {
    let crit = 0, high = 0, med = 0, low = 0, info = 0;
    this.allFindings.forEach((f) => {
      if (f.severity === "CRITICAL") crit++;
      else if (f.severity === "HIGH") high++;
      else if (f.severity === "MEDIUM") med++;
      else if (f.severity === "LOW") low++;
      else if (f.severity === "INFO") info++;
    });

    this.countCritical.innerText = crit;
    this.countHigh.innerText = high;
    this.countMedium.innerText = med;
    this.countLow.innerText = low;
    this.countInfo.innerText = info;

    document.getElementById("tab-count-all").innerText = this.allFindings.length;
    document.getElementById("tab-count-critical").innerText = crit;
    document.getElementById("tab-count-high").innerText = high;
    document.getElementById("tab-count-medium").innerText = med;
    document.getElementById("tab-count-low").innerText = low;
  }

  renderScorecard(summary) {
    const grade = summary ? summary.overall_security_grade : "-";
    const score = summary ? `${summary.weighted_score.toFixed(1)} / 100` : "0.0 / 100";

    this.gradeLetter.innerText = grade;
    this.scoreVal.innerText = score;

    const gradeColors = {
      "A+": "#10b981",
      A: "#10b981",
      B: "#3b82f6",
      C: "#eab308",
      D: "#f97316",
      F: "#ef4444",
      "-": "#64748b",
    };

    const col = gradeColors[grade] || "#64748b";
    this.gradeCircle.style.borderColor = col;
    this.gradeCircle.style.boxShadow = `0 0 25px ${col}66`;
    this.gradeLetter.style.color = col;

    if (summary) {
      this.countCritical.innerText = summary.critical_count;
      this.countHigh.innerText = summary.high_count;
      this.countMedium.innerText = summary.medium_count;
      this.countLow.innerText = summary.low_count;
      this.countInfo.innerText = summary.info_count;
    }
  }

  updateExportLinks(scanId) {
    this.btnExportHtml.href = `/api/scans/${scanId}/export/html`;
    this.btnExportSarif.href = `/api/scans/${scanId}/export/sarif`;
    this.btnExportJson.href = `/api/scans/${scanId}/export/json`;
  }

  renderFindings() {
    this.updateLiveSummaryCounts();
    const filtered = this.allFindings.filter((f) => {
      const matchFilter = this.activeFilter === "ALL" || f.severity === this.activeFilter;
      const matchSearch =
        !this.searchQuery ||
        f.title.toLowerCase().includes(this.searchQuery) ||
        f.check_id.toLowerCase().includes(this.searchQuery) ||
        (f.cwe_id && f.cwe_id.toLowerCase().includes(this.searchQuery));
      return matchFilter && matchSearch;
    });

    if (filtered.length === 0) {
      this.findingsList.innerHTML = `
        <div style="text-align: center; padding: 40px 20px; color: var(--text-muted);">
          <div style="font-size: 32px; margin-bottom: 8px;">🛡️</div>
          <div>No vulnerabilities matching current filter criteria.</div>
        </div>
      `;
      return;
    }

    this.findingsList.innerHTML = filtered
      .map((f, idx) => {
        const sevClass = `severity-${f.severity.toLowerCase()}`;
        const codeSnippet = f.remediation_code_snippet
          ? `
          <div class="code-block-container">
            <div class="code-header">
              <span>Remediation Code Snippet</span>
              <button class="btn-copy" onclick="window.copySnippet('snip-${idx}')">Copy</button>
            </div>
            <pre id="snip-${idx}"><code>${this.escapeHtml(f.remediation_code_snippet)}</code></pre>
          </div>
        `
          : "";

        return `
        <div class="finding-card ${sevClass}">
          <div class="finding-header" onclick="window.toggleCard('fc-${idx}')">
            <div class="finding-title-group">
              <span class="severity-badge ${sevClass}">${f.severity}</span>
              <span class="check-id">${this.escapeHtml(f.check_id)}</span>
              <span class="finding-title">${this.escapeHtml(f.title)}</span>
            </div>
            <div class="finding-header-meta">
              <span class="cvss-pill">CVSS ${f.cvss_score.toFixed(1)}</span>
              <span class="chevron" id="chev-fc-${idx}">▼</span>
            </div>
          </div>
          <div class="finding-body" id="body-fc-${idx}">
            <div class="tags-row">
              ${f.cwe_id ? `<span class="meta-tag">${this.escapeHtml(f.cwe_id)}</span>` : ""}
              ${f.owasp_category ? `<span class="meta-tag">${this.escapeHtml(f.owasp_category)}</span>` : ""}
              ${f.nist_control ? `<span class="meta-tag">${this.escapeHtml(f.nist_control)}</span>` : ""}
              <span class="meta-tag engine-tag">${this.escapeHtml(f.engine)}</span>
              <span class="source-tool-badge source-tool--${(f.source_tool || 'native').toLowerCase()}">[${this.escapeHtml(f.source_tool || 'native')}]</span>
            </div>

            <p class="finding-desc"><strong>Description:</strong> ${this.escapeHtml(f.description)}</p>
            <p class="finding-impact"><strong>Impact:</strong> ${this.escapeHtml(f.impact)}</p>

            <div class="evidence-box">
              <h4>Evidence & Location</h4>
              <div class="evidence-row">
                <span class="ev-label">Location:</span>
                <code>${this.escapeHtml(f.evidence.location)}</code>
              </div>
              <div class="evidence-row">
                <span class="ev-label">Observed:</span>
                <code class="obs-code">${this.escapeHtml(f.evidence.observed_value)}</code>
              </div>
              <div class="evidence-row">
                <span class="ev-label">Expected:</span>
                <code class="exp-code">${this.escapeHtml(f.evidence.expected_value || "Secure Configuration")}</code>
              </div>
            </div>

            <div class="remediation-box">
              <h4>Remediation Guidance</h4>
              <p>${this.escapeHtml(f.remediation)}</p>
              ${codeSnippet}
            </div>
          </div>
        </div>
      `;
      })
      .join("");
  }

  async openHistoryModal() {
    this.historyModal.style.display = "flex";
    try {
      const res = await fetch("/api/scans/history?limit=30");
      if (!res.ok) return;
      const data = await res.json();
      this.renderHistoryTable(data.scans || []);
    } catch (e) {
      console.error(e);
    }
  }

  closeHistoryModal() {
    this.historyModal.style.display = "none";
  }

  renderHistoryTable(scans) {
    if (scans.length === 0) {
      this.historyTableBody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--text-muted);">No past scans recorded yet.</td></tr>`;
      return;
    }

    this.historyTableBody.innerHTML = scans
      .map((s) => {
        const time = s.created_at ? new Date(s.created_at).toLocaleString() : "N/A";
        const grade = s.summary ? s.summary.overall_security_grade : "-";
        const score = s.summary ? s.summary.weighted_score.toFixed(1) : "-";
        const findCount = s.findings ? s.findings.length : 0;

        return `
        <tr>
          <td>${time}</td>
          <td><strong>${this.escapeHtml(s.target.name || s.target.value)}</strong></td>
          <td><code>${s.target.type}</code></td>
          <td><span class="badge" style="font-weight: 800; font-size: 14px;">${grade}</span></td>
          <td>${score}</td>
          <td>${findCount}</td>
          <td>
            <button class="btn btn-xs btn-outline" onclick="window.app.loadPastScan('${s.id}')">View</button>
            <button class="btn btn-xs btn-ghost" style="color: var(--color-critical);" onclick="window.app.deletePastScan('${s.id}')">Delete</button>
          </td>
        </tr>
      `;
      })
      .join("");
  }

  async loadPastScan(scanId) {
    this.closeHistoryModal();
    try {
      const res = await fetch(`/api/scans/${scanId}`);
      if (!res.ok) return;
      const job = await res.json();

      this.currentScanId = job.id;
      this.targetInput.value = job.target.value;
      this.targetName.value = job.target.name || "";
      this.allFindings = job.findings || [];
      this.discoveredEndpoints = job.discovered_endpoints || [];

      this.updateProgress(job.progress_percent || 100, job.current_stage || "Completed.");
      this.renderScorecard(job.summary);
      this.renderFindings();
      this.renderDiscoveredEndpoints();
      this.updateExportLinks(job.id);

      if (job.summary?.authenticated_session_active) {
        this.updateAuthStatusBadge("ACTIVE", true);
      }

      this.resultsDashboard.style.display = "block";
      this.progressHud.style.display = "block";

      // Render logs
      this.terminalWindow.innerHTML = "";
      (job.logs || []).forEach((l) => {
        this.appendLog(l.engine, l.level, l.message, l.timestamp);
      });
    } catch (e) {
      console.error(e);
    }
  }

  async deletePastScan(scanId) {
    if (!confirm("Are you sure you want to delete this scan record?")) return;
    try {
      await fetch(`/api/scans/${scanId}`, { method: "DELETE" });
      this.openHistoryModal();
    } catch (e) {
      console.error(e);
    }
  }

  escapeHtml(str) {
    if (!str) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }
}

// Global helpers for inline onclick event handlers
window.toggleCard = function (id) {
  const body = document.getElementById("body-" + id);
  const chev = document.getElementById("chev-" + id);
  if (body) body.classList.toggle("open");
  if (chev) chev.classList.toggle("open");
};

window.copySnippet = function (id) {
  const el = document.getElementById(id);
  if (el) {
    navigator.clipboard.writeText(el.innerText).then(() => {
      alert("Remediation code snippet copied to clipboard.");
    });
  }
};

window.filterFindingsBySeverity = function (sev) {
  const tab = document.querySelector(`.filter-tab[data-filter="${sev}"]`);
  if (tab) tab.click();
};

document.addEventListener("DOMContentLoaded", () => {
  window.app = new ScanStreamManager();
  // Load tool capabilities immediately on page load (Contract 04 v4.1.0)
  window.app.loadSystemCapabilities();
});
