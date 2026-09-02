/**
 * CyberAssess Security Platform - Frontend HUD Controller
 * Pure Vanilla Zero-Build Architecture (Contract 07 & Contract 04 v4.1.0)
 */

class ScanStreamManager {
  constructor() {
    // Access tokens are intentionally memory-only. Do not persist credentials
    // in localStorage/sessionStorage where any injected script can recover them.
    this.accessToken = null;
    this.currentScanId = null;
    this.eventSource = null;
    this.allFindings = [];
    this.discoveredEndpoints = [];
    this.activeFilter = "ALL";
    this.searchQuery = "";

    this.initElements();
    this.attachEventListeners();
    this.checkAuthStatus();
    this.checkSystemHealth();
    this.detectTargetType();
    this.loadSystemCapabilities();
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

    // Discovered Subdomains OSINT HUD (Contract 07 v4.1.0)
    this.subdomainsHud = document.getElementById("subdomains-hud");
    this.subdomainsCountBadge = document.getElementById("subdomains-count-badge");
    this.subdomainsTableBody = document.getElementById("subdomains-table-body");
    this.btnToggleSubdomains = document.getElementById("btn-toggle-subdomains");
    this.subdomainsTableContainer = document.getElementById("subdomains-table-container");
    this.discoveredSubdomains = [];

    // HTTP Repeater Pentester Workbench (Contract 07 v4.1.0)
    this.btnOpenRepeater = document.getElementById("btn-open-repeater");
    this.btnCloseRepeater = document.getElementById("btn-close-repeater");
    this.repeaterModal = document.getElementById("repeater-modal");
    this.btnRepSend = document.getElementById("btn-rep-send");
    this.repMethod = document.getElementById("rep-method");
    this.repUrl = document.getElementById("rep-url");
    this.repHeaders = document.getElementById("rep-headers");
    this.repBody = document.getElementById("rep-body");
    this.repStatusBadge = document.getElementById("rep-status-badge");
    this.repMetricTime = document.getElementById("rep-metric-time");
    this.repMetricSize = document.getElementById("rep-metric-size");
    this.repMetricTls = document.getElementById("rep-metric-tls");
    this.repRespHeaders = document.getElementById("rep-resp-headers");
    this.repRespBody = document.getElementById("rep-resp-body");

    // Toolbox & Adapters Manager (Contract 07 v6.0.0)
    this.btnOpenToolbox = document.getElementById("btn-open-toolbox");
    this.btnCloseToolbox = document.getElementById("btn-close-toolbox");
    this.toolboxModal = document.getElementById("toolbox-modal");
    this.btnInstallAllTools = document.getElementById("btn-install-all-tools");
    this.toolboxTableBody = document.getElementById("toolbox-table-body");
    this.toolboxTerminalLog = document.getElementById("toolbox-terminal-log");
    this.toolboxInstallProgressBar = document.getElementById("toolbox-install-progress-bar");
    this.toolboxInstallStage = document.getElementById("toolbox-install-stage");
    this.toolboxInstalledCount = document.getElementById("toolbox-installed-count");
    this.toolEventsSource = null;

    // Tool Setup & Installation Guide Modal
    this.toolInstructionsModal = document.getElementById("tool-instructions-modal");
    this.instToolTitle = document.getElementById("inst-tool-title");
    this.instToolSubtitle = document.getElementById("inst-tool-subtitle");
    this.instToolBody = document.getElementById("inst-tool-body");
    this.instToolDocsLink = document.getElementById("inst-tool-docs-link");
    this.btnInstRecheck = document.getElementById("btn-inst-recheck");
    this._instRecheckTool = null;

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
    this.countTotal = document.getElementById("count-total");
    this.countPassed = document.getElementById("count-passed");
    this.metaEngineCount = document.getElementById("meta-engine-count");
    this.metaDuration = document.getElementById("meta-duration");
    this.metaChecks = document.getElementById("meta-checks");

    // Export Buttons
    this.btnExportHtml = document.getElementById("btn-export-html");
    this.btnExportSarif = document.getElementById("btn-export-sarif");
    this.btnExportJson = document.getElementById("btn-export-json");
    this.btnExportCycloneDx = document.getElementById("btn-export-cyclonedx");
    this.btnExportSpdx = document.getElementById("btn-export-spdx");

    // Findings
    this.findingsList = document.getElementById("findings-list-container");
    this.filterTabs = document.querySelectorAll(".filter-tab");
    this.searchInput = document.getElementById("findings-search");
    this.findingsToolFilter = document.getElementById("findings-tool-filter");
    this.selectedToolFilter = "ALL";

    // History Modal
    this.btnOpenHistory = document.getElementById("btn-open-history");
    this.btnCloseHistory = document.getElementById("btn-close-history");
    this.historyModal = document.getElementById("history-modal");
    this.historyTableBody = document.getElementById("history-table-body");

    // Asset Inventory Modal
    this.btnOpenAssets = document.getElementById("btn-open-assets");
    this.btnCloseAssets = document.getElementById("btn-close-assets");
    this.assetsModal = document.getElementById("assets-modal");
    this.assetsTableBody = document.getElementById("assets-table-body");
    this.btnCreateAssetToggle = document.getElementById("btn-create-asset-toggle");
    this.btnSaveNewAsset = document.getElementById("btn-save-new-asset");
    this.assetCreateFormContainer = document.getElementById("asset-create-form-container");

    // User Authentication Modal
    this.btnOpenAuth = document.getElementById("btn-open-auth");
    this.btnCloseAuth = document.getElementById("btn-close-auth");
    this.authModal = document.getElementById("auth-modal");
    this.btnSubmitLogin = document.getElementById("btn-submit-login");
    this.btnLogout = document.getElementById("btn-logout");
    this.userRoleBadge = document.getElementById("user-role-badge");
    this.authUsernameInput = document.getElementById("auth-username-input");
    this.authPasswordInput = document.getElementById("auth-password-input");
    this.authCurrentUsername = document.getElementById("auth-current-username");
    this.authCurrentRole = document.getElementById("auth-current-role");

    // Assessment Intelligence & Telemetry Hub Modal
    this.btnOpenTelemetry = document.getElementById("btn-open-telemetry");
    this.btnCloseTelemetry = document.getElementById("btn-close-telemetry");
    this.telemetryModal = document.getElementById("telemetry-modal");
    this.telemetryLogsContainer = document.getElementById("telemetry-logs-container");
    this.telemetryLogSearch = document.getElementById("telemetry-log-search");
    this.telemetryFilterTool = document.getElementById("telemetry-filter-tool");
    this.telemetryFilterLevel = document.getElementById("telemetry-filter-level");
    this.telemetryEndpointsContainer = document.getElementById("telemetry-endpoints-container");
    this.telemetryEndpointsTbody = document.getElementById("telemetry-endpoints-tbody");
    this.telemetryMatrixTbody = document.getElementById("telemetry-matrix-tbody");
    this.telemetrySubdomainsTbody = document.getElementById("telemetry-subdomains-tbody");
    this.telemetryLinksCount = document.getElementById("telemetry-links-count");
    this.telemetryToolsCount = document.getElementById("telemetry-tools-count");
    this.telemetryScanMeta = document.getElementById("telemetry-scan-meta");
    this.telemetryEndpointSearch = document.getElementById("telemetry-endpoint-search");
    this.telemetryEndpointFilterStatus = document.getElementById("telemetry-endpoint-filter-status");
    this.telemetryEndpointStats = document.getElementById("telemetry-endpoint-stats");
    this.btnCopyTelemetryLogs = document.getElementById("btn-copy-telemetry-logs");
    this.btnExportTelemetryJson = document.getElementById("btn-export-telemetry-json");
    this.currentTelemetryData = null;
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

    // Toggle Subdomains HUD Table (Contract 07 v4.1.0)
    if (this.btnToggleSubdomains) {
      this.btnToggleSubdomains.addEventListener("click", () => {
        const isHidden = this.subdomainsTableContainer.style.display === "none";
        this.subdomainsTableContainer.style.display = isHidden ? "block" : "none";
        this.btnToggleSubdomains.innerText = isHidden ? "Collapse" : "Expand";
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

    // Tool Selector Filter
    if (this.findingsToolFilter) {
      this.findingsToolFilter.addEventListener("change", (e) => {
        this.selectedToolFilter = e.target.value;
        this.renderFindings();
      });
    }

    // History Modal
    this.btnOpenHistory.addEventListener("click", () => this.openHistoryModal());
    this.btnCloseHistory.addEventListener("click", () => this.closeHistoryModal());
    this.historyModal.addEventListener("click", (e) => {
      if (e.target === this.historyModal) this.closeHistoryModal();
    });

    // HTTP Repeater Modal (Contract 07 v4.1.0)
    if (this.btnOpenRepeater) {
      this.btnOpenRepeater.addEventListener("click", () => this.openRepeaterModal());
    }
    if (this.btnCloseRepeater) {
      this.btnCloseRepeater.addEventListener("click", () => this.closeRepeaterModal());
    }
    if (this.repeaterModal) {
      this.repeaterModal.addEventListener("click", (e) => {
        if (e.target === this.repeaterModal) this.closeRepeaterModal();
      });
    }
    if (this.btnRepSend) {
      this.btnRepSend.addEventListener("click", () => this.handleSendRepeater());
    }

    // Toolbox & Adapters Modal (Contract 07 v6.0.0)
    if (this.btnOpenToolbox) {
      this.btnOpenToolbox.addEventListener("click", () => this.openToolboxModal());
    }
    if (this.btnCloseToolbox) {
      this.btnCloseToolbox.addEventListener("click", () => this.closeToolboxModal());
    }
    if (this.toolboxModal) {
      this.toolboxModal.addEventListener("click", (e) => {
        if (e.target === this.toolboxModal) this.closeToolboxModal();
      });
    }
    if (this.btnInstallAllTools) {
      this.btnInstallAllTools.addEventListener("click", () => this.handleInstallAllTools());
    }

    // Tool Setup & Installation Guide Modal
    const closeInst = () => this.closeToolInstructionsModal();
    document.getElementById("btn-close-tool-instructions")?.addEventListener("click", closeInst);
    document.getElementById("btn-close-tool-instructions-footer")?.addEventListener("click", closeInst);
    if (this.toolInstructionsModal) {
      this.toolInstructionsModal.addEventListener("click", (e) => {
        if (e.target === this.toolInstructionsModal) closeInst();
      });
    }
    if (this.btnInstRecheck) {
      this.btnInstRecheck.addEventListener("click", async () => {
        if (this._instRecheckTool) {
          closeInst();
          await this.refreshToolboxData();
        }
      });
    }

    // Asset Inventory Modal Listeners
    if (this.btnOpenAssets) {
      this.btnOpenAssets.addEventListener("click", () => this.openAssetsModal());
    }
    if (this.btnCloseAssets) {
      this.btnCloseAssets.addEventListener("click", () => this.closeAssetsModal());
    }
    if (this.assetsModal) {
      this.assetsModal.addEventListener("click", (e) => {
        if (e.target === this.assetsModal) this.closeAssetsModal();
      });
    }
    if (this.btnCreateAssetToggle) {
      this.btnCreateAssetToggle.addEventListener("click", () => {
        if (this.assetCreateFormContainer) {
          const isHidden = this.assetCreateFormContainer.style.display === "none";
          this.assetCreateFormContainer.style.display = isHidden ? "block" : "none";
        }
      });
    }
    if (this.btnSaveNewAsset) {
      this.btnSaveNewAsset.addEventListener("click", () => this.handleSaveNewAsset());
    }

    // User Authentication Modal Listeners
    if (this.btnOpenAuth) {
      this.btnOpenAuth.addEventListener("click", () => this.openAuthModal());
    }
    if (this.btnCloseAuth) {
      this.btnCloseAuth.addEventListener("click", () => this.closeAuthModal());
    }
    if (this.authModal) {
      this.authModal.addEventListener("click", (e) => {
        if (e.target === this.authModal) this.closeAuthModal();
      });
    }
    if (this.btnSubmitLogin) {
      this.btnSubmitLogin.addEventListener("click", () => this.handleLogin());
    }
    if (this.btnLogout) {
      this.btnLogout.addEventListener("click", () => this.handleLogout());
    }

    // Telemetry Hub Listeners
    if (this.btnOpenTelemetry) {
      this.btnOpenTelemetry.addEventListener("click", () => this.openTelemetryModal());
    }
    if (this.btnCloseTelemetry) {
      this.btnCloseTelemetry.addEventListener("click", () => this.closeTelemetryModal());
    }
    if (this.telemetryModal) {
      this.telemetryModal.addEventListener("click", (e) => {
        if (e.target === this.telemetryModal) this.closeTelemetryModal();
      });
    }

    // Telemetry Tab Switching
    const tabBtns = document.querySelectorAll(".telemetry-tab-btn");
    tabBtns.forEach((btn) => {
      btn.addEventListener("click", () => {
        tabBtns.forEach((b) => b.classList.remove("active"));
        btn.classList.add("active");
        const targetTab = btn.getAttribute("data-tab");
        document.querySelectorAll(".telemetry-tab-pane").forEach((pane) => {
          pane.style.display = pane.id === `pane-telemetry-${targetTab}` ? "block" : "none";
        });
      });
    });

    // Telemetry Filters
    if (this.telemetryLogSearch) {
      this.telemetryLogSearch.addEventListener("input", () => this.renderTelemetryLogs());
    }
    if (this.telemetryFilterTool) {
      this.telemetryFilterTool.addEventListener("change", () => this.renderTelemetryLogs());
    }
    if (this.telemetryFilterLevel) {
      this.telemetryFilterLevel.addEventListener("change", () => this.renderTelemetryLogs());
    }
    if (this.telemetryEndpointSearch) {
      this.telemetryEndpointSearch.addEventListener("input", () => this.renderTelemetryEndpoints());
    }
    if (this.telemetryEndpointFilterStatus) {
      this.telemetryEndpointFilterStatus.addEventListener("change", () => this.renderTelemetryEndpoints());
    }
    if (this.btnCopyTelemetryLogs) {
      this.btnCopyTelemetryLogs.addEventListener("click", () => this.copyTelemetryLogs());
    }
    if (this.btnExportTelemetryJson) {
      this.btnExportTelemetryJson.addEventListener("click", () => this.exportTelemetryJson());
    }
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
      const res = await this.authFetch("/api/scans/start", {
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
      this.btnCancel.disabled = true;
      this.btnCancel.innerHTML = `<span>⏳</span> Cancelling...`;
      this.updateProgress(null, "Cancelling active security assessment...");
      await this.authFetch(`/api/scans/${this.currentScanId}/cancel`, { method: "POST" });
      this.appendLog("orchestrator", "WARNING", "Scan cancellation requested by user.");
    } catch (e) {
      console.error("Cancellation error:", e);
      this.btnCancel.disabled = false;
      this.btnCancel.innerHTML = `<span>🛑</span> Cancel Active Scan`;
    }
  }

  connectEventStream(scanId) {
    if (this.eventSource) {
      this.eventSource.close();
    }

    this.eventSource = this.openAuthenticatedEventStream(`/api/scans/${scanId}/events`);

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
      if (!this.allFindings.some((f) => (f.id && f.id === finding.id) || (f.fingerprint && f.fingerprint === finding.fingerprint))) {
        this.allFindings.push(finding);
        this.renderFindings();
        this.updateLiveSummaryCounts();
      }
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

    this.eventSource.addEventListener("subdomain_discovered", (e) => {
      const sub = JSON.parse(e.data);
      this.addSubdomain(sub);
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
      this.btnCancel.disabled = false;
      this.btnCancel.innerHTML = `<span>🛑</span> Cancel Active Scan`;
      if (summary.authenticated_session_active) {
        this.updateAuthStatusBadge("ACTIVE", true);
      }
      this.eventSource.close();
    });

    this.eventSource.addEventListener("cancelled", (e) => {
      let msg = "Scan cancelled by user.";
      try {
        const d = JSON.parse(e.data);
        if (d && d.message) msg = d.message;
      } catch (_) {}
      this.updateProgress(null, msg);
      this.btnLaunch.style.display = "inline-flex";
      this.btnCancel.style.display = "none";
      this.btnCancel.disabled = false;
      this.btnCancel.innerHTML = `<span>🛑</span> Cancel Active Scan`;
      if (this.eventSource) this.eventSource.close();
    });

    this.eventSource.addEventListener("failed", (e) => {
      let reason = "Assessment execution failed.";
      try {
        const d = JSON.parse(e.data);
        if (d && d.reason) reason = d.reason;
      } catch (_) {}
      this.updateProgress(null, `Scan failed: ${reason}`);
      this.btnLaunch.style.display = "inline-flex";
      this.btnCancel.style.display = "none";
      this.btnCancel.disabled = false;
      this.btnCancel.innerHTML = `<span>🛑</span> Cancel Active Scan`;
      if (this.eventSource) this.eventSource.close();
    });

    this.eventSource.addEventListener("error", (e) => {
      if (this.eventSource && this.eventSource.readyState === EventSource.CLOSED) {
        this.btnLaunch.style.display = "inline-flex";
        this.btnCancel.style.display = "none";
        this.btnCancel.disabled = false;
        this.btnCancel.innerHTML = `<span>🛑</span> Cancel Active Scan`;
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

  // Contract 07 v4.1.0: OSINT Subdomain Recon Management
  addSubdomain(subdomain) {
    if (!this.discoveredSubdomains.some((s) => s.domain === subdomain.domain)) {
      this.discoveredSubdomains.push(subdomain);
      this.renderDiscoveredSubdomains();
    }
  }

  renderDiscoveredSubdomains() {
    if (!this.subdomainsHud) return;

    if (this.discoveredSubdomains.length === 0) {
      this.subdomainsHud.style.display = "none";
      return;
    }

    this.subdomainsHud.style.display = "block";
    if (this.subdomainsCountBadge) {
      this.subdomainsCountBadge.innerText = `${this.discoveredSubdomains.length} Subdomain${this.discoveredSubdomains.length === 1 ? "" : "s"}`;
    }

    this.subdomainsTableBody.innerHTML = this.discoveredSubdomains
      .map((sub) => {
        const ipsStr = (sub.ip_addresses || []).join(", ") || "-";
        const cnamesStr = (sub.cname_targets || []).join(", ") || "-";
        const takeoverBadge = sub.is_takeover_vulnerable
          ? '<span class="tag-takeover-vuln">VULNERABLE (CWE-698)</span>'
          : '<span style="color: var(--text-dim);">SECURE</span>';

        return `
        <tr>
          <td><strong style="color: var(--text-main); font-family: var(--font-mono);">${this.escapeHtml(sub.domain)}</strong></td>
          <td><code style="font-size: 11px;">${this.escapeHtml(ipsStr)}</code></td>
          <td><code style="font-size: 11px; color: var(--accent-cyan);">${this.escapeHtml(cnamesStr)}</code></td>
          <td>${takeoverBadge}</td>
          <td>
            <button class="btn btn-xs btn-outline" onclick="window.app.setTargetSubdomain(decodeURIComponent('${this.encodeInlineArg(sub.domain)}'))">Scan</button>
          </td>
        </tr>
      `;
      })
      .join("");
  }

  setTargetSubdomain(domain) {
    if (this.targetInput) {
      this.targetInput.value = `https://${domain}`;
      this.detectTargetType();
      window.scrollTo({ top: 0, behavior: "smooth" });
    }
  }

  // Contract 07 v4.1.0: Interactive HTTP Repeater Workbench
  openRepeaterModal() {
    if (this.repeaterModal) {
      this.repeaterModal.style.display = "flex";
      if (this.targetInput && this.targetInput.value && !this.repUrl.value) {
        this.repUrl.value = this.targetInput.value;
      }
    }
  }

  closeRepeaterModal() {
    if (this.repeaterModal) {
      this.repeaterModal.style.display = "none";
    }
  }

  async handleSendRepeater() {
    if (!this.repUrl || !this.repUrl.value) {
      alert("Please specify a request URL.");
      return;
    }

    const url = this.repUrl.value.trim();
    const method = (this.repMethod ? this.repMethod.value : "GET").toUpperCase();
    const headersRaw = this.repHeaders ? this.repHeaders.value.trim() : "";
    const bodyRaw = this.repBody ? this.repBody.value : "";

    // Parse headers (line-by-line key: value or json)
    const headers = {};
    if (headersRaw) {
      if (headersRaw.startsWith("{")) {
        try {
          Object.assign(headers, JSON.parse(headersRaw));
        } catch (_) {}
      } else {
        headersRaw.split("\n").forEach((line) => {
          const colonIdx = line.indexOf(":");
          if (colonIdx > 0) {
            const k = line.substring(0, colonIdx).trim();
            const v = line.substring(colonIdx + 1).trim();
            if (k) headers[k] = v;
          }
        });
      }
    }

    if (this.btnRepSend) {
      this.btnRepSend.innerText = "Sending...";
      this.btnRepSend.disabled = true;
    }

    try {
      const payload = {
        url: url,
        method: method,
        headers: headers,
        body: bodyRaw || null,
        follow_redirects: false,
        timeout_seconds: 10.0,
      };

      const resp = await this.authFetch("/api/tools/repeater", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      if (!resp.ok) {
        const err = await resp.json();
        throw new Error(err.detail || `HTTP Error ${resp.status}`);
      }

      const resData = await resp.json();

      // Render status & metrics
      if (this.repStatusBadge) {
        this.repStatusBadge.innerText = `${resData.status_code}`;
        this.repStatusBadge.className = `resp-status-badge ${resData.status_code >= 400 ? "status-badge-4xx" : "status-badge-2xx"}`;
      }
      if (this.repMetricTime) {
        this.repMetricTime.innerText = `${resData.duration_ms.toFixed(1)} ms`;
      }
      if (this.repMetricSize) {
        this.repMetricSize.innerText = `${resData.content_length} B`;
      }
      if (this.repMetricTls) {
        this.repMetricTls.innerText = resData.tls_version ? `${resData.tls_version}` : "TLS ---";
      }

      // Render response headers
      if (this.repRespHeaders) {
        const hdrsFormatted = Object.entries(resData.headers || {})
          .map(([k, v]) => `${k}: ${v}`)
          .join("\n");
        this.repRespHeaders.innerHTML = `<code>${this.escapeHtml(hdrsFormatted)}</code>`;
      }

      // Render response body
      if (this.repRespBody) {
        this.repRespBody.innerHTML = `<code>${this.escapeHtml(resData.body || "(Empty response body)")}</code>`;
      }
    } catch (e) {
      alert(`Repeater Request Failed: ${e.message}`);
    } finally {
      if (this.btnRepSend) {
        this.btnRepSend.innerText = "Send";
        this.btnRepSend.disabled = false;
      }
    }
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
    if (this.btnExportCycloneDx) this.btnExportCycloneDx.href = `/api/scans/${scanId}/export/sbom/cyclonedx`;
    if (this.btnExportSpdx) this.btnExportSpdx.href = `/api/scans/${scanId}/export/sbom/spdx`;
  }

  renderFindings() {
    this.updateLiveSummaryCounts();

    // Dynamically populate tool filter options from findings
    if (this.findingsToolFilter) {
      const currentSelected = (this.selectedToolFilter || "ALL").toLowerCase();
      const toolsSet = new Set(this.allFindings.map((f) => (f.source_tool || "native").toLowerCase()));
      const sortedTools = Array.from(toolsSet).sort();
      this.findingsToolFilter.innerHTML = `
        <option value="ALL">All Tools (${this.allFindings.length})</option>
        ${sortedTools.map((t) => {
          const count = this.allFindings.filter((f) => (f.source_tool || "native").toLowerCase() === t).length;
          return `<option value="${t}" ${currentSelected === t ? "selected" : ""}>${t.toUpperCase()} (${count})</option>`;
        }).join("")}
      `;
    }

    const filtered = this.allFindings.filter((f) => {
      const toolVal = (f.source_tool || "native").toLowerCase();
      const matchTool =
        !this.selectedToolFilter ||
        this.selectedToolFilter === "ALL" ||
        toolVal === this.selectedToolFilter.toLowerCase();
      const matchFilter = this.activeFilter === "ALL" || f.severity === this.activeFilter;
      const matchSearch =
        !this.searchQuery ||
        f.title.toLowerCase().includes(this.searchQuery) ||
        f.check_id.toLowerCase().includes(this.searchQuery) ||
        toolVal.includes(this.searchQuery) ||
        (f.cwe_id && f.cwe_id.toLowerCase().includes(this.searchQuery));
      return matchTool && matchFilter && matchSearch;
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

        const curlPoc = f.reproduction_curl
          ? `
          <div class="curl-poc-box">
            <div class="curl-poc-header">
              <span>⚡ Reproduction cURL Command</span>
              <button class="btn-copy" onclick="window.copySnippet('curl-${idx}')">Copy cURL</button>
            </div>
            <pre id="curl-${idx}"><code>${this.escapeHtml(f.reproduction_curl)}</code></pre>
          </div>
        `
          : "";

        const taintTrace = f.taint_trace && f.taint_trace.length
          ? `
          <div class="taint-ladder-box">
            <h4>🧬 AST Dataflow Taint Flow Trace</h4>
            <div class="taint-ladder">
              ${f.taint_trace.map((step, sIdx) => {
                let stepClass = "taint-prop";
                if (step.startsWith("Source")) stepClass = "taint-source";
                else if (step.startsWith("Sink")) stepClass = "taint-sink";
                return `
                  <div class="taint-step ${stepClass}">
                    <span class="step-num">${sIdx + 1}</span>
                    <span class="step-content"><code>${this.escapeHtml(step)}</code></span>
                  </div>
                `;
              }).join("")}
            </div>
          </div>
        `
          : "";

        const verifiedSecret = f.verified_secret && f.verified_secret.verified
          ? `
          <div class="verified-secret-badge" style="display: inline-flex; align-items: center; gap: 6px; background: rgba(239, 68, 68, 0.2); border: 1px solid #ef4444; color: #fca5a5; padding: 3px 8px; border-radius: 4px; font-weight: 700; font-size: 11px; margin-right: 6px;">
            <span>⚡ VERIFIED LIVE CREDENTIAL</span>
            <span style="color: #fff;">(${this.escapeHtml(f.verified_secret.credential_name || 'Active')})</span>
          </div>
        `
          : "";

        const toolName = f.source_tool || "native";

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
              ${verifiedSecret}
              ${f.cwe_id ? `<span class="meta-tag">${this.escapeHtml(f.cwe_id)}</span>` : ""}
              ${f.owasp_category ? `<span class="meta-tag">${this.escapeHtml(f.owasp_category)}</span>` : ""}
              ${f.nist_control ? `<span class="meta-tag">${this.escapeHtml(f.nist_control)}</span>` : ""}
              <span class="meta-tag engine-tag">${this.escapeHtml(f.engine)}</span>
              <span class="source-tool-badge source-tool--${this.escapeHtml(toolName.toLowerCase())}" style="cursor: pointer;" title="Click to filter findings by ${this.escapeHtml(toolName)}" onclick="event.stopPropagation(); window.app.filterByTool(decodeURIComponent('${this.encodeInlineArg(toolName)}'))">[${this.escapeHtml(toolName)}]</span>
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

            ${curlPoc}
            ${taintTrace}
          </div>
        </div>
      `;
      })
      .join("");
  }

  async openHistoryModal() {
    this.historyModal.style.display = "flex";
    try {
      const res = await this.authFetch("/api/scans/history?limit=30");
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
            <button class="btn btn-xs btn-outline" onclick="window.app.openTelemetryModal('${s.id}')">📊 Telemetry</button>
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
      const res = await this.authFetch(`/api/scans/${scanId}`);
      if (!res.ok) return;
      const job = await res.json();

      this.currentScanId = job.id;
      this.updateExportLinks(this.currentScanId);

      // Render summary & scorecard
      if (job.summary) {
        this.renderScorecard(job.summary);
      }

      // Render findings
      this.allFindings = job.findings || [];
      this.renderFindings();

      // Render discovered endpoints & subdomains
      this.discoveredEndpoints = job.discovered_endpoints || [];
      this.renderDiscoveredEndpoints();
      this.discoveredSubdomains = job.discovered_subdomains || [];
      this.renderDiscoveredSubdomains();

      if (this.resultsDashboard) this.resultsDashboard.style.display = "block";
      if (this.progressHud) this.progressHud.style.display = "block";

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
      await this.authFetch(`/api/scans/${scanId}`, { method: "DELETE" });
      this.openHistoryModal();
    } catch (e) {
      console.error(e);
    }
  }

  async loadSystemCapabilities() {
    try {
      const res = await this.authFetch("/api/system/capabilities");
      if (!res.ok) return;
      const data = await res.json();
      const tools = data.tools || [];
      let activeCount = 0;

      tools.forEach((tool) => {
        const pill = document.getElementById(`tool-pill-${tool.name}`);
        if (pill) {
          pill.classList.remove("tool-pill--active", "tool-pill--fallback", "tool-pill--disabled");
          const modeSpan = pill.querySelector(".tool-pill-mode");
          const iconSpan = pill.querySelector(".tool-pill-icon");

          // Availability only means that a binary was detected.  It is not
          // evidence that the binary passed managed trust and version gates.
          if (tool.execution_mode === "ADAPTER_ACTIVE") {
            pill.classList.add("tool-pill--active");
            if (modeSpan) modeSpan.innerText = tool.version || "ACTIVE";
            if (iconSpan) iconSpan.innerText = "🟢";
            activeCount++;
          } else if (tool.execution_mode === "DISABLED") {
            pill.classList.add("tool-pill--disabled");
            if (modeSpan) modeSpan.innerText = "DISABLED";
            if (iconSpan) iconSpan.innerText = "⚪";
          } else {
            pill.classList.add("tool-pill--fallback");
            if (modeSpan) modeSpan.innerText = "NATIVE FALLBACK";
            if (iconSpan) iconSpan.innerText = "🟡";
          }
        }
      });

      if (this.toolboxInstalledCount) {
        this.toolboxInstalledCount.innerText = activeCount;
      }
    } catch (e) {
      console.error("Failed to load system capabilities:", e);
    }
  }

  async openToolboxModal() {
    if (!this.toolboxModal) return;
    this.toolboxModal.style.display = "flex";
    this.connectToolEventsStream();
    await this.refreshToolboxData();
  }

  closeToolboxModal() {
    if (this.toolboxModal) {
      this.toolboxModal.style.display = "none";
    }
  }

  async refreshToolboxData() {
    try {
      const res = await this.authFetch("/api/system/tools");
      if (!res.ok) return;
      const tools = await res.json();
      this.renderToolboxTable(tools);
    } catch (e) {
      console.error("Failed to fetch tool list:", e);
    }
  }

  renderToolboxTable(tools) {
    if (!this.toolboxTableBody) return;
    let installedCount = 0;

    this.toolboxTableBody.innerHTML = tools
      .map((t) => {
        const isInstalled = t.status === "INSTALLED" || t.is_installed || (t.path && t.path.length > 0);
        if (isInstalled) installedCount++;

        let statusBadge = `<span class="badge-missing">NOT INSTALLED</span>`;
        if (t.status === "INSTALLING") {
          statusBadge = `<span class="badge-installing">INSTALLING (${t.progress_percent || 0}%)</span>`;
        } else if (isInstalled) {
          statusBadge = `<span class="badge-installed">INSTALLED</span>`;
        }

        const methodLabel = t.install_method === "SYSTEM_PACKAGE_MANAGER" ? "OS / PKG MGR" : String(t.install_method || "").replace("_", " ");
        const methodBadge = `<span class="method-tag">${this.escapeHtml(methodLabel)}</span>`;
        const pathOrVersion = t.version
          ? this.escapeHtml(t.version)
          : (t.path ? `<code class="path-code">${this.escapeHtml(t.path)}</code>` : `<span style="color: var(--text-dim);">-</span>`);
        const toolArg = this.encodeInlineArg(t.name);

        let actionBtn = "";
        if (t.install_method === "SYSTEM_PACKAGE_MANAGER") {
          const btnText = isInstalled ? "📖 Setup Guide" : "📖 How to Install";
          actionBtn = `<button class="btn btn-xs btn-outline" onclick="window.app.openToolInstructionsModal(decodeURIComponent('${toolArg}'))">${btnText}</button>`;
        } else if (t.status === "INSTALLING") {
          actionBtn = `<button class="btn btn-xs btn-outline" style="color: var(--color-critical); border-color: var(--color-critical);" onclick="window.app.handleCancelTool(decodeURIComponent('${toolArg}'))">⏹ Cancel</button>`;
        } else if (isInstalled) {
          actionBtn = `<button class="btn btn-xs btn-outline" onclick="window.app.handleInstallTool(decodeURIComponent('${toolArg}'), true)">Reinstall</button>`;
        } else {
          actionBtn = `<button class="btn-install-tool" onclick="window.app.handleInstallTool(decodeURIComponent('${toolArg}'), false)">⚡ Install</button>`;
        }

        return `
          <tr>
            <td>
              <div class="tool-name-cell">
                <span>${this.escapeHtml(t.display_name || t.name)}</span>
              </div>
            </td>
            <td><code>${this.escapeHtml(t.category)}</code></td>
            <td>${methodBadge}</td>
            <td>${statusBadge}</td>
            <td>${pathOrVersion}</td>
            <td>${actionBtn}</td>
          </tr>
        `;
      })
      .join("");

    if (this.toolboxInstalledCount) {
      this.toolboxInstalledCount.innerText = installedCount;
    }
  }

  async handleCancelTool(toolName) {
    this.appendToolboxLog(`[CANCEL] Requesting cancellation of '${toolName}' installation...`);
    try {
      const res = await this.authFetch(`/api/system/tools/${toolName}/cancel`, { method: "POST" });
      if (res.ok) {
        const data = await res.json();
        this.appendToolboxLog(`[CANCEL] ${data.message}`);
        this.refreshToolboxData();
      }
    } catch (e) {
      this.appendToolboxLog(`[ERROR] Failed to cancel: ${e.message}`);
    }
  }

  // =========================================================================
  // Tool Setup & Installation Guide Modal
  // =========================================================================

  /** Per-tool installation option data with all recommended methods */
  _getToolInstallOptions(toolName) {
    const DATA = {
      nmap: {
        displayName: "Nmap Network & Port Scanner (NSE)",
        subtitle: "Enterprise-grade port discovery, banner grabber, and OS/service fingerprinting engine.",
        docsUrl: "https://nmap.org/download.html",
        options: [
          {
            title: "Option 1: Windows Package Manager (winget) — Recommended",
            recommended: true,
            desc: "Installs official Nmap alongside the required Npcap packet capture kernel driver.",
            snippet: "winget install Insecure.Nmap",
            explanation: "• 'winget install': Downloads and invokes the verified Microsoft package.\n• 'Insecure.Nmap': Official publisher identifier for Gordon Lyon's Nmap project.\n• Verification: Run 'nmap --version' in a new terminal.",
          },
          {
            title: "Option 2: Official Windows Installer (with GUI & Npcap)",
            recommended: false,
            desc: "Direct executable setup wizard with custom drive installation options.",
            snippet: "https://nmap.org/dist/nmap-setup.exe",
            isLink: true,
            explanation: "Download and run the installer. Ensure 'Npcap' is checked during setup so raw socket SYN packets can be sent.",
          },
          {
            title: "Option 3: Chocolatey Package Manager",
            recommended: false,
            desc: "Automated install via Chocolatey.",
            snippet: "choco install nmap",
            explanation: "Fetches and runs the silent installer with Npcap dependencies.",
          },
          {
            title: "Linux (Debian / Ubuntu / Kali / WSL)",
            recommended: false,
            desc: "Standard APT package repository install.",
            snippet: "sudo apt-get update && sudo apt-get install -y nmap",
            explanation: "• '-y': Automatically confirms prompts.\n• Verification: 'nmap --version'",
          },
          {
            title: "macOS (Homebrew)",
            recommended: false,
            desc: "Standard Homebrew package.",
            snippet: "brew install nmap",
            explanation: "Verification: 'nmap --version'",
          },
        ],
      },
    };
    return DATA[toolName] || null;
  }

  openToolInstructionsModal(toolName) {
    const data = this._getToolInstallOptions(toolName);
    if (!data || !this.toolInstructionsModal) return;

    this._instRecheckTool = toolName;

    if (this.instToolTitle) this.instToolTitle.textContent = `📖 ${data.displayName} — Setup Guide`;
    if (this.instToolSubtitle) this.instToolSubtitle.textContent = data.subtitle;
    if (this.instToolDocsLink) {
      this.instToolDocsLink.href = data.docsUrl;
      this.instToolDocsLink.textContent = "🌐 Official Website";
    }

    if (this.instToolBody) {
      this.instToolBody.innerHTML = data.options.map((opt) => {
        const recBadge = opt.recommended
          ? `<span class="instruction-badge-recommended">✓ Recommended</span>`
          : "";
        const snippetAction = opt.isLink
          ? `<a href="${this.escapeHtml(opt.snippet)}" target="_blank" class="btn-copy-code">Open ↗</a>`
          : `<button class="btn-copy-code" onclick="navigator.clipboard.writeText(decodeURIComponent('${this.encodeInlineArg(opt.snippet)}')).then(()=>this.textContent='Copied!').catch(()=>{})">📋 Copy</button>`;

        const explanationHtml = opt.explanation
          ? `<div class="instruction-explanation">${this.escapeHtml(opt.explanation).replace(/\n/g, '<br>')}</div>`
          : "";

        return `
          <div class="instruction-option-card">
            <div class="instruction-option-header">
              <span class="instruction-option-title">${this.escapeHtml(opt.title)} ${recBadge}</span>
            </div>
            <p class="instruction-option-desc">${this.escapeHtml(opt.desc)}</p>
            <div class="code-snippet-box">
              <code>${this.escapeHtml(opt.snippet)}</code>
              ${snippetAction}
            </div>
            ${explanationHtml}
          </div>
        `;
      }).join("");
    }

    this.toolInstructionsModal.style.display = "flex";
  }

  closeToolInstructionsModal() {
    if (this.toolInstructionsModal) this.toolInstructionsModal.style.display = "none";
    this._instRecheckTool = null;
  }

  async handleInstallTool(toolName, force = false) {
    this.appendToolboxLog(`[INIT] Requesting in-app installation for '${toolName}' (force=${force})...`);
    this.updateToolboxStage(`Initiating ${toolName}...`, 5);
    try {
      const res = await this.authFetch(`/api/system/tools/${toolName}/install`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ force: force }),
      });
      if (!res.ok) {
        const err = await res.json();
        this.appendToolboxLog(`[ERROR] Failed to start install: ${err.detail || res.statusText}`);
        return;
      }
      const data = await res.json();
      this.appendToolboxLog(`[QUEUED] ${data.message} (Task ID: ${data.task_id})`);
      this.refreshToolboxData();
    } catch (e) {
      this.appendToolboxLog(`[ERROR] Network error: ${e.message}`);
    }
  }

  async handleInstallAllTools() {
    this.appendToolboxLog(`[INIT] Requesting batch in-app installation for all missing user-space tools...`);
    this.updateToolboxStage("Starting batch install...", 5);
    try {
      const res = await this.authFetch("/api/system/tools/install-all", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ force: false }),
      });
      if (!res.ok) {
        const err = await res.json();
        this.appendToolboxLog(`[ERROR] Failed to trigger batch install: ${err.detail || res.statusText}`);
        return;
      }
      const data = await res.json();
      this.appendToolboxLog(`[BATCH] Queued ${data.length} tool installation jobs.`);
      this.refreshToolboxData();
    } catch (e) {
      this.appendToolboxLog(`[ERROR] Network error: ${e.message}`);
    }
  }

  openAuthenticatedEventStream(url) {
    const controller = new AbortController();
    const listeners = new Map();
    let closed = false;
    let source;

    const dispatch = (type, event) => {
      (listeners.get(type) || []).forEach((listener) => listener(event));
    };
    const parseEvent = (raw) => {
      const fields = raw.split("\n");
      let eventType = "message";
      const data = [];
      fields.forEach((line) => {
        if (line.startsWith("event:")) eventType = line.slice(6).trim();
        else if (line.startsWith("data:")) data.push(line.slice(5).trimStart());
      });
      if (data.length) dispatch(eventType, { data: data.join("\n") });
    };

    source = {
      readyState: 0,
      onerror: null,
      addEventListener: (type, listener) => {
        if (!listeners.has(type)) listeners.set(type, []);
        listeners.get(type).push(listener);
      },
      close: () => {
        closed = true;
        source.readyState = 2;
        controller.abort();
      },
    };

    (async () => {
      try {
        const token = this.accessToken || "";
        const headers = token ? { Authorization: `Bearer ${token}` } : {};
        const response = await fetch(url, { headers, signal: controller.signal });
        if (!response.ok || !response.body) throw new Error(`SSE request failed (${response.status})`);
        source.readyState = 1;
        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let buffer = "";
        while (!closed) {
          const { value, done } = await reader.read();
          if (done) break;
          buffer += decoder.decode(value, { stream: true });
          const events = buffer.split("\n\n");
          buffer = events.pop() || "";
          events.filter(Boolean).forEach(parseEvent);
        }
        if (!closed) source.readyState = 2;
      } catch (error) {
        if (!closed) {
          source.readyState = 2;
          const event = { error };
          dispatch("error", event);
          if (typeof source.onerror === "function") source.onerror(event);
        }
      }
    })();
    return source;
  }

  connectToolEventsStream() {
    if (this.toolEventsSource) return;
    try {
      this.toolEventsSource = this.openAuthenticatedEventStream("/api/system/tools/events");

      this.toolEventsSource.addEventListener("install_progress", (e) => {
        const d = JSON.parse(e.data);
        this.updateToolboxStage(d.stage || `Installing ${d.tool_name}...`, d.percent || 0);
      });

      this.toolEventsSource.addEventListener("install_log", (e) => {
        const d = JSON.parse(e.data);
        this.appendToolboxLog(`[${d.tool_name}] ${d.message}`);
      });

      this.toolEventsSource.addEventListener("install_completed", (e) => {
        const d = JSON.parse(e.data);
        this.appendToolboxLog(`[SUCCESS] ${d.message || d.tool_name + ' installed.'}`);
        this.updateToolboxStage(`${d.tool_name} installed successfully!`, 100);
        this.refreshToolboxData();
        this.loadSystemCapabilities();
      });

      this.toolEventsSource.addEventListener("install_failed", (e) => {
        const d = JSON.parse(e.data);
        this.appendToolboxLog(`[FAILURE] [${d.tool_name}] ${d.error}`);
        this.updateToolboxStage(`Installation failed for ${d.tool_name}`, 0);
        this.refreshToolboxData();
      });

      this.toolEventsSource.onerror = () => {
        // Handled by browser reconnection
      };
    } catch (e) {
      console.error("Failed to connect tool events stream:", e);
    }
  }

  updateToolboxStage(stage, percent) {
    if (this.toolboxInstallStage) {
      this.toolboxInstallStage.innerText = stage;
    }
    if (this.toolboxInstallProgressBar) {
      this.toolboxInstallProgressBar.style.width = `${Math.min(100, Math.max(0, percent))}%`;
    }
  }

  appendToolboxLog(msg) {
    if (!this.toolboxTerminalLog) return;
    const time = new Date().toLocaleTimeString();
    this.toolboxTerminalLog.textContent += `\n[${time}] ${msg}`;
    this.toolboxTerminalLog.scrollTop = this.toolboxTerminalLog.scrollHeight;
  }

  // ========================================================================
  // Asset Inventory Management & Posture Tracking
  // ========================================================================

  async openAssetsModal() {
    if (!this.assetsModal) return;
    this.assetsModal.style.display = "flex";
    await this.loadAssets();
  }

  closeAssetsModal() {
    if (this.assetsModal) this.assetsModal.style.display = "none";
  }

  async loadAssets() {
    if (!this.assetsTableBody) return;
    try {
      const res = await this.authFetch("/api/assets");
      if (!res.ok) return;
      const data = await res.json();
      const assets = data.items || [];
      if (assets.length === 0) {
        this.assetsTableBody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-muted);">No assets registered yet. Click "Add New Asset" above.</td></tr>`;
        return;
      }
      this.assetsTableBody.innerHTML = assets.map(a => `
        <tr>
          <td><strong>${this.escapeHtml(a.name)}</strong></td>
          <td><span class="meta-tag">${this.escapeHtml(a.type)}</span></td>
          <td><code>${this.escapeHtml(a.target_value)}</code></td>
          <td><span class="badge ${a.criticality === 'CRITICAL' ? 'badge-critical' : a.criticality === 'HIGH' ? 'badge-high' : 'badge-none'}">${this.escapeHtml(a.criticality)}</span></td>
          <td>${a.active_findings_count || 0}</td>
          <td>
            <button class="btn btn-xs btn-primary" onclick="window.auditAsset(decodeURIComponent('${this.encodeInlineArg(a.target_value)}'), decodeURIComponent('${this.encodeInlineArg(a.type)}'))">Audit</button>
            <button class="btn btn-xs btn-danger" onclick="window.deleteAsset(decodeURIComponent('${this.encodeInlineArg(a.id)}'))">Delete</button>
          </td>
        </tr>
      `).join("");
    } catch (e) {
      console.error("Failed to load assets:", e);
    }
  }

  async handleSaveNewAsset() {
    const nameEl = document.getElementById("asset-new-name");
    const typeEl = document.getElementById("asset-new-type");
    const critEl = document.getElementById("asset-new-criticality");
    const targetEl = document.getElementById("asset-new-target");

    if (!nameEl || !targetEl || !nameEl.value.trim() || !targetEl.value.trim()) {
      alert("Please specify asset name and target URI / path.");
      return;
    }

    try {
      const res = await this.authFetch("/api/assets", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: nameEl.value.trim(),
          type: typeEl.value,
          criticality: critEl.value,
          target_value: targetEl.value.trim(),
        }),
      });
      if (res.ok) {
        nameEl.value = "";
        targetEl.value = "";
        if (this.assetCreateFormContainer) this.assetCreateFormContainer.style.display = "none";
        await this.loadAssets();
      } else {
        const err = await res.json();
        alert(`Error: ${err.detail || "Failed to save asset."}`);
      }
    } catch (e) {
      alert(`Network error saving asset: ${e}`);
    }
  }

  // ========================================================================
  // User Authentication & Session Management
  // ========================================================================

  async authFetch(url, options = {}) {
    options.headers = options.headers || {};
    const token = this.accessToken;
    if (token) {
      if (typeof options.headers.set === "function") {
        options.headers.set("Authorization", `Bearer ${token}`);
      } else {
        options.headers["Authorization"] = `Bearer ${token}`;
      }
    }
    const res = await fetch(url, options);
    if (res.status === 401 && !url.includes("/api/auth/")) {
      this.openAuthModal();
    }
    return res;
  }

  async checkAuthStatus() {
    try {
      const res = await fetch("/api/auth/status");
      if (res.ok) {
        const data = await res.json();
        if (!data.initialized) {
          console.warn("CyberAssess is uninitialized. First-run administrator bootstrap required.");
        }
      }
      const token = this.accessToken;
      if (token) {
        const meRes = await this.authFetch("/api/auth/me");
        if (meRes.ok) {
          const user = await meRes.json();
          if (this.userRoleBadge) this.userRoleBadge.innerText = user.role;
          if (this.authCurrentUsername) this.authCurrentUsername.innerText = user.username;
          if (this.authCurrentRole) this.authCurrentRole.innerText = user.role;
          if (this.authStatusBadge) {
            this.authStatusBadge.innerText = `USER: ${user.username} (${user.role})`;
            this.authStatusBadge.className = "auth-status-badge badge-admin";
          }
        } else {
          this.accessToken = null;
        }
      }
    } catch (e) {
      console.error("Auth status check failed:", e);
    }
  }

  openAuthModal() {
    if (this.authModal) this.authModal.style.display = "flex";
  }

  closeAuthModal() {
    if (this.authModal) this.authModal.style.display = "none";
  }

  async handleLogin() {
    const u = this.authUsernameInput ? this.authUsernameInput.value.trim() : "";
    const p = this.authPasswordInput ? this.authPasswordInput.value.trim() : "";
    if (!u || !p) {
      alert("Please enter username and password.");
      return;
    }

    try {
      const res = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: u, password: p }),
      });
      if (res.ok) {
        const data = await res.json();
        this.accessToken = data.access_token;
        if (this.userRoleBadge) this.userRoleBadge.innerText = data.user.role;
        if (this.authCurrentUsername) this.authCurrentUsername.innerText = data.user.username;
        if (this.authCurrentRole) this.authCurrentRole.innerText = data.user.role;
        if (this.authStatusBadge) {
          this.authStatusBadge.innerText = `USER: ${data.user.username} (${data.user.role})`;
          this.authStatusBadge.className = "auth-status-badge badge-admin";
        }
        this.closeAuthModal();
      } else {
        const err = await res.json();
        alert(`Authentication failed: ${err.detail || 'Invalid credentials'}`);
      }
    } catch (e) {
      alert(`Login connection error: ${e}`);
    }
  }

  async handleLogout() {
    if (this.accessToken) {
      try {
        await this.authFetch("/api/auth/logout", { method: "POST" });
      } catch (e) {
        console.warn("Session revocation request failed; clearing local session state.");
      }
    }
    this.accessToken = null;
    if (this.userRoleBadge) this.userRoleBadge.innerText = "VIEWER";
    if (this.authCurrentUsername) this.authCurrentUsername.innerText = "Anonymous";
    if (this.authCurrentRole) this.authCurrentRole.innerText = "VIEWER";
    if (this.authStatusBadge) {
      this.authStatusBadge.innerText = "AUTH: NONE";
      this.authStatusBadge.className = "auth-status-badge badge-none";
    }
    this.closeAuthModal();
  }

  // --- Assessment Intelligence & Telemetry Hub Implementation ---

  async openTelemetryModal(scanId = null) {
    const targetScanId = scanId || this.currentScanId;
    if (this.telemetryModal) {
      this.telemetryModal.style.display = "flex";
    }

    if (!targetScanId) {
      if (this.telemetryLogsContainer) {
        this.telemetryLogsContainer.innerHTML = `<div style="color: var(--text-muted); text-align: center; padding: 40px;">No scan selected. Please launch a new assessment or view a past scan from the History archive.</div>`;
      }
      return;
    }

    await this.loadTelemetryData(targetScanId);
  }

  closeTelemetryModal() {
    if (this.telemetryModal) {
      this.telemetryModal.style.display = "none";
    }
  }

  async loadTelemetryData(scanId) {
    try {
      if (this.telemetryScanMeta) {
        this.telemetryScanMeta.innerText = `Loading telemetry and reconnaissance for scan: ${scanId}...`;
      }

      const res = await this.authFetch(`/api/scans/${scanId}/telemetry`);
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || `HTTP ${res.status}`);
      }

      this.currentTelemetryData = await res.json();

      if (this.telemetryScanMeta) {
        this.telemetryScanMeta.innerText = `Scan: ${this.currentTelemetryData.scan_id} | Target: ${this.currentTelemetryData.target_value} | Profile: ${this.currentTelemetryData.profile} | Status: ${this.currentTelemetryData.status}`;
      }

      if (this.telemetryLinksCount) {
        this.telemetryLinksCount.innerText = `${(this.currentTelemetryData.discovered_endpoints || []).length}`;
      }
      if (this.telemetryToolsCount) {
        this.telemetryToolsCount.innerText = `${(this.currentTelemetryData.tools_executed || []).length}`;
      }

      this.renderTelemetryLogs();
      this.renderTelemetryEndpoints();
      this.renderTelemetryMatrix();
      this.renderTelemetrySurface();
    } catch (e) {
      console.error("Failed to load telemetry:", e);
      if (this.telemetryLogsContainer) {
        this.telemetryLogsContainer.innerHTML = `<div style="color: var(--color-critical); padding: 20px;">Failed to load assessment telemetry: ${this.escapeHtml(e.message)}</div>`;
      }
    }
  }

  renderTelemetryLogs() {
    if (!this.telemetryLogsContainer || !this.currentTelemetryData) return;

    const searchTerm = this.telemetryLogSearch ? this.telemetryLogSearch.value.trim().toLowerCase() : "";
    const toolFilter = this.telemetryFilterTool ? this.telemetryFilterTool.value : "ALL";
    const levelFilter = this.telemetryFilterLevel ? this.telemetryFilterLevel.value : "ALL";

    let logs = this.currentTelemetryData.logs || [];

    if (toolFilter !== "ALL") {
      const tfLower = toolFilter.toLowerCase();
      logs = logs.filter((l) => (l.tool && l.tool.toLowerCase() === tfLower) || (l.engine && l.engine.toLowerCase() === tfLower) || (l.message && l.message.toLowerCase().includes(tfLower)));
    }

    if (levelFilter !== "ALL") {
      logs = logs.filter((l) => (l.level || "INFO").toUpperCase() === levelFilter);
    }

    if (searchTerm) {
      logs = logs.filter((l) => 
        (l.message && l.message.toLowerCase().includes(searchTerm)) ||
        (l.engine && l.engine.toLowerCase().includes(searchTerm)) ||
        (l.tool && l.tool.toLowerCase().includes(searchTerm))
      );
    }

    if (logs.length === 0) {
      this.telemetryLogsContainer.innerHTML = `<div style="color: var(--text-muted); text-align: center; padding: 30px;">No telemetry logs matched the specified filter criteria.</div>`;
      return;
    }

    this.telemetryLogsContainer.innerHTML = logs.map((l) => {
      const timeStr = l.timestamp ? new Date(l.timestamp).toLocaleTimeString() : "--:--:--";
      const lvl = (l.level || "INFO").toLowerCase();
      const source = l.tool ? l.tool : (l.engine || "orchestrator");
      return `
        <div class="telemetry-log-item">
          <span class="telemetry-log-time">[${timeStr}]</span>
          <span class="telemetry-log-tag level-${lvl}">${lvl}</span>
          <span class="telemetry-log-source">[${this.escapeHtml(source)}]</span>
          <span class="telemetry-log-message">${this.escapeHtml(l.message)}</span>
        </div>
      `;
    }).join("");
  }

  renderTelemetryEndpoints() {
    const container = document.getElementById("telemetry-endpoints-container") || this.telemetryEndpointsTbody;
    if (!container || !this.currentTelemetryData) return;

    const searchTerm = this.telemetryEndpointSearch ? this.telemetryEndpointSearch.value.trim().toLowerCase() : "";
    const filterState = this.telemetryEndpointFilterStatus ? this.telemetryEndpointFilterStatus.value : "ALL";
    let endpoints = this.currentTelemetryData.discovered_endpoints || [];

    // Filter by search
    if (searchTerm) {
      endpoints = endpoints.filter((ep) => 
        (ep.url && ep.url.toLowerCase().includes(searchTerm)) ||
        (ep.method && ep.method.toLowerCase().includes(searchTerm)) ||
        (ep.status_code && String(ep.status_code).includes(searchTerm)) ||
        (ep.content_type && ep.content_type.toLowerCase().includes(searchTerm)) ||
        (ep.tools_executed && ep.tools_executed.some(t => t.toLowerCase().includes(searchTerm))) ||
        (ep.tests_performed && ep.tests_performed.some(tp => tp.test_name.toLowerCase().includes(searchTerm) || tp.details.toLowerCase().includes(searchTerm)))
      );
    }

    // Filter by status dropdown
    if (filterState === "VULN") {
      endpoints = endpoints.filter((ep) => (ep.finding_ids && ep.finding_ids.length > 0) || (ep.tests_performed && ep.tests_performed.some(t => t.status === "VULNERABLE")));
    } else if (filterState === "SAFE") {
      endpoints = endpoints.filter((ep) => (!ep.finding_ids || ep.finding_ids.length === 0) && (!ep.tests_performed || !ep.tests_performed.some(t => t.status === "VULNERABLE")));
    } else if (filterState === "FORMS") {
      endpoints = endpoints.filter((ep) => ep.has_forms || ep.discovered_forms > 0);
    } else if (filterState === "AUTH") {
      endpoints = endpoints.filter((ep) => ep.is_authenticated);
    }

    if (this.telemetryEndpointStats) {
      this.telemetryEndpointStats.innerText = `Showing ${endpoints.length} of ${(this.currentTelemetryData.discovered_endpoints || []).length} links`;
    }

    if (endpoints.length === 0) {
      container.innerHTML = `<div style="text-align: center; color: var(--text-muted); padding: 35px; background: rgba(255,255,255,0.01); border-radius: 6px; border: 1px dashed var(--border-subtle);">No tested links match the selected filter criteria.</div>`;
      return;
    }

    // Correlate with all findings for rich cards
    const allFindingsMap = new Map();
    (this.allFindings || []).forEach(f => allFindingsMap.set(f.id, f));

    container.innerHTML = endpoints.map((ep, idx) => {
      const sc = ep.status_code || 200;
      let scClass = "status-2xx";
      if (sc >= 300 && sc < 400) scClass = "status-3xx";
      else if (sc >= 400 && sc < 500) scClass = "status-4xx";
      else if (sc >= 500) scClass = "status-5xx";

      const method = (ep.method || "GET").toUpperCase();
      const isAuth = ep.is_authenticated;
      const tests = ep.tests_performed || [];
      const tools = ep.tools_executed || ["native_dast", "katana", "parameter_fuzzer"];
      const vulnTests = tests.filter(t => t.status === "VULNERABLE");

      // Correlate findings
      const linkedFindings = (ep.finding_ids || []).map(id => allFindingsMap.get(id)).filter(Boolean);

      const statusBadge = linkedFindings.length > 0 || vulnTests.length > 0
        ? `<span class="badge" style="background: rgba(239, 68, 68, 0.2); color: #ef4444; border: 1px solid #ef4444; font-weight: 700;">⚠️ ${linkedFindings.length || vulnTests.length} Finding(s)</span>`
        : `<span class="badge" style="background: rgba(16, 185, 129, 0.2); color: #10b981; border: 1px solid #10b981; font-weight: 700;">✅ Clean (All Safe)</span>`;

      // Tools badges
      const toolChips = tools.map(t => `<span class="badge badge-info" style="font-size: 10px; padding: 2px 6px; text-transform: uppercase;">${this.escapeHtml(t)}</span>`).join(" ");

      // Tests Table Rows
      const testRows = tests.map(t => {
        const isVuln = t.status === "VULNERABLE";
        const tStatusBadge = isVuln
          ? `<span class="badge badge-danger" style="font-weight: 700;">FAIL / VULNERABLE</span>`
          : `<span class="badge badge-success" style="font-weight: 700;">PASS / SAFE</span>`;
        return `
          <tr style="border-bottom: 1px solid rgba(255,255,255,0.04);">
            <td style="font-weight: 600; color: #fff;">${this.escapeHtml(t.test_name)}</td>
            <td><code>${this.escapeHtml(t.category || "Web Security")}</code></td>
            <td><span class="badge badge-ghost" style="font-size: 11px;">${this.escapeHtml(t.tool)}</span></td>
            <td>${tStatusBadge}</td>
            <td style="font-size: 12px; color: var(--text-muted);">${this.escapeHtml(t.details || "-")}</td>
          </tr>
        `;
      }).join("");

      // Findings rows if any
      const findingsListHtml = linkedFindings.length > 0 ? `
        <div style="margin-top: 18px; margin-bottom: 16px;">
          <h5 style="color: #f87171; font-size: 13px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 10px; display: flex; align-items: center; gap: 6px;">
            🚨 Vulnerabilities Detected on this Link (${linkedFindings.length})
          </h5>
          <div style="display: flex; flex-direction: column; gap: 8px;">
            ${linkedFindings.map(f => `
              <div style="background: rgba(239, 68, 68, 0.08); border: 1px solid rgba(239, 68, 68, 0.3); border-left: 4px solid var(--color-critical); padding: 10px 14px; border-radius: 4px; font-size: 12px;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px; flex-wrap: wrap; gap: 6px;">
                  <strong style="color: #fff; font-size: 13px;">${this.escapeHtml(f.title)}</strong>
                  <div style="display: flex; gap: 6px; align-items: center;">
                    ${f.cwe_id ? `<span class="badge badge-ghost" style="font-size: 10px;">${this.escapeHtml(f.cwe_id)}</span>` : ''}
                    <span class="badge badge-danger" style="font-weight: 700;">${this.escapeHtml(f.severity)} (${f.cvss_score || 'CVSS N/A'})</span>
                  </div>
                </div>
                <div style="color: #cbd5e1; font-size: 12px; line-height: 1.5; margin-bottom: 6px;">${this.escapeHtml(f.description || '')}</div>
                ${f.remediation ? `<div style="color: var(--accent-cyan); font-size: 11px; margin-top: 6px; padding-top: 6px; border-top: 1px dashed rgba(255,255,255,0.1);"><strong>💡 Remediation:</strong> ${this.escapeHtml(f.remediation)}</div>` : ''}
              </div>
            `).join("")}
          </div>
        </div>
      ` : "";

      const cardId = `ep-card-${idx}`;

      return `
        <div class="endpoint-dossier-card" style="background: #0d1520; border: 1px solid var(--border-subtle); border-radius: 6px; overflow: visible; transition: border-color 0.2s; margin-bottom: 12px;">
          <!-- Card Header (Click to Expand) -->
          <div style="padding: 12px 16px; display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; gap: 10px; cursor: pointer; user-select: none;" onclick="window.app.toggleEndpointDossier('${cardId}')">
            <div style="display: flex; align-items: center; gap: 10px; flex: 1; min-width: 300px;">
              <span id="${cardId}-icon" style="font-size: 12px; color: var(--accent-cyan); width: 14px;">▶</span>
              <span class="badge ${method === 'POST' ? 'badge-warning' : (method === 'DELETE' ? 'badge-danger' : 'badge-info')}" style="font-weight: 700; font-size: 11px;">${this.escapeHtml(method)}</span>
              <span style="font-family: monospace; font-size: 13px; font-weight: 600; color: #fff; word-break: break-all;">${this.escapeHtml(ep.url)}</span>
            </div>
            <div style="display: flex; align-items: center; gap: 8px;">
              <span class="link-status-badge ${scClass}">${sc}</span>
              ${isAuth ? `<span class="badge" style="background: rgba(59, 130, 246, 0.2); color: #60a5fa; border: 1px solid #3b82f6;">🔒 Auth</span>` : `<span class="badge badge-ghost" style="color: var(--text-muted);">🔓 Public</span>`}
              ${ep.has_forms || ep.discovered_forms > 0 ? `<span class="badge badge-warning" style="font-size: 11px;">📝 ${ep.discovered_forms || 1} Form(s)</span>` : ''}
              <span class="badge badge-ghost" style="font-size: 11px;">🧪 ${tests.length} Tests</span>
              ${statusBadge}
            </div>
          </div>

          <!-- Card Body (Expandable Dossier) -->
          <div id="${cardId}-body" style="display: none; padding: 16px 18px; background: rgba(0,0,0,0.3); border-top: 1px solid var(--border-subtle);">
            
            <!-- Tools Executed Section -->
            <div style="margin-bottom: 14px; display: flex; align-items: center; gap: 8px; flex-wrap: wrap;">
              <span style="font-size: 12px; font-weight: 600; color: var(--text-muted); text-transform: uppercase;">🛠️ Tools Run on this Link:</span>
              <div style="display: flex; flex-wrap: wrap; gap: 4px;">
                ${toolChips}
              </div>
            </div>

            <!-- Security Tests Evaluated Section -->
            <div style="margin-bottom: 14px;">
              <h5 style="color: var(--accent-cyan); font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 8px;">🧪 Security Checks & Vulnerability Tests Evaluated (${tests.length})</h5>
              <div class="history-table-container" style="background: #080d14; border-radius: 4px; max-height: none; overflow-x: auto;">
                <table class="data-table monospace-table" style="font-size: 12px;">
                  <thead>
                    <tr>
                      <th style="width: 220px;">Security Check / Probe</th>
                      <th style="width: 140px;">Category</th>
                      <th style="width: 120px;">Tool / Source</th>
                      <th style="width: 150px;">Evaluation Outcome</th>
                      <th>Observed Findings & Details</th>
                    </tr>
                  </thead>
                  <tbody>
                    ${testRows}
                  </tbody>
                </table>
              </div>
            </div>

            <!-- Correlated Findings Section -->
            ${findingsListHtml}

            <!-- Action Bar -->
            <div style="margin-top: 18px; padding-top: 12px; border-top: 1px solid rgba(255,255,255,0.06); display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; gap: 10px;">
              <div style="font-size: 11px; color: var(--text-muted);">
                Content-Type: <code>${this.escapeHtml(ep.content_type || 'text/html')}</code> | Crawl Depth: <code>${ep.depth || 0}</code>
              </div>
              <div style="display: flex; gap: 8px;">
                <button class="btn btn-xs btn-outline" onclick="navigator.clipboard.writeText(decodeURIComponent('${this.encodeInlineArg(ep.url)}'))">📋 Copy URL</button>
                <button class="btn btn-xs btn-primary" onclick="window.app.sendLinkToRepeater('${this.encodeInlineArg(ep.url)}', decodeURIComponent('${this.encodeInlineArg(method)}'))">⚡ Send to HTTP Repeater</button>
              </div>
            </div>

          </div>
        </div>
      `;
    }).join("");
  }

  toggleEndpointDossier(cardId) {
    const body = document.getElementById(`${cardId}-body`);
    const icon = document.getElementById(`${cardId}-icon`);
    if (!body) return;
    const isHidden = body.style.display === "none";
    body.style.display = isHidden ? "block" : "none";
    if (icon) icon.innerText = isHidden ? "▼" : "▶";
    if (isHidden) {
      setTimeout(() => {
        body.scrollIntoView({ behavior: "smooth", block: "nearest" });
      }, 50);
    }
  }

  renderTelemetryMatrix() {
    if (!this.telemetryMatrixTbody || !this.currentTelemetryData) return;

    const tools = this.currentTelemetryData.tools_executed || [];
    if (tools.length === 0) {
      this.telemetryMatrixTbody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--text-muted); padding: 25px;">No tool execution telemetry records available.</td></tr>`;
      return;
    }

    this.telemetryMatrixTbody.innerHTML = tools.map((t) => {
      let statusBadge = `<span class="badge badge-success">PASS</span>`;
      if (t.status === "FINDINGS") statusBadge = `<span class="badge" style="background: var(--color-critical); color: #fff;">FINDINGS</span>`;
      else if (t.status === "FAILED") statusBadge = `<span class="badge badge-danger">FAILED</span>`;
      else if (t.status === "PARTIAL") statusBadge = `<span class="badge badge-warning">PARTIAL</span>`;

      const runtimeStr = t.duration_seconds > 0 ? `${t.duration_seconds.toFixed(2)}s` : "< 1.0s";
      const endpointsCount = (t.endpoints_tested || []).length;
      const scopeStr = endpointsCount > 0 ? `${endpointsCount} locations` : (this.currentTelemetryData.target_value || "Target Host");

      const viewFindingsBtn = t.findings_count > 0
        ? `<button class="btn btn-xs btn-primary" onclick="window.app.viewToolFindings(decodeURIComponent('${this.encodeInlineArg(t.tool_name)}'))">🔍 View ${t.findings_count} Findings</button>`
        : "";
      const viewLogsBtn = `<button class="btn btn-xs btn-outline" onclick="window.app.viewToolLogs(decodeURIComponent('${this.encodeInlineArg(t.tool_name)}'))">📜 View Logs</button>`;

      return `
        <tr>
          <td><strong style="color: var(--accent-cyan); text-transform: uppercase;">${this.escapeHtml(t.tool_name)}</strong></td>
          <td><code>${this.escapeHtml(t.engine)}</code></td>
          <td>${statusBadge}</td>
          <td>${runtimeStr}</td>
          <td><strong>${t.findings_count}</strong></td>
          <td>${t.log_count} events</td>
          <td><span style="font-size: 11px; color: var(--text-muted);">${this.escapeHtml(scopeStr)}</span></td>
          <td>
            <div style="display: flex; gap: 6px;">
              ${viewFindingsBtn}
              ${viewLogsBtn}
            </div>
          </td>
        </tr>
      `;
    }).join("");
  }

  filterByTool(toolName) {
    this.selectedToolFilter = toolName;
    if (this.findingsToolFilter) {
      this.findingsToolFilter.value = toolName.toLowerCase();
    }
    this.renderFindings();
    if (this.findingsList) {
      this.findingsList.scrollIntoView({ behavior: "smooth" });
    }
  }

  viewToolFindings(toolName) {
    this.closeTelemetryModal();
    this.filterByTool(toolName);
  }

  viewToolLogs(toolName) {
    const logsTabBtn = document.querySelector('.telemetry-tab-btn[data-tab="logs"]');
    if (logsTabBtn) logsTabBtn.click();
    if (this.telemetryFilterTool) {
      this.telemetryFilterTool.value = toolName.toLowerCase();
      this.renderTelemetryLogs();
    }
  }

  renderTelemetrySurface() {
    if (!this.telemetrySubdomainsTbody || !this.currentTelemetryData) return;

    const subdomains = this.currentTelemetryData.discovered_subdomains || [];
    if (subdomains.length === 0) {
      this.telemetrySubdomainsTbody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 20px;">No subdomains discovered via OSINT for this target.</td></tr>`;
      return;
    }

    this.telemetrySubdomainsTbody.innerHTML = subdomains.map((sub) => {
      const ips = (sub.ip_addresses && sub.ip_addresses.length > 0)
        ? sub.ip_addresses.map(ip => `<span class="badge badge-info" style="font-family: monospace; font-size: 11px; margin-right: 4px;">${this.escapeHtml(ip)}</span>`).join("")
        : `<span class="badge badge-ghost" style="color: var(--text-muted); font-size: 11px;">Inactive / Unresolved</span>`;

      const cnames = (sub.cname_targets && sub.cname_targets.length > 0)
        ? sub.cname_targets.map(c => `<code>${this.escapeHtml(c)}</code>`).join(", ")
        : `<span style="color: var(--text-muted);">-</span>`;

      const takeover = sub.is_takeover_vulnerable 
        ? `<span class="badge badge-danger">⚠️ Vulnerable</span>` 
        : `<span class="badge badge-success">Safe</span>`;

      const source = sub.discovered_via || "OSINT / Passive DNS";

      return `
        <tr>
          <td><strong style="color: #fff; font-family: monospace;">${this.escapeHtml(sub.domain)}</strong></td>
          <td>${ips}</td>
          <td>${cnames}</td>
          <td>${takeover}</td>
          <td><span class="badge badge-ghost" style="font-size: 11px;">${this.escapeHtml(source)}</span></td>
        </tr>
      `;
    }).join("");
  }

  sendLinkToRepeater(encodedUrl, method = "GET") {
    const url = decodeURIComponent(encodedUrl);
    this.closeTelemetryModal();
    if (this.repUrlInput) this.repUrlInput.value = url;
    if (this.repMethodSelect) this.repMethodSelect.value = method;
    this.openRepeaterModal();
  }

  copyTelemetryLogs() {
    if (!this.telemetryLogsContainer) return;
    const text = this.telemetryLogsContainer.innerText;
    navigator.clipboard.writeText(text).then(() => {
      alert("Visible telemetry logs copied to clipboard.");
    });
  }

  exportTelemetryJson() {
    if (!this.currentTelemetryData) {
      alert("No telemetry data loaded to export.");
      return;
    }
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(this.currentTelemetryData, null, 2));
    const dlAnchor = document.createElement("a");
    dlAnchor.setAttribute("href", dataStr);
    dlAnchor.setAttribute("download", `telemetry_${this.currentTelemetryData.scan_id}.json`);
    document.body.appendChild(dlAnchor);
    dlAnchor.click();
    dlAnchor.remove();
  }

  encodeInlineArg(value) {
    return encodeURIComponent(String(value ?? ""));
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

window.auditAsset = function (val, type) {
  const input = document.getElementById("target-input");
  if (input) {
    input.value = val;
    if (window.app) window.app.detectTargetType();
    if (window.app) window.app.closeAssetsModal();
    input.focus();
  }
};

window.deleteAsset = async function (id) {
  if (!confirm("Are you sure you want to delete this monitored asset?")) return;
  try {
    const res = await (window.app ? window.app.authFetch(`/api/assets/${id}`, { method: "DELETE" }) : fetch(`/api/assets/${id}`, { method: "DELETE" }));
    if (res.ok && window.app) {
      await window.app.loadAssets();
    }
  } catch (e) {
    alert("Failed to delete asset: " + e);
  }
};

document.addEventListener("DOMContentLoaded", () => {
  window.app = new ScanStreamManager();
  // Load tool capabilities immediately on page load (Contract 04 v4.1.0)
  window.app.loadSystemCapabilities();
});
