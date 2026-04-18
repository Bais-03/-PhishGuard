const DEBUG = true;
const SETTINGS_DEFAULTS = {
  autoScan: true,
  warningStyle: "banner",
  backendUrl: "http://localhost:8000",
  extensionEnabled: true,
  themePreference: "system"
};
const HISTORY_STORAGE_KEY = "scanHistory";
const HISTORY_STORAGE_LIMIT = 20;
const HISTORY_UI_LIMIT = 10;

const urlTabButton = document.getElementById("urlTabButton");
const emailTabButton = document.getElementById("emailTabButton");
const urlPanel = document.getElementById("urlPanel");
const emailPanel = document.getElementById("emailPanel");
const scoreRing = document.getElementById("scoreRing");
const scoreValue = document.getElementById("scoreValue");
const verdictLabel = document.getElementById("verdictLabel");
const currentUrl = document.getElementById("currentUrl");
const reasonsList = document.getElementById("reasonsList");
const manualUrl = document.getElementById("manualUrl");
const scanButton = document.getElementById("scanButton");
const refreshButton = document.getElementById("refreshButton");
const autoScanToggle = document.getElementById("autoScanToggle");
const statusMessage = document.getElementById("statusMessage");
const healthLink = document.getElementById("healthLink");
const emailScoreRing = document.getElementById("emailScoreRing");
const emailScoreValue = document.getElementById("emailScoreValue");
const emailVerdictLabel = document.getElementById("emailVerdictLabel");
const emailSummary = document.getElementById("emailSummary");
const emailReasonsList = document.getElementById("emailReasonsList");
const emailInput = document.getElementById("emailInput");
const analyzeEmailButton = document.getElementById("analyzeEmailButton");
const falsePositiveRow = document.getElementById("falsePositiveRow");
const falsePositiveButton = document.getElementById("falsePositiveButton");

// ✅ NEW: Separate history for URL and email
const urlHistoryToggleButton = document.getElementById("urlHistoryToggleButton");
const urlHistoryList = document.getElementById("urlHistoryList");
const urlHistoryEmpty = document.getElementById("urlHistoryEmpty");
const emailHistoryToggleButton = document.getElementById("emailHistoryToggleButton");
const emailHistoryList = document.getElementById("emailHistoryList");
const emailHistoryEmpty = document.getElementById("emailHistoryEmpty");

let activeTabName = "url";
let currentUrlState = null;
let currentThemePreference = "system";
let urlHistoryExpanded = false;
let emailHistoryExpanded = false;

/**
 * Popup debug logger.
 */
function debugLog(scope, details = {}) {
  if (!DEBUG) return;
  console.log(`[PhishGuard][popup] ${scope}`, details);
}

function severityForScore(score) {
  if (score >= 60) return { label: "PHISHING", color: "#EF4444" };
  if (score >= 35) return { label: "SUSPICIOUS", color: "#F59E0B" };
  return { label: "LIKELY SAFE", color: "#22C55E" };
}

function resolveTheme(preference) {
  if (preference === "light" || preference === "dark") return preference;
  return window.matchMedia?.("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

function applyTheme(preference) {
  currentThemePreference = preference || "system";
  document.body.dataset.theme = resolveTheme(currentThemePreference);
}

/**
 * ScanHistory store with type filtering.
 */
class ScanHistory {
  constructor() {
    this.storageKey = HISTORY_STORAGE_KEY;
    this.storageLimit = HISTORY_STORAGE_LIMIT;
  }

  async getAll() {
    const stored = await chrome.storage.local.get(this.storageKey);
    return Array.isArray(stored[this.storageKey]) ? stored[this.storageKey] : [];
  }

  async add(item) {
    const existing = await this.getAll();
    const dedupeKey = `${item.type || "url"}|${item.url || item.subject || ""}|${item.verdict || ""}|${item.riskScore || 0}`;
    const next = [
      {
        ...item,
        dedupeKey,
        timestamp: item.timestamp || new Date().toISOString()
      },
      ...existing.filter((entry) => entry?.dedupeKey !== dedupeKey)
    ].slice(0, this.storageLimit);

    await chrome.storage.local.set({ [this.storageKey]: next });
  }

  async getByType(type) {
    const all = await this.getAll();
    return all.filter(item => item.type === type).slice(0, HISTORY_UI_LIMIT);
  }
}

const scanHistory = new ScanHistory();

function setStatus(message, isError = false) {
  statusMessage.textContent = message || "";
  statusMessage.style.color = isError ? "#b91c1c" : "";
}

function renderReasons(reasons) {
  reasonsList.innerHTML = "";
  const topReasons = Array.isArray(reasons) ? reasons.slice(0, 3) : [];
  topReasons.forEach((reason) => {
    const item = document.createElement("li");
    item.textContent = reason;
    reasonsList.appendChild(item);
  });
  if (topReasons.length === 0) {
    const item = document.createElement("li");
    item.textContent = "No notable phishing indicators reported.";
    reasonsList.appendChild(item);
  }
}

function renderEmailReasons(reasons) {
  emailReasonsList.innerHTML = "";
  const topReasons = Array.isArray(reasons) ? reasons.slice(0, 3) : [];
  if (topReasons.length === 0) {
    const item = document.createElement("li");
    item.textContent = "No notable phishing indicators reported.";
    emailReasonsList.appendChild(item);
  } else {
    topReasons.forEach((reason) => {
      const item = document.createElement("li");
      item.textContent = reason;
      emailReasonsList.appendChild(item);
    });
  }
}

function setActiveTab(tabName) {
  activeTabName = tabName;
  const showingUrl = tabName === "url";
  urlPanel.hidden = !showingUrl;
  emailPanel.hidden = showingUrl;
  urlTabButton.classList.toggle("active", showingUrl);
  emailTabButton.classList.toggle("active", !showingUrl);
  
  // Refresh the history for the active tab
  if (showingUrl) {
    renderUrlHistory();
  } else {
    renderEmailHistory();
  }
}

function renderFalsePositiveButton(state) {
  const result = state?.result;
  const isPhishing = result && Number(result.score || 0) >= 60;
  falsePositiveRow.hidden = !isPhishing;
  falsePositiveButton.disabled = false;
  falsePositiveButton.textContent = "✅ This looks safe";
}

async function renderAnalysisState(state) {
  currentUrlState = state || null;
  const result = state?.result;
  
  if (!result) {
    scoreValue.textContent = "--";
    verdictLabel.textContent = state?.status === "backend-offline" ? "Backend offline" : "Waiting for scan";
    verdictLabel.style.color = "#64748b";
    currentUrl.textContent = state?.url || "No active URL";
    renderReasons(state?.error ? [state.error] : []);
    renderFalsePositiveButton(state);
    return;
  }

  const severity = severityForScore(result.score);
  scoreRing.style.setProperty("--score", Math.max(0, Math.min(100, result.score)));
  scoreRing.style.setProperty("--ring-color", severity.color);
  scoreValue.textContent = String(result.score);
  verdictLabel.textContent = result.verdict || severity.label;
  verdictLabel.style.color = severity.color;
  currentUrl.textContent = state.url || "No active URL";
  renderReasons(result.reasons);
  renderFalsePositiveButton(state);

  // Save to URL history only
  await scanHistory.add({
    type: "url",
    url: state.url || "",
    verdict: result.verdict || severity.label,
    riskScore: Number(result.score || 0),
    timestamp: new Date().toISOString()
  });
  
  await renderUrlHistory();
}

async function renderEmailAnalysisState(state) {
  const result = state?.result;

  if (!result) {
    emailScoreValue.textContent = "--";
    emailVerdictLabel.textContent = state?.status === "error" ? "Email analysis failed" : "Paste an email to analyze";
    emailVerdictLabel.style.color = "#64748b";
    emailSummary.textContent = state?.error || "RFC 2822 email content";
    renderEmailReasons(state?.error ? [state.error] : []);
    emailScoreRing.style.setProperty("--score", 0);
    emailScoreRing.style.setProperty("--ring-color", "#22C55E");
    return;
  }

  const severity = severityForScore(result.score);
  emailScoreRing.style.setProperty("--score", Math.max(0, Math.min(100, result.score)));
  emailScoreRing.style.setProperty("--ring-color", severity.color);
  emailScoreValue.textContent = String(result.score);
  emailVerdictLabel.textContent = result.verdict || severity.label;
  emailVerdictLabel.style.color = severity.color;
  emailSummary.textContent = "Email analysis complete";
  renderEmailReasons(result.reasons || []);

  // Extract subject for display
  const subjectLine = emailInput.value.split("\n").find(line => line.startsWith("Subject:")) || "Email analysis";
  const subject = subjectLine.replace("Subject:", "").trim();

  await scanHistory.add({
    type: "email",
    subject: subject,
    verdict: result.verdict || severity.label,
    riskScore: Number(result.score || 0),
    timestamp: new Date().toISOString(),
    rawEmail: emailInput.value.trim()
  });
  
  await renderEmailHistory();
}

/**
 * ✅ NEW: Render only URL history
 */
// ... [ALL EXISTING CODE REMAINS EXACTLY THE SAME up to line ~300] ...

// ⚠️ ONLY REPLACE THE renderUrlHistory() and renderEmailHistory() functions
// All other code stays IDENTICAL to your existing version

/**
 * ✅ UPDATED: Render only URL history with enhanced UI cards
 */
async function renderUrlHistory() {
  const items = await scanHistory.getByType("url");
  urlHistoryList.innerHTML = "";
  urlHistoryEmpty.hidden = items.length > 0;

  items.forEach((item) => {
    const card = document.createElement("div");
    card.className = "history-card";
    card.dataset.type = "url";
    card.dataset.url = item.url || "";
    
    // Determine risk level
    const riskScore = item.riskScore || 0;
    let riskLevel = "safe";
    let riskIcon = "";
    if (riskScore >= 60) {
      riskLevel = "phishing";
      riskIcon = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>';
    } else if (riskScore >= 35) {
      riskLevel = "suspicious";
      riskIcon = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M12 8v4M12 16h.01"/><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>';
    } else {
      riskLevel = "safe";
      riskIcon = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M20 6L9 17l-5-5"/><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>';
    }
    
    // Format relative time
    const timestamp = new Date(item.timestamp || Date.now());
    const now = new Date();
    const diffMs = now - timestamp;
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);
    let timeAgo;
    if (diffMins < 1) timeAgo = 'Just now';
    else if (diffMins < 60) timeAgo = `${diffMins} min ago`;
    else if (diffHours < 24) timeAgo = `${diffHours} hour${diffHours > 1 ? 's' : ''} ago`;
    else timeAgo = `${diffDays} day${diffDays > 1 ? 's' : ''} ago`;
    
    // Truncate URL for preview
    let urlPreview = item.url || "URL scan";
    if (urlPreview.length > 60) {
      urlPreview = urlPreview.substring(0, 57) + "...";
    }
    
    card.innerHTML = `
      <div class="history-card-header">
        <span class="risk-badge ${riskLevel}">
          ${riskIcon}
          ${item.verdict || "Unknown"}
        </span>
        <span class="history-timestamp">${timeAgo}</span>
      </div>
      <div class="history-target">
        <strong>Score ${item.riskScore ?? "--"}</strong> • ${urlPreview}
      </div>
      <div class="history-preview">${item.url ? new URL(item.url).hostname : "URL scan"}</div>
    `;
    
    card.addEventListener("click", () => {
      if (card.dataset.url) {
        manualUrl.value = card.dataset.url;
        analyzeManualUrl();
      }
    });
    
    urlHistoryList.appendChild(card);
  });

  urlHistoryList.hidden = !urlHistoryExpanded || items.length === 0;
  urlHistoryToggleButton.textContent = urlHistoryExpanded ? "Hide" : "Show";
}

/**
 * ✅ UPDATED: Render only email history with enhanced UI cards
 */
async function renderEmailHistory() {
  const items = await scanHistory.getByType("email");
  emailHistoryList.innerHTML = "";
  emailHistoryEmpty.hidden = items.length > 0;

  items.forEach((item) => {
    const card = document.createElement("div");
    card.className = "history-card";
    card.dataset.type = "email";
    card.dataset.rawEmail = item.rawEmail || "";
    
    // Determine risk level
    const riskScore = item.riskScore || 0;
    let riskLevel = "safe";
    let riskIcon = "";
    if (riskScore >= 60) {
      riskLevel = "phishing";
      riskIcon = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>';
    } else if (riskScore >= 35) {
      riskLevel = "suspicious";
      riskIcon = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M12 8v4M12 16h.01"/><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>';
    } else {
      riskLevel = "safe";
      riskIcon = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M20 6L9 17l-5-5"/><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>';
    }
    
    // Format relative time
    const timestamp = new Date(item.timestamp || Date.now());
    const now = new Date();
    const diffMs = now - timestamp;
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);
    let timeAgo;
    if (diffMins < 1) timeAgo = 'Just now';
    else if (diffMins < 60) timeAgo = `${diffMins} min ago`;
    else if (diffHours < 24) timeAgo = `${diffHours} hour${diffHours > 1 ? 's' : ''} ago`;
    else timeAgo = `${diffDays} day${diffDays > 1 ? 's' : ''} ago`;
    
    // Truncate subject for preview
    let subjectPreview = item.subject || "Email scan";
    if (subjectPreview.length > 50) {
      subjectPreview = subjectPreview.substring(0, 47) + "...";
    }
    
    card.innerHTML = `
      <div class="history-card-header">
        <span class="risk-badge ${riskLevel}">
          ${riskIcon}
          ${item.verdict || "Unknown"}
        </span>
        <span class="history-timestamp">${timeAgo}</span>
      </div>
      <div class="history-target">
        <strong>Score ${item.riskScore ?? "--"}</strong> • ${subjectPreview}
      </div>
      <div class="history-preview">📧 Email analysis</div>
    `;
    
    card.addEventListener("click", () => {
      if (card.dataset.rawEmail) {
        setActiveTab("email");
        emailInput.value = card.dataset.rawEmail;
        analyzeEmail();
      }
    });
    
    emailHistoryList.appendChild(card);
  });

  emailHistoryList.hidden = !emailHistoryExpanded || items.length === 0;
  emailHistoryToggleButton.textContent = emailHistoryExpanded ? "Hide" : "Show";
}

// ... [ALL EXISTING CODE CONTINUES UNCHANGED]
async function getActiveTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}

async function loadSettings() {
  const settings = await chrome.storage.sync.get(SETTINGS_DEFAULTS);
  autoScanToggle.checked = Boolean(settings.autoScan);
  applyTheme(settings.themePreference || "system");
  return settings;
}

async function loadTabAnalysis() {
  const tab = await getActiveTab();
  if (!tab?.id) {
    setStatus("No active tab found.", true);
    return;
  }

  manualUrl.value = tab.url && /^https?:/.test(tab.url) ? tab.url : "";
  const response = await chrome.runtime.sendMessage({
    type: "PHISHGUARD_GET_TAB_ANALYSIS",
    tabId: tab.id
  });

  if (!response?.ok) {
    setStatus(response?.error || "Unable to load analysis.", true);
    return;
  }

  await renderAnalysisState(response.state);
  if (response.state?.status === "backend-offline") {
    setStatus("Backend offline. Using cached results if available.", true);
  } else if (response.state?.source === "stale-cache") {
    setStatus("Showing stale cache because the backend is unavailable.");
  } else if (response.state?.source === "fresh-cache") {
    setStatus("Loaded from cache.");
  } else if (response.state?.status === "loading") {
    setStatus("Analyzing current page...");
  } else {
    setStatus("");
  }
}

async function loadEmailAnalysis() {
  const tab = await getActiveTab();
  if (!tab?.id) return;

  const response = await chrome.runtime.sendMessage({
    type: "PHISHGUARD_GET_EMAIL_ANALYSIS",
    tabId: tab.id
  });

  if (!response?.ok) {
    debugLog("email.load_failed", { error: response?.error });
    return;
  }

  if (response.state?.rawEmail && !emailInput.value.trim()) {
    emailInput.value = response.state.rawEmail;
  }
  await renderEmailAnalysisState(response.state);
}

async function analyzeManualUrl() {
  const tab = await getActiveTab();
  const url = manualUrl.value.trim();

  if (!tab?.id || !url) {
    setStatus("Enter a valid URL to scan.", true);
    return;
  }

  setStatus("Scanning URL...");
  const response = await chrome.runtime.sendMessage({
    type: "PHISHGUARD_ANALYZE_URL",
    tabId: tab.id,
    url
  });

  if (!response?.ok) {
    setStatus(response?.error || "Scan failed.", true);
    return;
  }

  await renderAnalysisState(response.state);
  setStatus(response.state?.source === "fresh-cache" ? "Loaded from cache." : "Scan complete.");
}

async function analyzeEmail() {
  const rawEmail = emailInput.value.trim();

  if (!rawEmail) {
    setStatus("Paste a raw email to analyze.", true);
    return;
  }

  setStatus("Analyzing email...");

  try {
    const response = await chrome.runtime.sendMessage({
      type: "PHISHGUARD_ANALYZE_EMAIL",
      rawEmail
    });

    if (!response?.ok) {
      setStatus(response?.error || "Email analysis failed.", true);
      await renderEmailAnalysisState({
        status: "error",
        error: response?.error || "Email analysis failed."
      });
      return;
    }

    const state = response.state || {
      status: "ready",
      result: response.result,
      source: "network",
      updatedAt: Date.now()
    };

    await renderEmailAnalysisState(state);
    setStatus("Email analysis complete.");
  } catch (error) {
    debugLog("email.analysis_failed", { message: error?.message || String(error) });
    setStatus(error.message || "Email analysis failed.", true);
    await renderEmailAnalysisState({
      status: "error",
      error: error.message || "Email analysis failed."
    });
  }
}

async function reportFalsePositive() {
  if (!currentUrlState?.result || !currentUrlState?.url) return;

  falsePositiveButton.disabled = true;
  falsePositiveButton.textContent = "Sending...";

  try {
    const response = await chrome.runtime.sendMessage({
      type: "PHISHGUARD_REPORT_FALSE_POSITIVE",
      payload: {
        url: currentUrlState.url,
        verdict: currentUrlState.result.verdict,
        score: currentUrlState.result.score,
        reasons: currentUrlState.result.reasons,
        signature: `${currentUrlState.url}:${currentUrlState.result.score}:${currentUrlState.result.verdict}`,
        source: "popup"
      }
    });

    if (response?.ok) {
      falsePositiveButton.textContent = response.duplicate ? "Already reported" : "Reported ✓";
      setStatus(response.duplicate ? "This false positive was already reported." : "False positive report sent.");
    } else {
      falsePositiveButton.textContent = "Unavailable";
      setStatus("Unable to send false positive report.", true);
    }
  } catch (error) {
    falsePositiveButton.textContent = "Unavailable";
    setStatus(error?.message || "Unable to send false positive report.", true);
  } finally {
    setTimeout(() => {
      falsePositiveButton.disabled = false;
      if (!falsePositiveRow.hidden) {
        falsePositiveButton.textContent = "✅ This looks safe";
      }
    }, 1500);
  }
}

// Event Listeners
scanButton.addEventListener("click", () => analyzeManualUrl());
analyzeEmailButton.addEventListener("click", () => analyzeEmail());
falsePositiveButton.addEventListener("click", () => reportFalsePositive());

urlTabButton.addEventListener("click", () => setActiveTab("url"));
emailTabButton.addEventListener("click", () => setActiveTab("email"));

refreshButton.addEventListener("click", async () => {
  const tab = await getActiveTab();
  if (!tab?.id || !tab.url) {
    setStatus("No active tab available.", true);
    return;
  }
  manualUrl.value = tab.url;
  await analyzeManualUrl();
});

autoScanToggle.addEventListener("change", async () => {
  await chrome.storage.sync.set({ autoScan: autoScanToggle.checked });
  setStatus(autoScanToggle.checked ? "Automatic scanning enabled." : "Automatic scanning disabled.");
});

healthLink.addEventListener("click", async (event) => {
  event.preventDefault();
  setStatus("Checking backend health...");
  const response = await chrome.runtime.sendMessage({ type: "PHISHGUARD_GET_HEALTH" });
  if (!response?.ok) {
    setStatus(response?.error || "Backend health check failed.", true);
    return;
  }
  setStatus(`Backend status: ${response.health.status}`);
});

// ✅ NEW: URL history toggle
urlHistoryToggleButton.addEventListener("click", async () => {
  urlHistoryExpanded = !urlHistoryExpanded;
  await renderUrlHistory();
});

// ✅ NEW: Email history toggle
emailHistoryToggleButton.addEventListener("click", async () => {
  emailHistoryExpanded = !emailHistoryExpanded;
  await renderEmailHistory();
});

// ✅ NEW: Click handlers for history items
urlHistoryList.addEventListener("click", async (event) => {
  const button = event.target.closest(".history-item");
  if (!button || button.dataset.type !== "url") return;
  if (button.dataset.url) {
    manualUrl.value = button.dataset.url;
    await analyzeManualUrl();
  }
});

emailHistoryList.addEventListener("click", async (event) => {
  const button = event.target.closest(".history-item");
  if (!button || button.dataset.type !== "email") return;
  if (button.dataset.rawEmail) {
    setActiveTab("email");
    emailInput.value = button.dataset.rawEmail;
    await analyzeEmail();
  }
});

// Watch system theme changes
window.matchMedia?.("(prefers-color-scheme: dark)").addEventListener?.("change", () => {
  if (currentThemePreference === "system") applyTheme("system");
});

// Initialize
await loadSettings();
await loadTabAnalysis();
await loadEmailAnalysis();
await renderUrlHistory();
await renderEmailHistory();
setActiveTab("url");