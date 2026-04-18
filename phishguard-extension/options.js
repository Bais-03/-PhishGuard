const DEBUG = true;
const SETTINGS_DEFAULTS = {
  autoScan: true,
  warningStyle: "banner",
  backendUrl: "http://localhost:8000",
  themePreference: "system",
  whitelistDomains: []
};

const autoScan = document.getElementById("autoScan");
const warningStyle = document.getElementById("warningStyle");
const backendUrl = document.getElementById("backendUrl");
const themePreference = document.getElementById("themePreference");
const settingsBlob = document.getElementById("settingsBlob");
const status = document.getElementById("status");
const domainInput = document.getElementById("domainInput");
const addDomainButton = document.getElementById("addDomainButton");
const domainList = document.getElementById("domainList");
const exportWhitelistButton = document.getElementById("exportWhitelistButton");
const importWhitelistButton = document.getElementById("importWhitelistButton");

let currentThemePreference = "system";

/**
 * ✅ NEW CODE
 * Options page logger.
 * @param {string} scope
 * @param {Record<string, unknown>} [details]
 */
function debugLog(scope, details = {}) {
  if (!DEBUG) {
    return;
  }

  console.log(`[PhishGuard][options] ${scope}`, details);
}

function setStatus(message, isError = false) {
  status.textContent = message;
  status.style.color = isError ? "#b91c1c" : "";
}

/**
 * ✅ NEW CODE
 * Resolves the visual theme.
 * @param {string} preference
 * @returns {"light" | "dark"}
 */
function resolveTheme(preference) {
  if (preference === "light" || preference === "dark") {
    return preference;
  }

  return window.matchMedia?.("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

/**
 * ✅ NEW CODE
 * Applies the options page theme.
 * @param {string} preference
 */
function applyTheme(preference) {
  currentThemePreference = preference || "system";
  document.body.dataset.theme = resolveTheme(currentThemePreference);
}

/**
 * ✅ NEW CODE
 * Normalizes a whitelist domain.
 * @param {string} domain
 * @returns {string}
 */
function normalizeDomain(domain) {
  return String(domain || "")
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, "")
    .replace(/\/.*$/, "")
    .replace(/^\*\./, "");
}

/**
 * ✅ NEW CODE
 * Returns the current whitelist domains.
 * @returns {Promise<string[]>}
 */
async function getWhitelistDomains() {
  const settings = await chrome.storage.sync.get(SETTINGS_DEFAULTS);
  return Array.isArray(settings.whitelistDomains)
    ? settings.whitelistDomains.map(normalizeDomain).filter(Boolean)
    : [];
}

/**
 * ✅ NEW CODE
 * Callable helper requested by the task. This is intentionally isolated and not injected into scan logic.
 * @param {string} url
 * @returns {Promise<{ ok: boolean, whitelisted: boolean, matchedDomain: string | null }>}
 */
async function isWhitelisted(url) {
  try {
    const parsed = new URL(url);
    const hostname = parsed.hostname.toLowerCase();
    const domains = await getWhitelistDomains();
    const matchedDomain = domains.find((domain) => hostname === domain || hostname.endsWith(`.${domain}`)) || null;

    return {
      ok: true,
      whitelisted: Boolean(matchedDomain),
      matchedDomain
    };
  } catch (_error) {
    return {
      ok: false,
      whitelisted: false,
      matchedDomain: null
    };
  }
}

globalThis.isWhitelisted = isWhitelisted;

/**
 * ✅ NEW CODE
 * Renders whitelist domains.
 * @param {string[]} domains
 */
function renderWhitelist(domains) {
  domainList.innerHTML = "";

  if (!domains.length) {
    const empty = document.createElement("div");
    empty.className = "domain-item";
    empty.innerHTML = "<span>No domains whitelisted yet.</span>";
    domainList.appendChild(empty);
    return;
  }

  domains.forEach((domain) => {
    const item = document.createElement("div");
    item.className = "domain-item";
    item.innerHTML = `<span>${domain}</span><button class="secondary" type="button" data-domain="${domain}">Remove</button>`;
    domainList.appendChild(item);
  });
}

async function loadSettings() {
  const settings = await chrome.storage.sync.get(SETTINGS_DEFAULTS);
  autoScan.checked = Boolean(settings.autoScan);
  warningStyle.value = settings.warningStyle || SETTINGS_DEFAULTS.warningStyle;
  backendUrl.value = settings.backendUrl || SETTINGS_DEFAULTS.backendUrl;
  themePreference.value = settings.themePreference || SETTINGS_DEFAULTS.themePreference;
  applyTheme(themePreference.value);
  renderWhitelist(await getWhitelistDomains());
}

async function saveSettings() {
  const whitelistDomains = await getWhitelistDomains();
  const nextSettings = {
    autoScan: autoScan.checked,
    warningStyle: warningStyle.value,
    backendUrl: backendUrl.value.trim() || SETTINGS_DEFAULTS.backendUrl,
    themePreference: themePreference.value,
    whitelistDomains
  };

  await chrome.storage.sync.set(nextSettings);
  applyTheme(nextSettings.themePreference);
  setStatus("Settings saved.");
}

async function clearCache() {
  await chrome.runtime.sendMessage({
    type: "PHISHGUARD_CLEAR_CACHE"
  });
  setStatus("Cached analysis results cleared.");
}

async function exportSettings() {
  const settings = await chrome.storage.sync.get(SETTINGS_DEFAULTS);
  settingsBlob.value = JSON.stringify(settings, null, 2);
  setStatus("Settings exported to the text box.");
}

async function importSettings() {
  try {
    const parsed = JSON.parse(settingsBlob.value);
    const nextSettings = {
      autoScan: Boolean(parsed.autoScan),
      warningStyle: ["banner", "toast", "notification", "badge"].includes(parsed.warningStyle)
        ? parsed.warningStyle
        : SETTINGS_DEFAULTS.warningStyle,
      backendUrl: typeof parsed.backendUrl === "string" && parsed.backendUrl.trim()
        ? parsed.backendUrl.trim()
        : SETTINGS_DEFAULTS.backendUrl,
      themePreference: ["system", "light", "dark"].includes(parsed.themePreference)
        ? parsed.themePreference
        : SETTINGS_DEFAULTS.themePreference,
      whitelistDomains: Array.isArray(parsed.whitelistDomains)
        ? parsed.whitelistDomains.map(normalizeDomain).filter(Boolean)
        : await getWhitelistDomains()
    };

    await chrome.storage.sync.set(nextSettings);
    await loadSettings();
    setStatus("Settings imported.");
  } catch (error) {
    setStatus(error.message || "Invalid JSON", true);
  }
}

/**
 * ✅ NEW CODE
 * Adds a whitelist domain.
 */
async function addDomain() {
  const normalized = normalizeDomain(domainInput.value);
  if (!normalized) {
    setStatus("Enter a valid domain to whitelist.", true);
    return;
  }

  const domains = await getWhitelistDomains();
  const nextDomains = Array.from(new Set([...domains, normalized])).sort();
  await chrome.storage.sync.set({ whitelistDomains: nextDomains });
  domainInput.value = "";
  renderWhitelist(nextDomains);
  setStatus("Domain added to whitelist.");
}

/**
 * ✅ NEW CODE
 * Removes a whitelist domain.
 * @param {string} domain
 */
async function removeDomain(domain) {
  const domains = await getWhitelistDomains();
  const nextDomains = domains.filter((item) => item !== normalizeDomain(domain));
  await chrome.storage.sync.set({ whitelistDomains: nextDomains });
  renderWhitelist(nextDomains);
  setStatus("Domain removed from whitelist.");
}

/**
 * ✅ NEW CODE
 * Exports whitelist JSON.
 */
async function exportWhitelist() {
  const domains = await getWhitelistDomains();
  settingsBlob.value = JSON.stringify({ whitelistDomains: domains }, null, 2);
  setStatus("Whitelist exported to the text box.");
}

/**
 * ✅ NEW CODE
 * Imports whitelist JSON.
 */
async function importWhitelist() {
  try {
    const parsed = JSON.parse(settingsBlob.value);
    const nextDomains = Array.isArray(parsed.whitelistDomains)
      ? Array.from(new Set(parsed.whitelistDomains.map(normalizeDomain).filter(Boolean))).sort()
      : [];
    await chrome.storage.sync.set({ whitelistDomains: nextDomains });
    renderWhitelist(nextDomains);
    setStatus("Whitelist imported.");
  } catch (error) {
    debugLog("whitelist.import_failed", {
      message: error?.message || String(error)
    });
    setStatus(error.message || "Invalid whitelist JSON", true);
  }
}

document.getElementById("saveButton").addEventListener("click", () => {
  void saveSettings();
});
document.getElementById("clearCacheButton").addEventListener("click", () => {
  void clearCache();
});
document.getElementById("exportButton").addEventListener("click", () => {
  void exportSettings();
});
document.getElementById("importButton").addEventListener("click", () => {
  void importSettings();
});
addDomainButton.addEventListener("click", () => {
  void addDomain();
});
exportWhitelistButton.addEventListener("click", () => {
  void exportWhitelist();
});
importWhitelistButton.addEventListener("click", () => {
  void importWhitelist();
});
themePreference.addEventListener("change", () => {
  applyTheme(themePreference.value);
});
domainList.addEventListener("click", (event) => {
  const button = event.target.closest("button[data-domain]");
  if (!button) {
    return;
  }

  void removeDomain(button.dataset.domain || "");
});

window.matchMedia?.("(prefers-color-scheme: dark)").addEventListener?.("change", () => {
  if (currentThemePreference === "system") {
    applyTheme("system");
  }
});

await loadSettings();
