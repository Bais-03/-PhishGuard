import {
  checkEmail,
  checkUrl,
  getHealth,
  submitFalsePositiveFeedback
} from "./utils/api.js";

const DEBUG = true;
const CACHE_TTL_MS = 60 * 60 * 1000;
const STALE_GRACE_MS = 5 * 60 * 1000;
const CACHE_KEY = "analysisCache";
const FAILURE_CACHE_TTL_MS = 30 * 1000;
const FALSE_POSITIVE_KEY = "falsePositiveReports";
const ERROR_LOGS_KEY = "errorLogs";
const EXTENSION_TOGGLE_KEY = "extensionEnabled";
const THEME_STORAGE_KEY = "themePreference";
const STORAGE_META_KEY = "phishguardStorageMeta";
const SETTINGS_DEFAULTS = {
  autoScan: true,
  warningStyle: "banner",
  backendUrl: "http://localhost:8000",
  extensionEnabled: true,
  themePreference: "system",
  whitelistDomains: []
};

const recentScanEvents = new Map();
const temporaryFailureCache = new Map();
const EMAIL_CONTEXT_SELECTED = "phishguard-analyze-selected-email";
const EMAIL_CONTEXT_MAILTO = "phishguard-analyze-mailto-email";
const COMMAND_SCAN_PAGE = "phishguard-scan-page";
const COMMAND_OPEN_POPUP = "phishguard-open-popup";
const COMMAND_TOGGLE_EXTENSION = "phishguard-toggle-extension";

/**
 * ✅ NEW CODE
 * Shared debug logger.
 * @param {string} scope
 * @param {Record<string, unknown>} [details]
 */
function log(scope, details = {}) {
  if (!DEBUG) {
    return;
  }

  console.log(`[PhishGuard][background] ${scope}`, details);
}

/**
 * ✅ NEW CODE
 * Shared warning logger.
 * @param {string} scope
 * @param {unknown} error
 * @param {Record<string, unknown>} [details]
 */
function warn(scope, error, details = {}) {
  console.warn(`[PhishGuard][background] ${scope}`, {
    ...details,
    message: error?.message || String(error)
  });
}

function now() {
  return Date.now();
}

function scoreToSeverity(score) {
  if (score >= 60) return "phishing";
  if (score >= 35) return "suspicious";
  return "safe";
}

function severityToBadge(severity) {
  switch (severity) {
    case "phishing":
      return { color: "#EF4444", text: "60+" };
    case "suspicious":
      return { color: "#F59E0B", text: "35+" };
    default:
      return { color: "#22C55E", text: "OK" };
  }
}

/**
 * ✅ NEW CODE
 * Lightweight async sleep helper.
 * @param {number} ms
 * @returns {Promise<void>}
 */
function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * ✅ NEW CODE
 * Returns whether the error is retryable.
 * @param {unknown} error
 * @returns {boolean}
 */
function isRetryableError(error) {
  const message = String(error?.message || "").toLowerCase();
  const status = Number(error?.status || 0);

  return (
    Boolean(error?.isTimeout) ||
    message.includes("network") ||
    message.includes("failed to fetch") ||
    message.includes("fetch") ||
    message.includes("timeout") ||
    (status >= 500 && status < 600)
  );
}

/**
 * ✅ NEW CODE
 * Runs a promise with a timeout guard.
 * @template T
 * @param {Promise<T>} promise
 * @param {number} timeoutMs
 * @returns {Promise<T>}
 */
async function withTimeout(promise, timeoutMs) {
  let timeoutId = null;

  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timeoutId = setTimeout(() => {
          const error = new Error(`Request timed out after ${timeoutMs}ms`);
          error.isTimeout = true;
          reject(error);
        }, timeoutMs);
      })
    ]);
  } finally {
    if (timeoutId) {
      clearTimeout(timeoutId);
    }
  }
}

/**
 * ✅ NEW CODE
 * Non-intrusive retry wrapper that keeps the original API function as the fallback work unit.
 * @template T
 * @param {() => Promise<T>} apiFn
 * @param {{ cacheKey?: string, timeoutMs?: number, retries?: number, backoffMs?: number[] }} [options]
 * @returns {Promise<T>}
 */
async function analyzeWithRetry(apiFn, options = {}) {
  const retryDelays = Array.isArray(options.backoffMs) && options.backoffMs.length
    ? options.backoffMs
    : [1000, 2000, 4000];
  const maxAttempts = Math.min(
    Number(options.retries || retryDelays.length + 1),
    retryDelays.length + 1
  );
  const cacheKey = options.cacheKey || "";
  const timeoutMs = Number(options.timeoutMs || 12000);
  const cachedFailure = cacheKey ? temporaryFailureCache.get(cacheKey) : null;

  if (cachedFailure && cachedFailure.until > now()) {
    const cachedError = new Error(cachedFailure.message || "Temporary failure cached");
    cachedError.status = cachedFailure.status;
    cachedError.temporaryFailureCached = true;
    throw cachedError;
  }

  let lastError;

  for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
    try {
      const result = await withTimeout(apiFn(), timeoutMs);
      if (cacheKey) {
        temporaryFailureCache.delete(cacheKey);
      }
      return result;
    } catch (error) {
      lastError = error;
      if (!isRetryableError(error) || attempt >= maxAttempts - 1) {
        break;
      }

      await sleep(retryDelays[attempt] || retryDelays[retryDelays.length - 1]);
    }
  }

  if (cacheKey && isRetryableError(lastError)) {
    temporaryFailureCache.set(cacheKey, {
      until: now() + FAILURE_CACHE_TTL_MS,
      message: lastError?.message || "Temporary failure",
      status: lastError?.status || 0
    });
  }

  throw lastError;
}

/**
 * ✅ NEW CODE
 * Storage helper that cleans older data and sheds least-recently-used keys when needed.
 */
class StorageManager {
  constructor(area = chrome.storage.local) {
    this.area = area;
    this.maxBytes = 4.5 * 1024 * 1024;
    this.maxAgeMs = 7 * 24 * 60 * 60 * 1000;
  }

  /**
   * @returns {Promise<number>}
   */
  async getBytesInUse() {
    try {
      return await this.area.getBytesInUse(null);
    } catch (_error) {
      return 0;
    }
  }

  /**
   * @returns {Promise<Record<string, { updatedAt: number, lastAccessedAt: number }>>}
   */
  async getMeta() {
    try {
      const stored = await this.area.get(STORAGE_META_KEY);
      return stored[STORAGE_META_KEY] || {};
    } catch (_error) {
      return {};
    }
  }

  /**
   * @param {Record<string, { updatedAt: number, lastAccessedAt: number }>} meta
   * @returns {Promise<void>}
   */
  async setMeta(meta) {
    try {
      await this.area.set({ [STORAGE_META_KEY]: meta });
    } catch (_error) {}
  }

  /**
   * @param {string} key
   * @returns {Promise<void>}
   */
  async touch(key) {
    const meta = await this.getMeta();
    const timestamp = now();
    meta[key] = {
      updatedAt: meta[key]?.updatedAt || timestamp,
      lastAccessedAt: timestamp
    };
    await this.setMeta(meta);
  }

  /**
   * @param {string[]} [preferredKeys]
   * @returns {Promise<void>}
   */
  async cleanupExpired(preferredKeys = []) {
    const meta = await this.getMeta();
    const keysToRemove = [];
    const timestamp = now();

    Object.entries(meta).forEach(([key, entry]) => {
      if (!entry?.updatedAt || timestamp - entry.updatedAt > this.maxAgeMs) {
        keysToRemove.push(key);
        delete meta[key];
      }
    });

    for (const key of preferredKeys) {
      try {
        const stored = await this.area.get(key);
        const value = stored[key];
        if (Array.isArray(value)) {
          const filtered = value.filter((item) => {
            const itemTimestamp = Number(item?.timestamp || item?.updatedAt || item?.storedAt || 0);
            return !itemTimestamp || timestamp - itemTimestamp <= this.maxAgeMs;
          });
          if (filtered.length !== value.length) {
            await this.area.set({ [key]: filtered });
            meta[key] = {
              updatedAt: timestamp,
              lastAccessedAt: timestamp
            };
          }
        } else if (value && typeof value === "object") {
          let changed = false;
          const nextValue = { ...value };
          Object.entries(nextValue).forEach(([itemKey, itemValue]) => {
            const itemTimestamp = Number(itemValue?.timestamp || itemValue?.updatedAt || itemValue?.storedAt || itemValue?.reportedAt || 0);
            if (itemTimestamp && timestamp - itemTimestamp > this.maxAgeMs) {
              delete nextValue[itemKey];
              changed = true;
            }
          });
          if (changed) {
            await this.area.set({ [key]: nextValue });
            meta[key] = {
              updatedAt: timestamp,
              lastAccessedAt: timestamp
            };
          }
        }
      } catch (_error) {}
    }

    if (keysToRemove.length) {
      try {
        await this.area.remove(keysToRemove);
      } catch (_error) {}
    }

    await this.setMeta(meta);
  }

  /**
   * @returns {Promise<void>}
   */
  async evictLRU() {
    let bytesInUse = await this.getBytesInUse();
    if (bytesInUse <= this.maxBytes) {
      return;
    }

    const meta = await this.getMeta();
    const candidates = Object.entries(meta)
      .filter(([key]) => key !== STORAGE_META_KEY)
      .sort((left, right) => (left[1]?.lastAccessedAt || 0) - (right[1]?.lastAccessedAt || 0));

    for (const [key] of candidates) {
      try {
        await this.area.remove(key);
        delete meta[key];
        bytesInUse = await this.getBytesInUse();
        if (bytesInUse <= this.maxBytes) {
          break;
        }
      } catch (_error) {}
    }

    await this.setMeta(meta);
  }

  /**
   * @param {string} key
   * @param {unknown} value
   * @returns {Promise<{ ok: boolean, key: string, bytesInUse: number }>}
   */
  async safeSet(key, value) {
    try {
      await this.cleanupExpired([CACHE_KEY, FALSE_POSITIVE_KEY, ERROR_LOGS_KEY, "scanHistory"]);
      await this.area.set({ [key]: value });

      const meta = await this.getMeta();
      const timestamp = now();
      meta[key] = {
        updatedAt: timestamp,
        lastAccessedAt: timestamp
      };
      await this.setMeta(meta);
      await this.evictLRU();

      return {
        ok: true,
        key,
        bytesInUse: await this.getBytesInUse()
      };
    } catch (error) {
      warn("storage.safe_set_failed", error, { key });
      return {
        ok: false,
        key,
        bytesInUse: await this.getBytesInUse()
      };
    }
  }
}

/**
 * ✅ NEW CODE
 * Deduplicates requests and returns the same promise for duplicate work.
 */
class RequestDebouncer {
  constructor() {
    this.pending = new Map();
    this.ttl = {
      url: 2000,
      email: 5000
    };
  }

  /**
   * @template T
   * @param {"url" | "email"} kind
   * @param {string} key
   * @param {() => Promise<T>} task
   * @returns {Promise<T>}
   */
  run(kind, key, task) {
    const ttlMs = this.ttl[kind] || 2000;
    const existing = this.pending.get(key);

    if (existing && now() - existing.createdAt <= ttlMs) {
      return existing.promise;
    }

    const promise = (async () => {
      try {
        return await task();
      } finally {
        setTimeout(() => {
          this.pending.delete(key);
        }, ttlMs);
      }
    })();

    this.pending.set(key, {
      createdAt: now(),
      promise
    });

    return promise;
  }
}

/**
 * ✅ NEW CODE
 * Non-blocking error collector.
 */
class ErrorTracker {
  constructor(storageManager) {
    this.storageManager = storageManager;
    this.maxLogs = 50;
    this.endpointPath = "";
  }

  /**
   * @param {string} endpointPath
   */
  setEndpoint(endpointPath) {
    this.endpointPath = endpointPath;
  }

  /**
   * @param {string} scope
   * @param {unknown} error
   * @param {Record<string, unknown>} [details]
   * @returns {Promise<void>}
   */
  async capture(scope, error, details = {}) {
    try {
      const stored = await chrome.storage.local.get(ERROR_LOGS_KEY);
      const logs = Array.isArray(stored[ERROR_LOGS_KEY]) ? stored[ERROR_LOGS_KEY] : [];
      const nextEntry = {
        scope,
        message: error?.message || String(error),
        stack: error?.stack || "",
        details,
        timestamp: new Date().toISOString()
      };
      const nextLogs = [nextEntry, ...logs].slice(0, this.maxLogs);
      await this.storageManager.safeSet(ERROR_LOGS_KEY, nextLogs);

      if (this.endpointPath) {
        void fetch(this.endpointPath, {
          method: "POST",
          headers: {
            "Content-Type": "application/json"
          },
          body: JSON.stringify(nextEntry)
        }).catch(() => {});
      }
    } catch (_error) {}
  }

  /**
   * @template T
   * @param {string} scope
   * @param {() => Promise<T>} task
   * @param {Record<string, unknown>} [details]
   * @returns {Promise<T>}
   */
  async wrap(scope, task, details = {}) {
    try {
      return await task();
    } catch (error) {
      await this.capture(scope, error, details);
      throw error;
    }
  }
}

const storageManager = new StorageManager();
const requestDebouncer = new RequestDebouncer();
const errorTracker = new ErrorTracker(storageManager);

async function showNotification(tabId, result, severity) {
  const notificationId = `phishguard-${tabId}-${Date.now()}`;
  const notificationOptions = {
    type: "basic",
    iconUrl: "icons/icon128.png",
    title: severity === "phishing" ? "PhishGuard: Phishing Detected" : "PhishGuard: Suspicious Site",
    message: `${result.verdict} • Score ${result.score}\n${result.reasons?.[0] || "Proceed with caution"}`,
    priority: 2,
    requireInteraction: false,
    buttons: [{ title: "Close" }]
  };

  try {
    const tab = await chrome.tabs.get(tabId);
    if (tab.active) {
      await chrome.notifications.create(notificationId, notificationOptions);
      log("notification.shown", { tabId, severity, notificationId });
    }
  } catch (error) {
    warn("notification.failed", error, { tabId });
    await errorTracker.capture("notification.failed", error, { tabId });
  }
}

function isAnalyzableUrl(urlString) {
  try {
    const url = new URL(urlString);
    return url.protocol === "http:" || url.protocol === "https:";
  } catch (_error) {
    return false;
  }
}

async function getSettings() {
  const settings = await chrome.storage.sync.get(SETTINGS_DEFAULTS);
  return {
    ...SETTINGS_DEFAULTS,
    ...settings
  };
}

async function getCache() {
  const stored = await chrome.storage.local.get(CACHE_KEY);
  await storageManager.touch(CACHE_KEY);
  return stored[CACHE_KEY] || {};
}

async function setCache(cache) {
  await storageManager.safeSet(CACHE_KEY, cache);
}

async function getCachedEntry(url) {
  const cache = await getCache();
  const entry = cache[url] || null;
  if (entry) {
    entry.lastAccessedAt = now();
    cache[url] = entry;
    await setCache(cache);
  }
  return entry;
}

async function putCachedEntry(url, result) {
  const cache = await getCache();
  cache[url] = {
    result,
    storedAt: now(),
    lastAccessedAt: now()
  };
  await setCache(cache);
}

async function clearExpiredCache() {
  const cache = await getCache();
  const cutoff = now() - CACHE_TTL_MS - STALE_GRACE_MS;
  let changed = false;

  Object.entries(cache).forEach(([url, entry]) => {
    if (!entry?.storedAt || entry.storedAt < cutoff) {
      delete cache[url];
      changed = true;
    }
  });

  if (changed) {
    await setCache(cache);
  }

  log("cache.cleaned", { changed, remaining: Object.keys(cache).length });
}

function buildEmailState(rawEmail, result, source = "network", reason = "email-analysis") {
  const severity = scoreToSeverity(result.score);
  return {
    status: "ready",
    trigger: "email",
    reason,
    inputType: "email",
    rawEmail,
    result,
    severity,
    source,
    updatedAt: now()
  };
}

function normalizeMailtoToRawEmail(linkUrl) {
  try {
    const url = new URL(linkUrl);
    if (url.protocol !== "mailto:") return "";
    const to = decodeURIComponent(url.pathname || "").trim();
    const subject = url.searchParams.get("subject") || "";
    const body = url.searchParams.get("body") || "";
    const cc = url.searchParams.get("cc") || "";
    return [
      to ? `To: ${to}` : "",
      cc ? `Cc: ${cc}` : "",
      subject ? `Subject: ${subject}` : "",
      "MIME-Version: 1.0",
      "Content-Type: text/plain; charset=UTF-8",
      "",
      body
    ].filter(Boolean).join("\n");
  } catch (_error) {
    return "";
  }
}

async function setEmailAnalysisState(tabId, state) {
  await chrome.storage.session.set({ [`emailAnalysis:${tabId}`]: state });
  log("email.state.set", { tabId, status: state?.status, source: state?.source });
}

async function getEmailAnalysisState(tabId) {
  const stored = await chrome.storage.session.get(`emailAnalysis:${tabId}`);
  return stored[`emailAnalysis:${tabId}`] || null;
}

function isFresh(entry) {
  return entry && now() - entry.storedAt <= CACHE_TTL_MS;
}

function isStaleButUsable(entry) {
  if (!entry) return false;
  const age = now() - entry.storedAt;
  return age > CACHE_TTL_MS && age <= CACHE_TTL_MS + STALE_GRACE_MS;
}

async function updateBadge(tabId, result, backendOffline = false) {
  if (backendOffline) {
    await chrome.action.setBadgeBackgroundColor({ tabId, color: "#64748B" });
    await chrome.action.setBadgeText({ tabId, text: "OFF" });
    return;
  }

  const severity = scoreToSeverity(result.score);
  const badge = severityToBadge(severity);
  const scoreText = String(Math.max(0, Math.min(99, Math.round(result.score))));
  await chrome.action.setBadgeBackgroundColor({ tabId, color: badge.color });
  await chrome.action.setBadgeText({ tabId, text: severity === "safe" ? "OK" : scoreText });
}

async function clearBadge(tabId) {
  await chrome.action.setBadgeText({ tabId, text: "" });
}

async function notifyContent(tabId, payload) {
  try {
    await chrome.tabs.sendMessage(tabId, payload);
  } catch (_error) {}
}

async function setTabState(tabId, state) {
  await chrome.storage.session.set({ [`tabState:${tabId}`]: state });
}

async function getTabState(tabId) {
  const stored = await chrome.storage.session.get(`tabState:${tabId}`);
  return stored[`tabState:${tabId}`] || null;
}

/**
 * ✅ NEW CODE
 * Broadcasts theme changes to active content scripts.
 * @param {string} themePreference
 * @returns {Promise<void>}
 */
async function broadcastTheme(themePreference) {
  try {
    const tabs = await chrome.tabs.query({});
    await Promise.all(
      tabs
        .filter((tab) => typeof tab.id === "number")
        .map((tab) => notifyContent(tab.id, {
          type: "PHISHGUARD_APPLY_THEME",
          themePreference
        }))
    );
  } catch (error) {
    await errorTracker.capture("theme.broadcast_failed", error);
  }
}

/**
 * ✅ NEW CODE
 * Returns active tab or null.
 * @returns {Promise<chrome.tabs.Tab | null>}
 */
async function getActiveTab() {
  const [tab] = await chrome.tabs.query({
    active: true,
    currentWindow: true
  });

  return tab || null;
}

async function analyzeUrlWithCache(url, options = {}) {
  const entry = await getCachedEntry(url);
  if (isFresh(entry)) {
    return { result: { ...entry.result, cache_hit: true }, source: "fresh-cache" };
  }

  try {
    const result = await requestDebouncer.run("url", `url:${url}`, () =>
      analyzeWithRetry(() => checkUrl(url), {
        cacheKey: `url:${url}`,
        timeoutMs: options.timeoutMs || 12000
      })
    );
    await putCachedEntry(url, result);
    return { result, source: "network" };
  } catch (error) {
    if (isStaleButUsable(entry)) {
      return { result: { ...entry.result, cache_hit: true, stale: true }, source: "stale-cache", error };
    }
    return { error };
  }
}

async function analyzeEmail(rawEmail, tabId = null, trigger = "popup") {
  if (!rawEmail || !rawEmail.trim()) {
    throw new Error("Email content is required");
  }

  const trimmedEmail = rawEmail.trim();
  const result = await requestDebouncer.run(
    "email",
    `email:${trimmedEmail.slice(0, 512)}`,
    () => analyzeWithRetry(() => checkEmail(trimmedEmail), {
      cacheKey: `email:${trimmedEmail.slice(0, 512)}`,
      timeoutMs: 15000
    })
  );

  const state = buildEmailState(trimmedEmail, result, "network", trigger);
  if (typeof tabId === "number") {
    await setEmailAnalysisState(tabId, state);
  }
  return state;
}

function shouldProcessEvent(tabId, url, reason) {
  const dedupeKey = `${tabId}:${reason}:${url}`;
  const lastSeenAt = recentScanEvents.get(dedupeKey) || 0;
  if (now() - lastSeenAt < 400) return false;
  recentScanEvents.set(dedupeKey, now());
  return true;
}

/**
 * ✅ NEW CODE
 * Returns a stable false-positive signature.
 * @param {{ url?: string, verdict?: string, score?: number, signature?: string }} payload
 * @returns {string}
 */
function buildFalsePositiveSignature(payload = {}) {
  if (payload.signature) {
    return payload.signature;
  }

  return [
    payload.url || "",
    payload.verdict || "",
    Number(payload.score || 0)
  ].join("|");
}

/**
 * ✅ NEW CODE
 * Loads duplicate false-positive report state.
 * @returns {Promise<Record<string, { reportedAt: number, source: string }>>}
 */
async function getFalsePositiveReports() {
  const stored = await chrome.storage.local.get(FALSE_POSITIVE_KEY);
  await storageManager.touch(FALSE_POSITIVE_KEY);
  return stored[FALSE_POSITIVE_KEY] || {};
}

/**
 * ✅ NEW CODE
 * Handles an optional false-positive report without impacting scanning.
 * @param {{ url?: string, verdict?: string, score?: number, reasons?: string[], source?: string, signature?: string }} payload
 * @returns {Promise<{ ok: boolean, duplicate: boolean, signature: string }>}
 */
async function reportFalsePositive(payload = {}) {
  const signature = buildFalsePositiveSignature(payload);
  const reports = await getFalsePositiveReports();

  if (reports[signature]) {
    return {
      ok: true,
      duplicate: true,
      signature
    };
  }

  try {
    await submitFalsePositiveFeedback({
      url: payload.url || "",
      verdict: payload.verdict || "UNKNOWN",
      score: Number(payload.score || 0),
      reasons: Array.isArray(payload.reasons) ? payload.reasons : [],
      source: payload.source || "extension",
      reported_at: new Date().toISOString()
    });
  } catch (error) {
    await errorTracker.capture("false_positive.submit_failed", error, {
      signature
    });
    return {
      ok: false,
      duplicate: false,
      signature
    };
  }

  reports[signature] = {
    reportedAt: now(),
    source: payload.source || "extension"
  };
  await storageManager.safeSet(FALSE_POSITIVE_KEY, reports);

  return {
    ok: true,
    duplicate: false,
    signature
  };
}

async function processTabUrl(tabId, url, trigger = "auto", reason = "unknown") {
  if (!isAnalyzableUrl(url)) {
    await clearBadge(tabId);
    await notifyContent(tabId, { type: "PHISHGUARD_HIDE_BANNER" });
    await setTabState(tabId, { url, status: "ignored", trigger, reason, updatedAt: now() });
    return;
  }

  const settings = await getSettings();
  if (!settings.extensionEnabled) {
    await clearBadge(tabId);
    await notifyContent(tabId, { type: "PHISHGUARD_HIDE_BANNER" });
    await setTabState(tabId, { url, status: "disabled", trigger, reason, updatedAt: now() });
    return;
  }

  if (trigger === "auto" && !settings.autoScan) {
    await clearBadge(tabId);
    await notifyContent(tabId, { type: "PHISHGUARD_HIDE_BANNER" });
    await setTabState(tabId, { url, status: "disabled", trigger, reason, updatedAt: now() });
    return;
  }

  const state = { url, status: "loading", trigger, reason, updatedAt: now() };
  await setTabState(tabId, state);
  const analysis = await errorTracker.wrap(
    "url.process_failed",
    () => analyzeUrlWithCache(url),
    { tabId, url, trigger, reason }
  );

  if (analysis.error) {
    await updateBadge(tabId, null, true);
    await notifyContent(tabId, { type: "PHISHGUARD_HIDE_BANNER" });
    await setTabState(tabId, {
      ...state,
      status: "backend-offline",
      error: analysis.error.message,
      updatedAt: now()
    });
    return;
  }

  const result = analysis.result;
  const severity = scoreToSeverity(result.score);
  const nextState = {
    url,
    status: "ready",
    trigger,
    reason,
    result,
    severity,
    source: analysis.source,
    updatedAt: now()
  };
  await updateBadge(tabId, result, false);
  await setTabState(tabId, nextState);

  const bannerPayload = {
    ...result,
    severity,
    warningStyle: settings.warningStyle,
    themePreference: settings.themePreference
  };

  if (settings.warningStyle === "badge") {
    await notifyContent(tabId, { type: "PHISHGUARD_HIDE_BANNER" });
    return;
  }

  if (settings.warningStyle === "notification") {
    if (severity === "phishing" || severity === "suspicious") {
      await showNotification(tabId, result, severity);
    }
    await notifyContent(tabId, { type: "PHISHGUARD_HIDE_BANNER" });
    return;
  }

  if (severity === "phishing" || severity === "suspicious") {
    await notifyContent(tabId, {
      type: "PHISHGUARD_SHOW_RESULT",
      payload: bannerPayload
    });
  } else {
    await notifyContent(tabId, { type: "PHISHGUARD_HIDE_BANNER" });
  }
}

async function scheduleAutoScan(tabId, url, reason) {
  if (!shouldProcessEvent(tabId, url, reason)) return;
  try {
    await processTabUrl(tabId, url, "auto", reason);
  } catch (error) {
    warn("scan.schedule.failed", error, { tabId, url, reason });
    await errorTracker.capture("scan.schedule_failed", error, { tabId, url, reason });
  }
}

async function createContextMenus() {
  try {
    await chrome.contextMenus.removeAll();
  } catch (_error) {}

  try {
    await chrome.contextMenus.create({
      id: EMAIL_CONTEXT_SELECTED,
      title: "Analyze selected text as email",
      contexts: ["selection"]
    });
    await chrome.contextMenus.create({
      id: EMAIL_CONTEXT_MAILTO,
      title: "Analyze mailto link as email",
      contexts: ["link"],
      targetUrlPatterns: ["mailto:*"]
    });
  } catch (_error) {}
}

/**
 * ✅ NEW CODE
 * Toggles the extension scanning state safely.
 * @returns {Promise<{ enabled: boolean }>}
 */
async function toggleExtensionEnabled() {
  const settings = await getSettings();
  const enabled = !settings.extensionEnabled;
  await chrome.storage.sync.set({
    [EXTENSION_TOGGLE_KEY]: enabled
  });

  if (!enabled) {
    const tabs = await chrome.tabs.query({});
    await Promise.all(
      tabs
        .filter((tab) => typeof tab.id === "number")
        .map(async (tab) => {
          await clearBadge(tab.id);
          await notifyContent(tab.id, { type: "PHISHGUARD_HIDE_BANNER" });
        })
    );
  }

  return { enabled };
}

/**
 * ✅ NEW CODE
 * Handles keyboard commands without changing existing popup or navigation flows.
 * @param {string} command
 * @returns {Promise<void>}
 */
async function handleCommand(command) {
  try {
    switch (command) {
      case COMMAND_SCAN_PAGE: {
        const tab = await getActiveTab();
        if (tab?.id && tab.url) {
          await processTabUrl(tab.id, tab.url, "manual", "command.scan-page");
        }
        break;
      }

      case COMMAND_OPEN_POPUP: {
        if (typeof chrome.action.openPopup === "function") {
          await chrome.action.openPopup();
        }
        break;
      }

      case COMMAND_TOGGLE_EXTENSION: {
        const result = await toggleExtensionEnabled();
        log("extension.toggled", result);
        break;
      }

      default:
        break;
    }
  } catch (error) {
    await errorTracker.capture("command.failed", error, { command });
  }
}

chrome.runtime.onInstalled.addListener(() => {
  void (async () => {
    await chrome.storage.sync.set(await getSettings());
    await clearExpiredCache();
    await createContextMenus();
    chrome.alarms.create("phishguard-cache-cleanup", { periodInMinutes: 15 });
    chrome.alarms.create("phishguard-storage-cleanup", { periodInMinutes: 60 });
  })();
});

chrome.runtime.onStartup.addListener(() => {
  void (async () => {
    await createContextMenus();
    await storageManager.cleanupExpired([CACHE_KEY, FALSE_POSITIVE_KEY, ERROR_LOGS_KEY, "scanHistory"]);
  })();
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === "phishguard-cache-cleanup") {
    void clearExpiredCache();
  }

  if (alarm.name === "phishguard-storage-cleanup") {
    void storageManager.cleanupExpired([CACHE_KEY, FALSE_POSITIVE_KEY, ERROR_LOGS_KEY, "scanHistory"]);
  }
});

chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId !== 0 || !details.url) return;
  void scheduleAutoScan(details.tabId, details.url, "webNavigation.onCommitted");
});

chrome.webNavigation.onHistoryStateUpdated.addListener((details) => {
  if (details.frameId !== 0 || !details.url) return;
  void scheduleAutoScan(details.tabId, details.url, "webNavigation.onHistoryStateUpdated");
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.url && isAnalyzableUrl(changeInfo.url)) {
    void scheduleAutoScan(tabId, changeInfo.url, "tabs.onUpdated.url");
  } else if (changeInfo.status === "complete" && tab?.url && isAnalyzableUrl(tab.url)) {
    void scheduleAutoScan(tabId, tab.url, "tabs.onUpdated.complete");
  }
});

chrome.tabs.onActivated.addListener((activeInfo) => {
  void (async () => {
    try {
      const tab = await chrome.tabs.get(activeInfo.tabId);
      if (tab?.url && isAnalyzableUrl(tab.url)) {
        await scheduleAutoScan(activeInfo.tabId, tab.url, "tabs.onActivated");
      }
    } catch (error) {
      await errorTracker.capture("tabs.activate_failed", error, { tabId: activeInfo.tabId });
    }
  })();
});

chrome.tabs.onRemoved.addListener((tabId) => {
  void chrome.storage.session.remove([`tabState:${tabId}`, `emailAnalysis:${tabId}`]);
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
  void (async () => {
    const tabId = tab?.id;
    try {
      if (info.menuItemId === EMAIL_CONTEXT_SELECTED) {
        const rawEmail = info.selectionText?.trim() || "";
        if (!rawEmail) throw new Error("No selected text");
        await analyzeEmail(rawEmail, typeof tabId === "number" ? tabId : null, "context-menu-selection");
      } else if (info.menuItemId === EMAIL_CONTEXT_MAILTO) {
        const rawEmail = normalizeMailtoToRawEmail(info.linkUrl || "");
        if (!rawEmail) throw new Error("Invalid mailto link");
        await analyzeEmail(rawEmail, typeof tabId === "number" ? tabId : null, "context-menu-mailto");
      }
    } catch (error) {
      warn("contextMenu.analysis.failed", error);
      await errorTracker.capture("context_menu.analysis_failed", error);
      if (typeof tabId === "number") {
        await setEmailAnalysisState(tabId, {
          status: "error",
          trigger: "email",
          reason: "context-menu",
          error: error.message,
          updatedAt: now()
        });
      }
    }
  })();
});

chrome.commands?.onCommand.addListener((command) => {
  void handleCommand(command);
});

chrome.storage.onChanged.addListener((changes, areaName) => {
  if (areaName !== "sync") {
    return;
  }

  if (changes.themePreference) {
    void broadcastTheme(changes.themePreference.newValue || "system");
  }
});

globalThis.addEventListener?.("unhandledrejection", (event) => {
  void errorTracker.capture("unhandledrejection", event.reason || new Error("Unhandled rejection"));
});

globalThis.addEventListener?.("error", (event) => {
  void errorTracker.capture("service_worker.error", event.error || new Error(event.message || "Unknown service worker error"));
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  void (async () => {
    try {
      switch (message?.type) {
        case "PHISHGUARD_GET_TAB_ANALYSIS": {
          const tabId = message.tabId ?? sender.tab?.id;
          if (typeof tabId !== "number") {
            sendResponse({ ok: false, error: "No tab id provided" });
            return;
          }
          const tabState = await getTabState(tabId);
          sendResponse({ ok: true, state: tabState });
          return;
        }

        case "PHISHGUARD_ANALYZE_URL": {
          const tabId = message.tabId ?? sender.tab?.id;
          const url = message.url;
          if (typeof tabId !== "number" || !url) {
            sendResponse({ ok: false, error: "tabId and url are required" });
            return;
          }
          await processTabUrl(tabId, url, "manual", "runtime.message");
          const tabState = await getTabState(tabId);
          sendResponse({ ok: true, state: tabState });
          return;
        }

        case "PHISHGUARD_ANALYZE_EMAIL": {
          const rawEmail = message.rawEmail;
          if (!rawEmail) {
            sendResponse({ ok: false, error: "rawEmail is required" });
            return;
          }
          try {
            const state = await analyzeEmail(rawEmail, sender.tab?.id, "popup");
            sendResponse({ ok: true, result: state.result, state });
          } catch (error) {
            await errorTracker.capture("runtime.email_analysis_failed", error);
            sendResponse({ ok: false, error: error.message });
          }
          return;
        }

        case "PHISHGUARD_GET_EMAIL_ANALYSIS": {
          const tabId = message.tabId ?? sender.tab?.id;
          if (typeof tabId !== "number") {
            sendResponse({ ok: false, error: "No tab id provided" });
            return;
          }
          const state = await getEmailAnalysisState(tabId);
          sendResponse({ ok: true, state });
          return;
        }

        case "PHISHGUARD_EMAILSCAN_SUBMIT": {
          const tabId = sender.tab?.id;
          if (typeof tabId !== "number") {
            sendResponse({ ok: false, error: "No tab id available for email auto-scan" });
            return;
          }
          if (!message.rawEmail || !message.rawEmail.trim()) {
            sendResponse({ ok: false, error: "rawEmail is required" });
            return;
          }
          const state = await emailScanHandleAutoEmail(tabId, message.rawEmail, {
            source: message.source,
            pageUrl: message.pageUrl,
            reason: message.reason || "email-auto-scan"
          });
          sendResponse({ ok: true, state });
          return;
        }

        case "PHISHGUARD_REPORT_FALSE_POSITIVE": {
          const result = await reportFalsePositive(message.payload || {});
          sendResponse(result);
          return;
        }

        case "PHISHGUARD_GET_SETTINGS": {
          sendResponse({ ok: true, settings: await getSettings() });
          return;
        }

        case "PHISHGUARD_GET_HEALTH": {
          const health = await getHealth();
          sendResponse({ ok: true, health });
          return;
        }

        case "PHISHGUARD_CLEAR_CACHE": {
          await chrome.storage.local.remove(CACHE_KEY);
          sendResponse({ ok: true });
          return;
        }

        default:
          sendResponse({ ok: false, error: "Unknown message type" });
      }
    } catch (error) {
      await errorTracker.capture("runtime.message_failed", error, {
        type: message?.type
      });
      sendResponse({ ok: false, error: error.message });
    }
  })();

  return true;
});

function emailScanLog(scope, details = {}) {
  log(`email-scan.${scope}`, details);
}

function emailScanShouldShowWarning(result) {
  return result && (result.score >= 35 || result.verdict === "PHISHING" || result.verdict === "SUSPICIOUS");
}

function emailScanBuildState(rawEmail, analysisState, metadata = {}) {
  return {
    ...analysisState,
    trigger: "email-auto-scan",
    reason: metadata.reason || "email-auto-scan",
    source: metadata.source || "unknown",
    pageUrl: metadata.pageUrl || "",
    rawEmail
  };
}

async function emailScanHandleAutoEmail(tabId, rawEmail, metadata = {}) {
  emailScanLog("analyze.start", {
    tabId,
    source: metadata.source,
    reason: metadata.reason
  });

  const settings = await getSettings();
  if (!settings.extensionEnabled) {
    return {
      status: "disabled",
      trigger: "email-auto-scan",
      reason: metadata.reason || "email-auto-scan",
      updatedAt: now()
    };
  }

  const analysisState = await analyzeEmail(rawEmail, tabId, metadata.reason || "email-auto-scan");
  const nextState = emailScanBuildState(rawEmail, analysisState, metadata);

  if (typeof tabId === "number") {
    await setEmailAnalysisState(tabId, nextState);
  }

  if (emailScanShouldShowWarning(nextState.result)) {
    const severity = scoreToSeverity(nextState.result.score);

    if (settings.warningStyle === "notification") {
      await showNotification(tabId, nextState.result, severity);
    } else if (settings.warningStyle !== "badge") {
      await notifyContent(tabId, {
        type: "PHISHGUARD_SHOW_RESULT",
        payload: {
          ...nextState.result,
          severity,
          warningStyle: settings.warningStyle,
          themePreference: settings.themePreference
        }
      });
    }
  }

  emailScanLog("analyze.complete", {
    tabId,
    score: nextState.result?.score,
    verdict: nextState.result?.verdict
  });

  return nextState;
}
