const DEFAULT_BACKEND_URL = "http://localhost:8000";
const RETRY_DELAYS_MS = [1000, 2000, 4000];

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function getStoredSettings() {
  if (!chrome?.storage?.sync) {
    return {};
  }

  return chrome.storage.sync.get({
    backendUrl: DEFAULT_BACKEND_URL
  });
}

export async function getBackendUrl() {
  const settings = await getStoredSettings();
  return (settings.backendUrl || DEFAULT_BACKEND_URL).replace(/\/+$/, "");
}

async function requestJson(path, body, method = body ? "POST" : "GET") {
  const baseUrl = await getBackendUrl();
  let lastError;

  for (let attempt = 0; attempt < RETRY_DELAYS_MS.length; attempt += 1) {
    try {
      const response = await fetch(`${baseUrl}${path}`, {
        method,
        headers: {
          "Content-Type": "application/json"
        },
        body: body ? JSON.stringify(body) : undefined
      });

      if (response.ok) {
        return await response.json();
      }

      const text = await response.text();
      const error = new Error(text || `Request failed with status ${response.status}`);
      error.status = response.status;
      throw error;
    } catch (error) {
      lastError = error;
      if (attempt === RETRY_DELAYS_MS.length - 1) {
        break;
      }
      await sleep(RETRY_DELAYS_MS[attempt]);
    }
  }

  throw lastError;
}

function normalizeResult(result) {
  return {
    score: Number(result?.score ?? 0),
    verdict: String(result?.verdict ?? "UNKNOWN"),
    flags: Array.isArray(result?.flags) ? result.flags : [],
    reasons: Array.isArray(result?.reasons) ? result.reasons : [],
    analyzed_at: result?.analyzed_at || new Date().toISOString(),
    cache_hit: Boolean(result?.cache_hit),
    duration_ms: Number(result?.duration_ms ?? 0),
    input_type: result?.input_type || "url"
  };
}

export async function checkUrl(url) {
  const result = await requestJson("/analyze/url", { url });
  return normalizeResult(result);
}

export async function checkEmail(rawEmail) {
  const result = await requestJson("/analyze/email", { raw_email: rawEmail });
  return normalizeResult(result);
}

export async function getHealth() {
  return requestJson("/health");
}

/**
 * ✅ NEW CODE
 * Optional false-positive feedback endpoint.
 * @param {Record<string, unknown>} payload
 * @returns {Promise<Record<string, unknown>>}
 */
export async function submitFalsePositiveFeedback(payload) {
  return requestJson("/api/feedback/false-positive", payload, "POST");
}
