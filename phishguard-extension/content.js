(function () {
  const DEBUG = true;
  const BANNER_ID = "phishguard-warning-banner";
  const THEME_STORAGE_KEY = "themePreference";
  let dismissedSignature = null;

  /**
   * ✅ NEW CODE
   * Debug logger for the content script.
   * @param {string} scope
   * @param {Record<string, unknown>} [details]
   */
  function debugLog(scope, details = {}) {
    if (!DEBUG) {
      return;
    }

    console.log(`[PhishGuard][content] ${scope}`, details);
  }

  /**
   * ✅ NEW CODE
   * Returns the effective theme for banners and injected UI.
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
   * Applies content banner theme using a lightweight data attribute.
   * @param {string} [preference]
   */
  function applyBannerTheme(preference) {
    try {
      const banner = document.getElementById(BANNER_ID);
      if (!banner) {
        return;
      }

      banner.dataset.theme = resolveTheme(preference);
    } catch (error) {
      debugLog("theme.apply_failed", {
        message: error?.message || String(error)
      });
    }
  }

  /**
   * ✅ NEW CODE
   * Loads the saved theme for the injected banner.
   * @returns {Promise<void>}
   */
  async function loadBannerTheme() {
    try {
      const stored = await chrome.storage.sync.get({
        [THEME_STORAGE_KEY]: "system"
      });

      applyBannerTheme(stored.themePreference);
    } catch (error) {
      debugLog("theme.load_failed", {
        message: error?.message || String(error)
      });
      applyBannerTheme("system");
    }
  }

  /**
   * ✅ NEW CODE
   * Watches system theme changes when the user preference is set to system.
   */
  function watchSystemTheme() {
    const media = window.matchMedia?.("(prefers-color-scheme: dark)");
    if (!media) {
      return;
    }

    const applyIfSystem = async () => {
      try {
        const stored = await chrome.storage.sync.get({
          [THEME_STORAGE_KEY]: "system"
        });

        if (stored.themePreference === "system") {
          applyBannerTheme("system");
        }
      } catch (_error) {
        applyBannerTheme("system");
      }
    };

    if (typeof media.addEventListener === "function") {
      media.addEventListener("change", applyIfSystem);
    } else if (typeof media.addListener === "function") {
      media.addListener(applyIfSystem);
    }
  }

  function ensureBanner() {
    let banner = document.getElementById(BANNER_ID);
    if (banner) {
      return banner;
    }

    banner = document.createElement("div");
    banner.id = BANNER_ID;
    banner.hidden = true;
    banner.innerHTML = [
      '<div class="phishguard-banner__content">',
      '  <div class="phishguard-banner__summary">',
      '    <div class="phishguard-banner__eyebrow">PhishGuard warning</div>',
      '    <div class="phishguard-banner__title"></div>',
      '    <div class="phishguard-banner__meta"></div>',
      "  </div>",
      '  <div class="phishguard-banner__actions">',
      '    <a class="phishguard-banner__report" href="#" target="_blank" rel="noreferrer">Report false positive</a>',
      '    <button type="button" class="phishguard-banner__safe" hidden>This is safe</button>',
      '    <button type="button" class="phishguard-banner__close" aria-label="Close warning">&times;</button>',
      "  </div>",
      "</div>"
    ].join("");

    banner.querySelector(".phishguard-banner__close").addEventListener("click", () => {
      dismissedSignature = banner.dataset.signature || null;
      hideBanner();
    });

    banner.querySelector(".phishguard-banner__report").addEventListener("click", (event) => {
      event.preventDefault();
      void reportFalsePositive("content-link");
    });

    banner.querySelector(".phishguard-banner__safe").addEventListener("click", async () => {
      const button = banner.querySelector(".phishguard-banner__safe");
      button.disabled = true;

      try {
        const response = await reportFalsePositive("content-banner");
        if (response?.ok) {
          button.textContent = response.duplicate ? "Already reported" : "Thanks for the report";
        } else {
          button.textContent = "Report unavailable";
        }
      } catch (_error) {
        button.textContent = "Report unavailable";
      } finally {
        window.setTimeout(() => {
          button.disabled = false;
        }, 1200);
      }
    });

    document.documentElement.appendChild(banner);
    void loadBannerTheme();
    return banner;
  }

  function hideBanner() {
    const banner = ensureBanner();
    banner.hidden = true;
  }

  /**
   * ✅ NEW CODE
   * Sends a false-positive report request to the background service worker.
   * @param {string} source
   * @returns {Promise<Record<string, unknown> | null>}
   */
  async function reportFalsePositive(source) {
    const banner = ensureBanner();

    try {
      const response = await chrome.runtime.sendMessage({
        type: "PHISHGUARD_REPORT_FALSE_POSITIVE",
        payload: {
          source,
          url: window.location.href,
          verdict: banner.dataset.verdict || "Unknown",
          score: Number(banner.dataset.score || 0),
          reasons: banner.dataset.reasons ? JSON.parse(banner.dataset.reasons) : [],
          signature: banner.dataset.signature || ""
        }
      });

      debugLog("false_positive.submitted", {
        source,
        ok: response?.ok,
        duplicate: response?.duplicate
      });

      return response || null;
    } catch (error) {
      debugLog("false_positive.failed", {
        source,
        message: error?.message || String(error)
      });
      return null;
    }
  }

  function showBanner(payload) {
    if (!payload || (payload.severity !== "phishing" && payload.severity !== "suspicious")) {
      hideBanner();
      return;
    }

    if (payload.warningStyle === "notification") {
      hideBanner();
      return;
    }

    const signature = `${window.location.href}:${payload.score}:${payload.verdict}`;
    if (dismissedSignature === signature) {
      return;
    }

    const banner = ensureBanner();
    const title = banner.querySelector(".phishguard-banner__title");
    const meta = banner.querySelector(".phishguard-banner__meta");
    const safeButton = banner.querySelector(".phishguard-banner__safe");

    banner.dataset.signature = signature;
    banner.dataset.verdict = payload.verdict || "Unknown";
    banner.dataset.score = String(payload.score || 0);
    banner.dataset.reasons = JSON.stringify(Array.isArray(payload.reasons) ? payload.reasons : []);

    banner.classList.toggle("phishguard-banner--toast", payload.warningStyle === "toast");
    banner.classList.toggle("phishguard-banner--danger", payload.severity === "phishing");
    banner.classList.toggle("phishguard-banner--warning", payload.severity === "suspicious");

    title.textContent =
      payload.severity === "phishing"
        ? "Potential phishing site detected"
        : "This page looks suspicious";

    meta.textContent = `${payload.verdict} • Score ${payload.score}`;
    safeButton.hidden = payload.severity !== "phishing";
    safeButton.textContent = "This is safe";
    safeButton.disabled = false;
    banner.hidden = false;
    applyBannerTheme(payload.themePreference);
  }

  chrome.runtime.onMessage.addListener((message) => {
    if (message?.type === "PHISHGUARD_SHOW_RESULT") {
      showBanner(message.payload);
    }
    if (message?.type === "PHISHGUARD_HIDE_BANNER") {
      hideBanner();
    }
    if (message?.type === "PHISHGUARD_APPLY_THEME") {
      applyBannerTheme(message.themePreference);
    }
  });

  function emailScanLog(scope, details = {}) {
    debugLog(`email-scan.${scope}`, details);
  }

  function emailScanIsSupportedHost() {
    return [
      "mail.google.com",
      "outlook.live.com",
      "outlook.office.com",
      "outlook.office365.com"
    ].includes(window.location.hostname);
  }

  function emailScanGetText(selectorList, root = document) {
    for (const selector of selectorList) {
      const element = root.querySelector(selector);
      const text = element?.textContent?.trim();
      if (text) {
        return text;
      }
    }
    return "";
  }

  /**
   * ✅ NEW CODE
   * Extracts a Gmail sender value while preserving the current selector order first.
   * @param {ParentNode} [root]
   * @returns {string}
   */
  function extractEmailFromGmail(root = document) {
    const selectors = [
      ".gD[email]",
      "span[email].gD",
      ".go span[email]",
      ".gF .gD",
      '[name="from"]',
      "[data-hovercard-id]"
    ];

    for (const selector of selectors) {
      const element = root.querySelector(selector);
      if (!element) {
        continue;
      }

      const value =
        element.getAttribute?.("email") ||
        element.getAttribute?.("data-hovercard-id") ||
        element.value ||
        element.textContent?.trim() ||
        "";

      if (value) {
        return value.trim();
      }
    }

    return "";
  }

  /**
   * ✅ NEW CODE
   * Extracts the Gmail body from existing selectors first, then safe fallbacks.
   * @param {ParentNode} [root]
   * @returns {string}
   */
  function extractGmailBodyWithFallbacks(root = document) {
    const selectors = [
      ".a3s.aiL",
      ".a3s",
      "div[data-message-id] .ii.gt",
      'div[role="listitem"] .ii.gt',
      'div[data-message-id] div[dir="auto"]',
      'div[data-message-id] div[dir="ltr"]',
      ".ii.gt div[dir]",
      ".adn.ads"
    ];

    return emailScanGetText(selectors, root);
  }

  function emailScanExtractGmail() {
    const subject = emailScanGetText([
      "h2[data-thread-perm-id]",
      "h2.hP",
      "h2[data-legacy-thread-id]"
    ]);
    const from = extractEmailFromGmail(document);
    const body = extractGmailBodyWithFallbacks(document);

    if (!subject && !from && !body) {
      return null;
    }

    return {
      provider: "gmail",
      subject,
      from,
      body
    };
  }

  function emailScanExtractOutlook() {
    const subject = emailScanGetText([
      '[role="main"] [role="heading"]',
      '[data-app-section="MailReadCompose"] [role="heading"]',
      '[aria-label="Reading Pane"] [role="heading"]'
    ]);
    const from = emailScanGetText([
      '[aria-label^="From"] span',
      '[title][data-testid="sender"]',
      '[data-testid="messageHeader"] [email]'
    ]);
    const body = emailScanGetText([
      '[aria-label*="Message body"]',
      '[data-app-section="MailReadCompose"] div[dir="ltr"]',
      '[role="document"]'
    ]);

    if (!subject && !from && !body) {
      return null;
    }

    return {
      provider: "outlook",
      subject,
      from,
      body
    };
  }

  function emailScanBuildRawEmail(extracted) {
    if (!extracted) {
      return "";
    }

    return [
      extracted.from ? `From: ${extracted.from}` : "",
      "To: Me",
      extracted.subject ? `Subject: ${extracted.subject}` : "",
      "MIME-Version: 1.0",
      "Content-Type: text/plain; charset=UTF-8",
      "",
      extracted.body || ""
    ]
      .filter(Boolean)
      .join("\n");
  }

  function emailScanExtractCurrentEmail() {
    if (!emailScanIsSupportedHost()) {
      return null;
    }

    if (window.location.hostname === "mail.google.com") {
      return emailScanExtractGmail();
    }

    return emailScanExtractOutlook();
  }

  let emailScanLastSignature = "";
  let emailScanLastRunAt = 0;
  let emailScanDebounceTimer = null;

  function emailScanScheduleScan(reason) {
    if (!emailScanIsSupportedHost()) {
      return;
    }

    window.clearTimeout(emailScanDebounceTimer);
    emailScanDebounceTimer = window.setTimeout(async () => {
      const extracted = emailScanExtractCurrentEmail();
      const rawEmail = emailScanBuildRawEmail(extracted);

      if (!rawEmail.trim()) {
        return;
      }

      const signature = `${window.location.href}|${extracted.provider}|${extracted.subject}|${extracted.from}|${(extracted.body || "").slice(0, 500)}`;
      if (signature === emailScanLastSignature && Date.now() - emailScanLastRunAt < 5000) {
        return;
      }

      emailScanLastSignature = signature;
      emailScanLastRunAt = Date.now();
      emailScanLog("scan.submit", {
        reason,
        provider: extracted.provider,
        subject: extracted.subject
      });

      try {
        await chrome.runtime.sendMessage({
          type: "PHISHGUARD_EMAILSCAN_SUBMIT",
          rawEmail,
          source: extracted.provider,
          pageUrl: window.location.href,
          reason
        });
      } catch (error) {
        emailScanLog("scan.submit_failed", {
          reason,
          message: error?.message || String(error)
        });
      }
    }, 900);
  }

  function initEmailScanner() {
    if (!emailScanIsSupportedHost()) {
      return;
    }

    emailScanLog("init", {
      host: window.location.hostname
    });

    emailScanScheduleScan("initial");

    const observer = new MutationObserver(() => {
      emailScanScheduleScan("mutation");
    });

    observer.observe(document.documentElement, {
      childList: true,
      subtree: true
    });

    window.addEventListener("popstate", () => emailScanScheduleScan("popstate"));
    window.addEventListener("hashchange", () => emailScanScheduleScan("hashchange"));
    document.addEventListener("click", () => emailScanScheduleScan("click"), true);
  }

  void loadBannerTheme();
  watchSystemTheme();
  initEmailScanner();
})();
