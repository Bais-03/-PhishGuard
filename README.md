# PhishGuard 🛡️

**Real-time phishing and email threat detection — directly in your browser.**

PhishGuard is a Manifest V3 Chrome extension that silently analyzes every page you visit and every email you open, scoring them for phishing risk and surfacing warnings before you interact with anything dangerous. It connects to a FastAPI backend for ML-powered analysis, and is engineered for resilience: stale caching, exponential-backoff retries, request deduplication, and LRU storage eviction keep it working even when the backend is unreachable.

---

## Key Highlights

- **Dual-surface threat detection** — Analyzes both URLs and raw email content (RFC 2822) through separate, purpose-built pipelines.
- **Automatic Gmail & Outlook scanning** — A MutationObserver-powered content scanner extracts sender, subject, and body from open emails and submits them for analysis without any user action.
- **Four warning styles** — Full-page banner, corner toast, native desktop notification, or badge-only — all user-configurable.
- **Production-grade retry layer** — Three-attempt exponential backoff (1 s → 2 s → 4 s) with a 12-second timeout guard and a 30-second failure cache that prevents retry storms.
- **Smart two-tier caching** — Results are served from a fresh 1-hour cache; stale results (up to 5 minutes past TTL) are used as a fallback when the backend is offline.
- **False-positive feedback loop** — Users can report incorrect verdicts from the banner or popup, with per-report deduplication stored locally and forwarded to the backend.
- **LRU storage management** — A `StorageManager` class tracks last-accessed timestamps and evicts least-recently-used entries to stay within Chrome's 4.5 MB local storage cap.
- **Keyboard-first controls** — Three keyboard shortcuts for scanning the active page, toggling the extension, and opening the popup — all configurable via the manifest.

---

## Project Overview

### The Problem

Phishing attacks consistently exploit the gap between what a URL or email looks like and what it actually does. Browser-native warnings catch only a fraction of threats, and most users have no way to interrogate a suspicious page or email without copying links into external tools.

### The Solution

PhishGuard embeds a threat-analysis client directly into the browser. It monitors every top-level navigation and every email opened in Gmail or Outlook, forwards the content to a FastAPI backend for scoring, and renders the result inline — as a banner, toast, notification, or badge — without requiring the user to take any action. For pages that can't be automatically scanned (e.g., pages navigated to via history state), the popup provides a manual scan interface for both URLs and raw email content.

### Why It Matters

Phishing is primarily a context problem: attackers win when users don't have enough information at the moment of decision. PhishGuard surfaces that information at exactly the right time, in the right place, with enough detail (verdict, score, and top reasons) to make an informed choice.

---

## Features

### Automatic URL Scanning

**What it does:** Every top-level HTTP/HTTPS navigation — whether via a standard page load, history state update, or tab switch — is automatically submitted for analysis.

**How it works:** Three Chrome event listeners (`webNavigation.onCommitted`, `webNavigation.onHistoryStateUpdated`, and `tabs.onUpdated`) feed into a `scheduleAutoScan` function. A per-tab deduplication guard (`shouldProcessEvent`) enforces a 400 ms minimum window between duplicate events for the same URL and reason code, preventing redundant API calls on SPAs that fire multiple navigation events per route change. Auto-scanning is gated on the `autoScan` setting and the global `extensionEnabled` toggle.

**Why it matters:** Users don't have to think about scanning — protection is passive and continuous.

---

### Email Analysis — Gmail & Outlook (Auto-Scan)

**What it does:** When the user opens an email in Gmail or Outlook (including Outlook 365 and Outlook Live), the extension extracts the sender, subject, and body and submits them as a synthetic RFC 2822 message for phishing analysis. This happens automatically with no user interaction.

**How it works:** `content.js` initializes `initEmailScanner()` on supported hostnames (`mail.google.com`, `outlook.live.com`, `outlook.office.com`, `outlook.office365.com`). A `MutationObserver` watches the document root for DOM changes, and also listens to `popstate`, `hashchange`, and `click` events — all of which can indicate that a new email has been opened in these SPAs. Scans are debounced to 900 ms. A per-session signature (`url|provider|subject|from|body[:500]`) prevents re-scanning the same email within 5 seconds.

Extraction uses provider-specific selector chains:
- **Gmail:** `.gD[email]`, `.a3s.aiL`, `h2.hP` and several fallback selectors
- **Outlook:** `[role="main"] [role="heading"]`, `[aria-label*="Message body"]`, and similar accessible attributes

The extracted fields are assembled into a minimal RFC 2822 string and sent to the background service worker via `chrome.runtime.sendMessage`.

**Why it matters:** Email is the primary phishing vector. Scanning emails in-context, automatically, closes the gap between receiving a message and acting on it.

---

### Manual URL & Email Analysis (Popup)

**What it does:** The popup exposes a dual-tab interface — one for URL scanning and one for raw email analysis — so users can analyze any content on demand.

**How it works:** The URL tab pre-fills with the current tab's URL and accepts any HTTP/HTTPS URL for manual submission. The email tab accepts pasted RFC 2822 email content and forwards it to the background service worker for analysis. Both tabs render a score ring, verdict label, and up to three detection reasons. Results are immediately saved to the relevant scan history.

**Why it matters:** Gives power users a direct interface to the analysis engine, useful for inspecting forwarded emails or suspicious links found outside the browser.

---

### Scoring & Verdict System

**What it does:** Every analysis result carries a numeric risk score (0–100) and a categorical verdict used to drive the severity of warnings.

**How it works:** The `scoreToSeverity` function in `background.js` applies two thresholds:

| Score Range | Severity    | Badge Color | Banner Style      |
|-------------|-------------|-------------|-------------------|
| 0 – 34      | Safe        | `#22C55E`   | Hidden            |
| 35 – 59     | Suspicious  | `#F59E0B`   | Yellow warning    |
| 60 – 100    | Phishing    | `#EF4444`   | Red danger banner |

The backend returns a `verdict` string (e.g., `PHISHING`, `SUSPICIOUS`, `LIKELY_SAFE`), a `score`, an array of `reasons`, and metadata including `analyzed_at`, `cache_hit`, `duration_ms`, and `input_type`.

**Why it matters:** A single numeric score gives users an immediately graspable risk signal without requiring them to interpret technical details.

---

### Warning Styles

**What it does:** Users can choose how — and how intrusively — warnings are presented.

**How it works:** The `warningStyle` setting is forwarded to the content script alongside every analysis result. The content script (`content.js`) and background service worker (`background.js`) jointly enforce the selected style:

| Style          | Description                                                                 |
|----------------|-----------------------------------------------------------------------------|
| `banner`       | Full-width fixed banner injected at `z-index: 2147483647` at the top of the page. Turns red for phishing, amber for suspicious. |
| `toast`        | Same banner element, repositioned to the top-right corner as a rounded card (max 420 px wide, responsive on mobile). |
| `notification` | Native Chrome desktop notification with verdict, score, and first reason. Only shown on active tabs. |
| `badge`        | Extension icon badge only — no in-page UI. Green `OK`, amber score number, or red score number. |

**Why it matters:** Different users and contexts require different interruption levels. A security researcher wants full details; a casual user may only want a subtle badge.

---

### False-Positive Reporting

**What it does:** Users can flag incorrect phishing verdicts from both the in-page banner and the popup, sending structured feedback to the backend.

**How it works:** Each report is identified by a stable signature derived from the URL, verdict, and score. Before submitting, the background service worker checks `chrome.storage.local` for an existing report with the same signature — duplicate submissions are blocked and the user is shown an "Already reported" response. On a first report, the payload (`url`, `verdict`, `score`, `reasons`, `source`, `reported_at`) is POSTed to `/api/feedback/false-positive`. The report is then persisted locally regardless of the API response to prevent retry spam.

The banner's "This is safe" button is shown exclusively for `phishing`-severity results. The popup's "✅ This looks safe" button appears only when the current URL score is ≥ 60.

**Why it matters:** A feedback loop improves backend model accuracy over time and builds user trust by giving them recourse when a verdict is wrong.

---

### Scan History

**What it does:** The popup maintains separate, type-segmented scan histories for URLs and emails, displayed as interactive cards.

**How it works:** Results are written to `chrome.storage.local` under a `scanHistory` key. The `ScanHistory` class deduplicates by a compound key (`type|url-or-subject|verdict|score`) and caps storage at 20 entries. The UI renders up to 10 entries per type, each as a card showing the risk badge, verdict, score, a truncated target, and a relative timestamp ("Just now", "3 min ago", "2 hours ago"). Cards are clickable — clicking a URL card re-runs the scan for that URL; clicking an email card loads the raw content back into the email input and re-analyzes it.

**Why it matters:** Users can audit recent scans and quickly re-examine a previously flagged URL or email without re-navigating to it.

---

### Domain Whitelist

**What it does:** Users can add domains to a persistent whitelist, bypassing all scanning for those domains.

**How it works:** Domains are normalized on entry: scheme stripped, path stripped, leading `*.` stripped, and lowercased. Matching at runtime checks both exact hostname equality and subdomain suffix matching (`hostname.endsWith('.domain')`). The whitelist is stored in `chrome.storage.sync` (synced across devices) and is editable from the options page with add/remove controls and a JSON import/export path.

**Why it matters:** Eliminates false-positive noise for trusted internal or personal domains without disabling the extension globally.

---

### Settings — Import / Export

**What it does:** All settings (including the whitelist) can be exported as JSON and re-imported, allowing backup, sharing, or programmatic configuration.

**How it works:** `options.js` serializes the full `chrome.storage.sync` object to a textarea. Import validates and sanitizes each field before writing — `warningStyle` must be one of the four known values, `themePreference` must be `system`/`light`/`dark`, and `backendUrl` must be a non-empty string. The whitelist has its own separate export/import path that operates independently of the full settings blob.

---

### Theming

**What it does:** The extension UI (popup, options page, and in-page banner) supports light, dark, and system-matched themes.

**How it works:** The `themePreference` setting is stored in `chrome.storage.sync`. When it changes, `background.js` broadcasts a `PHISHGUARD_APPLY_THEME` message to all open tabs via `chrome.tabs.query`. The content script applies the resolved theme to the banner via a `data-theme` attribute, which triggers CSS variable overrides defined in `warning.css`. The options page and popup resolve the system theme using `window.matchMedia('(prefers-color-scheme: dark)')` and re-apply on media change events.

---

### Keyboard Shortcuts

Three global keyboard shortcuts are registered in `manifest.json`:

| Shortcut (Default) | Mac Equivalent | Action                          |
|--------------------|----------------|---------------------------------|
| `Ctrl+Shift+S`     | `Cmd+Shift+S`  | Scan the active tab immediately |
| `Ctrl+Shift+P`     | `Cmd+Shift+P`  | Open the extension popup        |
| `Ctrl+Shift+O`     | `Cmd+Shift+O`  | Toggle the extension on/off     |

---

### Context Menu Integration

**What it does:** Right-clicking on selected text or a `mailto:` link exposes two context menu actions for on-demand email analysis.

**How it works:** On install and startup, `createContextMenus()` registers two items: "Analyze selected text as email" (shown on text selections) and "Analyze mailto link as email" (shown on `mailto:` links). Selected text is submitted directly as raw email content. `mailto:` links are parsed via the `URL` API — `to`, `subject`, `body`, and `cc` parameters are extracted and assembled into an RFC 2822 string before analysis.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        Chrome Extension                         │
│                                                                 │
│  ┌─────────────┐    messages     ┌──────────────────────────┐  │
│  │  content.js │◄───────────────►│      background.js       │  │
│  │             │                 │   (Service Worker MV3)   │  │
│  │ • Banner UI │                 │                          │  │
│  │ • Email DOM │                 │ • analyzeUrlWithCache()  │  │
│  │   scraper   │                 │ • analyzeEmail()         │  │
│  │ • Theme     │                 │ • StorageManager (LRU)   │  │
│  │   watcher   │                 │ • RequestDebouncer       │  │
│  └─────────────┘                 │ • ErrorTracker           │  │
│                                  │ • analyzeWithRetry()     │  │
│  ┌─────────────┐                 │ • reportFalsePositive()  │  │
│  │  popup.js   │◄───────────────►│ • Badge / Notification   │  │
│  │             │                 │ • Context Menus          │  │
│  │ • URL tab   │                 │ • Keyboard Commands      │  │
│  │ • Email tab │                 └──────────┬───────────────┘  │
│  │ • History   │                            │                  │
│  │ • FP report │                            │ HTTP (fetch)     │
│  └─────────────┘                            │                  │
│                                             │                  │
│  ┌─────────────┐                            │                  │
│  │ options.js  │  chrome.storage.sync        │                  │
│  │             │  (settings, whitelist)      │                  │
│  │ • Settings  │                            │                  │
│  │ • Whitelist │                            │                  │
│  │ • Import /  │                            │                  │
│  │   Export    │                            │                  │
│  └─────────────┘                            │                  │
└─────────────────────────────────────────────┼─────────────────┘
                                              │
                              ┌───────────────▼──────────────┐
                              │       FastAPI Backend         │
                              │    (http://localhost:8000)    │
                              │                              │
                              │  POST /analyze/url           │
                              │  POST /analyze/email         │
                              │  GET  /health                │
                              │  POST /api/feedback/         │
                              │       false-positive         │
                              └──────────────────────────────┘
```

**Storage layers:**

| Layer                       | Contents                                          | Scope  |
|-----------------------------|---------------------------------------------------|--------|
| `chrome.storage.sync`       | Settings, whitelist domains                       | Synced |
| `chrome.storage.local`      | Analysis cache, scan history, false-positive log  | Local  |
| `chrome.storage.session`    | Per-tab URL state, per-tab email analysis state   | Session|
| In-memory (`Map`)           | Dedup event log, temporary failure cache          | Runtime|

---

## Core Technical Deep Dive

### Retry & Resilience Layer (`analyzeWithRetry`)

The `analyzeWithRetry` wrapper in `background.js` provides three tiers of resilience:

1. **Temporary failure cache** — If a request to a given cache key (e.g., `url:https://example.com`) has recently failed with a retryable error, a 30-second in-memory block prevents further attempts for that key. This avoids hammering an offline backend on every navigation.

2. **Timeout guard** — Each attempt is raced against a `Promise`-based timeout (default 12 s for URLs, 15 s for emails). The timeout error sets `isTimeout: true`, which `isRetryableError` recognizes as a retryable condition.

3. **Exponential backoff** — On retryable failures, the wrapper sleeps for 1 s, 2 s, then 4 s between attempts. Non-retryable errors (e.g., HTTP 4xx) fail immediately without retrying.

### Caching Strategy

```
Navigation → getCachedEntry(url)
                 │
          ┌──────┴──────┐
        Fresh?         Stale (within grace)?
       (< 1 hr)        (1 hr – 65 min)
          │                   │
    Return cache         Backend offline?
    (cache_hit: true)    ├── Yes → return stale (stale: true)
                         └── No  → fetch fresh, update cache
```

Cache entries store `storedAt` and `lastAccessedAt` timestamps. The `StorageManager` runs a cleanup alarm every 15 minutes to remove entries older than `TTL + STALE_GRACE_MS`, and an LRU eviction alarm every 60 minutes to shed entries when storage exceeds 4.5 MB.

### Request Deduplication (`RequestDebouncer`)

The `RequestDebouncer` class maintains a `Map` of pending promises keyed by request type and target. If a second request arrives for the same key within the TTL window (2 s for URLs, 5 s for emails), it receives the same `Promise` rather than spawning a new HTTP request. This prevents redundant parallel requests that can occur when multiple navigation events fire in rapid succession for the same URL.

### Storage Management (`StorageManager`)

`StorageManager` wraps `chrome.storage.local` with three capabilities:

- **`cleanupExpired`** — Iterates all tracked keys; for array values it filters by item timestamp, for object values it deletes stale entries by timestamp field.
- **`evictLRU`** — Queries `getBytesInUse()` and sorts tracked keys by `lastAccessedAt` ascending, evicting entries until storage is below 4.5 MB.
- **`safeSet`** — Runs `cleanupExpired` before every write, then updates the metadata index, then calls `evictLRU` after the write.

### Error Tracking (`ErrorTracker`)

All background errors are captured by the `ErrorTracker` class, which stores up to 50 log entries in `chrome.storage.local` with scope, message, stack trace, details, and ISO timestamp. If a reporting endpoint path is configured, entries are also POSTed asynchronously (fire-and-forget, swallowed on failure). Unhandled promise rejections and uncaught service worker errors are captured via global `unhandledrejection` and `error` listeners.

### API Client (`utils/api.js`)

The API client exports four functions: `checkUrl`, `checkEmail`, `getHealth`, and `submitFalsePositiveFeedback`. All requests read `backendUrl` from `chrome.storage.sync` at call time, ensuring the setting change takes effect immediately without reloading. All responses are passed through `normalizeResult`, which coerces types and provides defaults for every field, preventing null-reference errors in consuming code regardless of partial backend responses.

---

## Chrome Extension Components

### `background.js` — Service Worker

The central orchestrator. Implements all scanning logic, caching, notification dispatch, badge updates, context menus, keyboard commands, and the runtime message router.

Key message types handled:

| Message Type                       | Handler                        |
|------------------------------------|--------------------------------|
| `PHISHGUARD_GET_TAB_ANALYSIS`      | Returns tab state from session storage |
| `PHISHGUARD_ANALYZE_URL`           | Triggers manual URL analysis   |
| `PHISHGUARD_ANALYZE_EMAIL`         | Triggers manual email analysis |
| `PHISHGUARD_GET_EMAIL_ANALYSIS`    | Returns email state from session storage |
| `PHISHGUARD_EMAILSCAN_SUBMIT`      | Handles auto-scan email submission from content script |
| `PHISHGUARD_REPORT_FALSE_POSITIVE` | Deduplicates and forwards false-positive report |
| `PHISHGUARD_GET_SETTINGS`          | Returns current settings       |
| `PHISHGUARD_GET_HEALTH`            | Proxies `/health` to popup     |
| `PHISHGUARD_CLEAR_CACHE`           | Removes analysis cache key     |

### `content.js` — In-Page Script

Runs at `document_idle` on all HTTP/HTTPS pages. Responsibilities:

- **Banner lifecycle** — `ensureBanner()` lazily creates the banner DOM element once and returns it on subsequent calls. The banner is hidden by default and shown/hidden via `showBanner` / `hideBanner` in response to background messages.
- **Dismiss state** — A per-session `dismissedSignature` variable prevents a dismissed banner from re-appearing for the same URL/score/verdict combination.
- **Email auto-scan** — `initEmailScanner()` detects supported email clients and wires up the `MutationObserver`, navigation event listeners, and the 900 ms debounced scan scheduler.
- **Theme** — Loads the saved theme preference on init, watches `prefers-color-scheme` media changes, and responds to `PHISHGUARD_APPLY_THEME` messages from the background.

### `popup.js` — Extension Popup

Dual-tab UI (URL / Email) with:
- Score ring with CSS-variable-driven arc for the current risk score
- Top-3 detection reasons list
- Auto-scan toggle (writes directly to `chrome.storage.sync`)
- Backend health check link
- Separate, collapsible scan history panels for URLs and emails
- False-positive report button (shown only for phishing-severity URL results)

### `options.js` — Settings Page

Full settings management with:
- Auto-scan toggle, warning style selector, theme selector, backend URL input
- Whitelist domain manager (add / remove / normalize)
- Full settings JSON export / import with per-field validation
- Separate whitelist JSON export / import
- Cache clear (forwarded to background via `PHISHGUARD_CLEAR_CACHE`)
- Live theme preview (applies immediately on dropdown change)

### `utils/api.js` — Backend Client

Stateless HTTP client. Reads backend URL from storage on every call. Implements three-attempt retry with exponential backoff for all requests. Normalizes all responses through a single `normalizeResult` function.

### `warning.css` — Banner Stylesheet

Fully scoped to `#phishguard-warning-banner` to prevent style leakage. Uses CSS custom properties for all colors, enabling theme switching via a single `data-theme` attribute. The toast variant is implemented with a CSS class modifier (`phishguard-banner--toast`) that repositions the element and applies border-radius. Includes a responsive breakpoint at 600 px.

---

## Setup & Installation

### Prerequisites

- Google Chrome 109+ (Manifest V3 service worker support)
- The PhishGuard FastAPI backend running and accessible

### Extension Installation

1. Clone or download this repository.
2. Open `chrome://extensions` in Chrome.
3. Enable **Developer mode** (toggle in the top-right corner).
4. Click **Load unpacked**.
5. Select the root directory of this repository (the folder containing `manifest.json`).
6. The PhishGuard icon will appear in the Chrome toolbar.

### Backend Configuration

By default, the extension expects the backend at `http://localhost:8000`. To change this:

1. Click the PhishGuard icon → the popup opens.
2. Navigate to the options page via the gear icon, or go to `chrome://extensions` → PhishGuard → **Details** → **Extension options**.
3. Update the **Backend URL** field and click **Save settings**.

### First Run

Once installed and the backend is running:

1. Navigate to any HTTP/HTTPS URL — the extension will scan it automatically if **Automatic scanning** is enabled (the default).
2. Open Gmail or Outlook and click on any email — it will be scanned automatically.
3. The extension badge will show `OK` (green), a score number (amber/red), or `OFF` (grey, if the backend is unreachable).

---

## Screenshots

| Popup — URL Scan | Popup — Email Scan | In-Page Banner |
|---|---|---|
| ![URL Scan](./assets/popup-url.png) | ![Email Scan](./assets/popup-email.png) | ![Banner](./assets/banner.png) |

| Options Page | Toast Warning | Scan History |
|---|---|---|
| ![Options](./assets/options.png) | ![Toast](./assets/toast.png) | ![History](./assets/history.png) |

---

## Security & Privacy

**Data transmission:** The extension sends URL strings and email content (sender, subject, body) to the configured backend URL. By default this is `http://localhost:8000` — a local server that never transmits data externally. Users connecting to a remote backend should ensure it is served over HTTPS.

**Data storage:** Analysis results are cached in `chrome.storage.local`, which is sandboxed to the extension and inaccessible to web pages. Settings and the whitelist are in `chrome.storage.sync`, which syncs across signed-in Chrome profiles via Google's sync infrastructure. No data is sent to any third-party service by the extension itself.

**False-positive reports:** Reports include the URL, verdict, score, detection reasons, and a timestamp. No browsing history, cookies, or personally identifying information beyond the reported URL is included.

**Content script isolation:** `content.js` runs in an isolated world and communicates with the background service worker exclusively via `chrome.runtime.sendMessage`. It does not access page JavaScript or cookies.

**Permissions:** The extension requests only the permissions required for its function:

| Permission        | Purpose                                               |
|-------------------|-------------------------------------------------------|
| `activeTab`       | Read the URL of the current tab for scanning          |
| `storage`         | Persist settings, cache, and history                  |
| `webNavigation`   | Detect navigations for auto-scanning                  |
| `tabs`            | Update badge, send messages to content scripts        |
| `alarms`          | Scheduled cache cleanup                               |
| `notifications`   | Desktop notification warning style                   |
| `contextMenus`    | Right-click email analysis actions                    |

---

## Performance & Optimizations

**Request deduplication:** The `RequestDebouncer` ensures that parallel navigation events for the same URL share a single in-flight HTTP request. Without this, SPA frameworks that fire multiple navigation events per route change would produce redundant API calls.

**Event deduplication:** `shouldProcessEvent` enforces a 400 ms guard per `tabId:reason:url` tuple. This prevents the background service worker from being re-entered for the same navigation by overlapping Chrome event sources.

**Email scan debouncing:** The content script debounces email scan submissions to 900 ms and compares a per-session signature before submitting. This prevents repeated scans of the same email when the page's MutationObserver fires on unrelated DOM changes.

**Stale-while-revalidate caching:** Analysis results are served immediately from cache when fresh, reducing perceived latency to zero for repeat visits. A stale fallback window (5 minutes beyond the 1-hour TTL) maintains functionality during brief backend outages without serving arbitrarily old data.

**Temporary failure cache:** Retryable failures populate a 30-second in-memory block per cache key, preventing the retry layer from running on every navigation while a backend is down.

**LRU eviction:** Storage is bounded at 4.5 MB. The `StorageManager` evicts the least-recently-used entries first, preserving the most relevant cached results and discarding old ones.

**Async badge updates:** Badge text and color updates are fire-and-forget. They do not block the analysis pipeline and will fail silently if the tab has been closed.

---

## Future Improvements

- **Scan queue with priority scheduling** — Queue pending scans for multiple open tabs and prioritize the active tab, preventing the service worker from issuing parallel backend requests on browser startup when many tabs restore at once.
- **Local ML pre-filter** — Run a lightweight on-device heuristic (URL length, suspicious TLD, homoglyph detection) before the backend call and skip the network request for obviously safe URLs (e.g., well-known domains with no URL path anomalies).
- **Expanded email client support** — Add selector chains for Fastmail, ProtonMail, and Yahoo Mail.
- **Scan history search and filtering** — Add a search input and verdict filter to the history panels so users can find previously flagged URLs quickly.
- **Options page scan history view** — Surface the full 20-entry history in the options page with CSV export.
- **Backend health indicator in popup** — Display a persistent status dot in the popup header showing whether the backend is reachable, rather than only surfacing this on demand.
- **Allowlist by URL pattern** — Extend the whitelist from exact domain matching to glob and regex patterns for more granular control.
- **Firefox / Edge support** — The codebase is close to WebExtensions API compatible; porting would require replacing `chrome.*` calls with `browser.*` and validating Manifest V3 support on each target.

---

## Contributing

Contributions are welcome. Please follow these steps:

1. Fork the repository and create a feature branch from `main`.
2. Keep changes focused — one feature or fix per pull request.
3. Add or update inline JSDoc comments for any new functions.
4. Test the extension manually against the scenarios in the original README (phishing URL, backend offline, style changes).
5. Open a pull request with a clear description of what was changed and why.

Bug reports and feature requests should be filed as GitHub Issues.

---

## License

MIT License. See [LICENSE](./LICENSE) for full terms.
