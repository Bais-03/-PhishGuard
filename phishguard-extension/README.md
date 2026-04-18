# PhishGuard Chrome Extension

Manifest V3 Chrome extension for the existing FastAPI phishing analysis backend at `http://localhost:8000`.

## Features

- Automatic URL scanning on top-level navigations via `chrome.webNavigation.onCommitted`
- Manual URL analysis from the popup
- Risk banner injection for suspicious and phishing pages
- Toast notification support for non-intrusive warnings
- System notification support for desktop alerts
- Badge updates for safe, suspicious, and phishing verdicts
- One-hour storage cache with five-minute stale fallback when the backend is offline
- User settings for auto-scan, warning style (banner/toast/notification/badge), and backend URL
- Import/export settings and cache clearing from the options page

## Warning Styles

| Style | Description |
|-------|-------------|
| Banner | Red/yellow banner at top of page |
| Toast | Small corner popup (non-intrusive) |
| Notification | Desktop system notification |
| Badge | Extension icon badge only |

## Files

- `manifest.json`: MV3 manifest and permissions
- `background.js`: service worker with navigation scanning, caching, throttling, badge updates, and notifications
- `content.js`: in-page warning banner
- `warning.css`: banner styling
- `popup.html` / `popup.js`: active-tab analysis, manual scan, backend health, auto-scan toggle
- `options.html` / `options.js`: settings management with import/export
- `utils/api.js`: backend client with retries and exponential backoff
- `icons/`: Extension icons (16, 48, 128)

## Installation

1. Start the FastAPI backend on `http://localhost:8000`
2. Open `chrome://extensions`
3. Enable Developer mode
4. Click `Load unpacked`
5. Select the `phishguard-extension` folder

## Testing

1. Navigate to `http://paypal-verify.xyz/login` → Should show red banner
2. Turn off backend → Should show cached results (stale cache)
3. Change warning style in Options → Should respect user preference

## Notes

- The extension only scans main-frame HTTP(S) navigations to avoid subresource noise.
- Domain scans are rate-limited to one request every two seconds per hostname.
- Notifications require Chrome's notification permission (granted at install).