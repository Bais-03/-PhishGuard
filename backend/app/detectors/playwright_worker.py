"""
playwright_worker.py — runs in a completely separate process from FastAPI.
Receives a URL via argv, outputs JSON flags to stdout.
Must be invoked via asyncio.create_subprocess_exec(), never imported directly.
"""
import asyncio
import sys
import json
import re
import urllib.parse
from playwright.async_api import async_playwright

KNOWN_BRANDS = [
    "paypal", "amazon", "google", "microsoft", "apple", "netflix",
    "facebook", "instagram", "chase", "wellsfargo", "bankofamerica",
]


async def analyze(url: str) -> list[dict]:
    flags = []

    async with async_playwright() as p:
        browser = await p.chromium.launch(
            args=[
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-extensions",
                "--disable-gpu",
                "--block-new-web-contents",
                "--disable-javascript",  # Enable only if JS rendering is needed
            ]
        )

        context = await browser.new_context(
            viewport={"width": 1280, "height": 800},
            user_agent="Mozilla/5.0 PhishGuard/1.0",
        )

        # Block media, fonts, websockets to reduce attack surface
        async def block_unnecessary(route):
            if route.request.resource_type in ["media", "font", "websocket", "image"]:
                await route.abort()
            else:
                await route.continue_()

        await context.route("**/*", block_unnecessary)

        page = await context.new_page()

        try:
            response = await page.goto(url, wait_until="domcontentloaded", timeout=10000)

            # Check for login/credential forms
            password_inputs = await page.query_selector_all("input[type='password']")
            if password_inputs:
                flags.append({
                    "type": "LOGIN_FORM_RENDERED",
                    "severity": "HIGH",
                    "score": 25,
                    "detail": f"Playwright: rendered page has {len(password_inputs)} password field(s)",
                    "source": "playwright",
                })

            # Brand impersonation in page title
            title = await page.title()
            final_url = page.url
            actual_domain = urllib.parse.urlparse(final_url).netloc.lower()

            for brand in KNOWN_BRANDS:
                if brand in title.lower() and brand not in actual_domain:
                    flags.append({
                        "type": "BRAND_IMPERSONATION_IN_TITLE",
                        "severity": "CRITICAL",
                        "score": 35,
                        "detail": f"Playwright: title '{title[:60]}' references '{brand}' but domain is '{actual_domain}'",
                        "source": "playwright",
                    })
                    break

            # Redirect detection
            if final_url != url:
                flags.append({
                    "type": "REDIRECT_DETECTED",
                    "severity": "MEDIUM",
                    "score": 8,
                    "detail": f"Playwright: redirected to {final_url[:80]}",
                    "source": "playwright",
                })

        except Exception as e:
            # Worker errors are non-fatal — just output empty
            pass
        finally:
            await browser.close()

    return flags


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(json.dumps([]))
        sys.exit(0)

    url = sys.argv[1]
    result = asyncio.run(analyze(url))
    print(json.dumps(result))
