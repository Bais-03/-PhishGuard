"""
Layer 4 — Content & Deep Analysis
- Email body text analysis (plain text emails)
- HTML DOM analysis (credential forms, anchor mismatches, tracking pixels, brand impersonation)
- Subdomain imitation detection (NEW)
- httpx redirect chain following (max 5 hops)
- Optional Playwright headless render (subprocess-sandboxed)
"""
import asyncio
import json
import re
import urllib.parse
from bs4 import BeautifulSoup
import httpx

from app.models.schemas import Flag, Severity, AnalysisContext
from app.core.config import get_settings

settings = get_settings()

KNOWN_BRANDS_CONTENT = [
    "paypal", "amazon", "google", "microsoft", "apple", "netflix",
    "facebook", "instagram", "chase", "wellsfargo", "bankofamerica",
    "citibank", "irs", "linkedin", "dropbox", "github",
]


# ── Email Body Text Analysis (for plain text emails) ──────────────

def analyze_email_body_text(body_text: str) -> list[Flag]:
    """Analyze plain text email body for phishing indicators."""
    flags = []
    
    if not body_text:
        return flags
    
    body_lower = body_text.lower()
    
    # Check for suspicious links in text (http:// without proper context)
    url_pattern = re.compile(r'https?://[^\s]+')
    urls_in_text = url_pattern.findall(body_text)
    
    for url in urls_in_text:
        # Check for IP-based URLs in email body
        if re.search(r'https?://\d+\.\d+\.\d+\.\d+', url):
            flags.append(Flag(
                type="IP_URL_IN_EMAIL_BODY",
                severity=Severity.LOW,
                score=8,
                detail=f"Email contains raw IP URL: {url[:50]}",
                source="content",
            ))
            break
    
    # Check for excessive exclamation marks (urgency)
    exclamation_count = body_text.count('!')
    if exclamation_count >= 3:
        flags.append(Flag(
            type="EXCESSIVE_EXCLAMATIONS",
            severity=Severity.LOW,
            score=5,
            detail=f"Found {exclamation_count} exclamation marks in email body (urgency signal)",
            source="content",
        ))
    
    # Check for ALL CAPS sections
    caps_pattern = re.compile(r'[A-Z]{10,}')
    caps_matches = caps_pattern.findall(body_text)
    if caps_matches:
        flags.append(Flag(
            type="ALL_CAPS_PHRASE",
            severity=Severity.LOW,
            score=5,
            detail=f"Found ALL CAPS phrase: {caps_matches[0][:30]}",
            source="content",
        ))
    
    # Check for generic greetings (not personalized)
    generic_greetings = [
        r"dear (?:customer|user|member|client|valued (?:customer|member))",
        r"hello (?:there|user|customer)",
        r"attention (?:valued )?(?:customer|member)",
    ]
    for greeting in generic_greetings:
        if re.search(greeting, body_lower):
            flags.append(Flag(
                type="GENERIC_GREETING",
                severity=Severity.LOW,
                score=5,
                detail="Email uses generic greeting instead of personalized salutation",
                source="content",
            ))
            break
    
    return flags


# ── HTML Content Analysis ─────────────────────────────────────────

def looks_like_url(s: str) -> bool:
    return s.startswith("http://") or s.startswith("https://")


def domains_match(url1: str, url2: str) -> bool:
    try:
        d1 = urllib.parse.urlparse(url1).netloc.lower().split(":")[0]
        d2 = urllib.parse.urlparse(url2).netloc.lower().split(":")[0]
        return d1 == d2
    except Exception:
        return False


def analyze_html_content(html: str, page_url: str = "") -> list[Flag]:
    flags = []
    if not html:
        return flags

    soup = BeautifulSoup(html, "html.parser")

    # 1. Credential harvesting — password input fields
    password_fields = soup.find_all("input", {"type": "password"})
    if password_fields:
        flags.append(Flag(
            type="CREDENTIAL_FORM_DETECTED",
            severity=Severity.HIGH,
            score=30,
            detail=f"Found {len(password_fields)} password input field(s) — likely credential harvesting form",
            source="content",
        ))

    # 2. Anchor text vs href mismatch
    mismatches = []
    for anchor in soup.find_all("a", href=True):
        href = anchor.get("href", "")
        text = anchor.get_text().strip()
        if looks_like_url(text) and href and not domains_match(text, href):
            mismatches.append(f"Shows: {text[:40]} | Links to: {href[:40]}")

    if mismatches:
        flags.append(Flag(
            type="ANCHOR_HREF_MISMATCH",
            severity=Severity.HIGH,
            score=25,
            detail=mismatches[0],
            source="content",
        ))

    # 3. Tracking pixel detection
    tracking_pixels = []
    for img in soup.find_all("img"):
        w = str(img.get("width", ""))
        h = str(img.get("height", ""))
        if w in ("1", "0") and h in ("1", "0"):
            tracking_pixels.append(img.get("src", ""))

    if tracking_pixels:
        flags.append(Flag(
            type="TRACKING_PIXEL",
            severity=Severity.LOW,
            score=5,
            detail=f"Found {len(tracking_pixels)} 1x1 tracking pixel(s)",
            source="content",
        ))

    # 4. HTML-to-text ratio
    page_text = soup.get_text()
    if len(html) > 500 and len(page_text) / len(html) < 0.10:
        flags.append(Flag(
            type="HIGH_HTML_TO_TEXT_RATIO",
            severity=Severity.MEDIUM,
            score=10,
            detail=f"HTML/text ratio {len(page_text)/len(html):.2f} — heavy HTML with little visible text",
            source="content",
        ))

    # 5. Brand impersonation in page title vs actual domain
    title_tag = soup.find("title")
    if title_tag and page_url:
        title_text = title_tag.get_text().lower()
        actual_domain = urllib.parse.urlparse(page_url).netloc.lower()
        for brand in KNOWN_BRANDS_CONTENT:
            if brand in title_text and brand not in actual_domain:
                flags.append(Flag(
                    type="BRAND_IMPERSONATION_IN_TITLE",
                    severity=Severity.CRITICAL,
                    score=45,
                    detail=f"Page title references '{brand}' but domain is '{actual_domain}'",
                    source="content",
                ))
                break

    # 6. External suspicious resources
    page_domain = urllib.parse.urlparse(page_url).netloc.lower() if page_url else ""
    for tag in soup.find_all(["script", "iframe", "link"]):
        src = tag.get("src") or tag.get("href") or ""
        if src.startswith("http") and page_domain and page_domain not in src:
            ext_domain = urllib.parse.urlparse(src).netloc.lower()
            # Simple heuristic: IP-based external resource
            if re.match(r"\d+\.\d+\.\d+\.\d+", ext_domain):
                flags.append(Flag(
                    type="SUSPICIOUS_EXTERNAL_RESOURCE",
                    severity=Severity.MEDIUM,
                    score=12,
                    detail=f"Loads resource from IP address: {ext_domain}",
                    source="content",
                ))
                break

    return flags


# ============================================================
# NEW: SUBDOMAIN IMITATION DETECTION
# ============================================================

def check_subdomain_imitation(url: str) -> Flag:
    """
    Detect subdomain imitation pattern: real-brand.com.attacker.com
    Example: drive.google.com.secure-verify.com
    """
    if not url:
        return Flag(type="NO_SUBDOMAIN_IMITATION", severity=Severity.NONE, score=0, source="content")
    
    try:
        parsed = urllib.parse.urlparse(url)
        netloc = parsed.netloc.lower()
        
        if not netloc:
            return Flag(type="NO_SUBDOMAIN_IMITATION", severity=Severity.NONE, score=0, source="content")
        
        # Check if netloc contains a known brand in the subdomain section
        # Pattern: brand.com.something.com
        parts = netloc.split(".")
        
        for i, part in enumerate(parts):
            if part in KNOWN_BRANDS_CONTENT and i + 2 < len(parts):
                # Brand appears before the final domain
                # actual registrable domain = last two labels
                actual_domain = ".".join(parts[-2:]) if len(parts) >= 2 else netloc

                # Build the canonical domain we'd expect for this brand
                expected_domain = f"{part}.com"

                # FIXED: compare actual_domain directly, not via substring
                # Old bug: `expected_domain not in netloc` was True for
                # drive.google.com.secure-verify.com because netloc contains
                # the substring "google.com", so the flag never fired.
                if actual_domain != expected_domain:
                    return Flag(
                        type="SUBDOMAIN_IMITATION",
                        severity=Severity.HIGH,
                        score=25,
                        detail=f"URL uses subdomain deception: '{part}' appears in subdomain but actual domain is '{actual_domain}'",
                        source="content",
                    )
    except Exception:
        pass
    
    return Flag(type="NO_SUBDOMAIN_IMITATION", severity=Severity.NONE, score=0, source="content")


# ============================================================
# NEW: EMAIL LINK ACTION KEYWORDS DETECTION
# ============================================================

URL_ACTION_KEYWORDS = [
    "login", "signin", "verify", "confirm", "secure",
    "account", "update", "billing", "payment", "credential",
    "restore", "unlock", "validate", "authenticate"
]


def check_email_link_keywords(urls: list[str]) -> Flag:
    """Check if email contains links with suspicious action keywords."""
    if not urls:
        return Flag(type="EMAIL_LINK_CLEAN", severity=Severity.NONE, score=0, source="content")
    
    for url in urls:
        url_lower = url.lower()
        for keyword in URL_ACTION_KEYWORDS:
            if f"/{keyword}" in url_lower or f"/{keyword}/" in url_lower:
                return Flag(
                    type="EMAIL_LINK_ACTION_KEYWORDS",
                    severity=Severity.MEDIUM,
                    score=15,
                    detail=f"Email contains link with suspicious action keyword: {url[:60]}",
                    source="content",
                )
    return Flag(type="EMAIL_LINK_CLEAN", severity=Severity.NONE, score=0, source="content")


# ── Redirect Chain Follower ────────────────────────────────────────

async def check_redirect_chain(url: str) -> list[Flag]:
    flags = []
    try:
        async with httpx.AsyncClient(
            max_redirects=5,
            timeout=8.0,
            follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 PhishGuard/1.0"},
        ) as client:
            resp = await client.get(url)
            history = resp.history

            if history:
                flags.append(Flag(
                    type="REDIRECT_DETECTED",
                    severity=Severity.MEDIUM,
                    score=12,
                    detail=f"URL redirects through {len(history)} hop(s) → final: {str(resp.url)[:80]}",
                    source="redirect",
                ))

            # Analyze final destination HTML
            if "text/html" in resp.headers.get("content-type", ""):
                content_flags = analyze_html_content(resp.text, str(resp.url))
                flags.extend(content_flags)

    except httpx.TooManyRedirects:
        flags.append(Flag(
            type="EXCESSIVE_REDIRECTS",
            severity=Severity.HIGH,
            score=22,
            detail="URL exceeds 5 redirect hops",
            source="redirect",
        ))
    except Exception:
        pass

    return flags


# ── Playwright Sandboxed Execution ────────────────────────────────

async def analyze_with_playwright(url: str) -> list[Flag]:
    """
    Runs Playwright in a completely isolated subprocess.
    Never runs in the same process as FastAPI.
    """
    if not settings.enable_playwright:
        return []

    try:
        proc = await asyncio.create_subprocess_exec(
            "python",
            "app/detectors/playwright_worker.py",
            url,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            limit=1024 * 1024,
        )

        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=settings.playwright_timeout_ms / 1000,
            )
        except asyncio.TimeoutError:
            proc.kill()
            return [Flag(
                type="PLAYWRIGHT_TIMEOUT",
                severity=Severity.NONE,
                score=0,
                detail="Playwright analysis timed out",
                source="playwright",
            )]

        if stdout.strip():
            raw = json.loads(stdout.decode())
            return [Flag(**f) for f in raw if f]

    except Exception as e:
        pass

    return []


# ── Layer 4 Entrypoint ────────────────────────────────────────────

async def run_layer4(ctx: AnalysisContext, use_playwright: bool = False) -> list[Flag]:
    flags = []

    # Analyze email body text (for plain text emails)
    if ctx.body_text:
        flags.extend(analyze_email_body_text(ctx.body_text))
    
    # Analyze email HTML body if present
    if ctx.body_html:
        flags.extend(analyze_html_content(ctx.body_html))

    # NEW: Check for email link action keywords
    if ctx.mode == "email" and ctx.urls:
        flags.append(check_email_link_keywords(ctx.urls))

    # NEW: Check for subdomain imitation in URLs
    for url in ctx.urls[:3]:
        flags.append(check_subdomain_imitation(url))

    # Redirect chain analysis for URLs
    for url in ctx.urls[:3]:
        redirect_flags = await check_redirect_chain(url)
        flags.extend(redirect_flags)

    # Optional Playwright deep render
    if use_playwright and ctx.urls:
        pw_flags = await analyze_with_playwright(ctx.urls[0])
        flags.extend(pw_flags)

    return [f for f in flags if f is not None]