"""
Layer 1 — Local Detectors (< 10ms)
"""
import re
import math
import urllib.parse
from urllib.parse import urlparse
from app.models.schemas import Flag, Severity, AnalysisContext

try:
    from confusable_homoglyphs import confusables
    HOMOGLYPH_LIB_AVAILABLE = True
except ImportError:
    HOMOGLYPH_LIB_AVAILABLE = False

# ============================================================
# URL DETECTION CONSTANTS
# ============================================================

SUSPICIOUS_TLDS = {
    "xyz", "top", "click", "link", "work", "date", "men",
    "club", "online", "live", "site", "tech", "review", "trade",
    "download", "bid", "loan", "win", "stream", "party", "gq", "ml", "tk"
}

URL_ACTION_KEYWORDS = [
    "login", "signin", "verify", "confirm", "secure",
    "account", "update", "billing", "payment", "credential",
    "restore", "unlock", "validate", "authenticate"
]

BRAND_NAMES = [
    "paypal", "amazon", "google", "microsoft", "apple", "netflix",
    "facebook", "instagram", "linkedin", "dropbox", "github",
    "chase", "wellsfargo", "bankofamerica", "citibank"
]

# Legitimate domains that can have brand names in subdomains
LEGITIMATE_BRAND_DOMAINS = {
    "google.com", "accounts.google.com", "myaccount.google.com",
    "amazon.com", "paypal.com", "microsoft.com", "apple.com",
    "github.com", "netflix.com", "spotify.com", "dropbox.com",
    "linkedin.com", "twitter.com", "facebook.com", "instagram.com",
    "reddit.com", "slack.com", "stripe.com"
}


def check_homoglyphs(domain: str) -> Flag:
    non_ascii = [c for c in domain if ord(c) > 127]
    if non_ascii:
        return Flag(
            type="UNICODE_DECEPTION",
            severity=Severity.CRITICAL,
            score=40,
            detail=f"Non-ASCII chars in domain: {non_ascii}",
            source="homoglyph",
        )

    if HOMOGLYPH_LIB_AVAILABLE:
        for char in domain:
            if confusables.is_dangerous(char):
                return Flag(
                    type="HOMOGLYPH_CHAR",
                    severity=Severity.HIGH,
                    score=32,
                    detail=f"Character {char!r} is a known Unicode confusable",
                    source="homoglyph",
                )

    return Flag(type="HOMOGLYPH_CLEAN", severity=Severity.NONE, score=0, source="homoglyph")


def url_entropy(url: str) -> float:
    if not url:
        return 0.0
    freq = {}
    for c in url:
        freq[c] = freq.get(c, 0) + 1
    length = len(url)
    return -sum((f / length) * math.log2(f / length) for f in freq.values())


def check_url_entropy(url: str) -> Flag:
    entropy = url_entropy(url)
    url_len = len(url)

    if entropy > 4.5 and url_len > 80:
        return Flag(
            type="HIGH_URL_ENTROPY",
            severity=Severity.LOW,
            score=8,
            detail=f"URL entropy {entropy:.2f} with length {url_len}",
            source="entropy",
        )
    return Flag(type="URL_ENTROPY_OK", severity=Severity.NONE, score=0, source="entropy")


IP_IN_URL_PATTERN = re.compile(r"https?://(\d{1,3}\.){3}\d{1,3}")


def check_ip_in_url(url: str) -> Flag:
    if IP_IN_URL_PATTERN.match(url):
        return Flag(
            type="IP_IN_URL",
            severity=Severity.MEDIUM,
            score=12,
            detail="URL uses raw IP address instead of domain name",
            source="url_structure",
        )
    return Flag(type="IP_IN_URL_CLEAN", severity=Severity.NONE, score=0, source="url_structure")


SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "short.io", "rb.gy", "cutt.ly", "is.gd", "v.gd",
}


def check_shortened_url(domain: str) -> Flag:
    if domain.lower() in SHORTENERS:
        return Flag(
            type="SHORTENED_URL",
            severity=Severity.MEDIUM,
            score=12,
            detail=f"URL uses shortener service: {domain}",
            source="url_structure",
        )
    return Flag(type="URL_NOT_SHORTENED", severity=Severity.NONE, score=0, source="url_structure")


URGENCY_KEYWORDS = [
    r"your account (?:will be|has been) (?:suspended|closed|locked|terminated)",
    r"verify your (?:account|identity|email|password) (?:now|immediately|urgently)",
    r"click here (?:now|immediately|urgently)",
    r"action required",
    r"immediate(?:ly)? (?:update|confirm|verify)",
    r"(?:limited|expires?|expiring) (?:time|soon|today|in \d+ hours?)",
    r"unusual (?:sign[-\s]in|activity|login) (?:detected|attempt)",
    r"password (?:expired|will expire|reset required)",
    r"(?:bank|paypal|amazon|apple|microsoft|google|irs|netflix) (?:account|security|alert)",
    r"suspend(?:ed| your account)",
    r"permanent (?:account )?suspension",
    r"within \d+ hours",
]

_URGENCY_RE = [re.compile(p, re.IGNORECASE) for p in URGENCY_KEYWORDS]

# Brand signatures that should NOT be flagged as urgency
BRAND_SIGNATURES = [
    "google security", "paypal security", "amazon security",
    "microsoft security", "apple security", "security alert",
    "google sign-in", "paypal receipt", "amazon order"
]


def check_urgency_keywords(text: str) -> Flag:
    # Skip if it's just a brand signature (not real urgency)
    text_lower = text.lower().strip()
    for signature in BRAND_SIGNATURES:
        if signature in text_lower or text_lower == signature:
            return Flag(type="NO_URGENCY_LANGUAGE", severity=Severity.NONE, score=0, source="content")
    
    matches = []
    for pattern in _URGENCY_RE:
        m = pattern.search(text)
        if m:
            matches.append(m.group(0)[:60])

    if len(matches) >= 3:
        return Flag(
            type="HIGH_URGENCY_LANGUAGE",
            severity=Severity.HIGH,
            score=35,
            detail=f"Multiple urgency phrases detected: {'; '.join(matches[:2])}",
            source="content",
        )
    elif matches:
        return Flag(
            type="URGENCY_LANGUAGE",
            severity=Severity.MEDIUM,
            score=20,
            detail=f"Urgency phrase: {matches[0]}",
            source="content",
        )
    return Flag(type="NO_URGENCY_LANGUAGE", severity=Severity.NONE, score=0, source="content")


RISKY_EXTENSIONS = {
    "exe", "bat", "cmd", "ps1", "vbs", "js", "jar",
    "docm", "xlsm", "pptm", "zip", "rar", "7z", "iso",
    "msi", "dll", "hta", "scr", "com",
}


def check_attachments(attachments: list[dict]) -> list[Flag]:
    flags = []
    for att in attachments:
        ext = att.get("extension", "").lower()
        if ext in RISKY_EXTENSIONS:
            flags.append(Flag(
                type="RISKY_ATTACHMENT",
                severity=Severity.HIGH,
                score=20,
                detail=f"Risky attachment: {att.get('filename', 'unknown')} (.{ext})",
                source="attachment",
            ))
    return flags


# ============================================================
# NEW URL DETECTION FUNCTIONS
# ============================================================

def check_suspicious_tld(domain: str) -> Flag:
    """Flag high-risk TLDs commonly used in phishing."""
    if not domain:
        return Flag(type="TLD_OK", severity=Severity.NONE, score=0, source="url_structure")
    
    parts = domain.split(".")
    tld = parts[-1].lower() if len(parts) > 1 else ""
    
    if tld in SUSPICIOUS_TLDS:
        return Flag(
            type="SUSPICIOUS_TLD",
            severity=Severity.MEDIUM,
            score=15,
            detail=f"Suspicious TLD '.{tld}' commonly used in phishing",
            source="url_structure",
        )
    return Flag(type="TLD_OK", severity=Severity.NONE, score=0, source="url_structure")


def check_url_action_keywords(url: str) -> Flag:
    """Flag suspicious action keywords in URL path or query string."""
    try:
        parsed = urlparse(url)
        path_lower = parsed.path.lower()
        query_lower = parsed.query.lower()

        found_keywords = []
        for keyword in URL_ACTION_KEYWORDS:
            # Check path (existing logic)
            if f"/{keyword}" in path_lower or path_lower.endswith(f"/{keyword}"):
                found_keywords.append(keyword)
            # NEW: also check query string values and keys
            elif keyword in query_lower:
                found_keywords.append(keyword)

        if found_keywords:
            return Flag(
                type="URL_ACTION_KEYWORDS",
                severity=Severity.MEDIUM,
                score=15,
                detail=f"Suspicious action keywords in URL: {', '.join(found_keywords[:3])}",
                source="url_structure",
            )
    except Exception:
        pass
    return Flag(type="URL_ACTION_CLEAN", severity=Severity.NONE, score=0, source="url_structure")


def check_brand_in_url(url: str, domain: str) -> Flag:
    """
    Check if URL contains a brand name but the actual domain is NOT that brand.
    Example: https://paypal-verify.xyz/ contains "paypal" but domain is not paypal.com
    """
    if not domain:
        return Flag(type="NO_BRAND_IMPERSONATION", severity=Severity.NONE, score=0, source="url_structure")
    
    url_lower = url.lower()
    domain_lower = domain.lower()
    
    # First, check if this is a legitimate domain (allow subdomains of trusted brands)
    for legit in LEGITIMATE_BRAND_DOMAINS:
        if domain_lower == legit or domain_lower.endswith(f".{legit}"):
            return Flag(type="NO_BRAND_IMPERSONATION", severity=Severity.NONE, score=0, source="url_structure")
    
    domain_clean = domain.replace("www.", "").split(".")[0] if domain else ""
    
    for brand in BRAND_NAMES:
        if brand in url_lower:
            # Brand found in URL, check if domain matches
            if brand not in domain_clean and brand != domain_clean:
                return Flag(
                    type="BRAND_IMPERSONATION_URL",
                    severity=Severity.HIGH,
                    score=30,
                    detail=f"URL contains brand '{brand}' but domain is '{domain}'",
                    source="url_structure",
                )
    return Flag(type="NO_BRAND_IMPERSONATION", severity=Severity.NONE, score=0, source="url_structure")


def check_no_https(url: str) -> Flag:
    """Flag URLs that use HTTP instead of HTTPS."""
    if url.startswith("http://"):
        return Flag(
            type="NO_HTTPS",
            severity=Severity.MEDIUM,
            score=12,
            detail="Connection not secure (HTTP instead of HTTPS)",
            source="url_structure",
        )
    return Flag(type="HTTPS_OK", severity=Severity.NONE, score=0, source="url_structure")


async def run_layer1(ctx: AnalysisContext) -> list[Flag]:
    flags = []

    for domain in ctx.domains:
        flags.append(check_homoglyphs(domain))

    for url in ctx.urls:
        flags.append(check_url_entropy(url))
        flags.append(check_ip_in_url(url))
        domain = urllib.parse.urlparse(url).netloc.lower().split(":")[0]
        flags.append(check_shortened_url(domain))
        
        # NEW URL CHECKS
        flags.append(check_suspicious_tld(domain))
        flags.append(check_url_action_keywords(url))
        flags.append(check_brand_in_url(url, domain))
        flags.append(check_no_https(url))

    combined_text = ctx.body_text + ctx.body_html
    if combined_text:
        flags.append(check_urgency_keywords(combined_text))

    flags.extend(check_attachments(ctx.attachments))

    return [f for f in flags if f is not None]