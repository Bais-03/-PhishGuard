"""
Layer 1 — Local Detectors (< 10ms)
"""
import re
import math
import urllib.parse
from app.models.schemas import Flag, Severity, AnalysisContext

try:
    from confusable_homoglyphs import confusables
    HOMOGLYPH_LIB_AVAILABLE = True
except ImportError:
    HOMOGLYPH_LIB_AVAILABLE = False


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


def check_urgency_keywords(text: str) -> Flag:
    matches = []
    for pattern in _URGENCY_RE:
        m = pattern.search(text)
        if m:
            matches.append(m.group(0)[:60])

    if len(matches) >= 3:
        return Flag(
            type="HIGH_URGENCY_LANGUAGE",
            severity=Severity.HIGH,
            score=35,  # This is working! Shows +35 in your screenshot
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


async def run_layer1(ctx: AnalysisContext) -> list[Flag]:
    flags = []

    for domain in ctx.domains:
        flags.append(check_homoglyphs(domain))

    for url in ctx.urls:
        flags.append(check_url_entropy(url))
        flags.append(check_ip_in_url(url))
        domain = urllib.parse.urlparse(url).netloc.lower().split(":")[0]
        flags.append(check_shortened_url(domain))

    combined_text = ctx.body_text + ctx.body_html
    if combined_text:
        flags.append(check_urgency_keywords(combined_text))

    flags.extend(check_attachments(ctx.attachments))

    return [f for f in flags if f is not None]