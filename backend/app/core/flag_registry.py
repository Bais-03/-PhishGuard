"""
flag_registry.py — Single source of truth for every flag PhishGuard can emit.

Each entry defines:
  base        — raw weight before confidence adjustment (0–45)
  confidence  — how reliable this signal is (0.0–1.0)
  severity    — CRITICAL / HIGH / MEDIUM / LOW / NONE
  category    — url | email | content | behavioral (for UI grouping)
  description — plain-English label shown in UI
  tier        — maps to severity for quick sorting

Rules:
  weighted = base × confidence
  CRITICAL flags (base >= 35) → hard score floor of 70
  NONE flags are pass signals → can reduce score via safe_discount
"""

from enum import Enum


class Tier(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    NONE     = "NONE"       # pass / clean signal


# ---------------------------------------------------------------------------
# MASTER FLAG REGISTRY
# ---------------------------------------------------------------------------
# Key → dict with: base, confidence, severity (alias tier), category, description
# ---------------------------------------------------------------------------
REGISTRY: dict[str, dict] = {

    # ── CRITICAL (base 35–45) ───────────────────────────────────────────────
    "GOOGLE_SAFE_BROWSING_HIT": {
        "base": 45, "confidence": 0.98,
        "severity": Tier.CRITICAL, "category": "behavioral",
        "description": "Google Safe Browsing: confirmed threat",
    },
    "VT_MALICIOUS": {
        "base": 40, "confidence": 0.95,
        "severity": Tier.CRITICAL, "category": "behavioral",
        "description": "VirusTotal: flagged by multiple AV engines",
    },
    "KNOWN_PHISHING_URL": {
        "base": 40, "confidence": 0.95,
        "severity": Tier.CRITICAL, "category": "behavioral",
        "description": "URL matches internal known-phishing blocklist",
    },
    "UNICODE_DECEPTION": {
        "base": 35, "confidence": 0.90,
        "severity": Tier.CRITICAL, "category": "url",
        "description": "Non-ASCII / Unicode characters in domain (IDN homoglyph attack)",
    },
    "BRAND_IMPERSONATION_IN_TITLE": {
        "base": 35, "confidence": 0.85,
        "severity": Tier.CRITICAL, "category": "content",
        "description": "Page title references a known brand but domain does not match",
    },

    # ── HIGH (base 20–34) ───────────────────────────────────────────────────
    "HOMOGLYPH_CHAR": {
        "base": 28, "confidence": 0.85,
        "severity": Tier.HIGH, "category": "url",
        "description": "Domain contains a Unicode confusable character",
    },
    "VERY_NEW_DOMAIN": {
        "base": 25, "confidence": 0.75,
        "severity": Tier.HIGH, "category": "url",
        "description": "Domain registered less than 30 days ago",
    },
    "CREDENTIAL_FORM_DETECTED": {
        "base": 25, "confidence": 0.80,
        "severity": Tier.HIGH, "category": "content",
        "description": "Password input field found — possible credential harvesting",
    },
    "LOGIN_FORM_RENDERED": {
        "base": 25, "confidence": 0.82,
        "severity": Tier.HIGH, "category": "content",
        "description": "Playwright: live login form rendered in headless browser",
    },
    "DKIM_FAIL": {
        "base": 22, "confidence": 0.85,
        "severity": Tier.HIGH, "category": "email",
        "description": "DKIM signature verification failed",
    },
    "LOOKALIKE_DOMAIN": {
        "base": 22, "confidence": 0.80,
        "severity": Tier.HIGH, "category": "url",
        "description": "Domain is visually similar to a known brand (typosquatting)",
    },
    "NO_SPF_RECORD": {
        "base": 20, "confidence": 0.80,
        "severity": Tier.HIGH, "category": "email",
        "description": "Sender domain has no SPF record",
    },
    "REPLY_TO_MISMATCH": {
        "base": 20, "confidence": 0.85,
        "severity": Tier.HIGH, "category": "email",
        "description": "Reply-To domain differs from From domain",
    },
    "HIGH_URGENCY_LANGUAGE": {
        "base": 20, "confidence": 0.65,
        "severity": Tier.HIGH, "category": "content",
        "description": "Multiple urgency / threat phrases detected in content",
    },
    "ANCHOR_HREF_MISMATCH": {
        "base": 20, "confidence": 0.90,
        "severity": Tier.HIGH, "category": "content",
        "description": "Anchor text shows one URL but href links to a different domain",
    },
    "ABUSEIPDB_FLAGGED": {
        "base": 15, "confidence": 0.70,
        "severity": Tier.HIGH, "category": "behavioral",
        "description": "Sender IP flagged in AbuseIPDB crowd-sourced abuse database",
    },
    "RISKY_ATTACHMENT": {
        "base": 15, "confidence": 0.70,
        "severity": Tier.HIGH, "category": "email",
        "description": "Email contains an attachment with a high-risk file extension",
    },
    "EXCESSIVE_REDIRECTS": {
        "base": 18, "confidence": 0.75,
        "severity": Tier.HIGH, "category": "url",
        "description": "URL exceeds 5 redirect hops — evasion technique",
    },

    # ── MEDIUM (base 8–19) ──────────────────────────────────────────────────
    "NO_DMARC_RECORD": {
        "base": 18, "confidence": 0.75,
        "severity": Tier.MEDIUM, "category": "email",
        "description": "Sender domain has no DMARC policy",
    },
    "VT_SUSPICIOUS": {
        "base": 20, "confidence": 0.75,
        "severity": Tier.MEDIUM, "category": "behavioral",
        "description": "VirusTotal: low-ratio suspicious engines flagged",
    },
    "RETURN_PATH_MISMATCH": {
        "base": 12, "confidence": 0.75,
        "severity": Tier.MEDIUM, "category": "email",
        "description": "Return-Path domain differs from From domain",
    },
    "NEW_DOMAIN": {
        "base": 12, "confidence": 0.65,
        "severity": Tier.MEDIUM, "category": "url",
        "description": "Domain registered 30–90 days ago",
    },
    "NO_MX_RECORD": {
        "base": 10, "confidence": 0.70,
        "severity": Tier.MEDIUM, "category": "email",
        "description": "Sender domain has no MX record — cannot legitimately send email",
    },
    "HIGH_HTML_TO_TEXT_RATIO": {
        "base": 10, "confidence": 0.60,
        "severity": Tier.MEDIUM, "category": "content",
        "description": "Heavy HTML with very little visible text — common in phishing kits",
    },
    "REDIRECT_DETECTED": {
        "base": 8, "confidence": 0.55,
        "severity": Tier.MEDIUM, "category": "url",
        "description": "URL redirects to a different domain",
    },
    "SHORTENED_URL": {
        "base": 10, "confidence": 0.60,
        "severity": Tier.MEDIUM, "category": "url",
        "description": "URL uses a link-shortening service (hides true destination)",
    },
    "WHOIS_UNAVAILABLE": {
        "base": 10, "confidence": 0.50,
        "severity": Tier.MEDIUM, "category": "url",
        "description": "WHOIS record unavailable or creation date missing",
    },
    "SUSPICIOUS_EXTERNAL_RESOURCE": {
        "base": 8, "confidence": 0.55,
        "severity": Tier.MEDIUM, "category": "content",
        "description": "Page loads a resource from a raw IP address",
    },

    # ── LOW (base 1–7) ──────────────────────────────────────────────────────
    "IP_IN_URL": {
        "base": 8, "confidence": 0.70,
        "severity": Tier.LOW, "category": "url",
        "description": "URL uses a raw IP address instead of a domain name",
    },
    "HIGH_URL_ENTROPY": {
        "base": 6, "confidence": 0.55,
        "severity": Tier.LOW, "category": "url",
        "description": "URL has high entropy and length — likely algorithmically generated",
    },
    "TRACKING_PIXEL": {
        "base": 5, "confidence": 0.45,
        "severity": Tier.LOW, "category": "content",
        "description": "1×1 hidden tracking pixel detected in email body",
    },
    "YOUNG_TLS_CERT": {
        "base": 8, "confidence": 0.60,
        "severity": Tier.LOW, "category": "url",
        "description": "TLS certificate issued less than 30 days ago",
    },
    "NOT_IN_TRANCO_TOP_1M": {
        "base": 5, "confidence": 0.40,
        "severity": Tier.LOW, "category": "behavioral",
        "description": "Domain not found in Tranco top-1M most visited domains",
    },
    "URGENCY_LANGUAGE": {
        "base": 8, "confidence": 0.55,
        "severity": Tier.LOW, "category": "content",
        "description": "Urgency / threat phrasing detected in content",
    },
    "VT_NOT_FOUND": {
        "base": 5, "confidence": 0.30,
        "severity": Tier.LOW, "category": "behavioral",
        "description": "URL not yet in VirusTotal — submitted for first scan",
    },
    "PLAYWRIGHT_TIMEOUT": {
        "base": 0, "confidence": 1.0,
        "severity": Tier.NONE, "category": "behavioral",
        "description": "Playwright deep-render timed out (non-fatal)",
    },

    # ── NONE — pass / clean signals (base = 0, reduce score via discount) ───
    "HOMOGLYPH_CLEAN": {
        "base": 0, "confidence": 1.0,
        "severity": Tier.NONE, "category": "url",
        "description": "No homoglyph or Unicode deception detected",
    },
    "DOMAIN_AGE_OK": {
        "base": 0, "confidence": 1.0,
        "severity": Tier.NONE, "category": "url",
        "description": "Domain is more than 90 days old",
    },
    "VT_CLEAN": {
        "base": 0, "confidence": 1.0,
        "severity": Tier.NONE, "category": "behavioral",
        "description": "VirusTotal: no engines flagged this URL",
    },
    "IN_TRANCO": {
        "base": 0, "confidence": 1.0,
        "severity": Tier.NONE, "category": "behavioral",
        "description": "Domain is in Tranco top-1M (high-traffic legitimate site)",
    },
    "SPF_PASS": {
        "base": 0, "confidence": 1.0,
        "severity": Tier.NONE, "category": "email",
        "description": "SPF record present and valid",
    },
    "DKIM_PASS": {
        "base": 0, "confidence": 1.0,
        "severity": Tier.NONE, "category": "email",
        "description": "DKIM signature verified successfully",
    },
    "DMARC_PASS": {
        "base": 0, "confidence": 1.0,
        "severity": Tier.NONE, "category": "email",
        "description": "DMARC policy present and aligned",
    },
    "MX_RECORD_OK": {
        "base": 0, "confidence": 1.0,
        "severity": Tier.NONE, "category": "email",
        "description": "MX records properly configured",
    },
    "TLS_CERT_OK": {
        "base": 0, "confidence": 1.0,
        "severity": Tier.NONE, "category": "url",
        "description": "TLS certificate valid and not newly issued",
    },
    "DOMAIN_OK": {
        "base": 0, "confidence": 1.0,
        "severity": Tier.NONE, "category": "url",
        "description": "Domain passes similarity checks",
    },
    "URL_NOT_SHORTENED": {
        "base": 0, "confidence": 1.0,
        "severity": Tier.NONE, "category": "url",
        "description": "URL does not use a shortening service",
    },
    "URL_ENTROPY_OK": {
        "base": 0, "confidence": 1.0,
        "severity": Tier.NONE, "category": "url",
        "description": "URL entropy within normal range",
    },
    "NO_URGENCY_LANGUAGE": {
        "base": 0, "confidence": 1.0,
        "severity": Tier.NONE, "category": "content",
        "description": "No urgency or threat language detected",
    },
    "IP_IN_URL_CLEAN": {
        "base": 0, "confidence": 1.0,
        "severity": Tier.NONE, "category": "url",
        "description": "URL uses a proper domain name (not a raw IP)",
    },
}

# ---------------------------------------------------------------------------
# Helper lookups
# ---------------------------------------------------------------------------

CRITICAL_BASE_THRESHOLD = 35  # base >= this → hard score floor applies

# Safe signals that provide a small score discount when present
# Each entry: flag_type → discount subtracted from raw_score
SAFE_SIGNAL_DISCOUNTS: dict[str, float] = {
    "IN_TRANCO":    8.0,   # very strong trust signal
    "VT_CLEAN":     6.0,   # VirusTotal cleared it
    "DKIM_PASS":    4.0,   # email auth passes
    "SPF_PASS":     3.0,
    "DMARC_PASS":   3.0,
    "DOMAIN_AGE_OK": 4.0,  # established domain
    "TLS_CERT_OK":  2.0,
    "MX_RECORD_OK": 2.0,
}

# Co-occurrence bonuses — when multiple signals appear together, add extra weight
# List of (frozenset_of_flag_types, bonus_score, description)
CO_OCCURRENCE_RULES: list[tuple] = [
    # Email auth triple-fail: high confidence the email is spoofed
    (
        frozenset({"NO_SPF_RECORD", "DKIM_FAIL", "NO_DMARC_RECORD"}),
        15.0,
        "Full email auth failure (SPF + DKIM + DMARC)",
    ),
    # Credential form + urgency: classic phishing kit pattern
    (
        frozenset({"CREDENTIAL_FORM_DETECTED", "HIGH_URGENCY_LANGUAGE"}),
        10.0,
        "Credential form combined with urgency language",
    ),
    # New domain + lookalike: strong typosquatting signal
    (
        frozenset({"VERY_NEW_DOMAIN", "LOOKALIKE_DOMAIN"}),
        12.0,
        "Newly registered lookalike domain",
    ),
    # Reply-To mismatch + no SPF: spoofed sender
    (
        frozenset({"REPLY_TO_MISMATCH", "NO_SPF_RECORD"}),
        8.0,
        "Mismatched reply-to with no SPF — likely spoofed sender",
    ),
    # Anchor mismatch + credential form: phishing page with deceptive links
    (
        frozenset({"ANCHOR_HREF_MISMATCH", "CREDENTIAL_FORM_DETECTED"}),
        10.0,
        "Deceptive link anchors combined with credential harvesting form",
    ),
    # VT malicious + GSB hit: double confirmation from two independent sources
    (
        frozenset({"VT_MALICIOUS", "GOOGLE_SAFE_BROWSING_HIT"}),
        8.0,
        "Confirmed phishing by both VirusTotal and Google Safe Browsing",
    ),
    # Homoglyph + new domain: sophisticated Unicode attack
    (
        frozenset({"UNICODE_DECEPTION", "VERY_NEW_DOMAIN"}),
        10.0,
        "Unicode homoglyph on a newly registered domain",
    ),
    # IP in URL + redirect: obfuscation stacking
    (
        frozenset({"IP_IN_URL", "REDIRECT_DETECTED"}),
        6.0,
        "IP-based URL with redirect chain — evasion stacking",
    ),
]


def get_flag(flag_type: str) -> dict:
    """Returns registry entry for a flag, with safe defaults for unknown types."""
    return REGISTRY.get(flag_type, {
        "base": 5,
        "confidence": 0.5,
        "severity": Tier.LOW,
        "category": "url",
        "description": flag_type.replace("_", " ").title(),
    })


def weighted_score(flag_type: str) -> float:
    entry = get_flag(flag_type)
    return entry["base"] * entry["confidence"]


def is_critical(flag_type: str) -> bool:
    return get_flag(flag_type)["base"] >= CRITICAL_BASE_THRESHOLD
