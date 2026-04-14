"""
PhishGuard Test Suite
Run with: pytest tests/ -v
"""
import pytest
import asyncio
from app.core.preprocessor import preprocess, looks_like_url, extract_domain
from app.core.scorer import calculate_score
from app.models.schemas import Flag, Severity
from app.detectors.layer1_local import (
    check_homoglyphs,
    check_url_entropy,
    check_ip_in_url,
    check_urgency_keywords,
)


# ── Preprocessor Tests ────────────────────────────────────────────

def test_looks_like_url():
    assert looks_like_url("https://google.com") is True
    assert looks_like_url("http://evil.tk") is True
    assert looks_like_url("not a url") is False


def test_extract_domain():
    assert extract_domain("https://paypal.com/signin") == "paypal.com"
    assert extract_domain("https://evil.paypa1.com/login") == "paypa1.com"


@pytest.mark.asyncio
async def test_preprocess_url():
    ctx = await preprocess("https://paypal.com/signin")
    assert ctx.mode == "url"
    assert "paypal.com" in ctx.urls[0]
    assert ctx.cache_key  # SHA256 generated


@pytest.mark.asyncio
async def test_preprocess_email():
    raw = (
        "From: sender@evil-domain.com\n"
        "Reply-To: harvest@otherdomain.net\n"
        "Subject: Urgent: Verify your account\n"
        "\n"
        "Click here: https://fake-paypal.com/login\n"
    )
    ctx = await preprocess(raw)
    assert ctx.mode == "email"
    assert ctx.sender_domain == "evil-domain.com"
    assert "https://fake-paypal.com/login" in ctx.urls


# ── Layer 1 Detector Tests ────────────────────────────────────────

def test_homoglyph_non_ascii():
    flag = check_homoglyphs("pаypal.com")  # 'а' is Cyrillic
    assert flag.type == "UNICODE_DECEPTION"
    assert flag.severity == Severity.CRITICAL


def test_homoglyph_clean():
    flag = check_homoglyphs("paypal.com")
    assert flag.type == "HOMOGLYPH_CLEAN"


def test_ip_in_url():
    flag = check_ip_in_url("http://192.168.1.1/login")
    assert flag.type == "IP_IN_URL"


def test_ip_in_url_clean():
    flag = check_ip_in_url("https://google.com/search")
    assert flag.type == "IP_IN_URL_CLEAN"


def test_urgency_keywords_high():
    text = (
        "Your account will be suspended. Verify your account immediately. "
        "Action required: your password expired."
    )
    flag = check_urgency_keywords(text)
    assert flag.type in ("HIGH_URGENCY_LANGUAGE", "URGENCY_LANGUAGE")


def test_urgency_keywords_clean():
    flag = check_urgency_keywords("Hello, here is your weekly newsletter.")
    assert flag.type == "NO_URGENCY_LANGUAGE"


def test_url_entropy_high():
    long_random = "https://xn--" + "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0" * 3 + ".com/path"
    flag = check_url_entropy(long_random)
    # Should flag as high entropy if entropy > 4.5 and len > 80
    assert flag.type in ("HIGH_URL_ENTROPY", "URL_ENTROPY_OK")


# ── Scoring Engine Tests ──────────────────────────────────────────

def test_score_phishing():
    flags = [
        Flag(type="GOOGLE_SAFE_BROWSING_HIT", severity=Severity.CRITICAL, score=45),
        Flag(type="CREDENTIAL_FORM_DETECTED", severity=Severity.HIGH, score=25),
        Flag(type="REPLY_TO_MISMATCH", severity=Severity.HIGH, score=20),
    ]
    result = calculate_score(flags)
    assert result.verdict == "PHISHING"
    assert result.score >= 70  # Hard floor due to CRITICAL flag


def test_score_likely_safe():
    flags = [
        Flag(type="IN_TRANCO", severity=Severity.NONE, score=0),
        Flag(type="DOMAIN_AGE_OK", severity=Severity.NONE, score=0),
        Flag(type="VT_CLEAN", severity=Severity.NONE, score=0),
    ]
    result = calculate_score(flags)
    assert result.verdict == "LIKELY SAFE"
    assert result.score < 35


def test_score_suspicious():
    flags = [
        Flag(type="NEW_DOMAIN", severity=Severity.MEDIUM, score=12),
        Flag(type="NO_DMARC_RECORD", severity=Severity.MEDIUM, score=18),
        Flag(type="SHORTENED_URL", severity=Severity.MEDIUM, score=10),
        Flag(type="URGENCY_LANGUAGE", severity=Severity.LOW, score=8),
    ]
    result = calculate_score(flags)
    assert result.verdict in ("SUSPICIOUS", "PHISHING")


def test_hard_floor_critical():
    """Any CRITICAL flag must push score to minimum 70."""
    flags = [
        Flag(type="GOOGLE_SAFE_BROWSING_HIT", severity=Severity.CRITICAL, score=45),
    ]
    result = calculate_score(flags)
    assert result.score >= 70
    assert result.verdict == "PHISHING"


def test_top_reasons_populated():
    flags = [
        Flag(type="DKIM_FAIL", severity=Severity.HIGH, score=22, detail="DKIM signature invalid"),
        Flag(type="REPLY_TO_MISMATCH", severity=Severity.HIGH, score=20, detail="From vs Reply-To mismatch"),
        Flag(type="NO_SPF_RECORD", severity=Severity.HIGH, score=20, detail="No SPF record found"),
        Flag(type="TRACKING_PIXEL", severity=Severity.LOW, score=5),
    ]
    result = calculate_score(flags)
    assert len(result.reasons) == 3
    # Highest-scored flags should be in reasons
    assert "DKIM signature invalid" in result.reasons
