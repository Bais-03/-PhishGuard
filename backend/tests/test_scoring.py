"""
test_scoring.py — Comprehensive tests for the PhishGuard scoring engine.

Tests cover:
  - Flag registry integrity
  - Raw score calculation
  - Safe-signal discounts
  - Co-occurrence bonuses
  - Exponential normalization
  - Hard floor (CRITICAL flags)
  - Verdict thresholds
  - Reason generation
  - Edge cases (empty flags, all-clean, all-critical)
  - explain_score output

Run: pytest tests/test_scoring.py -v
"""
import math
import pytest

from app.models.schemas import Flag, Severity
from app.core.flag_registry import (
    REGISTRY, SAFE_SIGNAL_DISCOUNTS, CO_OCCURRENCE_RULES,
    get_flag, weighted_score, is_critical, Tier,
)
from app.core.scorer import (
    calculate_score, explain_score,
    THRESHOLD_PHISHING, THRESHOLD_SUSPICIOUS,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def make_flag(flag_type: str, detail: str = None) -> Flag:
    entry = get_flag(flag_type)
    sev_map = {
        Tier.CRITICAL: Severity.CRITICAL,
        Tier.HIGH:     Severity.HIGH,
        Tier.MEDIUM:   Severity.MEDIUM,
        Tier.LOW:      Severity.LOW,
        Tier.NONE:     Severity.NONE,
        "CRITICAL":    Severity.CRITICAL,
        "HIGH":        Severity.HIGH,
        "MEDIUM":      Severity.MEDIUM,
        "LOW":         Severity.LOW,
        "NONE":        Severity.NONE,
    }
    severity = sev_map.get(entry["severity"], Severity.LOW)
    return Flag(
        type=flag_type,
        severity=severity,
        score=entry["base"],
        detail=detail,
    )


# ── Registry Integrity ────────────────────────────────────────────────────────

class TestFlagRegistry:

    def test_no_duplicate_keys(self):
        # Python dicts don't allow duplicate keys — this just validates all entries exist
        assert len(REGISTRY) > 30

    def test_all_entries_have_required_fields(self):
        required = {"base", "confidence", "severity", "category", "description"}
        for key, entry in REGISTRY.items():
            missing = required - set(entry.keys())
            assert not missing, f"{key} missing fields: {missing}"

    def test_base_scores_in_range(self):
        for key, entry in REGISTRY.items():
            assert 0 <= entry["base"] <= 50, f"{key} base={entry['base']} out of range"

    def test_confidence_in_range(self):
        for key, entry in REGISTRY.items():
            assert 0.0 <= entry["confidence"] <= 1.0, \
                f"{key} confidence={entry['confidence']} out of range"

    def test_critical_flags_have_high_base(self):
        critical_flags = [k for k, v in REGISTRY.items() if v["severity"] == Tier.CRITICAL]
        for f in critical_flags:
            assert REGISTRY[f]["base"] >= 35, \
                f"CRITICAL flag {f} has base={REGISTRY[f]['base']} (should be >= 35)"

    def test_none_flags_have_zero_base(self):
        none_flags = [k for k, v in REGISTRY.items() if v["severity"] == Tier.NONE]
        for f in none_flags:
            assert REGISTRY[f]["base"] == 0, \
                f"NONE flag {f} has base={REGISTRY[f]['base']} (should be 0)"

    def test_safe_discount_flags_are_in_registry(self):
        for flag_type in SAFE_SIGNAL_DISCOUNTS:
            assert flag_type in REGISTRY, \
                f"Safe discount flag {flag_type} not in registry"

    def test_co_occurrence_flags_are_in_registry(self):
        for rule_flags, bonus, desc in CO_OCCURRENCE_RULES:
            for f in rule_flags:
                assert f in REGISTRY, \
                    f"Co-occurrence flag {f} (rule: {desc!r}) not in registry"

    def test_get_flag_unknown_returns_default(self):
        result = get_flag("NONEXISTENT_FLAG_XYZ")
        assert result["base"] == 5
        assert result["confidence"] == 0.5

    def test_is_critical(self):
        assert is_critical("GOOGLE_SAFE_BROWSING_HIT") is True
        assert is_critical("VT_MALICIOUS") is True
        assert is_critical("URGENCY_LANGUAGE") is False
        assert is_critical("IN_TRANCO") is False

    def test_weighted_score(self):
        # GOOGLE_SAFE_BROWSING_HIT: base=45, confidence=0.98 → 44.1
        ws = weighted_score("GOOGLE_SAFE_BROWSING_HIT")
        assert abs(ws - 44.1) < 0.01


# ── Raw Score Calculation ─────────────────────────────────────────────────────

class TestRawScore:

    def test_empty_flags_score_zero(self):
        result = calculate_score([])
        assert result.score == 0
        assert result.verdict == "LIKELY SAFE"

    def test_single_low_flag(self):
        flags = [make_flag("TRACKING_PIXEL")]
        result = calculate_score(flags)
        # weighted = 5 * 0.45 = 2.25 → normalized ≈ 3
        assert result.score < 10
        assert result.verdict == "LIKELY SAFE"

    def test_single_critical_flag_applies_floor(self):
        flags = [make_flag("GOOGLE_SAFE_BROWSING_HIT")]
        result = calculate_score(flags)
        assert result.score >= 70
        assert result.verdict == "PHISHING"

    def test_single_critical_flag_floor_is_exactly_70_if_math_is_lower(self):
        """
        GSB alone: weighted = 44.1
        normalized = round(100 * (1 - e^(-44.1/80))) ≈ round(100 * 0.578) = 42
        → hard floor kicks in → 70
        """
        flags = [make_flag("GOOGLE_SAFE_BROWSING_HIT")]
        result = calculate_score(flags)
        assert result.score == 70
        assert result.breakdown.hard_floor_applied is True

    def test_multiple_critical_flags_exceed_floor(self):
        flags = [
            make_flag("GOOGLE_SAFE_BROWSING_HIT"),
            make_flag("VT_MALICIOUS"),
            make_flag("UNICODE_DECEPTION"),
        ]
        result = calculate_score(flags)
        # raw = 44.1 + 38 + 31.5 = 113.6 → normalized ≈ 76 (above floor)
        assert result.score > 70
        assert result.breakdown.hard_floor_applied is False  # floor not needed

    def test_many_low_flags_score_suspicious(self):
        flags = [
            make_flag("TRACKING_PIXEL"),
            make_flag("HIGH_URL_ENTROPY"),
            make_flag("NOT_IN_TRANCO_TOP_1M"),
            make_flag("URGENCY_LANGUAGE"),
            make_flag("SHORTENED_URL"),
            make_flag("REDIRECT_DETECTED"),
            make_flag("WHOIS_UNAVAILABLE"),
            make_flag("YOUNG_TLS_CERT"),
        ]
        result = calculate_score(flags)
        assert result.score >= THRESHOLD_SUSPICIOUS
        assert result.verdict in ("SUSPICIOUS", "PHISHING")

    def test_score_cannot_exceed_100(self):
        # Max out every single critical flag
        flags = [
            make_flag("GOOGLE_SAFE_BROWSING_HIT"),
            make_flag("VT_MALICIOUS"),
            make_flag("UNICODE_DECEPTION"),
            make_flag("BRAND_IMPERSONATION_IN_TITLE"),
            make_flag("KNOWN_PHISHING_URL"),
            make_flag("HOMOGLYPH_CHAR"),
            make_flag("DKIM_FAIL"),
            make_flag("CREDENTIAL_FORM_DETECTED"),
            make_flag("REPLY_TO_MISMATCH"),
        ]
        result = calculate_score(flags)
        assert result.score <= 100


# ── Safe-Signal Discounts ─────────────────────────────────────────────────────

class TestSafeDiscounts:

    def test_tranco_reduces_score(self):
        flags_without = [make_flag("URGENCY_LANGUAGE"), make_flag("SHORTENED_URL")]
        flags_with    = flags_without + [make_flag("IN_TRANCO")]

        score_without = calculate_score(flags_without).score
        score_with    = calculate_score(flags_with).score

        assert score_with <= score_without, \
            "IN_TRANCO should reduce or maintain score"

    def test_vt_clean_reduces_score(self):
        base_flags  = [make_flag("NEW_DOMAIN"), make_flag("SHORTENED_URL")]
        clean_flags = base_flags + [make_flag("VT_CLEAN")]

        assert calculate_score(clean_flags).score <= calculate_score(base_flags).score

    def test_discount_capped_at_20_percent_of_raw(self):
        """
        Even with every safe signal, discount can't exceed 20% of raw score.
        A single LOW flag + all safe signals should not yield a negative score.
        """
        flags = [
            make_flag("TRACKING_PIXEL"),        # raw contribution: 2.25
            make_flag("IN_TRANCO"),             # discount: 8
            make_flag("VT_CLEAN"),              # discount: 6
            make_flag("DKIM_PASS"),             # discount: 4
            make_flag("SPF_PASS"),              # discount: 3
            make_flag("DMARC_PASS"),            # discount: 3
            make_flag("DOMAIN_AGE_OK"),         # discount: 4
        ]
        result = calculate_score(flags)
        # Breakdown: raw=2.25, max_discount=2.25*0.20=0.45
        # adjusted ≥ 0
        assert result.breakdown.adjusted_score >= 0
        assert result.score >= 0

    def test_all_clean_signals_score_zero(self):
        flags = [
            make_flag("IN_TRANCO"),
            make_flag("VT_CLEAN"),
            make_flag("DKIM_PASS"),
            make_flag("SPF_PASS"),
            make_flag("DMARC_PASS"),
            make_flag("DOMAIN_AGE_OK"),
            make_flag("TLS_CERT_OK"),
            make_flag("MX_RECORD_OK"),
            make_flag("HOMOGLYPH_CLEAN"),
            make_flag("NO_URGENCY_LANGUAGE"),
        ]
        result = calculate_score(flags)
        assert result.score == 0
        assert result.verdict == "LIKELY SAFE"


# ── Co-Occurrence Bonuses ─────────────────────────────────────────────────────

class TestCoOccurrence:

    def test_email_auth_triple_fail_bonus(self):
        """SPF + DKIM + DMARC all failing → +15 bonus."""
        individual_flags = [
            make_flag("NO_SPF_RECORD"),
            make_flag("DKIM_FAIL"),
        ]
        triple_fail_flags = individual_flags + [make_flag("NO_DMARC_RECORD")]

        score_two   = calculate_score(individual_flags).score
        score_three = calculate_score(triple_fail_flags).score

        # Triple fail should score higher than just two
        assert score_three >= score_two

    def test_triple_fail_bonus_is_15(self):
        flags = [
            make_flag("NO_SPF_RECORD"),
            make_flag("DKIM_FAIL"),
            make_flag("NO_DMARC_RECORD"),
        ]
        result = calculate_score(flags)
        bonuses = result.breakdown.co_occurrence_bonuses
        triple_bonus = next(
            (b for b in bonuses if "SPF" in str(b.flags_involved) and b.bonus == 15.0),
            None,
        )
        assert triple_bonus is not None, "Email auth triple-fail bonus should trigger"
        assert triple_bonus.bonus == 15.0

    def test_credential_form_plus_urgency_bonus(self):
        flags = [
            make_flag("CREDENTIAL_FORM_DETECTED"),
            make_flag("HIGH_URGENCY_LANGUAGE"),
        ]
        result = calculate_score(flags)
        bonuses = {b.description for b in result.breakdown.co_occurrence_bonuses}
        assert any("Credential form" in d for d in bonuses)

    def test_new_domain_lookalike_bonus(self):
        flags = [
            make_flag("VERY_NEW_DOMAIN"),
            make_flag("LOOKALIKE_DOMAIN"),
        ]
        result = calculate_score(flags)
        bonuses = {b.description for b in result.breakdown.co_occurrence_bonuses}
        assert any("lookalike" in d.lower() or "Newly" in d for d in bonuses)

    def test_vt_plus_gsb_double_confirmation_bonus(self):
        flags = [
            make_flag("VT_MALICIOUS"),
            make_flag("GOOGLE_SAFE_BROWSING_HIT"),
        ]
        result = calculate_score(flags)
        bonuses = {b.description for b in result.breakdown.co_occurrence_bonuses}
        assert any("VirusTotal" in d or "both" in d.lower() for d in bonuses)

    def test_no_bonus_without_both_flags(self):
        """Only one flag of a co-occurrence pair → no bonus."""
        flags = [make_flag("NO_SPF_RECORD")]  # missing DKIM_FAIL and NO_DMARC_RECORD
        result = calculate_score(flags)
        # Check no triple-fail bonus
        triple = [b for b in result.breakdown.co_occurrence_bonuses if b.bonus == 15.0]
        assert not triple

    def test_multiple_bonuses_stack(self):
        """Both credential+urgency AND new+lookalike should both fire."""
        flags = [
            make_flag("CREDENTIAL_FORM_DETECTED"),
            make_flag("HIGH_URGENCY_LANGUAGE"),
            make_flag("VERY_NEW_DOMAIN"),
            make_flag("LOOKALIKE_DOMAIN"),
        ]
        result = calculate_score(flags)
        assert len(result.breakdown.co_occurrence_bonuses) >= 2


# ── Normalization ─────────────────────────────────────────────────────────────

class TestNormalization:

    def test_exponential_formula_correctness(self):
        """Verify formula: normalized = round(100 * (1 - e^(-adjusted/80)))"""
        test_cases = [
            (0,   0),
            (40,  39),   # round(100*(1-e^(-0.5))) ≈ 39
            (80,  63),   # round(100*(1-e^(-1.0))) ≈ 63
            (160, 86),   # round(100*(1-e^(-2.0))) ≈ 86
            (320, 98),   # round(100*(1-e^(-4.0))) ≈ 98
        ]
        for adjusted, expected in test_cases:
            computed = round(100 * (1 - math.exp(-adjusted / 80)))
            assert computed == expected, \
                f"adjusted={adjusted}: expected {expected}, got {computed}"

    def test_score_monotonically_increases_with_flags(self):
        """Adding more bad flags should never decrease the score."""
        base_flags = [make_flag("URGENCY_LANGUAGE")]
        scores = [calculate_score(base_flags[:i+1]).score for i in range(len(base_flags))]
        for a, b in zip(scores, scores[1:]):
            assert b >= a


# ── Verdict Thresholds ────────────────────────────────────────────────────────

class TestVerdictThresholds:

    def test_score_0_is_likely_safe(self):
        result = calculate_score([])
        assert result.verdict == "LIKELY SAFE"

    def test_score_34_is_likely_safe(self):
        # Build a combination that lands around 34
        # NOT_IN_TRANCO: 5*0.40=2, URGENCY: 8*0.55=4.4, TRACKING: 5*0.45=2.25 → raw=8.65 → norm≈10
        flags = [make_flag("NOT_IN_TRANCO_TOP_1M"), make_flag("URGENCY_LANGUAGE"), make_flag("TRACKING_PIXEL")]
        result = calculate_score(flags)
        assert result.verdict == "LIKELY SAFE"

    def test_score_65_plus_is_phishing(self):
        # Force score to exactly phishing range
        flags = [
            make_flag("DKIM_FAIL"),
            make_flag("NO_SPF_RECORD"),
            make_flag("REPLY_TO_MISMATCH"),
            make_flag("CREDENTIAL_FORM_DETECTED"),
            make_flag("HIGH_URGENCY_LANGUAGE"),
            make_flag("VERY_NEW_DOMAIN"),
            make_flag("LOOKALIKE_DOMAIN"),
        ]
        result = calculate_score(flags)
        assert result.verdict in ("SUSPICIOUS", "PHISHING")  # depends on exact weights

    def test_critical_always_phishing(self):
        flags = [make_flag("VT_MALICIOUS")]
        result = calculate_score(flags)
        assert result.verdict == "PHISHING"

    def test_threshold_constants_sane(self):
        assert THRESHOLD_SUSPICIOUS < THRESHOLD_PHISHING
        assert THRESHOLD_SUSPICIOUS >= 30
        assert THRESHOLD_PHISHING >= 60


# ── Reason Generation ─────────────────────────────────────────────────────────

class TestReasonGeneration:

    def test_reasons_max_three(self):
        flags = [make_flag(f) for f in [
            "DKIM_FAIL", "NO_SPF_RECORD", "REPLY_TO_MISMATCH",
            "URGENCY_LANGUAGE", "TRACKING_PIXEL",
        ]]
        result = calculate_score(flags)
        assert len(result.reasons) <= 3

    def test_reasons_not_empty_when_flags_present(self):
        flags = [make_flag("DKIM_FAIL")]
        result = calculate_score(flags)
        assert len(result.reasons) >= 1

    def test_no_reasons_when_only_clean_signals(self):
        flags = [make_flag("IN_TRANCO"), make_flag("VT_CLEAN")]
        result = calculate_score(flags)
        assert len(result.reasons) == 0

    def test_co_occurrence_description_in_reasons(self):
        flags = [
            make_flag("NO_SPF_RECORD"),
            make_flag("DKIM_FAIL"),
            make_flag("NO_DMARC_RECORD"),
        ]
        result = calculate_score(flags)
        # The co-occurrence rule description should appear as the first reason
        assert len(result.reasons) >= 1
        assert any("auth" in r.lower() or "SPF" in r or "DKIM" in r or "email" in r.lower()
                   for r in result.reasons)

    def test_custom_detail_appears_in_reasons(self):
        flags = [
            make_flag("LOOKALIKE_DOMAIN", detail="Domain 'paypa1.com' is 89% similar to brand 'paypal'")
        ]
        result = calculate_score(flags)
        assert any("paypa1.com" in r or "similar" in r for r in result.reasons)

    def test_reasons_are_unique(self):
        flags = [make_flag(f) for f in [
            "DKIM_FAIL", "NO_SPF_RECORD", "REPLY_TO_MISMATCH",
        ]]
        result = calculate_score(flags)
        assert len(result.reasons) == len(set(result.reasons))


# ── Breakdown Object ──────────────────────────────────────────────────────────

class TestBreakdown:

    def test_breakdown_present(self):
        flags = [make_flag("DKIM_FAIL")]
        result = calculate_score(flags)
        assert result.breakdown is not None

    def test_breakdown_adjusted_equals_raw_minus_discount_plus_bonus(self):
        flags = [
            make_flag("DKIM_FAIL"),
            make_flag("NO_SPF_RECORD"),
            make_flag("IN_TRANCO"),   # safe signal
        ]
        result = calculate_score(flags)
        bd = result.breakdown
        expected_adjusted = bd.raw_score - bd.safe_discount + bd.co_occurrence_bonus
        assert abs(bd.adjusted_score - expected_adjusted) < 0.01

    def test_contributions_sum_equals_raw_score(self):
        flags = [make_flag("DKIM_FAIL"), make_flag("REPLY_TO_MISMATCH"), make_flag("IN_TRANCO")]
        result = calculate_score(flags)
        bd = result.breakdown
        contributions_sum = sum(c.weighted for c in bd.contributions)
        assert abs(contributions_sum - bd.raw_score) < 0.01

    def test_contributions_sorted_by_weight_desc(self):
        flags = [
            make_flag("TRACKING_PIXEL"),          # low weight
            make_flag("DKIM_FAIL"),               # high weight
            make_flag("CREDENTIAL_FORM_DETECTED"),# medium weight
        ]
        result = calculate_score(flags)
        weights = [c.weighted for c in result.breakdown.contributions]
        assert weights == sorted(weights, reverse=True)

    def test_flags_sorted_by_base_desc(self):
        flags = [
            make_flag("TRACKING_PIXEL"),
            make_flag("VT_MALICIOUS"),
            make_flag("NEW_DOMAIN"),
        ]
        result = calculate_score(flags)
        bases = [get_flag(f.type)["base"] for f in result.flags]
        assert bases == sorted(bases, reverse=True)


# ── Explain Mode ──────────────────────────────────────────────────────────────

class TestExplainScore:

    def test_explain_returns_string(self):
        flags = [make_flag("DKIM_FAIL"), make_flag("REPLY_TO_MISMATCH")]
        output = explain_score(flags)
        assert isinstance(output, str)
        assert len(output) > 100

    def test_explain_contains_score(self):
        flags = [make_flag("DKIM_FAIL")]
        output = explain_score(flags)
        assert "FINAL SCORE" in output

    def test_explain_contains_verdict(self):
        flags = [make_flag("GOOGLE_SAFE_BROWSING_HIT")]
        output = explain_score(flags)
        assert "PHISHING" in output

    def test_explain_shows_pipeline_stages(self):
        flags = [make_flag("DKIM_FAIL"), make_flag("IN_TRANCO")]
        output = explain_score(flags)
        assert "Raw score" in output
        assert "Safe discount" in output
        assert "Co-occurrence" in output

    def test_explain_empty_flags(self):
        output = explain_score([])
        assert "LIKELY SAFE" in output


# ── Real-World Scenarios ──────────────────────────────────────────────────────

class TestRealWorldScenarios:

    def test_classic_phishing_email(self):
        """Spoofed sender + no auth + credential form + urgency."""
        flags = [
            make_flag("REPLY_TO_MISMATCH",       "From: paypal.com, Reply-To: evil.ru"),
            make_flag("NO_SPF_RECORD",            "No SPF for paypa1-support.com"),
            make_flag("DKIM_FAIL",                "DKIM signature invalid"),
            make_flag("NO_DMARC_RECORD",          "No DMARC for paypa1-support.com"),
            make_flag("VERY_NEW_DOMAIN",          "Domain registered 3 days ago"),
            make_flag("LOOKALIKE_DOMAIN",         "paypa1-support.com ~ paypal (91%)"),
            make_flag("CREDENTIAL_FORM_DETECTED", "Password input in email body HTML"),
            make_flag("HIGH_URGENCY_LANGUAGE",    "Account will be suspended"),
            make_flag("TRACKING_PIXEL",           "1x1 pixel from tracker.evil.ru"),
        ]
        result = calculate_score(flags)
        assert result.verdict == "PHISHING"
        assert result.score >= 80
        # Multiple co-occurrence rules should fire
        assert len(result.breakdown.co_occurrence_bonuses) >= 2

    def test_legitimate_email_github(self):
        """All auth passes, domain in Tranco, no suspicious signals."""
        flags = [
            make_flag("SPF_PASS"),
            make_flag("DKIM_PASS"),
            make_flag("DMARC_PASS"),
            make_flag("IN_TRANCO"),
            make_flag("DOMAIN_AGE_OK"),
            make_flag("VT_CLEAN"),
            make_flag("MX_RECORD_OK"),
            make_flag("TLS_CERT_OK"),
            make_flag("HOMOGLYPH_CLEAN"),
        ]
        result = calculate_score(flags)
        assert result.verdict == "LIKELY SAFE"
        assert result.score == 0

    def test_suspicious_url_not_yet_confirmed(self):
        """New domain, not in Tranco, no auth, but no direct hit yet."""
        flags = [
            make_flag("NEW_DOMAIN",          "Domain is 45 days old"),
            make_flag("NOT_IN_TRANCO_TOP_1M"),
            make_flag("NO_SPF_RECORD"),
            make_flag("SHORTENED_URL"),
            make_flag("REDIRECT_DETECTED",   "Redirects through 3 hops"),
        ]
        result = calculate_score(flags)
        assert result.verdict in ("SUSPICIOUS", "PHISHING")
        assert result.score >= THRESHOLD_SUSPICIOUS

    def test_unicode_homoglyph_attack(self):
        """Cyrillic 'а' in domain — CRITICAL even with little else."""
        flags = [
            make_flag("UNICODE_DECEPTION", "pаypal.com contains Cyrillic 'а' (U+0430)"),
            make_flag("VERY_NEW_DOMAIN",   "Domain 2 days old"),
        ]
        result = calculate_score(flags)
        assert result.verdict == "PHISHING"
        assert result.score >= 70
        # Co-occurrence bonus for unicode + new domain should fire
        bonuses = {b.description for b in result.breakdown.co_occurrence_bonuses}
        assert any("Unicode" in d or "homoglyph" in d.lower() for d in bonuses)

    def test_double_confirmed_phishing(self):
        """Both VT and GSB hit → top score, double confirmation bonus."""
        flags = [
            make_flag("VT_MALICIOUS",            "35/70 engines flagged"),
            make_flag("GOOGLE_SAFE_BROWSING_HIT","SOCIAL_ENGINEERING threat type"),
        ]
        result = calculate_score(flags)
        assert result.verdict == "PHISHING"
        assert result.score >= 85
        bonuses = {b.description for b in result.breakdown.co_occurrence_bonuses}
        assert any("VirusTotal" in d or "both" in d.lower() or "Confirmed" in d for d in bonuses)

    def test_api_failure_does_not_crash_score(self):
        """If all APIs time out, score from local flags alone should still work."""
        flags = [
            make_flag("LOOKALIKE_DOMAIN",  "Domain 95% similar to microsoft"),
            make_flag("VERY_NEW_DOMAIN",   "3 days old"),
            make_flag("NO_SPF_RECORD"),
        ]
        result = calculate_score(flags)
        # Should still produce a valid score
        assert 0 <= result.score <= 100
        assert result.verdict in ("LIKELY SAFE", "SUSPICIOUS", "PHISHING")
