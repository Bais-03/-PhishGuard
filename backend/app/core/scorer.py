"""
Scoring Engine — converts flags into final score with transparent breakdown.
"""
import math
from dataclasses import dataclass, field
from typing import List, Tuple
from app.models.schemas import Flag, Severity, ScoringResult

# Severity to base score mapping
SEVERITY_BASE_SCORES = {
    Severity.NONE: 0,
    Severity.LOW: 5,
    Severity.MEDIUM: 10,
    Severity.HIGH: 20,
    Severity.CRITICAL: 35,
}

# Confidence multipliers for different flag types
CONFIDENCE_MULTIPLIERS = {
    # High confidence detectors
    "BRAND_IMPERSONATION": 0.95,
    "BRAND_IMPERSONATION_DOMAIN_MISMATCH": 0.98,
    "REPLY_TO_MISMATCH": 0.90,
    "SENDER_LINK_MISMATCH": 0.92,
    "GOOGLE_SAFE_BROWSING_HIT": 0.99,
    "VT_MALICIOUS": 0.95,
    
    # Medium confidence
    "HIGH_URGENCY_LANGUAGE": 0.85,
    "CREDENTIAL_FORM_DETECTED": 0.88,
    "VERY_NEW_DOMAIN": 0.80,
    "NEW_DOMAIN": 0.75,
    "WHOIS_UNAVAILABLE": 0.70,
    
    # Lower confidence
    "URGENCY_LANGUAGE": 0.65,
    "LOOKALIKE_DOMAIN": 0.60,
    "NOT_IN_TRANCO_TOP_1M": 0.50,
    "VT_NOT_FOUND": 0.40,
    
    # Default
    "DEFAULT": 0.50,
}

# Flag categories for grouping
FLAG_CATEGORIES = {
    "BRAND_IMPERSONATION": "Content Analysis",
    "BRAND_IMPERSONATION_DOMAIN_MISMATCH": "DNS Analysis",
    "REPLY_TO_MISMATCH": "Email Headers",
    "SENDER_LINK_MISMATCH": "Email Headers",
    "HIGH_URGENCY_LANGUAGE": "Content Analysis",
    "URGENCY_LANGUAGE": "Content Analysis",
    "VERY_NEW_DOMAIN": "DNS Analysis",
    "NEW_DOMAIN": "DNS Analysis",
    "WHOIS_UNAVAILABLE": "DNS Analysis",
    "CREDENTIAL_FORM_DETECTED": "Content Analysis",
    "VT_MALICIOUS": "External APIs",
    "VT_NOT_FOUND": "External APIs",
    "VT_SUSPICIOUS": "External APIs",
    "GOOGLE_SAFE_BROWSING_HIT": "External APIs",
    "ABUSEIPDB_FLAGGED": "External APIs",
    "NOT_IN_TRANCO_TOP_1M": "External APIs",
    "SHORTENED_URL": "URL Analysis",
    "IP_IN_URL": "URL Analysis",
    "UNICODE_DECEPTION": "URL Analysis",
    "HOMOGLYPH_CHAR": "URL Analysis",
}

# Flag descriptions
FLAG_DESCRIPTIONS = {
    "BRAND_IMPERSONATION": "Email claims to be from one brand but links to different domain",
    "BRAND_IMPERSONATION_DOMAIN_MISMATCH": "Critical brand impersonation detected",
    "REPLY_TO_MISMATCH": "Reply-To address differs from From address",
    "SENDER_LINK_MISMATCH": "Sender domain doesn't match link domain",
    "HIGH_URGENCY_LANGUAGE": "Multiple urgency phrases detected",
    "URGENCY_LANGUAGE": "Urgency phrase detected",
    "VERY_NEW_DOMAIN": "Domain registered less than 30 days ago",
    "NEW_DOMAIN": "Domain registered less than 90 days ago",
    "WHOIS_UNAVAILABLE": "WHOIS information unavailable or domain very new",
    "CREDENTIAL_FORM_DETECTED": "Password input field detected",
    "VT_NOT_FOUND": "URL not previously scanned by VirusTotal",
    "NOT_IN_TRANCO_TOP_1M": "Domain not in top 1M legitimate sites",
}


@dataclass
class FlagContribution:
    flag_type: str
    base: int
    confidence: float
    weighted: float
    severity: str
    category: str
    description: str
    detail: str | None


@dataclass
class ScoreBreakdown:
    raw_score: float
    safe_discount: float
    co_occurrence_bonus: float
    adjusted_score: float
    normalized_score: int
    hard_floor_applied: bool
    contributions: List[FlagContribution] = field(default_factory=list)
    co_occurrence_bonuses: List[dict] = field(default_factory=list)


def calculate_score(flags: List[Flag]) -> ScoringResult:
    """Calculate final score from detected flags."""
    if not flags:
        return ScoringResult(
            score=0,
            verdict="LIKELY SAFE",
            reasons=["No phishing indicators detected."],
            flags=[],
            breakdown=None,
        )
    
    contributions = []
    total_weighted_score = 0.0
    
    # Calculate weighted score for each flag
    for flag in flags:
        if flag.severity == Severity.NONE or flag.score == 0:
            continue
            
        # Get base score from flag (already set in detector)
        base_score = flag.score
        
        # Get confidence multiplier
        confidence = CONFIDENCE_MULTIPLIERS.get(flag.type, CONFIDENCE_MULTIPLIERS["DEFAULT"])
        
        # Calculate weighted score
        weighted = base_score * confidence
        
        # Get category and description
        category = FLAG_CATEGORIES.get(flag.type, "General")
        description = FLAG_DESCRIPTIONS.get(flag.type, flag.type.replace("_", " ").title())
        
        contributions.append(FlagContribution(
            flag_type=flag.type,
            base=base_score,
            confidence=round(confidence, 2),
            weighted=round(weighted, 1),
            severity=flag.severity.value,
            category=category,
            description=description,
            detail=flag.detail,
        ))
        
        total_weighted_score += weighted
    
    raw_score = total_weighted_score
    
    # Apply safe discount (reduce score for legitimate signals)
    safe_discount = 0.0
    has_legitimate_signal = any(
        f.type in ["SPF_PASS", "DMARC_PASS", "IN_TRANCO", "DOMAIN_AGE_OK"]
        for f in flags
    )
    if has_legitimate_signal and raw_score > 0:
        safe_discount = min(15, raw_score * 0.1)
        raw_score -= safe_discount
    
    # Co-occurrence bonus (boost score when multiple related flags fire together)
    co_occurrence_bonus = 0.0
    co_occurrence_bonuses = []
    
    # Check for urgency + new domain combo
    has_urgency = any(f.type in ["HIGH_URGENCY_LANGUAGE", "URGENCY_LANGUAGE"] for f in flags)
    has_new_domain = any(f.type in ["VERY_NEW_DOMAIN", "NEW_DOMAIN", "WHOIS_UNAVAILABLE"] for f in flags)
    if has_urgency and has_new_domain:
        bonus = 10
        co_occurrence_bonus += bonus
        co_occurrence_bonuses.append({
            "flags_involved": ["URGENCY", "NEW_DOMAIN"],
            "bonus": bonus,
            "description": "Urgency + new domain = strong phishing signal",
        })
    
    # Check for brand impersonation + urgency
    has_brand_impersonation = any(
        f.type in ["BRAND_IMPERSONATION", "BRAND_IMPERSONATION_DOMAIN_MISMATCH", "SENDER_LINK_MISMATCH"]
        for f in flags
    )
    if has_brand_impersonation and has_urgency:
        bonus = 15
        co_occurrence_bonus += bonus
        co_occurrence_bonuses.append({
            "flags_involved": ["BRAND_IMPERSONATION", "URGENCY"],
            "bonus": bonus,
            "description": "Brand impersonation + urgency = critical phishing",
        })
    
    # Check for credential form + brand impersonation
    has_credential_form = any(f.type == "CREDENTIAL_FORM_DETECTED" for f in flags)
    if has_brand_impersonation and has_credential_form:
        bonus = 20
        co_occurrence_bonus += bonus
        co_occurrence_bonuses.append({
            "flags_involved": ["BRAND_IMPERSONATION", "CREDENTIAL_FORM"],
            "bonus": bonus,
            "description": "Brand impersonation with credential form = active phishing",
        })
    
    adjusted_score = raw_score + co_occurrence_bonus
    
    # Apply hard floor for certain combinations
    hard_floor_applied = False
    if has_brand_impersonation and has_urgency and adjusted_score < 65:
        adjusted_score = 65
        hard_floor_applied = True
    elif has_brand_impersonation and adjusted_score < 50:
        adjusted_score = 50
        hard_floor_applied = True
    elif has_urgency and has_new_domain and adjusted_score < 45:
        adjusted_score = 45
        hard_floor_applied = True
    
    # Normalize to 0-100
    normalized_score = min(100, max(0, int(round(adjusted_score))))
    
    # Determine verdict
    if normalized_score >= 60:
        verdict = "PHISHING"
    elif normalized_score >= 35:
        verdict = "SUSPICIOUS"
    else:
        verdict = "LIKELY SAFE"
    
    # Generate top reasons
    reasons = []
    
    # Add brand impersonation first (most important)
    if has_brand_impersonation:
        reasons.append("Email claims to be from one brand but links to different domain")
    
    # Add urgency
    if has_urgency:
        urgency_flags = [f for f in flags if "URGENCY" in f.type]
        if urgency_flags and urgency_flags[0].detail:
            reasons.append(urgency_flags[0].detail[:100])
        else:
            reasons.append("Urgent language detected")
    
    # Add new domain
    if has_new_domain:
        new_domain_flags = [f for f in flags if f.type in ["VERY_NEW_DOMAIN", "NEW_DOMAIN", "WHOIS_UNAVAILABLE"]]
        if new_domain_flags and new_domain_flags[0].detail:
            reasons.append(new_domain_flags[0].detail[:100])
        else:
            reasons.append("Domain appears to be newly registered")
    
    # Add Reply-To mismatch
    reply_to_mismatch = any(f.type == "REPLY_TO_MISMATCH" for f in flags)
    if reply_to_mismatch:
        reasons.append("Reply-To address differs from From address (common phishing technique)")
    
    # Add credential form
    if has_credential_form:
        reasons.append("Password input field detected on page")
    
    # Limit to top 5 reasons
    reasons = reasons[:5]
    
    if not reasons:
        reasons = ["No significant phishing indicators detected."]
    
    # Create breakdown object
    breakdown = ScoreBreakdown(
        raw_score=round(raw_score, 1),
        safe_discount=round(safe_discount, 1),
        co_occurrence_bonus=round(co_occurrence_bonus, 1),
        adjusted_score=round(adjusted_score, 1),
        normalized_score=normalized_score,
        hard_floor_applied=hard_floor_applied,
        contributions=contributions,
        co_occurrence_bonuses=co_occurrence_bonuses,
    )
    
    return ScoringResult(
        score=normalized_score,
        verdict=verdict,
        reasons=reasons,
        flags=flags,
        breakdown=breakdown,
    )


def explain_score(flags: List[Flag]) -> str:
    """Generate human-readable score explanation for debug endpoint."""
    result = calculate_score(flags)
    
    output = []
    output.append("=" * 60)
    output.append(f"SCORE: {result.score}/100 - {result.verdict}")
    output.append("=" * 60)
    output.append("\nFLAG CONTRIBUTIONS:")
    
    for c in result.breakdown.contributions:
        output.append(f"  {c.flag_type}: +{c.base} × {c.confidence} = {c.weighted} pts ({c.severity})")
        if c.detail:
            output.append(f"    └─ {c.detail}")
    
    if result.breakdown.co_occurrence_bonuses:
        output.append("\nCO-OCCURRENCE BONUSES:")
        for b in result.breakdown.co_occurrence_bonuses:
            output.append(f"  +{b['bonus']} pts: {b['description']}")
    
    output.append("\n" + "=" * 60)
    output.append(f"Raw: {result.breakdown.raw_score} | Bonus: +{result.breakdown.co_occurrence_bonus} | Final: {result.score}")
    
    return "\n".join(output)