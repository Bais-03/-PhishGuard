from __future__ import annotations
from pydantic import BaseModel, Field
from typing import Optional, Any, Literal, List
from datetime import datetime
from enum import Enum


class Severity(str, Enum):
    NONE     = "NONE"
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"


class Flag(BaseModel):
    type:     str
    severity: Severity
    score:    int
    detail:   Optional[str] = None
    source:   Optional[str] = None


class AnalysisContext(BaseModel):
    """Populated by preprocessor; consumed by all detector layers."""
    mode:      Literal["email", "url"] = "url"
    raw_input: str = ""
    cache_key: str = ""

    # URL mode
    urls:    list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)

    # Email mode
    headers:       dict        = Field(default_factory=dict)
    body_text:     str         = ""
    body_html:     str         = ""
    sender_domain: str         = ""
    sender_ip:     str         = ""
    attachments:   list[dict]  = Field(default_factory=list)


class FlagContributionOut(BaseModel):
    """Per-flag score contribution — serialisable for API response."""
    flag_type:   str
    base:        int
    confidence:  float
    weighted:    float
    severity:    str
    category:    str
    description: str
    detail:      Optional[str] = None


class CoOccurrenceBonusOut(BaseModel):
    flags_involved: list[str]
    bonus:          float
    description:    str


class ScoreBreakdownOut(BaseModel):
    """Full transparent breakdown returned by /analyze endpoints."""
    raw_score:            float
    safe_discount:        float
    co_occurrence_bonus:  float
    adjusted_score:       float
    normalized_score:     int
    hard_floor_applied:   bool
    contributions:        list[FlagContributionOut] = Field(default_factory=list)
    co_occurrence_bonuses: list[CoOccurrenceBonusOut] = Field(default_factory=list)


class ScoringResult(BaseModel):
    score:    int
    verdict:  Literal["PHISHING", "SUSPICIOUS", "LIKELY SAFE"]
    reasons:  list[str]
    flags:    list[Flag]
    breakdown: Optional[Any] = None


class AnalysisResult(BaseModel):
    score:       int
    verdict:     str
    flags:       list[Flag]
    reasons:     list[str]
    breakdown:   Optional[ScoreBreakdownOut] = None
    analyzed_at: datetime = Field(default_factory=datetime.utcnow)
    cache_hit:   bool     = False
    duration_ms: int      = 0
    input_type:  str      = "url"


class EmailInput(BaseModel):
    raw_email: str = Field(..., description="Raw RFC 2822 email string")


class UrlInput(BaseModel):
    url: str = Field(..., description="URL to analyze")