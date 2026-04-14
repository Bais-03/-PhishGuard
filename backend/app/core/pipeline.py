"""
Detection Pipeline Orchestrator
Runs all 4 layers, aggregates flags, scores, serialises breakdown for API.
"""
import asyncio
import time
from dataclasses import asdict

from app.models.schemas import (
    AnalysisContext, AnalysisResult, Flag,
    ScoreBreakdownOut, FlagContributionOut, CoOccurrenceBonusOut,
)
from app.core.preprocessor import preprocess
from app.core.scorer import calculate_score
from app.core.redis_client import (
    cache_get, cache_set, make_cache_key,
    TTL_EMAIL, TTL_URL_PHISHING, TTL_URL_SAFE,
)
from app.detectors.layer1_local  import run_layer1
from app.detectors.layer2_dns    import run_layer2
from app.detectors.layer3_apis   import run_layer3
from app.detectors.layer4_content import run_layer4
import structlog

logger = structlog.get_logger()


def _serialise_breakdown(bd) -> ScoreBreakdownOut:
    """Convert ScoreBreakdown dataclass → Pydantic model for JSON response."""
    if bd is None:
        return None
    
    # Handle contributions - they might be objects or dicts
    contributions = []
    for c in bd.contributions:
        if hasattr(c, 'flag_type'):
            # It's an object
            contributions.append(
                FlagContributionOut(
                    flag_type=c.flag_type,
                    base=c.base,
                    confidence=c.confidence,
                    weighted=c.weighted,
                    severity=c.severity,
                    category=c.category,
                    description=c.description,
                    detail=c.detail,
                )
            )
        else:
            # It's a dict
            contributions.append(
                FlagContributionOut(
                    flag_type=c.get("flag_type", ""),
                    base=c.get("base", 0),
                    confidence=c.get("confidence", 0),
                    weighted=c.get("weighted", 0),
                    severity=c.get("severity", ""),
                    category=c.get("category", ""),
                    description=c.get("description", ""),
                    detail=c.get("detail"),
                )
            )
    
    # Handle co-occurrence bonuses - they are dictionaries in your scorer
    co_occurrence_bonuses = []
    for b in bd.co_occurrence_bonuses:
        if hasattr(b, 'flags_involved'):
            # It's an object
            co_occurrence_bonuses.append(
                CoOccurrenceBonusOut(
                    flags_involved=b.flags_involved,
                    bonus=b.bonus,
                    description=b.description,
                )
            )
        else:
            # It's a dict (this is what your scorer returns)
            co_occurrence_bonuses.append(
                CoOccurrenceBonusOut(
                    flags_involved=b.get("flags_involved", []),
                    bonus=b.get("bonus", 0),
                    description=b.get("description", ""),
                )
            )
    
    return ScoreBreakdownOut(
        raw_score           = float(bd.raw_score) if bd.raw_score else 0,
        safe_discount       = float(bd.safe_discount) if bd.safe_discount else 0,
        co_occurrence_bonus = float(bd.co_occurrence_bonus) if bd.co_occurrence_bonus else 0,
        adjusted_score      = float(bd.adjusted_score) if bd.adjusted_score else 0,
        normalized_score    = int(bd.normalized_score) if bd.normalized_score else 0,
        hard_floor_applied  = bool(bd.hard_floor_applied) if bd.hard_floor_applied is not None else False,
        contributions       = contributions,
        co_occurrence_bonuses = co_occurrence_bonuses,
    )


async def run_pipeline(
    raw_input:      str,
    use_playwright: bool = False,
    skip_cache:     bool = False,
) -> AnalysisResult:

    start_ms = time.monotonic() * 1000

    # Step 1: Preprocess
    ctx: AnalysisContext = await preprocess(raw_input)
    prefix    = "email" if ctx.mode == "email" else "url"
    cache_key = make_cache_key(prefix, raw_input)

    # Step 2: Cache check
    if not skip_cache:
        cached = await cache_get(cache_key)
        if cached:
            result             = AnalysisResult(**cached)
            result.cache_hit   = True
            result.duration_ms = int(time.monotonic() * 1000 - start_ms)
            return result

    logger.info("pipeline_start", mode=ctx.mode, domains=ctx.domains[:3])

    # Step 3: Run layers 1–3 in parallel, then layer 4
    layer1_flags, layer2_flags, layer3_flags = await asyncio.gather(
        run_layer1(ctx),
        run_layer2(ctx),
        run_layer3(ctx),
    )
    all_flags: list[Flag] = layer1_flags + layer2_flags + layer3_flags

    layer4_flags = await run_layer4(ctx, use_playwright=use_playwright)
    all_flags.extend(layer4_flags)

    # Step 4: Score
    scoring = calculate_score(all_flags)

    duration_ms = int(time.monotonic() * 1000 - start_ms)

    breakdown_out = _serialise_breakdown(scoring.breakdown) if scoring.breakdown else None

    result = AnalysisResult(
        score       = scoring.score,
        verdict     = scoring.verdict,
        flags       = scoring.flags,
        reasons     = scoring.reasons,
        breakdown   = breakdown_out,
        cache_hit   = False,
        duration_ms = duration_ms,
        input_type  = ctx.mode,
    )

    # Step 5: Cache + audit log
    ttl = TTL_EMAIL if ctx.mode == "email" else (
        TTL_URL_PHISHING if scoring.verdict == "PHISHING" else TTL_URL_SAFE
    )
    await cache_set(cache_key, result.dict(), ttl)

    logger.info(
        "pipeline_done",
        score       = scoring.score,
        verdict     = scoring.verdict,
        flags       = len(all_flags),
        co_bonuses  = len(scoring.breakdown.co_occurrence_bonuses) if scoring.breakdown else 0,
        duration_ms = duration_ms,
    )

    return result