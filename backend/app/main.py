"""
PhishGuard — FastAPI Application
"""
import time
import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from app.core.config import get_settings
from app.core.redis_client import get_redis, close_redis, cache_stats
from app.core.pipeline import run_pipeline
from app.detectors.layer3_apis import load_tranco_into_memory
from app.models.schemas import EmailInput, UrlInput, AnalysisResult
import structlog

logger = structlog.get_logger()
settings = get_settings()

limiter = Limiter(key_func=get_remote_address, storage_uri=settings.redis_url)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("startup_begin")

    # Load Tranco list into memory
    count = load_tranco_into_memory(settings.tranco_file_path)
    logger.info("tranco_loaded", domains=count)

    # Verify Redis connection
    try:
        r = await get_redis()
        await r.ping()
        logger.info("redis_connected")
    except Exception as e:
        logger.warning("redis_unavailable", error=str(e))

    app.state.start_time = time.time()
    yield

    # Shutdown
    await close_redis()
    logger.info("shutdown_complete")


app = FastAPI(
    title="PhishGuard API",
    description="Production-grade phishing detection — Resonance 2K26",
    version="1.0.0",
    lifespan=lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Routes ────────────────────────────────────────────────────────

@app.post("/analyze/email", response_model=AnalysisResult, tags=["Detection"])
@limiter.limit(f"{settings.rate_limit_per_minute}/minute")
@limiter.limit(f"{settings.rate_limit_per_day}/day")
async def analyze_email(request: Request, data: EmailInput):
    """
    Analyze a raw RFC 2822 email string for phishing indicators.
    """
    if not data.raw_email.strip():
        raise HTTPException(status_code=400, detail="raw_email cannot be empty")

    result = await run_pipeline(data.raw_email, use_playwright=False)
    return result


@app.post("/analyze/url", response_model=AnalysisResult, tags=["Detection"])
@limiter.limit(f"{settings.rate_limit_per_minute}/minute")
@limiter.limit(f"{settings.rate_limit_per_day}/day")
async def analyze_url(request: Request, data: UrlInput):
    """
    Analyze a URL for phishing indicators.
    Optionally runs Playwright deep render for high-suspicion URLs.
    """
    url = data.url.strip()
    if not url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="URL must start with http:// or https://")

    # Quick pre-score to decide if Playwright is worth running
    result = await run_pipeline(url, use_playwright=False)

    # If suspicious/phishing and Playwright enabled, do deep scan
    if result.score >= 35 and settings.enable_playwright and not result.cache_hit:
        result = await run_pipeline(url, use_playwright=True, skip_cache=True)

    return result


@app.get("/health", tags=["System"])
async def health_check():
    """
    Health check — returns status of all dependencies.
    """
    redis_ok = False
    try:
        r = await get_redis()
        await r.ping()
        redis_ok = True
    except Exception:
        pass

    return {
        "status": "healthy" if redis_ok else "degraded",
        "redis": "ok" if redis_ok else "unavailable",
        "vt_api": "configured" if settings.vt_api_key else "not configured",
        "gsb_api": "configured" if settings.google_safe_browsing_key else "not configured",
        "abuseipdb": "configured" if settings.abuseipdb_key else "not configured",
        "uptime_s": round(time.time() - app.state.start_time, 1)
        if hasattr(app.state, "start_time")
        else 0,
        "version": "1.0.0",
    }


@app.get("/cache/stats", tags=["System"])
async def get_cache_stats():
    """
    Redis cache hit/miss statistics.
    """
    stats = await cache_stats()
    return stats


@app.get("/", tags=["System"])
async def root():
    return {
        "name": "PhishGuard",
        "version": "1.0.0",
        "docs": "/docs",
        "health": "/health",
    }


# ── Debug endpoint (show full score breakdown) ─────────────────────────────

from app.models.schemas import UrlInput as _UrlInput
from app.core.scorer import explain_score as _explain_score
from fastapi.responses import PlainTextResponse


@app.post("/debug/score", tags=["Debug"], response_class=PlainTextResponse)
async def debug_score(request: Request, data: _UrlInput):
    """
    Returns a plain-text score explanation trace — useful on demo day
    to walk judges through exactly how the score was calculated.
    """
    result = await run_pipeline(data.url.strip(), use_playwright=False, skip_cache=True)
    # Re-run explain_score on the returned flags
    explanation = _explain_score(result.flags)
    return explanation
