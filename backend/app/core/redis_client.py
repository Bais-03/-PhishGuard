import json
import hashlib
from typing import Any, Optional
import redis.asyncio as aioredis
from app.core.config import get_settings
import structlog

logger = structlog.get_logger()
settings = get_settings()

_redis_client: Optional[aioredis.Redis] = None


async def get_redis() -> aioredis.Redis:
    global _redis_client
    if _redis_client is None:
        _redis_client = aioredis.from_url(
            settings.redis_url,
            encoding="utf-8",
            decode_responses=True,
        )
    return _redis_client


async def close_redis():
    global _redis_client
    if _redis_client:
        await _redis_client.close()
        _redis_client = None


def make_cache_key(prefix: str, raw_input: str) -> str:
    digest = hashlib.sha256(raw_input.encode()).hexdigest()
    return f"{prefix}:{digest}"


# TTL constants (seconds)
TTL_EMAIL = 6 * 3600          # 6 hours
TTL_URL_PHISHING = 24 * 3600  # 24 hours
TTL_URL_SAFE = 3600           # 1 hour
TTL_DOMAIN_TRANCO = 7 * 86400 # 7 days
TTL_WHOIS = 48 * 3600         # 48 hours
TTL_VT = 24 * 3600            # 24 hours


async def cache_get(key: str) -> Optional[dict]:
    try:
        r = await get_redis()
        val = await r.get(key)
        if val:
            logger.info("cache_hit", key=key)
            return json.loads(val)
    except Exception as e:
        logger.warning("cache_get_error", key=key, error=str(e))
    return None


async def cache_set(key: str, value: dict, ttl: int) -> None:
    try:
        r = await get_redis()
        await r.setex(key, ttl, json.dumps(value))
    except Exception as e:
        logger.warning("cache_set_error", key=key, error=str(e))


async def cache_stats() -> dict:
    try:
        r = await get_redis()
        info = await r.info("stats")
        return {
            "hits": info.get("keyspace_hits", 0),
            "misses": info.get("keyspace_misses", 0),
            "hit_rate": round(
                info.get("keyspace_hits", 0)
                / max(1, info.get("keyspace_hits", 0) + info.get("keyspace_misses", 0))
                * 100,
                2,
            ),
        }
    except Exception as e:
        logger.warning("cache_stats_error", error=str(e))
        return {"hits": 0, "misses": 0, "hit_rate": 0}
