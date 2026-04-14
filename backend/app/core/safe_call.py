"""
Safe API call wrapper — every external API call uses this.
On timeout / rate-limit / error → returns zero-weight neutral result.
Never lets one API failure crash the whole analysis.
"""
import asyncio
from typing import Callable, Any
import structlog

logger = structlog.get_logger()


class RateLimitError(Exception):
    pass


async def safe_api_call(fn: Callable, source_name: str, timeout: float = 5.0) -> dict:
    """
    Wraps an async callable. Returns a zero-weight result on any failure.
    The weight_multiplier=0.0 tells the aggregator to ignore this source's score.
    """
    try:
        async with asyncio.timeout(timeout):
            return await fn()
    except asyncio.TimeoutError:
        logger.warning("api_timeout", source=source_name)
        return {
            "source": source_name,
            "status": "timeout",
            "score": 0,
            "weight_multiplier": 0.0,
            "flags": [],
        }
    except RateLimitError:
        logger.warning("api_rate_limited", source=source_name)
        await asyncio.sleep(0.5)
        return {
            "source": source_name,
            "status": "rate_limited",
            "score": 0,
            "weight_multiplier": 0.0,
            "flags": [],
        }
    except Exception as e:
        logger.warning("api_error", source=source_name, error=str(e))
        return {
            "source": source_name,
            "status": "error",
            "score": 0,
            "weight_multiplier": 0.0,
            "flags": [],
        }
