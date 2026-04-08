"""Redis caching layer with graceful fallback when Redis is unavailable."""

import hashlib
import json
import logging
from typing import Optional

from backend.app.core.config import (
    REDIS_URL, CACHE_TTL_SAFE, CACHE_TTL_SUSPICIOUS, CACHE_TTL_PHISHING,
)

logger = logging.getLogger(__name__)

_redis_client = None
_redis_available = False


def _get_redis():
    """Lazy-init Redis connection."""
    global _redis_client, _redis_available
    if _redis_client is not None:
        return _redis_client if _redis_available else None
    try:
        import redis
        _redis_client = redis.from_url(REDIS_URL, decode_responses=True, socket_timeout=2)
        _redis_client.ping()
        _redis_available = True
        logger.info("Redis connected at %s", REDIS_URL)
        return _redis_client
    except Exception:
        _redis_available = False
        _redis_client = True  # Sentinel to avoid retrying
        logger.warning("Redis unavailable – caching disabled")
        return None


def _cache_key(url: str) -> str:
    return f"shieldyono:scan:{hashlib.sha256(url.encode()).hexdigest()}"


def _ttl_for_tier(tier: str) -> int:
    return {
        "SAFE": CACHE_TTL_SAFE,
        "SUSPICIOUS": CACHE_TTL_SUSPICIOUS,
        "PHISHING": CACHE_TTL_PHISHING,
    }.get(tier, CACHE_TTL_SUSPICIOUS)


def get_cached_result(url: str) -> Optional[dict]:
    """Return cached scan result or None."""
    r = _get_redis()
    if r is None:
        return None
    try:
        data = r.get(_cache_key(url))
        if data:
            result = json.loads(data)
            result["cached"] = True
            return result
    except Exception as e:
        logger.warning("Cache read error: %s", e)
    return None


def set_cached_result(url: str, result: dict):
    """Cache a scan result with tier-appropriate TTL."""
    r = _get_redis()
    if r is None:
        return
    try:
        tier = result.get("risk_tier", "SUSPICIOUS")
        r.setex(_cache_key(url), _ttl_for_tier(tier), json.dumps(result, default=str))
    except Exception as e:
        logger.warning("Cache write error: %s", e)
