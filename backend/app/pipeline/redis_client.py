"""Lazy async Redis client — the SSE pub/sub bus (docs/01: "`redis` (SSE pub/sub
only)"). Mirrors the laziness of `app.core.db.get_engine`/`app.storage.client.
get_s3_client`: constructing a client at import time would couple importing any module
to a reachable Redis instance."""

from __future__ import annotations

from functools import lru_cache

import redis.asyncio as redis

from app.core.config import get_settings


@lru_cache
def get_redis() -> redis.Redis:
    settings = get_settings()
    return redis.from_url(settings.redis_url, decode_responses=True)
