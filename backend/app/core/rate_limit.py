"""Shared `slowapi` limiter. docs/06-PRIVACY-SECURITY.md: 5/min on login, 10/hour on
upload. One `Limiter` instance so both routers share the same in-memory bucket store."""

from __future__ import annotations

from fastapi import Request
from fastapi.responses import JSONResponse
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)


async def rate_limit_exceeded_handler(_request: Request, _exc: RateLimitExceeded) -> JSONResponse:
    """Same `{"detail", "code"}` envelope as every other error (docs/09), rather than
    slowapi's default plain-text 429."""
    return JSONResponse(
        status_code=429,
        content={"detail": "Too many requests. Try again later.", "code": "rate_limited"},
    )
