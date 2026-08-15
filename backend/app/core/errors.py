"""Uniform error envelope per docs/09-API-CONTRACT.md: `{"detail": "...", "code": "..."}`.

FastAPI's default `HTTPException` only emits `{"detail": ...}`. Routes that need the
documented shape raise `ApiError` instead; `api_error_handler` (wired in `app.main`)
renders it.
"""

from __future__ import annotations

from fastapi import Request
from fastapi.responses import JSONResponse


class ApiError(Exception):
    """Raise this, never a bare `HTTPException`, for any error a client should be able
    to branch on programmatically (`code`), not just display (`detail`)."""

    def __init__(self, *, status_code: int, code: str, detail: str) -> None:
        self.status_code = status_code
        self.code = code
        self.detail = detail
        super().__init__(detail)


async def api_error_handler(_request: Request, exc: ApiError) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code, content={"detail": exc.detail, "code": exc.code}
    )
