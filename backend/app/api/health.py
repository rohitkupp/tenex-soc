"""Unauthenticated health endpoint with real dependency checks.

Returns 200 when the API process is alive even if a dependency is down — the
per-dependency detail tells you which one. Deployment health checks should key
on this, not on a bare process liveness probe.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter

from app.core.config import get_settings
from app.core.db import ping as db_ping
from app.core.logging import get_logger

router = APIRouter()
log = get_logger(__name__)


def _check(name: str, fn: Any) -> dict[str, Any]:
    try:
        return {"name": name, "ok": True, **(fn() or {})}
    except Exception as exc:
        log.warning("health.dependency_failed", dependency=name, error=str(exc))
        return {"name": name, "ok": False, "error": type(exc).__name__}


@router.get("/health")
def health() -> dict[str, Any]:
    settings = get_settings()
    dependencies = [_check("postgres", db_ping)]
    return {
        "status": "ok" if all(d["ok"] for d in dependencies) else "degraded",
        "version": "0.1.0",
        "demo_mode": settings.demo_mode,
        "llm_enabled": settings.llm_enabled,
        "dependencies": dependencies,
    }
