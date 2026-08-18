"""FastAPI application entrypoint.

Uploads go browser → this API directly, never through Vercel, so the ~4.5 MB
serverless body limit never applies. See docs/01-ARCHITECTURE.md.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, suppress

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi.errors import RateLimitExceeded

from app.api import (
    analyses,
    auth,
    events,
    feedback,
    health,
    incident_detail,
    incidents,
    stream,
    tier2,
    uploads,
)
from app.core.config import get_settings
from app.core.csrf import CSRFMiddleware
from app.core.errors import ApiError, api_error_handler
from app.core.logging import configure_logging, get_logger
from app.core.rate_limit import limiter, rate_limit_exceeded_handler
from app.pipeline.reaper import reap_stale_analyses
from app.queue import dispatch
from app.queue.topology import declare_topology_on_new_channel, get_connection

settings = get_settings()
configure_logging(settings.log_level)
log = get_logger(__name__)


# Well below `reaper.STALE_AFTER`, so a stuck analysis surfaces within a few minutes of crossing
# the threshold rather than up to a full interval later.
REAP_INTERVAL_SECONDS = 300


async def _reap_periodically() -> None:
    """Run the reaper on an interval until cancelled. Never lets one failure end the loop: a
    transient database error must not silently disable stuck-analysis detection for the lifetime
    of the process, which is precisely the kind of quiet degradation this reaper exists to
    catch."""
    while True:
        try:
            await asyncio.sleep(REAP_INTERVAL_SECONDS)
            reaped = await asyncio.to_thread(reap_stale_analyses)
            if reaped:
                log.info("api.reaper_pass", n_reaped=len(reaped))
        except asyncio.CancelledError:
            raise
        except Exception:
            log.warning("api.reaper_failed", exc_info=True)


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    log.info(
        "api.startup",
        llm_enabled=settings.llm_enabled,
        model=settings.anthropic_model,
    )
    # Idempotent (app.queue.topology.declare_topology's docstring) — safe alongside
    # every worker doing the same at its own startup, in any order. Best-effort: a
    # broker that's briefly unreachable at boot shouldn't crash-loop the API process
    # (uploads/pipeline kickoff would fail loudly per-request instead, which is the
    # right place for that failure to surface).
    try:
        warmup_connection = await get_connection()
        try:
            await declare_topology_on_new_channel(warmup_connection)
        finally:
            await warmup_connection.close()
    except Exception:
        log.warning("api.topology_declare_failed", exc_info=True)

    # Nothing else in the system notices an analysis whose driving message was lost — see
    # `app.pipeline.reaper`. Runs here rather than as a separate worker because it is a few
    # seconds of work on an interval measured in minutes; a dedicated container for one UPDATE
    # would be more moving parts than the job is worth.
    reaper_task = asyncio.create_task(_reap_periodically())
    try:
        yield
    finally:
        reaper_task.cancel()
        with suppress(asyncio.CancelledError):
            await reaper_task
        await dispatch.close()
        log.info("api.shutdown")


app = FastAPI(
    title="Tenex SOC Analyst API",
    description=(
        "Layered detection funnel over security telemetry: OCSF normalization → rules → "
        "signal processing → entity-window ML → sequence models → graph correlation → "
        "agentic triage."
    ),
    version="0.1.0",
    docs_url="/api/docs",
    openapi_url="/api/openapi.json",
    lifespan=lifespan,
)

# Order matters here. Starlette wraps middleware so the *last* one added via
# `add_middleware` ends up outermost (runs first on the way in, last on the way out).
# CSRFMiddleware is added first (so it sits inside CORSMiddleware) precisely so that a
# 403 it raises still passes back out *through* CORSMiddleware on the way to the
# client: without CORS headers on an error response, a cross-origin `fetch` in the
# browser can't read the response at all (it surfaces as an opaque network failure,
# not the 403 with a body the frontend needs to render). See app.core.csrf.
app.add_middleware(CSRFMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,  # required for the httpOnly session + CSRF cookies to ride
    allow_methods=["*"],
    # "*" here does not literally echo "*" back (which the fetch spec forbids for
    # credentialed requests) — Starlette's CORSMiddleware mirrors the exact
    # Access-Control-Request-Headers value on preflight, which already covers
    # CSRF_HEADER_NAME ("X-CSRF-Token") and every other header the frontend sends.
    allow_headers=["*"],
)

# Wiring required for app.core.rate_limit / app.core.errors to take effect — every
# `@limiter.limit(...)` decorator in app/api needs `app.state.limiter`, and both error
# types need a handler that renders docs/09's `{"detail", "code"}` envelope instead of
# FastAPI's/slowapi's default shape.
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, rate_limit_exceeded_handler)
app.add_exception_handler(ApiError, api_error_handler)

app.include_router(health.router, prefix="/api", tags=["ops"])
app.include_router(auth.router, prefix="/api/auth", tags=["auth"])
app.include_router(uploads.router, prefix="/api", tags=["uploads"])
app.include_router(analyses.router, prefix="/api", tags=["analyses"])
app.include_router(stream.router, prefix="/api", tags=["analyses"])
app.include_router(events.router, prefix="/api", tags=["events"])
app.include_router(incident_detail.router, prefix="/api", tags=["incidents"])
app.include_router(incidents.router, prefix="/api", tags=["incidents"])
app.include_router(feedback.router, prefix="/api", tags=["feedback"])
app.include_router(tier2.router, prefix="/api", tags=["tier2"])
