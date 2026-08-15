"""FastAPI application entrypoint.

Uploads go browser → this API directly, never through Vercel, so the ~4.5 MB
serverless body limit never applies. See docs/01-ARCHITECTURE.md.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi.errors import RateLimitExceeded

from app.api import analyses, auth, health, uploads
from app.core.config import get_settings
from app.core.errors import ApiError, api_error_handler
from app.core.logging import configure_logging, get_logger
from app.core.rate_limit import limiter, rate_limit_exceeded_handler

settings = get_settings()
configure_logging(settings.log_level)
log = get_logger(__name__)


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    log.info(
        "api.startup",
        demo_mode=settings.demo_mode,
        llm_enabled=settings.llm_enabled,
        model=settings.anthropic_model,
    )
    yield
    log.info("api.shutdown")


app = FastAPI(
    title="Tenex SOC Analyst API",
    description=(
        "Layered detection funnel over security telemetry: OCSF normalization → rules → "
        "signal processing → entity-window ML → sequence models → graph correlation → "
        "agentic triage → response planning."
    ),
    version="0.1.0",
    docs_url="/api/docs",
    openapi_url="/api/openapi.json",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
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
