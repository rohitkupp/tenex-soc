"""FastAPI application entrypoint.

Uploads go browser → this API directly, never through Vercel, so the ~4.5 MB
serverless body limit never applies. See docs/01-ARCHITECTURE.md.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import health
from app.core.config import get_settings
from app.core.logging import configure_logging, get_logger

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

app.include_router(health.router, prefix="/api", tags=["ops"])
