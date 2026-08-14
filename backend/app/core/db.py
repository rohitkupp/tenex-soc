"""Database engine, session factory, and declarative base.

The engine is built lazily. Constructing it at import time would couple importing
*any* module to a resolvable driver and a reachable database — which breaks tests,
breaks `--help`, and turns a misconfigured DSN into an import error instead of a
connection error at the point of use.

Tenant isolation is enforced at the query layer (app/models/base.py, M1 onward),
not by remembering to add a filter. See docs/06-PRIVACY-SECURITY.md.
"""

from __future__ import annotations

from collections.abc import Iterator
from functools import lru_cache
from typing import Any

from sqlalchemy import Engine, create_engine, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.core.config import get_settings


class Base(DeclarativeBase):
    """Declarative base for every ORM model."""


@lru_cache
def get_engine() -> Engine:
    settings = get_settings()
    return create_engine(
        settings.database_url,
        pool_pre_ping=True,
        pool_size=10,
        max_overflow=20,
        future=True,
    )


@lru_cache
def get_session_factory() -> sessionmaker[Session]:
    return sessionmaker(bind=get_engine(), autoflush=False, expire_on_commit=False, future=True)


def get_db() -> Iterator[Session]:
    """FastAPI dependency. Commits on success, rolls back on any exception."""
    db = get_session_factory()()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def ping() -> dict[str, Any]:
    """Health probe: connectivity plus confirmation that pgvector is installed."""
    with get_engine().connect() as conn:
        conn.execute(text("SELECT 1"))
        has_vector = conn.execute(
            text("SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'vector')")
        ).scalar()
    return {"connected": True, "pgvector": bool(has_vector)}
