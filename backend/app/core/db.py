"""Database engine, session factory, and declarative base.

The engine is built lazily. Constructing it at import time would couple importing
*any* module to a resolvable driver and a reachable database — which breaks tests,
breaks `--help`, and turns a misconfigured DSN into an import error instead of a
connection error at the point of use.

Tenant isolation is enforced at the query layer (app/models/base.py, M1 onward),
not by remembering to add a filter. See docs/06-PRIVACY-SECURITY.md.
"""

from __future__ import annotations

import os
import re

from collections.abc import Iterator
from functools import lru_cache
from typing import Any, Final

from sqlalchemy import Engine, create_engine, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.core.config import get_settings

# One connection each, with one spare. Fourteen workers plus the API share a pooler capped at 15
# clients; a worker handles one message at a time, so anything larger is a claim on capacity it
# cannot use and another worker needs. See `get_engine`.
#
# Overridable by environment because the constraint is the *deployed* pooler's, not a property of
# the application. Under pytest a single test legitimately holds a session open while issuing an
# HTTP request that needs its own connection, which deadlocks against a ceiling of two and
# surfaces as `QueuePool limit of size 1 overflow 1 reached` half a minute later — a failure that
# reads like a leak rather than a configuration. The default stays production-safe: a deployment
# that sets nothing still gets 1+1.
DB_POOL_SIZE: Final[int] = int(os.environ.get("DB_POOL_SIZE", "1"))
DB_MAX_OVERFLOW: Final[int] = int(os.environ.get("DB_MAX_OVERFLOW", "1"))


class Base(DeclarativeBase):
    """Declarative base for every tenant-scoped ORM model, in the primary database."""


class Tier2Base(DeclarativeBase):
    """Declarative base for the Tier 2 database — a physically separate Postgres holding only
    pseudonymised, cross-tenant data.

    Deliberately a second `DeclarativeBase` rather than a schema inside `Base`. Two metadata
    objects mean a Tier 2 table and a tenant-scoped table cannot be joined in a query even by
    mistake, and `Base.metadata.create_all` can never reach across and create one in the wrong
    place. The separation CLAUDE.md rule 4 asks for is then a property of the wiring, not of
    everyone remembering which tables are which.
    """


_LOCAL_DB_HOSTS: Final[frozenset[str]] = frozenset(
    {"localhost", "127.0.0.1", "::1", "postgres", "tier2-postgres", "db"}
)


def assert_local_database(what: str) -> None:
    """Refuse to run a bulk-writing tool against a database that does not look local.

    The pytest suite grew this check after its migration round-trip nulled production columns
    (`tests/conftest.pytest_configure`). This is the same check for non-test entry points, added
    after the second incident of the same shape: `pipeline_demo fit-calibrators` — a harness that
    generates and ingests hundreds of thousands of synthetic events — was run on the deployed VM,
    whose `DATABASE_URL` is the production pooler. It filled the disk mid-run; Postgres died on
    `pg_wal: No space left on device` and crash-looped until the synthetic tenants were purged.

    Deliberately blunt, like its pytest sibling: a hostname allowlist, overridable by an explicit
    environment variable. A false positive costs a minute; a false negative costs an outage.
    """
    if os.environ.get("TENEX_ALLOW_NONLOCAL_DB") == "1":
        return
    url = get_settings().database_url
    match = re.search(r"@([^/:?]+)", url)
    host = match.group(1).lower() if match else None
    if host is not None and host not in _LOCAL_DB_HOSTS:
        raise RuntimeError(
            f"Refusing to run {what} against DATABASE_URL host {host!r}. It bulk-writes "
            "synthetic data and is meant for a local stack; running it against a deployed "
            "database has already caused a disk-full outage. Set TENEX_ALLOW_NONLOCAL_DB=1 "
            "only if you genuinely mean to target this database."
        )


@lru_cache
def get_engine() -> Engine:
    """Engine for the primary database.

    **Pool sizing is deliberately small.** The deployed topology is 14 worker containers plus the
    API against one managed pooler, and each of those holds its own pool: at the previous
    `pool_size=10, max_overflow=20` that is a theoretical 420 connections against a Supabase
    session-mode pooler capped at 15 clients. It did not merely risk exhaustion, it guaranteed it
    under load — a run whose triage had fully succeeded was dead-lettered at the next stage
    because no connection was available. Each worker processes one message at a time (prefetch 1),
    so a large pool buys nothing; the ceiling has to be shared, not claimed.

    `connect_args` disables psycopg's prepared statements, which is what makes transaction-mode
    pooling usable. In transaction mode a connection is handed back to the pooler between
    statements, so a prepared statement created on one physical connection may not exist on the
    next — surfacing as intermittent `prepared statement "..." does not exist` errors that look
    like corruption rather than configuration. Harmless in session mode, required in transaction
    mode, so it is set unconditionally rather than made another thing to remember when the URL
    changes.
    """
    settings = get_settings()
    return create_engine(
        settings.database_url,
        pool_pre_ping=True,
        pool_size=DB_POOL_SIZE,
        max_overflow=DB_MAX_OVERFLOW,
        pool_recycle=300,
        # `prepare_threshold: None` — transaction-mode pooling hands the connection back between
        # statements, so a prepared statement can vanish between uses (see the docstring).
        #
        # The TCP keepalives and timeouts exist because of a measured failure, not hygiene: when
        # the database crash-looped, in-flight queries were left waiting on sockets whose far end
        # was gone. Nothing ever timed out — psycopg's default is to wait forever — so those
        # checkouts never returned to the pool, and once all of them were hung the API answered
        # every request with a 30s QueuePool timeout until manually restarted. Keepalives detect
        # a dead peer in ~60s (30 idle + 3 probes × 10s) and fail the query, which returns the
        # connection to the pool and lets `pool_pre_ping` replace it.
        connect_args={
            "prepare_threshold": None,
            "connect_timeout": 10,
            "keepalives": 1,
            "keepalives_idle": 30,
            "keepalives_interval": 10,
            "keepalives_count": 3,
        },
        future=True,
    )


@lru_cache
def get_session_factory() -> sessionmaker[Session]:
    return sessionmaker(bind=get_engine(), autoflush=False, expire_on_commit=False, future=True)


@lru_cache
def get_tier2_engine() -> Engine:
    """Engine for the Tier 2 database. Smaller pool than the primary: only the `anonymize` and
    `tier2` stages touch it, at the end of a run, not on the request path."""
    settings = get_settings()
    return create_engine(
        settings.tier2_database_url,
        pool_pre_ping=True,
        # Tier 2 is a Postgres container on the same host with no pooler in front of it, so it
        # has no 15-client ceiling to respect — but only two stages touch it, at the end of a
        # run, so it needs very little either.
        pool_size=2,
        max_overflow=3,
        pool_recycle=300,
        future=True,
    )


@lru_cache
def get_tier2_session_factory() -> sessionmaker[Session]:
    return sessionmaker(
        bind=get_tier2_engine(), autoflush=False, expire_on_commit=False, future=True
    )


def init_tier2_schema() -> None:
    """Create the Tier 2 tables if they are absent.

    `create_all`, not Alembic, and that is a deliberate exception to CLAUDE.md's "Alembic for
    every schema change" rather than an oversight. Alembic here is configured against one URL
    and one metadata; a second migration tree for what is currently a two-table, append-only,
    derived store would cost more than it protects. Nothing in the Tier 2 database is a source
    of truth — every row is recomputed from the primary database on the next run — so the
    failure mode a migration history exists to prevent (an irreversible schema change over data
    you cannot regenerate) does not apply. If Tier 2 ever holds something that cannot be
    rebuilt, this needs to become a real migration tree.
    """
    # Import for the side effect of registering the models on `Tier2Base.metadata`.
    # Without this the call silently creates nothing when the caller happens not to
    # have imported them — a far worse failure than an unused-import lint.
    from app.models import tier2_event, tier2_signature  # noqa: F401

    engine = get_tier2_engine()
    with engine.begin() as conn:
        # Per-database, not per-cluster: the pgvector image ships the extension but each
        # database must enable it, and `tier2_signatures.embedding` is a `vector(1024)`.
        conn.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))
    Tier2Base.metadata.create_all(engine)
    _add_missing_tier2_columns(engine)
    _create_tier2_readonly_surface(engine)


# Columns added to a Tier 2 model after the table already exists somewhere. `create_all` only
# ever CREATEs — it inspects for the table's presence and skips it entirely, so a new attribute
# on the model is silently absent on every environment that already ran once, and the failure
# surfaces as an `UndefinedColumn` on the next sync rather than at startup.
#
# This is the price of the deliberate no-Alembic exception documented on `init_tier2_schema`.
# It stays honest for the same reason that exception does: the store is derived and every row is
# regenerable, so an additive, idempotent `ADD COLUMN IF NOT EXISTS` is the whole migration story
# a nullable column needs. Anything non-additive (a drop, a type change, a NOT NULL backfill) is
# the signal that Tier 2 has outgrown this and needs a real migration tree.
_TIER2_ADDED_COLUMNS: Final[tuple[tuple[str, str, str], ...]] = (
    ("tier2_signatures", "evidence_confidence", "REAL"),
)


def _add_missing_tier2_columns(engine: Engine) -> None:
    with engine.begin() as conn:
        for table, column, ddl_type in _TIER2_ADDED_COLUMNS:
            conn.execute(
                text(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {column} {ddl_type}")
            )


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


def get_tier2_db() -> Iterator[Session]:
    """FastAPI dependency for the Tier 2 database, mirroring `get_db`.

    Routes that read `tier2_signatures` (or its views) must depend on this, not `get_db` — that
    table moved out of the primary database, so a route still holding a `get_db` session queries
    a schema where it no longer exists and 500s. Every Tier 2 route reads the Tier 2 database
    now — the one former exception, `detector_reliability`, was removed with its chart.
    """
    db = get_tier2_session_factory()()
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


# The read-only surface docs/02 and docs/06 specify for Tier 2: two views over
# `tier2_signatures` and a locked-down role that can reach nothing else. It moved here with the
# table. Leaving it behind in the primary database would have granted a login SELECT on a view
# over a table that no longer exists there, while the real data sat in another database with no
# access control at all.
#
# Neither view exposes `embedding` — a 1024-dim vector is useless in a text-to-SQL answer and
# only bloats every row.
_READONLY_ROLE = "tier2_readonly"
_SIGNATURES_VIEW = "tier2_signatures_v"
_OVERLAP_VIEW = "tier2_indicator_overlap_v"


def _create_tier2_readonly_surface(engine: Engine) -> None:
    settings = get_settings()
    password = settings.tier2_readonly_db_password
    secret = password.get_secret_value() if hasattr(password, "get_secret_value") else password

    with engine.begin() as conn:
        dbname = conn.execute(text("SELECT current_database()")).scalar_one()
        # Passed as a session GUC rather than interpolated into the DDL text: the value never
        # appears in a statement string, so it cannot be broken out of by a crafted password.
        conn.execute(text("SELECT set_config('tenex.tier2_pw', :pw, true)"), {"pw": secret})
        # Postgres does not accept a bind parameter in CREATE/ALTER ROLE ... PASSWORD, so the
        # value has to reach the server as a literal. `format(..., %L)` inside a DO block is how
        # you do that without hand-rolling escaping — it applies Postgres's own quoting rules to
        # the password rather than trusting string concatenation.
        conn.execute(
            text(
                """
                DO $$
                DECLARE pw text := current_setting('tenex.tier2_pw');
                BEGIN
                    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tier2_readonly') THEN
                        EXECUTE format('ALTER ROLE tier2_readonly WITH PASSWORD %L', pw);
                    ELSE
                        EXECUTE format(
                            'CREATE ROLE tier2_readonly WITH LOGIN PASSWORD %L '
                            'NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION', pw
                        );
                    END IF;
                END $$;
                """
            )
        )

        # docs/06: "statement_timeout = 5s on the role", so it applies however the role connects.
        conn.execute(text(f"ALTER ROLE {_READONLY_ROLE} SET statement_timeout = '5s'"))
        conn.execute(text(f'GRANT CONNECT ON DATABASE "{dbname}" TO {_READONLY_ROLE}'))
        conn.execute(text(f"GRANT USAGE ON SCHEMA public TO {_READONLY_ROLE}"))

        conn.execute(
            text(
                f"CREATE OR REPLACE VIEW {_SIGNATURES_VIEW} AS "  # noqa: S608
                # `evidence_confidence` is appended *last* and must stay last. Postgres lets
                # CREATE OR REPLACE VIEW add columns only at the end of the select list —
                # inserting it next to `confidence`, where it reads better, makes the replace
                # fail on every environment whose view already exists.
                "SELECT id, tenant_hash, incident_type, mitre_techniques, source_types, "
                "confidence, indicator_hashes, observed_at, evidence_confidence "
                "FROM tier2_signatures"
            )
        )
        conn.execute(
            text(
                f"CREATE OR REPLACE VIEW {_OVERLAP_VIEW} AS "  # noqa: S608
                "SELECT indicator_hash, COUNT(*) AS signature_count, "
                "COUNT(DISTINCT tenant_hash) AS tenant_count, "
                "array_agg(DISTINCT incident_type) AS incident_types, "
                "MIN(observed_at) AS first_observed_at, MAX(observed_at) AS last_observed_at "
                "FROM tier2_signatures, LATERAL unnest(indicator_hashes) AS indicator_hash "
                "GROUP BY indicator_hash"
            )
        )
        # Exactly the two views, never the base table.
        conn.execute(
            text(f"GRANT SELECT ON {_SIGNATURES_VIEW}, {_OVERLAP_VIEW} TO {_READONLY_ROLE}")
        )
