"""The second, database-enforced layer docs/06 asks for: `app.tier2.sql_validator` is the
application-level gate, but every validated Tier 2 query is actually *executed* through a
connection authenticated as `tier2_readonly` — a dedicated Postgres role, provisioned by
`alembic/versions/*_tier2_readonly_role_and_views.py`, granted `SELECT` on exactly
`app.tier2.views.ALLOWED_VIEWS` and nothing else, with `statement_timeout = 5s` set on the
role itself. Never the app's own privileged `tenex` user — see that migration's docstring
for why a validator bypass should still hit a wall at the database.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Any

from sqlalchemy import Engine, create_engine, text
from sqlalchemy.engine import make_url

from app.core.config import Settings, get_settings

READONLY_ROLE_NAME = "tier2_readonly"

# Redundant with `ALTER ROLE tier2_readonly SET statement_timeout = '5s'` (the migration,
# the authoritative source per docs/06's literal wording "statement_timeout = 5s on the
# role") -- set again per-connection here as defense in depth, in case a future connection
# pooler/proxy sits between this engine and Postgres and doesn't preserve role-level GUC
# defaults across a pooled session.
_STATEMENT_TIMEOUT_MS = 5_000


def readonly_database_url(settings: Settings) -> str:
    """`settings.database_url` with the user/password swapped for the `tier2_readonly`
    role — same host, port, and database as the app's own connection, deliberately (this
    role's isolation comes entirely from Postgres grants, not from being on a different
    server)."""
    url = make_url(settings.database_url)
    return url.set(
        username=READONLY_ROLE_NAME,
        password=settings.tier2_readonly_db_password.get_secret_value(),
    ).render_as_string(hide_password=False)


@lru_cache
def get_readonly_engine() -> Engine:
    settings = get_settings()
    return create_engine(
        readonly_database_url(settings),
        pool_pre_ping=True,
        pool_size=5,
        max_overflow=5,
        future=True,
    )


def run_readonly_query(
    sql: str, *, engine: Engine | None = None
) -> tuple[list[str], list[list[Any]]]:
    """Executes `sql` (already validated + `LIMIT`-capped by `app.tier2.sql_validator` —
    this function does not itself validate anything) as `tier2_readonly` and returns
    `(column_names, rows)`, rows as plain JSON-safe lists (never SQLAlchemy `Row`/driver
    objects, so `app.schemas.tier2.Tier2QueryResponse` can serialize them without a custom
    encoder)."""
    engine = engine or get_readonly_engine()
    with engine.connect() as conn:
        conn.execute(text(f"SET statement_timeout = {_STATEMENT_TIMEOUT_MS}"))
        result = conn.execute(text(sql))
        columns = list(result.keys())
        rows = [list(row) for row in result.fetchall()]
    return columns, rows
