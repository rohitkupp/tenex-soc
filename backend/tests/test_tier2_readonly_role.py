"""Proves the database-level half of docs/06 "Text-to-SQL safety" against the *real*
`tier2_readonly` Postgres role provisioned by
`alembic/versions/ccb431c4c689_tier2_readonly_role_and_views.py` — not by inspecting the
migration's SQL text, by actually connecting as that role and trying.

Milestone brief: "Prove the read-only role genuinely cannot reach `events` or `users` —
connect AS that role and show the permission denied." This file is that proof.
"""

from __future__ import annotations

import psycopg
import pytest
from sqlalchemy import text

from app.core.config import get_settings
from app.core.db import get_engine
from app.tier2.readonly_db import READONLY_ROLE_NAME, get_readonly_engine, readonly_database_url
from app.tier2.views import ALLOWED_VIEWS


@pytest.fixture(scope="module")
def readonly_conn():
    settings = get_settings()
    conn = psycopg.connect(
        readonly_database_url(settings).replace("postgresql+psycopg://", "postgresql://")
    )
    conn.autocommit = True
    try:
        yield conn
    finally:
        conn.close()


def _cursor(conn):
    return conn.cursor()


# ---------------------------------------------------------------------------- role exists, correctly shaped


def test_role_exists_and_has_no_superuser_or_create_privileges() -> None:
    with get_engine().connect() as conn:
        row = conn.execute(
            text(
                "SELECT rolsuper, rolcreatedb, rolcreaterole, rolreplication "
                "FROM pg_roles WHERE rolname = :role"
            ),
            {"role": READONLY_ROLE_NAME},
        ).one_or_none()
    assert row is not None, f"{READONLY_ROLE_NAME} role does not exist — run `alembic upgrade head`"
    rolsuper, rolcreatedb, rolcreaterole, rolreplication = row
    assert rolsuper is False
    assert rolcreatedb is False
    assert rolcreaterole is False
    assert rolreplication is False


def test_role_has_five_second_statement_timeout() -> None:
    with get_engine().connect() as conn:
        setconfig = conn.execute(
            text("SELECT rolconfig FROM pg_roles WHERE rolname = :role"),
            {"role": READONLY_ROLE_NAME},
        ).scalar_one()
    assert setconfig is not None
    assert any("statement_timeout=5s" in entry for entry in setconfig)


# ---------------------------------------------------------------------------- what it CAN reach


def test_can_connect_as_the_readonly_role(readonly_conn) -> None:
    cur = _cursor(readonly_conn)
    cur.execute("SELECT current_user")
    assert cur.fetchone()[0] == READONLY_ROLE_NAME


@pytest.mark.parametrize("view_name", sorted(ALLOWED_VIEWS))
def test_can_select_from_every_allowlisted_view(readonly_conn, view_name: str) -> None:
    cur = _cursor(readonly_conn)
    cur.execute(f"SELECT * FROM {view_name} LIMIT 1")
    cur.fetchall()  # must not raise


def test_statement_timeout_is_five_seconds_on_this_connection(readonly_conn) -> None:
    cur = _cursor(readonly_conn)
    cur.execute("SHOW statement_timeout")
    assert cur.fetchone()[0] == "5s"


def test_a_slow_query_is_killed_by_statement_timeout(readonly_conn) -> None:
    """`pg_sleep` itself is blocked by `app.tier2.sql_validator`'s function blocklist, but
    the role-level `statement_timeout` is the independent, database-enforced backstop the
    milestone brief calls for -- this proves that backstop fires on its own, with no
    validator involved at all (a raw `pg_sleep` call over the wire)."""
    cur = _cursor(readonly_conn)
    with pytest.raises(psycopg.errors.QueryCanceled):
        cur.execute("SELECT pg_sleep(10)")


# ---------------------------------------------------------------------------- what it CANNOT reach


@pytest.mark.parametrize(
    "sql",
    [
        pytest.param("SELECT * FROM events LIMIT 1", id="events"),
        pytest.param("SELECT * FROM users LIMIT 1", id="users"),
        pytest.param("SELECT * FROM tier2_signatures LIMIT 1", id="tier2_signatures_base_table"),
        pytest.param("SELECT * FROM analyses LIMIT 1", id="analyses"),
        pytest.param("SELECT * FROM incidents LIMIT 1", id="incidents"),
        pytest.param("SELECT * FROM triage_verdicts LIMIT 1", id="triage_verdicts"),
        pytest.param("SELECT * FROM tenants LIMIT 1", id="tenants"),
        pytest.param("SELECT * FROM entities LIMIT 1", id="entities"),
    ],
)
def test_permission_denied_for_every_out_of_scope_table(readonly_conn, sql: str) -> None:
    cur = _cursor(readonly_conn)
    with pytest.raises(psycopg.errors.InsufficientPrivilege, match="permission denied"):
        cur.execute(sql)


def test_cannot_perform_ddl(readonly_conn) -> None:
    cur = _cursor(readonly_conn)
    with pytest.raises(psycopg.Error):
        cur.execute("DROP TABLE events")


def test_cannot_write_to_the_views_it_can_read() -> None:
    """`GRANT SELECT` only — no `INSERT`/`UPDATE`/`DELETE` grant on either view, so even a
    write through the view itself (not just the base table) is refused. Uses its own
    connection (autocommit) so a rejected statement doesn't poison `readonly_conn`'s
    session for the rest of the module."""
    settings = get_settings()
    conn = psycopg.connect(
        readonly_database_url(settings).replace("postgresql+psycopg://", "postgresql://")
    )
    conn.autocommit = True
    try:
        cur = conn.cursor()
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            cur.execute("DELETE FROM tier2_signatures_v")
    finally:
        conn.close()


def test_readonly_engine_can_be_used_directly() -> None:
    """`app.tier2.readonly_db.get_readonly_engine` (SQLAlchemy, not raw psycopg) is what
    `app.tier2.nl_to_sql`/`run_readonly_query` actually use -- proves that path works too,
    not just a hand-rolled psycopg connection."""
    engine = get_readonly_engine()
    with engine.connect() as conn:
        result = conn.execute(text(f"SELECT * FROM {sorted(ALLOWED_VIEWS)[0]} LIMIT 1"))
        result.fetchall()
