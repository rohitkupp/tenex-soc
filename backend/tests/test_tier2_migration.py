"""Proves the live database (after `alembic upgrade head`) actually matches
`app.tier2.views` — the drift guard `app.tier2.indicator_overlap`, `app.tier2.
technique_prevalence`, and `app.tier2.first_seen` all depend on being accurate (previously
also `app.tier2.sql_validator`'s allowlist and `app.tier2.nl_to_sql`'s system prompt, both
removed along with the NL-to-SQL chatbot). Also exercises the migration's
`downgrade()`/`upgrade()` round trip for real, since a migration that only ever runs forward
in practice is a common place for an untested `downgrade()` to silently rot.
"""

from __future__ import annotations

import pytest
from sqlalchemy import text

from app.core.db import get_engine
from app.tier2.readonly_db import READONLY_ROLE_NAME, get_readonly_engine
from app.tier2.views import ALLOWED_VIEWS, VIEW_SCHEMAS


def test_every_allowlisted_view_exists_in_the_live_database() -> None:
    with get_engine().connect() as conn:
        rows = conn.execute(
            text("SELECT table_name FROM information_schema.views WHERE table_name = ANY(:names)"),
            {"names": list(ALLOWED_VIEWS)},
        ).all()
    found = {row.table_name for row in rows}
    assert found == ALLOWED_VIEWS, (
        f"app.tier2.views.ALLOWED_VIEWS ({ALLOWED_VIEWS}) and the live database "
        f"({found}) have drifted — update the migration or this constant."
    )


@pytest.mark.parametrize("view_name", sorted(VIEW_SCHEMAS))
def test_view_columns_match_the_declared_schema(view_name: str) -> None:
    with get_engine().connect() as conn:
        rows = conn.execute(
            text(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_name = :view_name ORDER BY ordinal_position"
            ),
            {"view_name": view_name},
        ).all()
    actual_columns = [row.column_name for row in rows]
    expected_columns = [name for name, _type in VIEW_SCHEMAS[view_name]]
    assert actual_columns == expected_columns


def test_tier2_readonly_role_is_granted_select_on_exactly_the_allowlisted_views() -> None:
    """The role's actual `information_schema.role_table_grants` must match
    `ALLOWED_VIEWS` exactly — not a superset (which would silently widen the NL->SQL
    role's real reach beyond what `app.tier2.sql_validator` assumes) and not a subset
    (which would just break the feature)."""
    with get_engine().connect() as conn:
        rows = conn.execute(
            text(
                "SELECT table_name FROM information_schema.role_table_grants "
                "WHERE grantee = :role AND privilege_type = 'SELECT'"
            ),
            {"role": READONLY_ROLE_NAME},
        ).all()
    granted = {row.table_name for row in rows}
    assert granted == ALLOWED_VIEWS


def test_migration_downgrade_then_upgrade_round_trips_cleanly() -> None:
    """Runs the real `alembic` CLI machinery (`alembic.command`, the same entry point
    `alembic upgrade head`/`alembic downgrade <rev>` use, which is how this migration was
    actually applied and verified during development) against the live database — not a
    dry run, and not a hand-rolled re-invocation of `upgrade()`/`downgrade()` that skips
    Alembic's own `op` context setup. Restores the upgraded state afterwards regardless of
    outcome, since every other `tests/test_tier2_*.py` module depends on the role/views
    existing.

    Targets the tier2 migration's own revision id (`c59cf17b44e7`, its `down_revision`)
    rather than the relative `-1`/`+1` offsets this test originally used. Relative offsets
    are only correct while the tier2 migration happens to be the current head; the signup
    work's `88fcc9caf4ea` (`users.email_verified_at`) landed on top of it, and `-1` from head now
    downgrades *that* migration instead, leaving the tier2 role/views untouched and this
    test asserting against the wrong revision entirely. Pinning to `c59cf17b44e7` for the
    downgrade target and `head` for the upgrade target is future-proof against every
    migration added after this one, not just that one.
    """
    from alembic.config import Config

    from alembic import command

    cfg = Config("alembic.ini")

    # `app.tier2.readonly_db.get_readonly_engine` is `@lru_cache`d process-wide, so its
    # pool may be holding connections authenticated as the *current* `tier2_readonly`
    # role. `DROP ROLE` below doesn't force-disconnect those (Postgres only refuses the
    # drop for privilege/ownership conflicts, not live sessions) — but once a *new* role
    # object is created under the same name, a stale pooled connection tied to the old
    # one's now-gone identity starts failing every query with "permission denied", not a
    # clean reconnect. Disposing the pool (both before and after the round trip) is what
    # keeps this test — and every test file after it in this run — talking to a
    # connection that actually matches whichever role currently exists.
    get_readonly_engine().dispose()

    command.downgrade(cfg, "c59cf17b44e7")
    try:
        with get_engine().connect() as conn:
            role_gone = conn.execute(
                text("SELECT 1 FROM pg_roles WHERE rolname = :role"), {"role": READONLY_ROLE_NAME}
            ).scalar_one_or_none()
            views_gone = conn.execute(
                text(
                    "SELECT COUNT(*) FROM information_schema.views WHERE table_name = ANY(:names)"
                ),
                {"names": list(ALLOWED_VIEWS)},
            ).scalar_one()
        assert role_gone is None
        assert views_gone == 0
    finally:
        command.upgrade(cfg, "head")
        get_readonly_engine().dispose()

    # Re-verify the restored state independently of the try/finally above.
    with get_engine().connect() as conn:
        role_back = conn.execute(
            text("SELECT 1 FROM pg_roles WHERE rolname = :role"), {"role": READONLY_ROLE_NAME}
        ).scalar_one_or_none()
        views_back = conn.execute(
            text("SELECT table_name FROM information_schema.views WHERE table_name = ANY(:names)"),
            {"names": list(ALLOWED_VIEWS)},
        ).all()
    assert role_back is not None
    assert {row.table_name for row in views_back} == ALLOWED_VIEWS
