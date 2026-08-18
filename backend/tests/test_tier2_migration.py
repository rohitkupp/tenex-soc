"""Proves the live **Tier 2** database actually matches `app.tier2.views` — the drift guard
`app.tier2.indicator_overlap`, `app.tier2.technique_prevalence`, and `app.tier2.first_seen` all
depend on being accurate (previously also `app.tier2.sql_validator`'s allowlist and
`app.tier2.nl_to_sql`'s system prompt, both removed along with the NL-to-SQL chatbot).

The views and the read-only role moved out of the primary database with `tier2_signatures`
(migration `e2f71b3c8a45`) and are now provisioned by `app.core.db.init_tier2_schema`. The last
test here exercises that provisioning's re-runnability, which is the property the old
Alembic `downgrade()`/`upgrade()` round trip was checking.
"""

from __future__ import annotations

import pytest
from sqlalchemy import text

from app.core.db import get_tier2_engine, init_tier2_schema
from app.tier2.readonly_db import READONLY_ROLE_NAME, get_readonly_engine
from app.tier2.views import ALLOWED_VIEWS, VIEW_SCHEMAS


def test_every_allowlisted_view_exists_in_the_live_database() -> None:
    with get_tier2_engine().connect() as conn:
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
    with get_tier2_engine().connect() as conn:
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
    with get_tier2_engine().connect() as conn:
        rows = conn.execute(
            text(
                "SELECT table_name FROM information_schema.role_table_grants "
                "WHERE grantee = :role AND privilege_type = 'SELECT'"
            ),
            {"role": READONLY_ROLE_NAME},
        ).all()
    granted = {row.table_name for row in rows}
    assert granted == ALLOWED_VIEWS


def test_init_tier2_schema_is_idempotent_and_restores_a_dropped_surface() -> None:
    """The role, views and grants used to come from an Alembic migration against the primary
    database, and this test round-tripped that migration's `downgrade()`/`upgrade()`.

    They now come from `app.core.db.init_tier2_schema` against the Tier 2 database — see
    migration `e2f71b3c8a45` and that function's own docstring for why a second migration tree
    was not worth it for a derived, rebuildable store. The property worth testing is unchanged:
    provisioning must be re-runnable, and must restore the surface if it is missing. That is
    what makes it safe to call on every stage run and on a fresh CI database.
    """
    # `get_readonly_engine` is process-wide `@lru_cache`d, so its pool can hold connections
    # authenticated as a role object that is about to be replaced. A stale pooled connection
    # tied to a dropped role fails every query with "permission denied" rather than reconnecting
    # cleanly, so the pool is disposed on both sides of the drop.
    get_readonly_engine().dispose()

    with get_tier2_engine().begin() as conn:
        for view in ALLOWED_VIEWS:
            conn.execute(text(f"DROP VIEW IF EXISTS {view} CASCADE"))

    try:
        with get_tier2_engine().connect() as conn:
            gone = conn.execute(
                text(
                    "SELECT COUNT(*) FROM information_schema.views WHERE table_name = ANY(:names)"
                ),
                {"names": list(ALLOWED_VIEWS)},
            ).scalar_one()
        assert gone == 0, "precondition: the views should have been dropped"

        # Twice: the second call is the idempotency half, and must not raise.
        init_tier2_schema()
        init_tier2_schema()

        with get_tier2_engine().connect() as conn:
            restored = (
                conn.execute(
                    text(
                        "SELECT table_name FROM information_schema.views WHERE table_name = ANY(:n)"
                    ),
                    {"n": list(ALLOWED_VIEWS)},
                )
                .scalars()
                .all()
            )
            granted = (
                conn.execute(
                    text(
                        "SELECT table_name FROM information_schema.role_table_grants "
                        "WHERE grantee = :role AND privilege_type = 'SELECT'"
                    ),
                    {"role": READONLY_ROLE_NAME},
                )
                .scalars()
                .all()
            )
    finally:
        init_tier2_schema()
        get_readonly_engine().dispose()

    assert set(restored) == set(ALLOWED_VIEWS)
    assert set(granted) == set(ALLOWED_VIEWS)
