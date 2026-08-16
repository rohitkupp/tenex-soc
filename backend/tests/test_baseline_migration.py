"""Round-trips `744b82efc029` (docs/v2_migration change 1's baseline store tables) through the
real `alembic` CLI machinery, the same way `tests/test_tier2_migration.py` proves `c59cf17b44e7`'s
`downgrade()` isn't rotten. Targets the migration's own `down_revision` (`bcc348df665e`) rather
than a relative `-1`, for the same future-proofing reason that test gives: whatever other
migrations land on top of this one later, `command.upgrade(cfg, "head")` still walks all the way
back up regardless of how many, and `command.downgrade(cfg, "bcc348df665e")` still walks down
past all of them to the fixed target.
"""

from __future__ import annotations

from sqlalchemy import text

from app.core.db import get_engine

_TABLES = ("baseline_windows", "baseline_profiles", "baseline_contacts")


def test_baseline_migration_downgrade_then_upgrade_round_trips_cleanly() -> None:
    from alembic.config import Config

    from alembic import command

    cfg = Config("alembic.ini")

    # Same defensive dispose as tests/test_tier2_migration.py's round trip: a pooled
    # connection that ran a query against these tables before the DROP could otherwise hold
    # a stale relation cache entry once they're recreated.
    get_engine().dispose()
    command.downgrade(cfg, "bcc348df665e")
    try:
        with get_engine().connect() as conn:
            present = conn.execute(
                text(
                    "SELECT table_name FROM information_schema.tables WHERE table_name = ANY(:names)"
                ),
                {"names": list(_TABLES)},
            ).all()
        assert present == [], f"downgrade() left tables behind: {[r.table_name for r in present]}"
    finally:
        command.upgrade(cfg, "head")
        get_engine().dispose()

    with get_engine().connect() as conn:
        found = {
            row.table_name
            for row in conn.execute(
                text(
                    "SELECT table_name FROM information_schema.tables WHERE table_name = ANY(:names)"
                ),
                {"names": list(_TABLES)},
            ).all()
        }
    assert found == set(_TABLES)
