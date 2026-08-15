"""users email_verified_at

Self-serve signup: adds `users.email_verified_at`, nullable, no default. See
`app.core.verification`'s module docstring for the full design -- Supabase Auth's
built-in email sender is the email-ownership oracle, this app's own Postgres row is
the durable record of the outcome once we've read that oracle once.

**Why every existing row is backfilled to `now()` here, in the same migration that
adds the column, rather than left `NULL` for `app.api.auth.login`'s upstream check to
resolve lazily.** That upstream check only fires when
`Settings.email_verification_enabled` is true, i.e. `SUPABASE_URL` /
`SUPABASE_SERVICE_ROLE_KEY` are set -- which they are not for local dev, CI, or (as of
this migration) any environment this product has actually been deployed to. A backfill
of `NULL` would mean every account that existed before this migration -- including the
seeded demo user (`app/scripts/seed.py`) -- permanently 403s on login the moment this
migration runs, with no upstream Supabase row for any of them to ever be confirmed
against (they were never invited through Supabase; they predate that flow entirely).
`now()` is the only value that keeps "migrate" and "lock out every existing account"
from being the same event. New accounts, from this point on, are the ones that go
through the real signup flow and can be legitimately `NULL` until confirmed.

Revision ID: 88fcc9caf4ea
Revises: ccb431c4c689
Create Date: 2026-08-15 05:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "88fcc9caf4ea"
down_revision: str | None = "ccb431c4c689"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "users", sa.Column("email_verified_at", sa.DateTime(timezone=True), nullable=True)
    )
    # Backfill every pre-existing row -- see module docstring for why this can't be
    # left NULL. Deliberately unconditional (no WHERE): the column was just added, so
    # every row is NULL at this point in the migration; this also makes the statement
    # idempotent if this migration is ever re-run against a partially-migrated DB.
    op.execute("UPDATE users SET email_verified_at = now()")


def downgrade() -> None:
    op.drop_column("users", "email_verified_at")
