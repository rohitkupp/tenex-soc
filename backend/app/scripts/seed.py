"""`make seed` → `python -m app.scripts.seed`. Creates the single live tenant
(`northwind`, docs/v2_migration/MIGRATION-01-evidence-first.md change 23) + the demo user.

Credentials come from the environment with sane local defaults — never a hardcoded
secret shipped for anything beyond local dev. Idempotent: re-running it when the demo
user already exists is a no-op, not an error. The tenant name is not overridable — it
must be exactly `LIVE_TENANT_NAME` ("northwind") to match the corpus generator's
train-split org (see `app.models.tenant`'s docstring), unlike the email/password below,
which have no such downstream dependency.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime

from sqlalchemy import select

from app.core.db import get_session_factory
from app.core.logging import configure_logging, get_logger
from app.core.security import hash_password
from app.models.base import bypass_tenant_scope
from app.models.tenant import get_or_create_live_tenant
from app.models.user import User

log = get_logger(__name__)

DEFAULT_EMAIL = "demo@tenex.local"
DEFAULT_PASSWORD = "tenex-demo-password"  # noqa: S105 - documented local-only default


def seed() -> None:
    email = os.environ.get("SEED_USER_EMAIL", DEFAULT_EMAIL)
    password = os.environ.get("SEED_USER_PASSWORD", DEFAULT_PASSWORD)

    session = get_session_factory()()
    try:
        # Login-by-email lookup, same as app.api.auth.login: no tenant is known yet.
        with bypass_tenant_scope(session):
            existing = session.execute(select(User).where(User.email == email)).scalar_one_or_none()

        if existing is not None:
            log.info("seed.already_exists", email=email, tenant_id=str(existing.tenant_id))
            return

        tenant = get_or_create_live_tenant(session)

        # Born verified: the demo user must be able to log in immediately on a fresh
        # `make up` + `make migrate` + `make seed`, and there is no pre-existing row
        # for alembic/versions/88fcc9caf4ea_users_email_verified_at.py's backfill to
        # have caught (that migration only backfills rows that already exist at
        # migrate time). This is the same "no Supabase configured locally" fallback
        # app.api.auth.signup applies, applied here for the one account this script
        # ever creates.
        user = User(
            tenant_id=tenant.id,
            email=email,
            password_hash=hash_password(password),
            email_verified_at=datetime.now(UTC),
        )
        session.add(user)
        session.commit()

        log.info(
            "seed.created",
            tenant_id=str(tenant.id),
            tenant_name=tenant.name,
            user_id=str(user.id),
            email=email,
        )
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def main() -> None:
    configure_logging()
    seed()


if __name__ == "__main__":
    main()
