"""`make seed` → `python -m app.scripts.seed`. Creates the demo tenant + user.

Credentials come from the environment with sane local defaults — never a hardcoded
secret shipped for anything beyond local dev. Idempotent: re-running it when the demo
user already exists is a no-op, not an error.
"""

from __future__ import annotations

import os
import secrets

from sqlalchemy import select

from app.core.db import get_session_factory
from app.core.logging import configure_logging, get_logger
from app.core.security import hash_password
from app.models.base import bypass_tenant_scope
from app.models.tenant import Tenant
from app.models.user import User

log = get_logger(__name__)

DEFAULT_TENANT_NAME = "Demo Tenant"
DEFAULT_EMAIL = "demo@tenex.local"
DEFAULT_PASSWORD = "tenex-demo-password"  # noqa: S105 - documented local-only default


def seed() -> None:
    tenant_name = os.environ.get("SEED_TENANT_NAME", DEFAULT_TENANT_NAME)
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

        tenant = Tenant(name=tenant_name, pseudonym_salt=secrets.token_bytes(32))
        session.add(tenant)
        session.flush()  # assign tenant.id before the user row references it

        user = User(tenant_id=tenant.id, email=email, password_hash=hash_password(password))
        session.add(user)
        session.commit()

        log.info(
            "seed.created",
            tenant_id=str(tenant.id),
            tenant_name=tenant_name,
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
