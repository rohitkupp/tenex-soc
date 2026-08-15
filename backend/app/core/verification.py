"""Email-ownership oracle for self-serve signup (docs/06 "Self-serve signup and email
verification", docs/09's Auth table).

**The design.** This app never authenticates against Supabase and never stores a
second password there -- Supabase Auth is used for exactly one thing: proving someone
controls the mailbox behind a signup email. `send_verification_email` below calls
Supabase's admin `POST /auth/v1/invite` endpoint, which is the only built-in-sender
primitive in Supabase Auth that actually sends mail (`generate_link`, the other
obvious candidate, only *returns* a link -- it never sends anything, verified against
Supabase's own docs). Inviting an email creates a row in Supabase's own `auth.users`
table and mails a confirmation link; when the user clicks it, Supabase stamps that
row's `email_confirmed_at` and redirects the browser to `frontend_base_url`.

This app's own `users` table is, and remains, the actual identity and authorization
store -- `tenant_id`, `password_hash`, and now `email_verified_at` all live here, not
in Supabase. `is_email_confirmed_upstream` is how we read the *outcome* of that
Supabase-side click back into this system: `app.api.auth.login` calls it once per
still-unverified account, and on the first `True` read stamps this table's own
`email_verified_at` so every login after that is a single local column check, never a
second round trip to another system.

**The one real coupling, and why it's safe.** `is_email_confirmed_upstream` runs a
raw `SELECT ... FROM auth.users` against `Settings.database_url` -- which, in any
environment where `email_verification_enabled` is true, is deliberately the *same*
Supabase Postgres instance that Supabase Auth itself writes to. That's what makes a
webhook or a polling service unnecessary: this app already has read access to the
one row it needs. `auth.users` is a schema this app does not own and cannot migrate
-- it is Supabase's, not ours -- so it is read via `sqlalchemy.text()` rather than an
ORM-mapped class, and that raw SQL deliberately bypasses `app.models.base`'s
tenant-scope hook (that hook only ever wraps ORM-mapped, `TenantScopedMixin` classes;
`app.models.base`'s own docstring names raw `text()` SQL as its one known,
by-design boundary). Bypassing it here is correct, not a gap: `auth.users` is not a
tenant-scoped table in the first place -- it belongs to Supabase's schema, keyed by
email, with no `tenant_id` column to scope by -- so there is no tenant predicate to
have accidentally skipped.

**Local dev has no `auth` schema at all.** The Docker Postgres this repo's tests and
`make up` run against is a plain Postgres instance with none of Supabase's
infrastructure -- there is no `auth.users` table to query. `is_email_confirmed_upstream`
treats that (and any other reason the query can't execute -- wrong permissions, the
schema renamed, etc.) as "not confirmed" rather than letting it surface as a 500,
since a missing upstream oracle is not the caller's fault. In practice this function is
only ever reached when `Settings.email_verification_enabled` is true (see
`app.api.auth.login`), which itself requires a real Supabase project to be configured
-- so local dev never calls it at all. The defensive handling here is what keeps that
true by construction rather than by convention.
"""

from __future__ import annotations

import httpx
from sqlalchemy import text
from sqlalchemy.exc import DatabaseError, ProgrammingError
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.logging import get_logger

log = get_logger(__name__)

# Short on purpose: this call sits in the request path of POST /api/auth/signup and
# /resend-verification. A slow or hung Supabase would otherwise stall the response
# indefinitely; 5s is generous for a same-cloud-region admin API call and short enough
# that a caller notices "verification email might be delayed" long before a browser
# timeout, not "the site is down".
_SEND_TIMEOUT_SECONDS = 5.0


def send_verification_email(email: str) -> bool:
    """POST the Supabase Auth admin `invite` call, which both creates the upstream
    `auth.users` row (if it doesn't already exist) and sends the confirmation email in
    one request. Returns whether the call succeeded -- **never raises**. A signup or
    resend must not 500 because a third-party mail provider is slow, rate-limiting, or
    down: the account this app owns already exists (or the resend request is a no-op
    either way), and the user can always ask to resend."""
    settings = get_settings()
    try:
        response = httpx.post(
            f"{settings.supabase_url}/auth/v1/invite",
            headers={
                "Authorization": f"Bearer {settings.supabase_service_role_key.get_secret_value()}",
                "apikey": settings.supabase_service_role_key.get_secret_value(),
            },
            json={
                "email": email,
                "redirect_to": f"{settings.frontend_base_url}/login?verified=1",
            },
            timeout=_SEND_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
    except Exception as exc:  # deliberate, see docstring: this call must never propagate
        log.warning("verification.send_failed", error=str(exc))
        return False
    return True


def is_email_confirmed_upstream(db: Session, email: str) -> bool:
    """Has Supabase's own `auth.users` row for `email` been confirmed? See module
    docstring for the full design and why raw `text()` against another system's schema
    is the correct tool here, not an oversight of the tenant-scope hook.

    Returns `False` (never raises) both when the row exists but is unconfirmed *and*
    when the query can't run at all (no `auth` schema locally, wrong grants, etc.) --
    both are "not confirmed" from the caller's point of view. `ProgrammingError` is
    Postgres's category for "the object referenced doesn't exist" (e.g. `UndefinedTable`
    when there's no `auth` schema); `DatabaseError` is its broader parent, kept as a
    second, wider net for any other server-side failure of this specific query. A
    caught error rolls back `db` because Postgres aborts the entire transaction on the
    first failing statement -- without the rollback, every later query this request
    tries to run on the same session (including the login row lookup that led here)
    would fail too, not just this one.
    """
    try:
        # `.first()`, not `.scalar_one_or_none()`. The latter raises `MultipleResultsFound`
        # on a duplicate upstream row, and that exception is not a `DatabaseError` — it
        # would escape the handler below and 500 a login. `auth.users.email` is unique in
        # a stock Supabase project, so this should never happen; but "should never happen"
        # in a schema this app does not own and cannot migrate is exactly the kind of
        # assumption that should not be load-bearing on the login path. Any row confirms.
        row = db.execute(
            text("SELECT email_confirmed_at FROM auth.users WHERE email = :email LIMIT 1"),
            {"email": email},
        ).scalar()
    except (ProgrammingError, DatabaseError) as exc:
        log.warning("verification.upstream_query_failed", error=str(exc))
        db.rollback()
        return False
    # `row` is `email_confirmed_at` itself (the only selected column), so it is `None`
    # both when there is no matching upstream user at all and when there is one but
    # `email_confirmed_at` is still NULL -- both correctly mean "not confirmed yet".
    return row is not None
