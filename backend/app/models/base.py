"""Structural tenant isolation.

docs/06-PRIVACY-SECURITY.md is explicit: tenant isolation must be "enforce[d] via a
SQLAlchemy base query class, not by remembering." This module is that enforcement.

Every table that carries `tenant_id` (docs/02-DATA-MODEL.md) mixes in
`TenantScopedMixin`. A global `Session` event (`do_orm_execute`) inspects every
SELECT/UPDATE/DELETE that touches a tenant-scoped mapped class:

* If the executing `Session` has no tenant bound (`session.info["tenant_id"]` unset),
  the query is refused with `MissingTenantScopeError` *before it reaches the
  database*. A developer who forgets to scope a session gets a loud exception, not
  silently-wrong (or silently-leaked) rows.
* If a tenant *is* bound, a global `WHERE tenant_id = :tenant_id` criterion
  (`with_loader_criteria`) is transparently ANDed onto the statement — it cannot be
  omitted, and an explicit `.where(Model.tenant_id == ...)` elsewhere in the query is
  redundant, not required.

This is attached to `sqlalchemy.orm.Session` itself (not a subclass), so it applies to
*every* session the app constructs, including the plain one `app.core.db.get_db`
hands out — there is no "forgot to use the tenant-aware session" failure mode.

## The one legitimate cross-tenant lookup

Login authenticates by email, and `users.email` is a single globally-unique column
(docs/02) — by design, not by tenant. That lookup *cannot* supply a tenant_id, because
discovering the tenant is the point of the query. This is not a tenant-isolation
violation (it returns at most one globally-unique row, never a cross-tenant listing),
but it is the one place this module must be told to stand down. Use
`bypass_tenant_scope` for that, nowhere else — it is deliberately loud, narrow, and
grep-able.

## Known boundary

This guard hooks the ORM (`Session.execute`/`Session.scalars`/legacy `Session.query`).
Hand-written `text()` SQL or queries against a Core `Table` object (not a mapped
class) bypass it, same as `bypass_tenant_scope` does. The application does not do
that; if a future change introduces raw SQL against a tenant-scoped table, it must
add its own `tenant_id` predicate by hand and say so in a comment.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import ForeignKey, Uuid, event
from sqlalchemy.orm import Mapped, Session, mapped_column, with_loader_criteria
from sqlalchemy.orm.session import ORMExecuteState

from app.core.db import get_session_factory

_BYPASS_KEY = "_bypass_tenant_scope"
_TENANT_KEY = "tenant_id"


class MissingTenantScopeError(RuntimeError):
    """A tenant-scoped table was queried on a Session with no tenant bound.

    Fix by running the query through `tenant_session(tenant_id)` / `tenant_scope(...)`,
    not by adding a manual `.where(Model.tenant_id == ...)` — that would defeat the
    point of this module, which is that forgetting is structurally impossible.
    """


class TenantScopedMixin:
    """Mixin for every table that carries `tenant_id` per docs/02-DATA-MODEL.md."""

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("tenants.id"), nullable=False, index=True
    )


def _touches_tenant_scoped_table(state: ORMExecuteState) -> bool:
    return any(issubclass(mapper.class_, TenantScopedMixin) for mapper in state.all_mappers)


@event.listens_for(Session, "do_orm_execute")
def _enforce_tenant_scope(state: ORMExecuteState) -> None:
    if not (state.is_select or state.is_update or state.is_delete):
        return
    if not _touches_tenant_scoped_table(state):
        return
    if state.session.info.get(_BYPASS_KEY):
        return

    tenant_id = state.session.info.get(_TENANT_KEY)
    if tenant_id is None:
        raise MissingTenantScopeError(
            "Query touches a tenant-scoped table but this Session has no tenant bound. "
            "Use app.models.base.tenant_session(tenant_id) or tenant_scope(session, "
            "tenant_id) instead of a bare Session."
        )

    # `tenant_id` must be captured as a genuine closure variable, not a default
    # argument. with_loader_criteria's statement-cache key is computed from the
    # lambda's *closure cells* (`track_closure_variables=True`, the default) — a
    # default argument isn't a closure cell, so SQLAlchemy can't tell one tenant_id
    # apart from another and will silently reuse the first call's compiled statement
    # (and its baked-in bind value) for every later one. This bit the first version of
    # this module: two different tenants' sessions both got tenant A's filter.
    state.statement = state.statement.options(
        with_loader_criteria(
            TenantScopedMixin,
            lambda cls: cls.tenant_id == tenant_id,
            include_aliases=True,
        )
    )


def tenant_session(tenant_id: uuid.UUID) -> Session:
    """A new Session pre-bound to `tenant_id`. Every tenant-scoped query on it is
    automatically filtered; a bug can produce an empty result set, never another
    tenant's rows."""
    session = get_session_factory()()
    session.info[_TENANT_KEY] = tenant_id
    return session


@contextmanager
def tenant_scope(session: Session, tenant_id: uuid.UUID) -> Iterator[Session]:
    """Bind an existing Session (e.g. the request-scoped one from `app.core.db.get_db`)
    to `tenant_id` for the duration of the block, restoring whatever was bound before."""
    previous = session.info.get(_TENANT_KEY)
    session.info[_TENANT_KEY] = tenant_id
    try:
        yield session
    finally:
        if previous is None:
            session.info.pop(_TENANT_KEY, None)
        else:
            session.info[_TENANT_KEY] = previous


@contextmanager
def bypass_tenant_scope(session: Session) -> Iterator[Session]:
    """Escape hatch for the one legitimate cross-tenant lookup: authenticating a user
    by their globally-unique email before their tenant is known. Do not reach for this
    anywhere else — every other tenant-scoped query must go through `tenant_session`
    or `tenant_scope`."""
    previous = session.info.get(_BYPASS_KEY, False)
    session.info[_BYPASS_KEY] = True
    try:
        yield session
    finally:
        session.info[_BYPASS_KEY] = previous
