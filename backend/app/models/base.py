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

There are two more, narrower shapes that bypass it silently, both real bugs found and fixed
during this codebase's build (`app.learning.metrics.compute_learning_metrics`,
`app.learning.feedback._tenant_feedback_count` — see git history), and both guarded by a
regression test (`tests/test_tenant_isolation.py`, the "aggregate/JOIN-only class of gap"
section) rather than by code here, because neither is fixable in this module: `_touches_
tenant_scoped_table` decides whether to attach `with_loader_criteria` by walking
`ORMExecuteState.all_mappers`, which SQLAlchemy derives from the *top-level selected
columns'* owning entities, not from every mapper the statement's FROM/JOIN clause touches.

* **A bare select of a non-tenant-scoped, transitively-isolated table** (docs/02: `analyst_
  feedback`, `triage_verdicts`, `entity_edges` all carry no `tenant_id` column by design —
  isolation is meant to come from a join to a tenant-scoped parent). `select(AnalystFeedback)`
  alone has no tenant-scoped mapper anywhere in the statement — nothing to filter on, and no
  exception either, since `_touches_tenant_scoped_table` correctly reports "no", not "unsafe".
* **An aggregate or bare-column select whose *only* tenant-scoped table is a JOIN target.**
  `select(func.count(AnalystFeedback.id)).join(TriageVerdict, ...).join(Incident, ...)` compiles
  fine and even looks scoped (`Incident` is right there in the `.join()`), but `Incident` never
  appears in a *selected column*, so `all_mappers` never sees it and no filter gets attached.
  Wrapping the same column in `func.count(...)` does **not** trigger this — `func.count(Event.id)`
  is safe, because `Event.id`'s owning entity (`Event`, tenant-scoped) *is* the selected column's
  entity. The dangerous shape is specifically "the only tenant-scoped mapper is join-only."

Both require an explicit `.where(<ScopedModel>.tenant_id == tenant_id)` written by hand, same as
raw `text()` SQL does — there is no way to make the hook catch either shape without also being
able to see inside a query's FROM/JOIN clause, which `ORMExecuteState.all_mappers` deliberately
does not expose (see its docstring: "involved at the top level," i.e. the result-row columns).
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from typing import TypeVar

from sqlalchemy import ForeignKey, Uuid, event, select
from sqlalchemy.orm import Mapped, Session, mapped_column, with_loader_criteria
from sqlalchemy.orm.session import ORMExecuteState

from app.core.db import get_session_factory

_T = TypeVar("_T")

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


def get_scoped(session: Session, model: type[_T], pk: object) -> _T | None:
    """Primary-key lookup that is actually tenant-filtered. Use this instead of `Session.get()`
    for any tenant-scoped model whose id came from outside the process (a URL path, a queue
    message, a user-supplied filter).

    `Session.get()` consults the identity map *before* it emits SQL, and returns the cached object
    directly on a hit. `with_loader_criteria` — the mechanism the whole `_enforce_tenant_scope`
    hook above is built on — only ever applies to a statement that is actually executed, so an
    identity-map hit walks straight past it. On a warm session that already holds tenant A's
    incident, `session.get(Incident, that_id)` inside `tenant_scope(session, tenant_b)` returns
    tenant A's row.

    Request handlers get a fresh session per request (`app.core.db.get_db`), so nothing in the
    current HTTP surface can warm a session with another tenant's rows — but "isolation holds
    because of how the caller happens to manage sessions" is exactly the property this module
    exists to stop depending on. A `select()` always emits SQL, so it always receives the
    criteria.
    """
    return session.execute(
        select(model).where(model.__mapper__.primary_key[0] == pk)  # type: ignore[attr-defined]
    ).scalar_one_or_none()


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
