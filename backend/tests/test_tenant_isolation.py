"""Proves the structural tenant-isolation guarantee in app/models/base.py against the
real Postgres — not a mock, so a bug in the SQL SQLAlchemy actually emits would show
up here exactly as it would in production.

docs/06-PRIVACY-SECURITY.md: tenant isolation must be "enforce[d] via a SQLAlchemy
base query class, not by remembering." The tests below are the proof: a forgotten
tenant filter raises before touching the database (never returns another tenant's
rows), and a correctly tenant-bound session cannot see across tenants even when the
query itself has no `WHERE tenant_id = ...` at all — for SELECT, bulk UPDATE, and bulk
DELETE alike.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable

import pytest
from sqlalchemy import Select, delete, func, select, update
from sqlalchemy.orm import Session

from app.core.db import get_session_factory
from app.models.analyst_feedback import AnalystFeedback
from app.models.base import (
    MissingTenantScopeError,
    bypass_tenant_scope,
    tenant_scope,
    tenant_session,
)
from app.models.incident import Incident
from app.models.triage_verdict import TriageVerdict
from app.models.upload import Upload
from app.models.user import User
from tests.conftest import make_analysis, make_tenant, make_user
from tests.fixtures.db_rows import learning_cleanup  # noqa: F401
from tests.fixtures.response import make_incident, make_triage_verdict


@pytest.fixture
def two_tenants(tenant_cleanup: list[uuid.UUID]) -> tuple[User, User]:
    """Tenant A / User A and Tenant B / User B — the minimal fixture every isolation
    test in this file needs."""
    tenant_a = make_tenant(name="Tenant A")
    tenant_b = make_tenant(name="Tenant B")
    tenant_cleanup.extend([tenant_a.id, tenant_b.id])
    user_a = make_user(tenant_id=tenant_a.id, email="a@tenant-a.example")
    user_b = make_user(tenant_id=tenant_b.id, email="b@tenant-b.example")
    return user_a, user_b


def test_bare_session_raises_instead_of_leaking(two_tenants: tuple[User, User]) -> None:
    """The headline guarantee: forgetting to scope a session is a loud exception, not
    a silent cross-tenant read."""
    session = get_session_factory()()
    try:
        with pytest.raises(MissingTenantScopeError):
            session.execute(select(User))
    finally:
        session.close()


def test_tenant_session_sees_only_its_own_rows(two_tenants: tuple[User, User]) -> None:
    user_a, user_b = two_tenants
    session = tenant_session(user_a.tenant_id)
    try:
        # Deliberately unfiltered — the point is that no manual WHERE is needed *or
        # possible to omit by mistake*.
        rows = session.execute(select(User)).scalars().all()
        seen_ids = {row.id for row in rows}
        assert user_a.id in seen_ids
        assert user_b.id not in seen_ids
    finally:
        session.close()


def test_cannot_fetch_another_tenants_row_even_by_primary_key(
    two_tenants: tuple[User, User],
) -> None:
    """A bug that guesses/leaks another tenant's row id still can't read it — the
    global criterion applies regardless of what the query's own WHERE clause says."""
    user_a, user_b = two_tenants
    session = tenant_session(user_a.tenant_id)
    try:
        result = session.execute(select(User).where(User.id == user_b.id)).scalar_one_or_none()
        assert result is None
    finally:
        session.close()


def test_tenant_scope_context_manager_nests_and_restores(
    two_tenants: tuple[User, User],
) -> None:
    user_a, user_b = two_tenants
    session = get_session_factory()()
    try:
        with tenant_scope(session, user_a.tenant_id):
            ids = {u.id for u in session.execute(select(User)).scalars().all()}
            assert ids == {user_a.id}

            with tenant_scope(session, user_b.tenant_id):
                ids = {u.id for u in session.execute(select(User)).scalars().all()}
                assert ids == {user_b.id}

            # Back out of the nested block: tenant A again, not unbound.
            ids = {u.id for u in session.execute(select(User)).scalars().all()}
            assert ids == {user_a.id}

        # Back out of the outer block entirely: unbound again.
        with pytest.raises(MissingTenantScopeError):
            session.execute(select(User))
    finally:
        session.close()


def test_bypass_tenant_scope_is_the_only_way_to_do_a_global_lookup(
    two_tenants: tuple[User, User],
) -> None:
    """This is exactly what app.api.auth.login does: resolve the tenant *from* a
    globally-unique email, which is impossible to do pre-scoped."""
    user_a, _user_b = two_tenants
    session = get_session_factory()()
    try:
        with pytest.raises(MissingTenantScopeError):
            session.execute(select(User).where(User.email == user_a.email))

        with bypass_tenant_scope(session):
            found = session.execute(
                select(User).where(User.email == user_a.email)
            ).scalar_one_or_none()
        assert found is not None
        assert found.id == user_a.id
    finally:
        session.close()


def test_bulk_update_is_scoped_too(two_tenants: tuple[User, User]) -> None:
    """`with_loader_criteria` applies to ORM-enabled bulk UPDATE, not just SELECT — an
    update with no WHERE at all still only touches the bound tenant's rows."""
    user_a, user_b = two_tenants
    session = tenant_session(user_a.tenant_id)
    try:
        session.execute(update(User).values(password_hash="rotated"))
        session.commit()
    finally:
        session.close()

    session = get_session_factory()()
    try:
        with bypass_tenant_scope(session):
            refreshed_a = session.get(User, user_a.id)
            refreshed_b = session.get(User, user_b.id)
        assert refreshed_a is not None
        assert refreshed_b is not None
        assert refreshed_a.password_hash == "rotated"
        assert refreshed_b.password_hash != "rotated"
    finally:
        session.close()


def test_bulk_delete_is_scoped_too(tenant_cleanup: list[uuid.UUID]) -> None:
    tenant_a = make_tenant(name="Delete A")
    tenant_b = make_tenant(name="Delete B")
    tenant_cleanup.extend([tenant_a.id, tenant_b.id])
    user_a = make_user(tenant_id=tenant_a.id, email="del-a@example.com")
    user_b = make_user(tenant_id=tenant_b.id, email="del-b@example.com")

    session = get_session_factory()()
    try:
        upload_a = Upload(
            tenant_id=tenant_a.id,
            user_id=user_a.id,
            filename="a.log",
            size_bytes=1,
            sha256="d" * 64,
            storage_ref=f"{tenant_a.id}/{uuid.uuid4()}",
        )
        upload_b = Upload(
            tenant_id=tenant_b.id,
            user_id=user_b.id,
            filename="b.log",
            size_bytes=1,
            sha256="e" * 64,
            storage_ref=f"{tenant_b.id}/{uuid.uuid4()}",
        )
        session.add_all([upload_a, upload_b])
        session.commit()
    finally:
        session.close()

    # Delete-everything-in-Uploads, scoped to tenant A only.
    session = tenant_session(tenant_a.id)
    try:
        session.execute(delete(Upload))
        session.commit()
    finally:
        session.close()

    session = get_session_factory()()
    try:
        with bypass_tenant_scope(session):
            remaining_a = (
                session.execute(select(Upload).where(Upload.tenant_id == tenant_a.id))
                .scalars()
                .all()
            )
            remaining_b = (
                session.execute(select(Upload).where(Upload.tenant_id == tenant_b.id))
                .scalars()
                .all()
            )
    finally:
        session.close()

    assert remaining_a == []
    assert len(remaining_b) == 1


# ---------------------------------------------------------------------------- the aggregate/JOIN-only class of gap
#
# `_touches_tenant_scoped_table` (app/models/base.py) decides whether to attach
# `with_loader_criteria` by walking `ORMExecuteState.all_mappers` — which SQLAlchemy derives from
# each *top-level selected column*'s owning entity, not from every mapper the statement's FROM/JOIN
# clause happens to touch. A tenant-scoped table that is only ever a JOIN target — never itself
# selected — is invisible to that walk, so it gets no automatic filter at all, silently.
#
# This produced two real cross-tenant leaks (both since fixed): `app.learning.metrics.
# compute_learning_metrics` (a bare `select(AnalystFeedback)` — `AnalystFeedback` carries no
# `tenant_id` and mixes in no `TenantScopedMixin`; isolation was meant to be transitive through
# `verdict_id -> triage_verdicts -> incidents`, but nothing enforced that) and
# `app.learning.feedback._tenant_feedback_count` (`select(func.count(AnalystFeedback.id))
# .join(TriageVerdict, ...).join(Incident, ...)` — `Incident` *is* tenant-scoped, but only ever
# appears in a `.join()`, never in the selected columns, so it too was invisible to the hook).
#
# The tests below guard the *shape*, not those two call sites: they build the dangerous query
# directly against the ORM, independent of `app.learning.metrics`/`app.learning.feedback`'s own
# code, so any present or future function written in this shape is covered, not just the two
# that happened to get caught. `test_join_only_shape_leaks_without_an_explicit_filter` documents
# the boundary is real and permanent (a SQLAlchemy semantics fact, not a bug this module can fix);
# `test_join_only_shape_is_isolated_with_an_explicit_filter` proves the codebase's actual
# mitigation — an explicit `.where(<ScopedModel>.tenant_id == tenant_id)` alongside the join — is
# what makes this shape safe, for both an aggregate and a bare non-aggregate select.


def _seed_feedback(tenant_id: uuid.UUID, *, n: int) -> None:
    """One (analysis, incident, verdict) chain per feedback row, all under `tenant_id` —
    `AnalystFeedback` is reachable only by joining through `triage_verdicts` -> `incidents`
    (see this module's docstring above), so a realistic fixture has to build the whole chain,
    not just insert an `AnalystFeedback` row directly."""
    user = make_user(tenant_id=tenant_id, email=f"join-only-{uuid.uuid4()}@test.local")
    user_id = user.id

    analysis = make_analysis(tenant_id=tenant_id, user_id=user_id)
    for _ in range(n):
        incident = make_incident(tenant_id=tenant_id, analysis_id=analysis.id)
        verdict = make_triage_verdict(incident_id=incident.id, recommended_actions=[])
        session = get_session_factory()()
        try:
            feedback = AnalystFeedback(verdict_id=verdict.id, user_id=user_id, agrees=True)
            session.add(feedback)
            session.commit()
        finally:
            session.close()


@pytest.fixture
def two_tenants_with_feedback(
    learning_cleanup: list[uuid.UUID],  # noqa: F811
) -> tuple[uuid.UUID, uuid.UUID]:
    """Tenant A gets 3 `analyst_feedback` rows, tenant B gets 5 — different counts so a leaked
    aggregate is unmistakable (never coincidentally equal to the correctly-scoped one).
    `analyst_feedback` has no cascading delete of its own (see that model's docstring), hence
    `learning_cleanup` here rather than plain `tenant_cleanup` — it deletes `analyst_feedback`
    explicitly before tearing down the tenants these rows transitively belong to."""
    tenant_a = make_tenant(name="Join-Only A")
    tenant_b = make_tenant(name="Join-Only B")
    learning_cleanup.extend([tenant_a.id, tenant_b.id])
    _seed_feedback(tenant_a.id, n=3)
    _seed_feedback(tenant_b.id, n=5)
    return tenant_a.id, tenant_b.id


def _aggregate_query_no_filter() -> Select[tuple[int]]:
    """The exact shape `_tenant_feedback_count` used to compile: an aggregate over the
    non-scoped entity, `Incident` (tenant-scoped) present only as a JOIN target."""
    return (
        select(func.count(AnalystFeedback.id))
        .join(TriageVerdict, AnalystFeedback.verdict_id == TriageVerdict.id)
        .join(Incident, TriageVerdict.incident_id == Incident.id)
    )


def _bare_columns_query_no_filter() -> Select[tuple[uuid.UUID]]:
    """The non-aggregate sibling of the same shape: still only `AnalystFeedback.id` in the
    selected columns, `Incident` still only a JOIN target."""
    return (
        select(AnalystFeedback.id)
        .join(TriageVerdict, AnalystFeedback.verdict_id == TriageVerdict.id)
        .join(Incident, TriageVerdict.incident_id == Incident.id)
    )


def _count_seen(build_query: Callable[[], Select[tuple[object]]], session: Session) -> int:
    """`func.count(...)` returns one row holding the aggregate; a bare column select returns
    one row per match. Either way, this is "how many `analyst_feedback` rows did this query
    actually see" — the number both test functions below compare against."""
    stmt = build_query()
    is_aggregate = "count" in str(stmt.selected_columns[0]).lower()
    result = session.execute(stmt)
    if is_aggregate:
        return int(result.scalar_one())
    return len(result.scalars().all())


@pytest.mark.parametrize(
    "build_query",
    [_aggregate_query_no_filter, _bare_columns_query_no_filter],
    ids=["aggregate(count)", "bare-columns"],
)
def test_join_only_shape_leaks_without_an_explicit_filter(
    two_tenants_with_feedback: tuple[uuid.UUID, uuid.UUID],
    build_query: Callable[[], Select[tuple[object]]],
) -> None:
    """Characterizes the known, permanent boundary (app/models/base.py's own docstring): a
    tenant-bound session alone does **not** protect this query shape. Under tenant A's session,
    with no explicit `.where(Incident.tenant_id == ...)`, the naive query still sees tenant B's
    rows too — proof that relying on `tenant_session`/`with_loader_criteria` alone for a
    JOIN-only tenant-scoped entity is unsound by construction, not a bug that could be patched
    here. This is exactly why `compute_learning_metrics`/`_tenant_feedback_count` need (and now
    have) an explicit filter, and why every future function of this shape needs one too."""
    tenant_a, _tenant_b = two_tenants_with_feedback
    session = tenant_session(tenant_a)
    try:
        seen = _count_seen(build_query, session)
    finally:
        session.close()

    # Tenant A alone has 3 rows; if the query were actually scoped it could return at most 3.
    # Seeing all 8 (3 + 5) proves both tenants' rows came back.
    # `>= 8`, not `== 8`. This query is deliberately unscoped — that is the whole point of the
    # test — so it sees every row in the table, including any left by other tests that ran first.
    # Asserting an exact global count made the test depend on the rest of the suite's residue and
    # fail with "expected 8, got 28" when nothing about isolation had changed. What actually
    # demonstrates the gap is that the unscoped query returns *more than one tenant's worth*: the
    # scoped equivalent below can return at most tenant A's 3.
    assert seen >= 8, (
        f"expected the unfiltered join-only query to leak both tenants' rows (8 total), got "
        f"{seen} — either the fixture changed or SQLAlchemy's all_mappers semantics did"
    )


def _aggregate_query_explicit_filter(tenant_id: uuid.UUID) -> Select[tuple[int]]:
    return _aggregate_query_no_filter().where(Incident.tenant_id == tenant_id)


def _bare_columns_query_explicit_filter(tenant_id: uuid.UUID) -> Select[tuple[uuid.UUID]]:
    return _bare_columns_query_no_filter().where(Incident.tenant_id == tenant_id)


@pytest.mark.parametrize(
    "build_query",
    [_aggregate_query_explicit_filter, _bare_columns_query_explicit_filter],
    ids=["aggregate(count)", "bare-columns"],
)
def test_join_only_shape_is_isolated_with_an_explicit_filter(
    two_tenants_with_feedback: tuple[uuid.UUID, uuid.UUID],
    build_query: Callable[[uuid.UUID], Select[tuple[object]]],
) -> None:
    """The mitigation this codebase actually requires for a JOIN-only tenant-scoped entity — an
    explicit `.where(<ScopedModel>.tenant_id == tenant_id)` alongside the automatic hook, exactly
    the idiom `app.learning.metrics`/`app.learning.feedback` now use — does isolate correctly,
    for both an aggregate and a bare non-aggregate select. This is the "guard the class" half:
    any query of this shape that follows the required idiom is provably safe, regardless of
    which function it lives in."""
    tenant_a, tenant_b = two_tenants_with_feedback

    session = tenant_session(tenant_a)
    try:
        seen_a = _count_seen(lambda: build_query(tenant_a), session)
    finally:
        session.close()
    assert seen_a == 3

    session = tenant_session(tenant_b)
    try:
        seen_b = _count_seen(lambda: build_query(tenant_b), session)
    finally:
        session.close()
    assert seen_b == 5
