"""Read-side query helpers over the historical baseline store
(docs/v2_migration/MIGRATION-01-evidence-first.md, change 1).

"Every percentile in the system resolves against `baseline_profiles`, never against the
uploaded file" — `percentile_for` is that resolution point. "Rarity resolves against
`baseline_contacts` at three scopes ... 'Zero for Alice, one for Finance, four org-wide'" —
`contact_counts` is that one. Both are meant to be called from the evidence-extractor layer
(change 2, not yet built) once an entity-window's raw measurement needs historical context; this
change only builds the query surface, per the migration's own application order.

## Percentile method

`baseline_profiles` stores five summary numbers per `(entity, metric)`, not the raw sample —
that is the whole point of precomputing it (docs/04's L2 "robust z-score" is exactly this
`0.6745 * (x - median) / MAD` formula, `app.detection.features.robust_z`, its "one place both
sides import from"). `percentile_for` reuses that same formula and the same `MAD == 0` policy,
adapted to consume `baseline_profiles`' precomputed `p50` (as median) and `mad` directly instead
of a raw sample (`_robust_z_from_stats` below is not a re-export of `robust_z` — the signatures
differ on purpose, see its docstring), then maps the z-score to a percentile via the standard
normal CDF. This is exact, not approximate, for the round-number check a test can make: at
`x = median`, z = 0 and the percentile is exactly 50; at `x = median + mad`, z = 0.6745 (by
construction — 0.6745 is `Φ⁻¹(0.75)`, the reciprocal that makes MAD-based z resemble a standard
normal z under normality) and the percentile is `Φ(0.6745) * 100 ≈ 75`.

## Cold start

"An entity with `n_windows < 20` gets `baseline_status: 'insufficient_history'` ... Do not
silently emit a percentile computed from four windows." `PercentileResult.baseline_status` and
`.percentile` (`None` unless `"ok"`) make that the return type's job, not the caller's — a caller
that forgets to check `baseline_status` gets `percentile is None`, not a plausible-looking wrong
number.

## Department resolution in `contact_counts`

The department scope is resolved via `app.baseline.org_directory.department_for_user` — see that
module's docstring for why (no identity directory table; the single seeded live tenant's org is
reconstructed from the generator instead) and why an unresolved user gets `scope_value=None`
rather than a fabricated department.
"""

from __future__ import annotations

import math
import uuid
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Final, Literal

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.baseline.org_directory import department_for_user
from app.models.base import tenant_scope
from app.models.baseline_contact import BaselineContact
from app.models.baseline_profile import BaselineProfile

# docs/v2_migration change 1, "Cold start": fewer than this many windows and a percentile is
# not reported, however plausible it looks.
MIN_WINDOWS_FOR_BASELINE: Final[int] = 20

_ORG_SCOPE_VALUE = "org"  # matches app.baseline.loader._ORG_SCOPE_VALUE

BaselineStatus = Literal["ok", "insufficient_history"]
ContactScope = Literal["user", "department", "org"]

__all__ = [
    "MIN_WINDOWS_FOR_BASELINE",
    "ContactCounts",
    "PercentileResult",
    "ScopeContactCount",
    "contact_counts",
    "contact_counts_many",
    "percentile_for",
    "percentiles_for_many",
]


@dataclass(frozen=True, slots=True)
class PercentileResult:
    """Return type for `percentile_for`. `percentile` is only ever populated when
    `baseline_status == "ok"` — a cold-start entity gets `None`, never a number computed from a
    handful of windows."""

    entity_type: str
    entity_value: str
    metric: str
    value: float
    baseline_status: BaselineStatus
    n_windows: int
    percentile: float | None
    p50: float | None
    p95: float | None
    p99: float | None
    mean: float | None
    mad: float | None


@dataclass(frozen=True, slots=True)
class ScopeContactCount:
    scope: ContactScope
    # None only for scope="department" when app.baseline.org_directory couldn't place the user
    # in a department -- distinct from a resolved department with zero contacts, which carries
    # its real name here.
    scope_value: str | None
    contact_count: int
    first_seen: datetime | None
    last_seen: datetime | None
    # True whenever contact_count == 0: this scope has never contacted the domain in the
    # baseline period, i.e. it would be a first-seen event if it happened now.
    is_first_contact: bool


@dataclass(frozen=True, slots=True)
class ContactCounts:
    domain: str
    user: ScopeContactCount
    department: ScopeContactCount
    org: ScopeContactCount


def _robust_z_from_stats(x: float, median: float, mad: float) -> float:
    """docs/04 L2's robust z-score (`0.6745 * (x - median) / MAD`), computed from
    `baseline_profiles`' precomputed `p50`/`mad` rather than a raw sample -- this is why it is a
    sibling of `app.detection.features.robust_z`, not a call to it (that function computes
    median/MAD from a `Sequence[float]` it is handed; `baseline_profiles` stores the summary,
    not the sample, on purpose, so recomputing from raw `baseline_windows` on every lookup isn't
    necessary).

    **Diverges from `robust_z` in one deliberate way:** `robust_z`'s `MAD == 0` policy returns
    an *unsigned* `math.inf` (it feeds a magnitude/deviation score, where direction doesn't
    matter). A percentile needs direction -- an extreme value above a degenerate population maps
    to ~100, not ~0 -- so this returns a *signed* infinity instead.
    """
    if mad == 0:
        if x == median:
            return 0.0
        return math.inf if x > median else -math.inf
    return 0.6745 * (x - median) / mad


def _normal_cdf(z: float) -> float:
    if math.isinf(z):
        return 1.0 if z > 0 else 0.0
    return 0.5 * (1.0 + math.erf(z / math.sqrt(2.0)))


def percentile_for(
    session: Session,
    tenant_id: uuid.UUID,
    entity_type: str,
    entity_value: str,
    metric: str,
    value: float,
) -> PercentileResult:
    """Resolve `value` against `baseline_profiles`, never against the uploaded file.

    Missing profile row and `n_windows < MIN_WINDOWS_FOR_BASELINE` are handled identically —
    both are "not enough history to trust a percentile" — the only difference visible to the
    caller is `n_windows` (0 for a missing row).

    Resolving many entities of the same `(entity_type, metric)` at once? Use
    `percentiles_for_many` — it is this function's exact semantics over one query instead of
    one query per entity.
    """
    with tenant_scope(session, tenant_id):
        profile = session.execute(
            select(BaselineProfile).where(
                BaselineProfile.entity_type == entity_type,
                BaselineProfile.entity_value == entity_value,
                BaselineProfile.metric == metric,
            )
        ).scalar_one_or_none()

    return _percentile_from_profile(
        profile, entity_type=entity_type, entity_value=entity_value, metric=metric, value=value
    )


def percentiles_for_many(
    session: Session,
    tenant_id: uuid.UUID,
    entity_type: str,
    metric: str,
    values: Mapping[str, float],
) -> dict[str, PercentileResult]:
    """`percentile_for` for a whole set of entity values of one `(entity_type, metric)`, in a
    single `WHERE entity_value IN (...)` query instead of one round trip per entity.

    Semantically identical to calling `percentile_for` in a loop — both paths hand the same
    profile row (or `None`) to the same `_percentile_from_profile` — but a view resolving 20
    entities pays one network round trip rather than 20. That distinction is not academic
    against a managed Postgres a region away, where the round trip, not the query, is the cost.

    Every key of `values` is present in the returned mapping: an entity with no profile row
    resolves to the same `insufficient_history` result `percentile_for` returns for a miss, so
    a caller never has to distinguish "absent from the result" from "no baseline".
    """
    if not values:
        return {}

    with tenant_scope(session, tenant_id):
        profiles = (
            session.execute(
                select(BaselineProfile).where(
                    BaselineProfile.entity_type == entity_type,
                    BaselineProfile.metric == metric,
                    BaselineProfile.entity_value.in_(list(values)),
                )
            )
            .scalars()
            .all()
        )

    by_value = {p.entity_value: p for p in profiles}
    return {
        entity_value: _percentile_from_profile(
            by_value.get(entity_value),
            entity_type=entity_type,
            entity_value=entity_value,
            metric=metric,
            value=value,
        )
        for entity_value, value in values.items()
    }


def _percentile_from_profile(
    profile: BaselineProfile | None,
    *,
    entity_type: str,
    entity_value: str,
    metric: str,
    value: float,
) -> PercentileResult:
    """The pure half of `percentile_for`: profile row (or `None`) -> result. Shared verbatim
    with `percentiles_for_many` so the batch path can never drift from the single-entity one."""
    if profile is None:
        return PercentileResult(
            entity_type=entity_type,
            entity_value=entity_value,
            metric=metric,
            value=value,
            baseline_status="insufficient_history",
            n_windows=0,
            percentile=None,
            p50=None,
            p95=None,
            p99=None,
            mean=None,
            mad=None,
        )

    if profile.n_windows < MIN_WINDOWS_FOR_BASELINE:
        return PercentileResult(
            entity_type=entity_type,
            entity_value=entity_value,
            metric=metric,
            value=value,
            baseline_status="insufficient_history",
            n_windows=profile.n_windows,
            percentile=None,
            p50=profile.p50,
            p95=profile.p95,
            p99=profile.p99,
            mean=profile.mean,
            mad=profile.mad,
        )

    # A profile with n_windows >= MIN_WINDOWS_FOR_BASELINE always has real p50/mad (the loader
    # only ever writes both together, from datagen.labeled_corpus.build_baseline's median/MAD
    # computation) -- the None-handling above exists for the row itself being absent or thin,
    # not for a present-but-half-populated row.
    assert profile.p50 is not None and profile.mad is not None
    z = _robust_z_from_stats(value, profile.p50, profile.mad)
    percentile = min(100.0, max(0.0, _normal_cdf(z) * 100.0))

    return PercentileResult(
        entity_type=entity_type,
        entity_value=entity_value,
        metric=metric,
        value=value,
        baseline_status="ok",
        n_windows=profile.n_windows,
        percentile=percentile,
        p50=profile.p50,
        p95=profile.p95,
        p99=profile.p99,
        mean=profile.mean,
        mad=profile.mad,
    )


def _scope_result(
    scope: ContactScope, scope_value: str | None, row: BaselineContact | None
) -> ScopeContactCount:
    if scope_value is None:
        # department unresolved -- not "zero contacts", "we don't know the scope at all".
        return ScopeContactCount(
            scope=scope,
            scope_value=None,
            contact_count=0,
            first_seen=None,
            last_seen=None,
            is_first_contact=True,
        )
    if row is None:
        return ScopeContactCount(
            scope=scope,
            scope_value=scope_value,
            contact_count=0,
            first_seen=None,
            last_seen=None,
            is_first_contact=True,
        )
    return ScopeContactCount(
        scope=scope,
        scope_value=scope_value,
        contact_count=row.contact_count,
        first_seen=row.first_seen,
        last_seen=row.last_seen,
        is_first_contact=row.contact_count == 0,
    )


def contact_counts(session: Session, tenant_id: uuid.UUID, user: str, domain: str) -> ContactCounts:
    """Rarity at three scopes for `(user, domain)`: user, the user's department (via
    `app.baseline.org_directory.department_for_user`), and org-wide. A domain the org has
    contacted but this particular user never has reports `user.contact_count == 0,
    user.is_first_contact == True` alongside a non-zero `org.contact_count` -- exactly the "zero
    for Alice, ... four org-wide" case the migration doc names.

    Resolving many pairs at once? Use `contact_counts_many` — same semantics, one query for the
    whole set instead of one per pair.
    """
    with tenant_scope(session, tenant_id):
        rows = (
            session.execute(select(BaselineContact).where(BaselineContact.domain == domain))
            .scalars()
            .all()
        )

    return _contacts_from_rows(rows, user=user, domain=domain)


def contact_counts_many(
    session: Session, tenant_id: uuid.UUID, pairs: Iterable[tuple[str, str]]
) -> dict[tuple[str, str], ContactCounts]:
    """`contact_counts` over many `(user, domain)` pairs, in one `WHERE domain IN (...)` query.

    The single-pair form already fetches *every* scope row for its domain and filters in
    process, so batching costs nothing extra per domain — a view asking about 20 users across
    27 domains issues one query here instead of up to 540. Keyed by the `(user, domain)` tuple
    exactly as passed; duplicate pairs collapse to one entry.
    """
    wanted = list(dict.fromkeys(pairs))
    if not wanted:
        return {}

    domains = {domain for _, domain in wanted}
    with tenant_scope(session, tenant_id):
        rows = (
            session.execute(
                select(BaselineContact).where(BaselineContact.domain.in_(sorted(domains)))
            )
            .scalars()
            .all()
        )

    rows_by_domain: dict[str, list[BaselineContact]] = {domain: [] for domain in domains}
    for row in rows:
        rows_by_domain.setdefault(row.domain, []).append(row)

    return {
        (user, domain): _contacts_from_rows(
            rows_by_domain.get(domain, ()), user=user, domain=domain
        )
        for user, domain in wanted
    }


def _contacts_from_rows(
    rows: Iterable[BaselineContact], *, user: str, domain: str
) -> ContactCounts:
    """The pure half of `contact_counts`: this domain's scope rows -> the three-scope result.
    Shared verbatim with `contact_counts_many` so the batch path cannot drift."""
    department = department_for_user(user)
    by_scope = {(r.scope, r.scope_value): r for r in rows}

    user_row = by_scope.get(("user", user))
    dept_row = by_scope.get(("department", department)) if department is not None else None
    org_row = by_scope.get(("org", _ORG_SCOPE_VALUE))

    return ContactCounts(
        domain=domain,
        user=_scope_result("user", user, user_row),
        department=_scope_result("department", department, dept_row),
        org=_scope_result("org", _ORG_SCOPE_VALUE, org_row),
    )
