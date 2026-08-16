"""`app.baseline.resolve` — docs/v2_migration/MIGRATION-01-evidence-first.md, change 1.

Rows are inserted directly (bypassing `app.baseline.loader`) so each test controls its own
distribution/contact-count numbers precisely, independent of the loader's fixture data
(`tests/test_baseline_loader.py` covers the loader's own file-parsing/rollup behaviour).

`rosaa@northwind.example` (Finance) and `umad@northwind.example` (Engineering) are real users
of the deterministic seeded org `app.baseline.org_directory` reconstructs -- same two used in
`tests/test_baseline_loader.py`, for the same reason (a real `department_for_user` lookup, not a
stubbed one).
"""

from __future__ import annotations

import math
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime

import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.baseline.resolve import (
    MIN_WINDOWS_FOR_BASELINE,
    contact_counts,
    percentile_for,
)
from app.core.db import get_session_factory
from app.models.base import tenant_scope
from app.models.baseline_contact import BaselineContact
from app.models.baseline_profile import BaselineProfile
from tests.conftest import make_tenant

FINANCE_USER = "rosaa@northwind.example"
ENGINEERING_USER = "umad@northwind.example"
UNKNOWN_USER = "nobody@not-in-the-org.example"

_ORG_SCOPE_VALUE = "org"


@pytest.fixture
def db() -> Iterator[Session]:
    session = get_session_factory()()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


@pytest.fixture
def tenant_id(db: Session) -> Iterator[uuid.UUID]:
    tenant = make_tenant(name="Baseline Resolve Test Tenant")
    yield tenant.id
    with tenant_scope(db, tenant.id):
        db.execute(BaselineProfile.__table__.delete().where(BaselineProfile.tenant_id == tenant.id))
        db.execute(BaselineContact.__table__.delete().where(BaselineContact.tenant_id == tenant.id))
    db.execute(text("DELETE FROM tenants WHERE id = :id"), {"id": tenant.id})
    db.commit()


def _expected_percentile(x: float, median: float, mad: float) -> float:
    """Independently recomputes the documented formula (docs/04 L2's robust z-score, mapped
    through the standard normal CDF) rather than importing `app.baseline.resolve`'s private
    helpers -- this is checking the public `percentile_for` against the *documented* method, not
    against itself."""
    z = 0.6745 * (x - median) / mad
    return 0.5 * (1.0 + math.erf(z / math.sqrt(2.0))) * 100.0


# --------------------------------------------------------------------------------- percentile_for


def test_percentile_for_matches_the_documented_formula_on_a_known_distribution(
    db: Session, tenant_id: uuid.UUID
) -> None:
    with tenant_scope(db, tenant_id):
        db.add(
            BaselineProfile(
                tenant_id=tenant_id,
                entity_type="user",
                entity_value=FINANCE_USER,
                metric="n_events",
                p50=100.0,
                p95=140.0,
                p99=160.0,
                mean=101.0,
                mad=20.0,
                n_windows=40,
            )
        )
        db.commit()

    at_median = percentile_for(db, tenant_id, "user", FINANCE_USER, "n_events", 100.0)
    assert at_median.baseline_status == "ok"
    assert at_median.percentile == pytest.approx(50.0, abs=1e-9)

    above = percentile_for(db, tenant_id, "user", FINANCE_USER, "n_events", 120.0)  # median + mad
    assert above.baseline_status == "ok"
    assert above.percentile == pytest.approx(_expected_percentile(120.0, 100.0, 20.0), abs=1e-9)
    assert above.percentile == pytest.approx(75.0, abs=0.01)  # Φ(0.6745) ≈ 0.75 by construction

    below = percentile_for(db, tenant_id, "user", FINANCE_USER, "n_events", 80.0)  # median - mad
    assert below.baseline_status == "ok"
    assert below.percentile == pytest.approx(_expected_percentile(80.0, 100.0, 20.0), abs=1e-9)
    assert below.percentile == pytest.approx(100.0 - above.percentile, abs=1e-9)  # symmetry

    assert above.n_windows == 40
    assert above.p95 == 140.0 and above.p99 == 160.0  # carried through untouched for display


def test_percentile_for_mad_zero_maps_to_0_50_100(db: Session, tenant_id: uuid.UUID) -> None:
    """docs/04's robust-z MAD==0 policy, adapted with a *signed* infinity (see
    `app.baseline.resolve._robust_z_from_stats`'s docstring for why): a degenerate baseline
    (every window identical) puts the exact value at the 50th percentile and anything else at
    the extreme it deviates towards, not a finite-looking number that understates how anomalous
    it actually is.
    """
    with tenant_scope(db, tenant_id):
        db.add(
            BaselineProfile(
                tenant_id=tenant_id,
                entity_type="user",
                entity_value=FINANCE_USER,
                metric="blocked_ratio",
                p50=0.05,
                p95=0.05,
                p99=0.05,
                mean=0.05,
                mad=0.0,
                n_windows=30,
            )
        )
        db.commit()

    assert (
        percentile_for(db, tenant_id, "user", FINANCE_USER, "blocked_ratio", 0.05).percentile
        == 50.0
    )
    assert (
        percentile_for(db, tenant_id, "user", FINANCE_USER, "blocked_ratio", 0.9).percentile
        == 100.0
    )
    assert (
        percentile_for(db, tenant_id, "user", FINANCE_USER, "blocked_ratio", 0.0).percentile == 0.0
    )


def test_percentile_for_cold_start_missing_profile_yields_insufficient_history(
    db: Session, tenant_id: uuid.UUID
) -> None:
    result = percentile_for(db, tenant_id, "user", FINANCE_USER, "n_events", 42.0)
    assert result.baseline_status == "insufficient_history"
    assert result.percentile is None
    assert result.n_windows == 0


def test_percentile_for_cold_start_thin_profile_yields_insufficient_history_not_a_number(
    db: Session, tenant_id: uuid.UUID
) -> None:
    """n_windows < MIN_WINDOWS_FOR_BASELINE (20): the migration doc is explicit that this must
    not silently emit a percentile computed from a handful of windows."""
    assert MIN_WINDOWS_FOR_BASELINE == 20
    with tenant_scope(db, tenant_id):
        db.add(
            BaselineProfile(
                tenant_id=tenant_id,
                entity_type="user",
                entity_value=ENGINEERING_USER,
                metric="n_events",
                p50=37.5,
                p95=40.0,
                p99=40.0,
                mean=37.5,
                mad=2.5,
                n_windows=4,
            )
        )
        db.commit()

    result = percentile_for(db, tenant_id, "user", ENGINEERING_USER, "n_events", 200.0)
    assert result.baseline_status == "insufficient_history"
    assert result.percentile is None
    assert result.n_windows == 4
    # The caller still gets the raw stats for display -- just not a percentile computed from
    # four windows.
    assert result.p50 == 37.5
    assert result.mad == 2.5


# --------------------------------------------------------------------------------- contact_counts


def _insert_contact(
    db: Session,
    tenant_id: uuid.UUID,
    *,
    scope: str,
    scope_value: str,
    domain: str,
    count: int,
    first_seen: datetime = datetime(2025, 9, 1, tzinfo=UTC),
    last_seen: datetime = datetime(2026, 2, 25, tzinfo=UTC),
) -> None:
    with tenant_scope(db, tenant_id):
        db.add(
            BaselineContact(
                tenant_id=tenant_id,
                scope=scope,
                scope_value=scope_value,
                domain=domain,
                contact_count=count,
                first_seen=first_seen,
                last_seen=last_seen,
            )
        )
        db.commit()


def test_contact_counts_returns_all_three_scopes_with_correct_first_seen_flags(
    db: Session, tenant_id: uuid.UUID
) -> None:
    _insert_contact(
        db, tenant_id, scope="user", scope_value=FINANCE_USER, domain="github.com", count=7921
    )
    _insert_contact(
        db, tenant_id, scope="department", scope_value="Finance", domain="github.com", count=9000
    )
    _insert_contact(
        db, tenant_id, scope="org", scope_value=_ORG_SCOPE_VALUE, domain="github.com", count=40000
    )

    result = contact_counts(db, tenant_id, FINANCE_USER, "github.com")

    assert result.domain == "github.com"
    assert result.user.scope == "user" and result.user.contact_count == 7921
    assert result.user.is_first_contact is False
    assert result.department.scope_value == "Finance" and result.department.contact_count == 9000
    assert result.department.is_first_contact is False
    assert result.org.scope_value == _ORG_SCOPE_VALUE and result.org.contact_count == 40000
    assert result.org.is_first_contact is False
    for scope_result in (result.user, result.department, result.org):
        assert scope_result.first_seen is not None
        assert scope_result.last_seen is not None


def test_contact_counts_zero_for_user_but_present_department_and_org(
    db: Session, tenant_id: uuid.UUID
) -> None:
    """ "Zero for Alice, one for Finance, four org-wide" -- the migration doc's own example.
    Alice's row for this domain simply doesn't exist; department and org rows do."""
    _insert_contact(
        db,
        tenant_id,
        scope="department",
        scope_value="Finance",
        domain="rare-saas.example",
        count=1,
    )
    _insert_contact(
        db,
        tenant_id,
        scope="org",
        scope_value=_ORG_SCOPE_VALUE,
        domain="rare-saas.example",
        count=4,
    )

    result = contact_counts(db, tenant_id, FINANCE_USER, "rare-saas.example")

    assert result.user.contact_count == 0
    assert result.user.is_first_contact is True
    assert result.user.first_seen is None and result.user.last_seen is None
    assert result.department.contact_count == 1
    assert result.department.is_first_contact is False
    assert result.org.contact_count == 4
    assert result.org.is_first_contact is False


def test_contact_counts_zero_at_every_scope_for_a_never_contacted_domain(
    db: Session, tenant_id: uuid.UUID
) -> None:
    result = contact_counts(db, tenant_id, FINANCE_USER, "never-seen.example")
    assert result.user.contact_count == 0 and result.user.is_first_contact is True
    assert result.department.contact_count == 0 and result.department.is_first_contact is True
    assert result.org.contact_count == 0 and result.org.is_first_contact is True
    assert result.department.scope_value == "Finance"  # resolved, just zero -- not "unknown"


def test_contact_counts_unresolved_department_reports_none_not_a_guess(
    db: Session, tenant_id: uuid.UUID
) -> None:
    """A user outside the seeded org directory (app.baseline.org_directory) gets
    `department.scope_value is None`, distinguishing "we don't know this user's department"
    from "this user's department has zero contacts"."""
    result = contact_counts(db, tenant_id, UNKNOWN_USER, "github.com")
    assert result.department.scope_value is None
    assert result.department.contact_count == 0
    assert result.department.is_first_contact is True


def test_contact_counts_respects_tenant_scoping(db: Session, tenant_id: uuid.UUID) -> None:
    other = make_tenant(name="Baseline Resolve Test Tenant (other)")
    try:
        _insert_contact(
            db,
            tenant_id,
            scope="org",
            scope_value=_ORG_SCOPE_VALUE,
            domain="shared-domain.example",
            count=10,
        )
        _insert_contact(
            db,
            other.id,
            scope="org",
            scope_value=_ORG_SCOPE_VALUE,
            domain="shared-domain.example",
            count=999,
        )

        result = contact_counts(db, tenant_id, FINANCE_USER, "shared-domain.example")
        assert result.org.contact_count == 10

        other_result = contact_counts(db, other.id, FINANCE_USER, "shared-domain.example")
        assert other_result.org.contact_count == 999
    finally:
        with tenant_scope(db, other.id):
            db.execute(
                BaselineContact.__table__.delete().where(BaselineContact.tenant_id == other.id)
            )
        db.execute(text("DELETE FROM tenants WHERE id = :id"), {"id": other.id})
        db.commit()
