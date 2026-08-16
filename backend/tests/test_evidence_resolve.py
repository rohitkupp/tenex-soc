"""Unit tests for `app.detection.evidence.resolve_evidence` -- the DB-touching middle stage of
the evidence pipeline (`app.detection.evidence.payload`'s module docstring). Rows are inserted
directly into `baseline_profiles`/`baseline_contacts` (bypassing `app.baseline.loader`), the same
fixture pattern `tests/test_baseline_resolve.py` already established, so each test controls its
own baseline distribution independent of any seeded corpus.

This is the proof that historical context comes from the *baseline store*, not the uploaded
file: the same `RawEvidence` resolved against two different `baseline_profiles` rows for the
identical `(entity, metric)` must produce two different percentiles.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.baseline.resolve import MIN_WINDOWS_FOR_BASELINE
from app.core.db import get_session_factory
from app.detection.evidence.constants import EXTRACTOR_BEACONING, EXTRACTOR_RARITY
from app.detection.evidence.payload import (
    NOMINATION_PERCENTILE_THRESHOLD,
    BaselineQuery,
    ContactQuery,
    RawEvidence,
    finalize_evidence,
)
from app.detection.evidence.resolve_evidence import resolve_evidence
from app.models.base import tenant_scope
from app.models.baseline_contact import BaselineContact
from app.models.baseline_profile import BaselineProfile
from tests.conftest import make_tenant

_T0 = datetime(2026, 1, 1, tzinfo=UTC)
FINANCE_USER = "rosaa@northwind.example"  # real seeded org user -- tests/test_baseline_resolve.py
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
    tenant = make_tenant(name="Evidence Resolve Test Tenant")
    yield tenant.id
    with tenant_scope(db, tenant.id):
        db.execute(BaselineProfile.__table__.delete().where(BaselineProfile.tenant_id == tenant.id))
        db.execute(BaselineContact.__table__.delete().where(BaselineContact.tenant_id == tenant.id))
    db.execute(text("DELETE FROM tenants WHERE id = :id"), {"id": tenant.id})
    db.commit()


def _profile(
    db: Session,
    tenant_id: uuid.UUID,
    *,
    entity_type: str,
    entity_value: str,
    metric: str,
    p50: float,
    mad: float,
    n_windows: int = 40,
) -> None:
    """`session.merge` rather than `session.add` -- deliberately, so a test can call this twice
    for the identical `(tenant_id, entity_type, entity_value, metric)` primary key (`test_
    resolve_evidence_payload_changes_when_the_baseline_changes`'s whole premise: the *same*
    baseline row, updated to a new distribution) without a primary-key conflict on the second
    insert."""
    with tenant_scope(db, tenant_id):
        db.merge(
            BaselineProfile(
                tenant_id=tenant_id,
                entity_type=entity_type,
                entity_value=entity_value,
                metric=metric,
                p50=p50,
                p95=p50 + 4 * mad,
                p99=p50 + 6 * mad,
                mean=p50,
                mad=mad,
                n_windows=n_windows,
            )
        )
        db.commit()


def _raw_beaconing(value: float, *, entity_value: str = "10.0.0.5") -> RawEvidence:
    return RawEvidence(
        extractor=EXTRACTOR_BEACONING,
        entity={"type": "src_ip", "value": entity_value},
        window=(_T0, _T0 + timedelta(hours=1)),
        measurements={"requests": value},
        contributing_line_numbers=[1, 2, 3],
        baseline_queries=(
            BaselineQuery(
                entity_type="src_ip",
                entity_value=entity_value,
                metric="beaconing_requests",
                value=value,
                historical_prefix="beaconing",
            ),
        ),
    )


# --------------------------------------------------------------------------------- historical


def test_resolve_evidence_reads_percentile_from_the_baseline_store(
    db: Session, tenant_id: uuid.UUID
) -> None:
    _profile(
        db,
        tenant_id,
        entity_type="src_ip",
        entity_value="10.0.0.5",
        metric="beaconing_requests",
        p50=60.0,
        mad=5.0,
    )

    (draft,) = resolve_evidence(db, tenant_id, [_raw_beaconing(60.0)])

    assert draft.historical["beaconing_baseline_status"] == "ok"
    assert draft.historical["beaconing_percentile"] == pytest.approx(50.0, abs=1e-6)
    assert draft.historical["beaconing_n_windows"] == 40


def test_resolve_evidence_payload_changes_when_the_baseline_changes(
    db: Session, tenant_id: uuid.UUID
) -> None:
    """The proof this is no longer file-relative: identical `RawEvidence`, two different
    baseline distributions, two different percentiles."""
    raw = [_raw_beaconing(90.0)]

    _profile(
        db,
        tenant_id,
        entity_type="src_ip",
        entity_value="10.0.0.5",
        metric="beaconing_requests",
        p50=60.0,
        mad=5.0,
    )
    (draft_a,) = resolve_evidence(db, tenant_id, raw)

    _profile(
        db,
        tenant_id,
        entity_type="src_ip",
        entity_value="10.0.0.5",
        metric="beaconing_requests",
        p50=90.0,
        mad=5.0,
    )
    (draft_b,) = resolve_evidence(db, tenant_id, raw)

    assert draft_a.historical["beaconing_percentile"] != draft_b.historical["beaconing_percentile"]
    # Same value, now sitting at the new baseline's own median -- 50th percentile.
    assert draft_b.historical["beaconing_percentile"] == pytest.approx(50.0, abs=1e-6)


def test_resolve_evidence_cold_start_surfaces_in_the_payload_rather_than_being_dropped(
    db: Session, tenant_id: uuid.UUID
) -> None:
    # No profile row at all -- missing, not thin.
    (draft_missing,) = resolve_evidence(
        db, tenant_id, [_raw_beaconing(60.0, entity_value="10.0.0.9")]
    )
    assert draft_missing.historical["beaconing_baseline_status"] == "insufficient_history"
    assert draft_missing.historical["beaconing_percentile"] is None
    assert draft_missing.historical["beaconing_n_windows"] == 0
    assert "beaconing_percentile" in draft_missing.historical  # present, not dropped

    # Thin profile row -- n_windows < MIN_WINDOWS_FOR_BASELINE.
    assert MIN_WINDOWS_FOR_BASELINE == 20
    _profile(
        db,
        tenant_id,
        entity_type="src_ip",
        entity_value="10.0.0.7",
        metric="beaconing_requests",
        p50=60.0,
        mad=5.0,
        n_windows=4,
    )
    (draft_thin,) = resolve_evidence(
        db, tenant_id, [_raw_beaconing(200.0, entity_value="10.0.0.7")]
    )
    assert draft_thin.historical["beaconing_baseline_status"] == "insufficient_history"
    assert draft_thin.historical["beaconing_percentile"] is None
    assert draft_thin.historical["beaconing_n_windows"] == 4
    # Cold start is not eligible for nomination either -- `None > threshold` is never true.
    assert draft_thin.nomination_eligible is False


# --------------------------------------------------------------------------------- nomination


def test_nomination_eligible_above_995_percentile_not_below(
    db: Session, tenant_id: uuid.UUID
) -> None:
    _profile(
        db,
        tenant_id,
        entity_type="src_ip",
        entity_value="10.0.0.5",
        metric="beaconing_requests",
        p50=60.0,
        mad=1.0,
    )

    # Comfortably inside the distribution -- not eligible.
    (draft_normal,) = resolve_evidence(db, tenant_id, [_raw_beaconing(61.0)])
    assert draft_normal.historical["beaconing_percentile"] < NOMINATION_PERCENTILE_THRESHOLD
    assert draft_normal.nomination_eligible is False

    # Many MADs above the median -- comfortably past the 99.5th percentile.
    (draft_extreme,) = resolve_evidence(db, tenant_id, [_raw_beaconing(200.0)])
    assert draft_extreme.historical["beaconing_percentile"] > NOMINATION_PERCENTILE_THRESHOLD
    assert draft_extreme.nomination_eligible is True
    assert draft_extreme.nomination_score is not None
    assert 0.0 < draft_extreme.nomination_score <= 1.0

    payloads = finalize_evidence([draft_normal, draft_extreme])
    fired = [p for p in payloads if p.nominates_candidate]
    assert len(fired) == 1
    assert fired[0].measurements["requests"] == 200.0


# --------------------------------------------------------------------------------- rarity scopes


def test_resolve_evidence_rarity_carries_all_three_scopes_with_first_seen_flags(
    db: Session, tenant_id: uuid.UUID
) -> None:
    with tenant_scope(db, tenant_id):
        db.add(
            BaselineContact(
                tenant_id=tenant_id,
                scope="department",
                scope_value="Finance",
                domain="rare-saas.example",
                contact_count=1,
                first_seen=_T0 - timedelta(days=30),
                last_seen=_T0,
            )
        )
        db.add(
            BaselineContact(
                tenant_id=tenant_id,
                scope="org",
                scope_value=_ORG_SCOPE_VALUE,
                domain="rare-saas.example",
                contact_count=4,
                first_seen=_T0 - timedelta(days=60),
                last_seen=_T0,
            )
        )
        db.commit()

    raw = RawEvidence(
        extractor=EXTRACTOR_RARITY,
        entity={"type": "user", "value": FINANCE_USER, "domain": "rare-saas.example"},
        window=(_T0, _T0),
        measurements={"n_events_by_principal": 1},
        contributing_line_numbers=[42],
        contact_query=ContactQuery(user=FINANCE_USER, domain="rare-saas.example"),
    )

    (draft,) = resolve_evidence(db, tenant_id, [raw])

    # "Zero for Alice, one for Finance, four org-wide" -- the migration's own example.
    assert draft.measurements["user_contact_count"] == 0
    assert draft.measurements["department_contact_count"] == 1
    assert draft.measurements["org_contact_count"] == 4
    assert draft.historical["user_first_seen"] is True
    assert draft.historical["department_first_seen"] is False
    assert draft.historical["org_first_seen"] is False
    assert draft.historical["department_scope_value"] == "Finance"


def test_resolve_evidence_rarity_nominates_on_true_org_wide_first_contact(
    db: Session, tenant_id: uuid.UUID
) -> None:
    # No baseline_contacts rows at all for this domain -- never contacted, at any scope, in six
    # months of history.
    raw = RawEvidence(
        extractor=EXTRACTOR_RARITY,
        entity={"type": "user", "value": FINANCE_USER, "domain": "never-seen.example"},
        window=(_T0, _T0),
        measurements={"n_events_by_principal": 1},
        contributing_line_numbers=[1],
        contact_query=ContactQuery(user=FINANCE_USER, domain="never-seen.example"),
    )

    (draft,) = resolve_evidence(db, tenant_id, [raw])

    assert draft.nomination_eligible is True
    assert draft.nomination_score == 1.0
    assert draft.historical["baseline_domain_rarity"] == 1.0


# --------------------------------------------------------------------------------- determinism


def test_evidence_id_is_stable_across_two_full_resolve_and_finalize_runs(
    db: Session, tenant_id: uuid.UUID
) -> None:
    _profile(
        db,
        tenant_id,
        entity_type="src_ip",
        entity_value="10.0.0.5",
        metric="beaconing_requests",
        p50=60.0,
        mad=5.0,
    )
    raw = [
        _raw_beaconing(200.0, entity_value="10.0.0.5"),
        _raw_beaconing(70.0, entity_value="10.0.0.1"),
    ]

    run_a = finalize_evidence(resolve_evidence(db, tenant_id, raw))
    run_b = finalize_evidence(resolve_evidence(db, tenant_id, raw))

    ids_a = {(p.extractor, p.entity["value"]): p.evidence_id for p in run_a}
    ids_b = {(p.extractor, p.entity["value"]): p.evidence_id for p in run_b}
    assert ids_a == ids_b
