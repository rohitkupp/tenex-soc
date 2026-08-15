"""`app.learning.weights` — consumer 2, "Detector weight tuning" (docs/08 Part 2, §2)."""

from __future__ import annotations

import math
import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.learning.weights import MAX_FUSION_WEIGHT, MIN_FUSION_WEIGHT, retune_detector_weights
from app.models.base import tenant_scope
from app.models.detector_stats import DetectorStats
from tests.conftest import make_analysis, make_tenant, make_user
from tests.fixtures.learning import (
    learning_cleanup,
    learning_session,
    make_feedback,
    make_incident_with_verdict,
    make_signal,
)


def _feedback_event(
    session: Session,
    tenant_id: uuid.UUID,
    analysis_id: uuid.UUID,
    user_id: uuid.UUID,
    *,
    detector_key: str,
    positive: bool,
) -> None:
    sig = make_signal(
        session, tenant_id=tenant_id, analysis_id=analysis_id, detector_key=detector_key
    )
    _incident, verdict = make_incident_with_verdict(
        session,
        tenant_id=tenant_id,
        analysis_id=analysis_id,
        signals=[sig],
        disposition="true_positive" if positive else "false_positive",
    )
    make_feedback(session, verdict_id=verdict.id, user_id=user_id, agrees=True)


def test_retune_detector_weights_matches_the_documented_formula(
    learning_session: Session, learning_cleanup: list[uuid.UUID]
) -> None:
    tenant = make_tenant(name="Weights Formula Test Tenant")
    learning_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"weights-{uuid.uuid4()}@test.local")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)

    # `detector_stats.detector_key` is a *global* primary key (docs/02, no tenant_id in the
    # uniqueness constraint -- see app.models.detector_stats's docstring), so every test in this
    # file uses a run-unique suffix. Two isolated tenants asserting on a bare "test.good" would
    # otherwise collide with each other, or with a leftover row from an interrupted prior run.
    run = uuid.uuid4().hex[:8]
    good_key, bad_key = f"test.good.{run}", f"test.bad.{run}"

    # "good" detector: 8 TP, 2 FP -> precision 0.8
    for i in range(10):
        _feedback_event(
            learning_session, tenant.id, analysis.id, user.id, detector_key=good_key, positive=i < 8
        )
    # "bad" detector: 2 TP, 8 FP -> precision 0.2
    for i in range(10):
        _feedback_event(
            learning_session, tenant.id, analysis.id, user.id, detector_key=bad_key, positive=i < 2
        )
    learning_session.commit()

    result = retune_detector_weights(learning_session, tenant.id)

    # prior_precision = pooled TP / pooled (TP+FP) = (8+2) / 20 = 0.5
    assert result.prior_precision is not None
    assert math.isclose(result.prior_precision, 0.5)

    good = next(d for d in result.detectors if d.detector_key == good_key)
    bad = next(d for d in result.detectors if d.detector_key == bad_key)

    assert good.true_positives == 8
    assert good.false_positives == 2
    assert math.isclose(good.precision, 0.8)
    # fusion_weight = clamp(0.8 / 0.5, 0.25, 1.5) = clamp(1.6, ...) = 1.5
    assert math.isclose(good.weight_after, MAX_FUSION_WEIGHT)

    assert bad.true_positives == 2
    assert bad.false_positives == 8
    assert math.isclose(bad.precision, 0.2)
    # fusion_weight = clamp(0.2 / 0.5, 0.25, 1.5) = clamp(0.4, ...) = 0.4
    assert math.isclose(bad.weight_after, 0.4)

    with tenant_scope(learning_session, tenant.id):
        rows = {
            r.detector_key: r for r in learning_session.execute(select(DetectorStats)).scalars()
        }
    assert math.isclose(rows[good_key].fusion_weight, MAX_FUSION_WEIGHT)
    assert math.isclose(rows[bad_key].fusion_weight, 0.4)


def test_retune_detector_weights_clamps_at_the_floor(
    learning_session: Session, learning_cleanup: list[uuid.UUID]
) -> None:
    tenant = make_tenant(name="Weights Floor Test Tenant")
    learning_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"weights-floor-{uuid.uuid4()}@test.local")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)
    run = uuid.uuid4().hex[:8]
    always_wrong_key, mixed_key = f"test.always_wrong.{run}", f"test.mixed.{run}"

    # A detector analysts *always* dismiss (precision 0) alongside one with mixed results, so
    # prior_precision is > 0 and the ratio would clamp well below the floor without the clamp.
    for _ in range(10):
        _feedback_event(
            learning_session,
            tenant.id,
            analysis.id,
            user.id,
            detector_key=always_wrong_key,
            positive=False,
        )
    for i in range(10):
        _feedback_event(
            learning_session,
            tenant.id,
            analysis.id,
            user.id,
            detector_key=mixed_key,
            positive=i < 5,
        )
    learning_session.commit()

    result = retune_detector_weights(learning_session, tenant.id)
    always_wrong = next(d for d in result.detectors if d.detector_key == always_wrong_key)
    assert always_wrong.precision == 0.0
    assert math.isclose(always_wrong.weight_after, MIN_FUSION_WEIGHT)


def test_retune_detector_weights_is_idempotent_and_updates_existing_row(
    learning_session: Session, learning_cleanup: list[uuid.UUID]
) -> None:
    tenant = make_tenant(name="Weights Update Test Tenant")
    learning_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"weights-update-{uuid.uuid4()}@test.local")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)
    run = uuid.uuid4().hex[:8]
    stable_key, evolving_key = f"test.stable.{run}", f"test.evolving.{run}"

    # A second, stable detector so `prior_precision` (pooled across *all* detectors) differs from
    # the evolving detector's own precision -- with only one detector in the tenant,
    # prior_precision would always equal its own precision and the weight would trivially stay at
    # 1.0 forever, proving nothing about the update path this test exists to check.
    for i in range(10):
        _feedback_event(
            learning_session,
            tenant.id,
            analysis.id,
            user.id,
            detector_key=stable_key,
            positive=i < 5,
        )

    _feedback_event(
        learning_session, tenant.id, analysis.id, user.id, detector_key=evolving_key, positive=True
    )
    learning_session.commit()
    first = retune_detector_weights(learning_session, tenant.id)
    first_detector = next(d for d in first.detectors if d.detector_key == evolving_key)
    assert first_detector.true_positives == 1
    assert first_detector.false_positives == 0

    _feedback_event(
        learning_session, tenant.id, analysis.id, user.id, detector_key=evolving_key, positive=False
    )
    learning_session.commit()
    second = retune_detector_weights(learning_session, tenant.id)
    second_detector = next(d for d in second.detectors if d.detector_key == evolving_key)
    assert second_detector.true_positives == 1
    assert second_detector.false_positives == 1
    assert second_detector.weight_before == first_detector.weight_after
    assert second_detector.changed is True

    with tenant_scope(learning_session, tenant.id):
        stats_rows = (
            learning_session.execute(
                select(DetectorStats).where(DetectorStats.detector_key == evolving_key)
            )
            .scalars()
            .all()
        )
    assert len(stats_rows) == 1  # upsert, not a duplicate row
