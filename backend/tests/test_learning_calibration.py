"""`app.learning.calibration` — consumer 1, "Calibration refit" (docs/08 Part 2, §1)."""

from __future__ import annotations

import math
import uuid

from sqlalchemy.orm import Session

from app.learning.calibration import (
    apply_calibrator,
    refit_calibrators,
    should_refit_now,
    summarize_for_api,
)
from tests.conftest import make_analysis, make_tenant, make_user
from tests.fixtures.learning import (
    learning_cleanup,
    learning_session,
    make_feedback,
    make_incident_with_verdict,
    make_signal,
)


def _seed_miscalibrated_detector(
    session: Session, tenant_id: uuid.UUID, analysis_id: uuid.UUID, user_id: uuid.UUID
) -> None:
    """`stated_confidence` is fixed at 0.6 for every event regardless of outcome, but the *true*
    positive rate is only ~20% -- a textbook miscalibration (systematically overconfident) that
    isotonic regression should visibly correct. 15 labeled events (well above
    `min_samples`), 3 of them positive.
    """
    for i in range(15):
        label_positive = i < 3
        sig = make_signal(
            session,
            tenant_id=tenant_id,
            analysis_id=analysis_id,
            detector_key="test.miscalibrated",
            raw_score=0.6,
            confidence=0.6,
        )
        _incident, verdict = make_incident_with_verdict(
            session,
            tenant_id=tenant_id,
            analysis_id=analysis_id,
            signals=[sig],
            disposition="true_positive" if label_positive else "false_positive",
            fused_score=0.6,
        )
        make_feedback(session, verdict_id=verdict.id, user_id=user_id, agrees=True)
    session.commit()


def test_refit_calibrators_improves_brier_score_on_miscalibrated_detector(
    learning_session: Session, learning_cleanup: list[uuid.UUID]
) -> None:
    tenant = make_tenant(name="Calibration Test Tenant")
    learning_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"calib-{uuid.uuid4()}@test.local")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)

    _seed_miscalibrated_detector(learning_session, tenant.id, analysis.id, user.id)

    result = refit_calibrators(learning_session, tenant.id, persist=False)

    assert result.n_feedback_events == 15
    detector = next(d for d in result.detectors if d.detector_key == "test.miscalibrated")
    assert detector.fitted is True
    assert detector.brier_before is not None
    assert detector.brier_after is not None
    # Stated confidence (0.6) is far from the true 3/15 = 0.2 positive rate; the isotonic fit
    # should land close to that true rate and materially beat the naive stated-confidence score.
    assert detector.brier_after < detector.brier_before
    assert result.overall_brier_after is not None
    assert result.overall_brier_before is not None
    assert result.overall_brier_after < result.overall_brier_before


def test_refit_calibrators_skips_detector_with_too_few_samples(
    learning_session: Session, learning_cleanup: list[uuid.UUID]
) -> None:
    tenant = make_tenant(name="Calibration Sparse Tenant")
    learning_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"calib-sparse-{uuid.uuid4()}@test.local")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)

    sig = make_signal(
        learning_session,
        tenant_id=tenant.id,
        analysis_id=analysis.id,
        detector_key="test.sparse",
    )
    _incident, verdict = make_incident_with_verdict(
        learning_session, tenant_id=tenant.id, analysis_id=analysis.id, signals=[sig]
    )
    make_feedback(learning_session, verdict_id=verdict.id, user_id=user.id, agrees=True)
    learning_session.commit()

    result = refit_calibrators(learning_session, tenant.id, min_samples=5, persist=False)
    detector = next(d for d in result.detectors if d.detector_key == "test.sparse")
    assert detector.fitted is False
    assert detector.skip_reason is not None
    assert "need >= 5" in detector.skip_reason


def test_refit_calibrators_skips_single_class_detector(
    learning_session: Session, learning_cleanup: list[uuid.UUID]
) -> None:
    tenant = make_tenant(name="Calibration Single Class Tenant")
    learning_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"calib-single-{uuid.uuid4()}@test.local")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)

    for _ in range(6):
        sig = make_signal(
            learning_session,
            tenant_id=tenant.id,
            analysis_id=analysis.id,
            detector_key="test.all_positive",
        )
        _incident, verdict = make_incident_with_verdict(
            learning_session,
            tenant_id=tenant.id,
            analysis_id=analysis.id,
            signals=[sig],
            disposition="true_positive",
        )
        make_feedback(learning_session, verdict_id=verdict.id, user_id=user.id, agrees=True)
    learning_session.commit()

    result = refit_calibrators(learning_session, tenant.id, min_samples=5, persist=False)
    detector = next(d for d in result.detectors if d.detector_key == "test.all_positive")
    assert detector.fitted is False
    assert detector.skip_reason is not None
    assert "single-class" in detector.skip_reason


def test_apply_calibrator_falls_back_to_clamped_raw_score_when_unfitted() -> None:
    tenant_id = uuid.uuid4()
    assert apply_calibrator("no.such.detector", 0.42, tenant_id=tenant_id) == 0.42
    assert apply_calibrator("no.such.detector", 1.5, tenant_id=tenant_id) == 1.0
    assert apply_calibrator("no.such.detector", -0.5, tenant_id=tenant_id) == 0.0


def test_apply_calibrator_uses_persisted_artifact_after_refit(
    learning_session: Session, learning_cleanup: list[uuid.UUID]
) -> None:
    tenant = make_tenant(name="Calibration Persist Tenant")
    learning_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"calib-persist-{uuid.uuid4()}@test.local")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)

    _seed_miscalibrated_detector(learning_session, tenant.id, analysis.id, user.id)
    refit_calibrators(learning_session, tenant.id, persist=True)

    calibrated = apply_calibrator("test.miscalibrated", 0.6, tenant_id=tenant.id)
    # The fitted calibrator should map raw_score=0.6 close to the true positive rate (0.2), far
    # from the naive stated confidence (0.6) and the identity-passthrough fallback.
    assert math.isclose(calibrated, 0.2, abs_tol=0.15)


def test_should_refit_now_matches_documented_cadence() -> None:
    assert should_refit_now(50) is True
    assert should_refit_now(100) is True
    assert should_refit_now(49) is False
    assert should_refit_now(0) is False


def test_summarize_for_api_shape(
    learning_session: Session, learning_cleanup: list[uuid.UUID]
) -> None:
    tenant = make_tenant(name="Calibration Summary Tenant")
    learning_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"calib-summary-{uuid.uuid4()}@test.local")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)
    _seed_miscalibrated_detector(learning_session, tenant.id, analysis.id, user.id)

    result = refit_calibrators(learning_session, tenant.id, persist=False)
    payload = summarize_for_api(result)
    assert payload["n_feedback_events"] == 15
    assert "detectors" in payload
    detector_payload = next(
        d for d in payload["detectors"] if d["detector_key"] == "test.miscalibrated"
    )
    assert len(detector_payload["reliability_after"]) == 10  # docs/12: 10 bins
