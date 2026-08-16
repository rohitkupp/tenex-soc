"""`app.learning.feedback` — the orchestrator `POST /api/incidents/{id}/feedback` calls, wiring
all six consumers together (see that module's docstring for the order and cadence)."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy.orm import Session

from app.detection.fusion import anomaly_confidence_from_fused_score
from app.learning.feedback import (
    FeedbackInput,
    IncidentNotFoundError,
    IncidentNotTriagedError,
    record_feedback,
)
from app.models.analyst_feedback import AnalystFeedback
from app.models.base import tenant_scope
from app.models.incident import Incident
from tests.conftest import make_analysis, make_tenant, make_user
from tests.fixtures.learning import (  # noqa: F401
    learning_cleanup,
    learning_session,
    make_incident_with_verdict,
    make_signal,
)


def test_record_feedback_raises_for_unknown_incident(
    learning_session: Session,  # noqa: F811
    learning_cleanup: list[uuid.UUID],  # noqa: F811
) -> None:
    tenant = make_tenant(name="Feedback Unknown Incident Test Tenant")
    learning_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"fb-unknown-{uuid.uuid4()}@test.local")

    with pytest.raises(IncidentNotFoundError):
        record_feedback(
            learning_session,
            tenant.id,
            user_id=user.id,
            incident_id=uuid.uuid4(),
            data=FeedbackInput(agrees=True),
        )


def test_record_feedback_raises_for_incident_without_a_verdict(
    learning_session: Session,  # noqa: F811
    learning_cleanup: list[uuid.UUID],  # noqa: F811
) -> None:
    tenant = make_tenant(name="Feedback No Verdict Test Tenant")
    learning_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"fb-noverdict-{uuid.uuid4()}@test.local")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)

    with tenant_scope(learning_session, tenant.id):
        incident = Incident(
            analysis_id=analysis.id,
            tenant_id=tenant.id,
            title="No verdict yet",
            severity="low",
            fused_score=0.1,
            anomaly_confidence=anomaly_confidence_from_fused_score(0.1),
            entity_ids=[],
            signal_ids=[],
        )
        learning_session.add(incident)
        learning_session.flush()
    learning_session.commit()

    with pytest.raises(IncidentNotTriagedError):
        record_feedback(
            learning_session,
            tenant.id,
            user_id=user.id,
            incident_id=incident.id,
            data=FeedbackInput(agrees=True),
        )


def test_record_feedback_inserts_row_and_always_retunes_weights(
    learning_session: Session,  # noqa: F811
    learning_cleanup: list[uuid.UUID],  # noqa: F811
) -> None:
    tenant = make_tenant(name="Feedback Orchestration Test Tenant")
    learning_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"fb-orch-{uuid.uuid4()}@test.local")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)
    detector_key = f"test.orchestration.{uuid.uuid4().hex[:8]}"

    sig = make_signal(
        learning_session, tenant_id=tenant.id, analysis_id=analysis.id, detector_key=detector_key
    )
    incident, _verdict = make_incident_with_verdict(
        learning_session,
        tenant_id=tenant.id,
        analysis_id=analysis.id,
        signals=[sig],
        disposition="true_positive",
    )
    learning_session.commit()

    outcome = record_feedback(
        learning_session,
        tenant.id,
        user_id=user.id,
        incident_id=incident.id,
        data=FeedbackInput(agrees=True, note="looks right"),
    )
    learning_session.commit()

    with tenant_scope(learning_session, tenant.id):
        row = learning_session.get(AnalystFeedback, outcome.feedback_id)
    assert row is not None
    assert row.agrees is True
    assert row.note == "looks right"

    # Consumer 2 (weight tuning) always runs.
    changed_keys = {c.detector_key for c in outcome.weight_tuning.detectors}
    assert detector_key in changed_keys

    # Below the 50-event refit/retrain cadence, consumers 1 and 6 do not run on a single call.
    assert outcome.calibration_refit is None
    assert outcome.retrain_attempt is None

    # No dismissal_reason / mark_benign_baseline -> consumers 4 and 5 produce nothing.
    assert outcome.suppression_candidates == []
    assert outcome.benign_baseline_entries == []


def test_record_feedback_triggers_suppression_and_benign_baseline_when_flagged(
    learning_session: Session,  # noqa: F811
    learning_cleanup: list[uuid.UUID],  # noqa: F811
) -> None:
    tenant = make_tenant(name="Feedback Dismissal Test Tenant")
    learning_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"fb-dismiss-{uuid.uuid4()}@test.local")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)

    sig = make_signal(learning_session, tenant_id=tenant.id, analysis_id=analysis.id)
    incident, _verdict = make_incident_with_verdict(
        learning_session,
        tenant_id=tenant.id,
        analysis_id=analysis.id,
        signals=[sig],
        disposition="true_positive",
    )
    learning_session.commit()

    outcome = record_feedback(
        learning_session,
        tenant.id,
        user_id=user.id,
        incident_id=incident.id,
        data=FeedbackInput(
            agrees=False,
            dismissal_reason="known sanctioned scanner",
            mark_benign_baseline=True,
        ),
    )
    learning_session.commit()

    assert len(outcome.suppression_candidates) == 1
    assert len(outcome.benign_baseline_entries) == 1


def test_record_feedback_triggers_calibration_and_retrain_at_the_cadence_threshold(
    learning_session: Session,  # noqa: F811
    learning_cleanup: list[uuid.UUID],  # noqa: F811
) -> None:
    """docs/08 §1's "every 50 feedback events" cadence, exercised for real: the 50th feedback
    event on one tenant should trigger both the calibration refit and a classifier retrain
    attempt; the 49th should not.

    Unlike `tests/test_learning_retrain.py`, `record_feedback` has no `train_fn`/`model_key`
    injection point (it always drives `run_classifier_retrain` with its real defaults, matching
    what `POST /api/incidents/{id}/feedback` actually does) -- so the 50th call here really does
    import and run `lightgbm`. Skips, rather than fails, where that is not loadable; see
    `app/learning/classifier.py`'s module docstring.
    """
    try:
        import lightgbm  # noqa: F401
    except (ImportError, OSError) as exc:
        pytest.skip(f"lightgbm not loadable in this environment: {exc}")

    tenant = make_tenant(name="Feedback Cadence Test Tenant")
    learning_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"fb-cadence-{uuid.uuid4()}@test.local")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)

    last_outcome = None
    for i in range(50):
        sig = make_signal(learning_session, tenant_id=tenant.id, analysis_id=analysis.id)
        incident, _verdict = make_incident_with_verdict(
            learning_session,
            tenant_id=tenant.id,
            analysis_id=analysis.id,
            signals=[sig],
            disposition="true_positive" if i % 2 == 0 else "false_positive",
        )
        learning_session.commit()
        last_outcome = record_feedback(
            learning_session,
            tenant.id,
            user_id=user.id,
            incident_id=incident.id,
            data=FeedbackInput(agrees=True),
        )
        learning_session.commit()
        if i < 49:
            assert last_outcome.calibration_refit is None, f"refit fired early at event {i + 1}"

    assert last_outcome is not None
    assert last_outcome.calibration_refit is not None
    assert last_outcome.calibration_refit.n_feedback_events == 50
    assert last_outcome.retrain_attempt is not None


def test_record_feedback_is_tenant_isolated(
    learning_session: Session,  # noqa: F811
    learning_cleanup: list[uuid.UUID],  # noqa: F811
) -> None:
    tenant_a = make_tenant(name="Feedback Isolation Tenant A")
    tenant_b = make_tenant(name="Feedback Isolation Tenant B")
    learning_cleanup.append(tenant_a.id)
    learning_cleanup.append(tenant_b.id)
    user_a = make_user(tenant_id=tenant_a.id, email=f"fb-iso-a-{uuid.uuid4()}@test.local")
    user_b = make_user(tenant_id=tenant_b.id, email=f"fb-iso-b-{uuid.uuid4()}@test.local")
    analysis_a = make_analysis(tenant_id=tenant_a.id, user_id=user_a.id)

    sig = make_signal(learning_session, tenant_id=tenant_a.id, analysis_id=analysis_a.id)
    incident_a, _verdict = make_incident_with_verdict(
        learning_session, tenant_id=tenant_a.id, analysis_id=analysis_a.id, signals=[sig]
    )
    learning_session.commit()

    # Tenant B's session/user cannot see tenant A's incident.
    with pytest.raises(IncidentNotFoundError):
        record_feedback(
            learning_session,
            tenant_b.id,
            user_id=user_b.id,
            incident_id=incident_a.id,
            data=FeedbackInput(agrees=True),
        )
