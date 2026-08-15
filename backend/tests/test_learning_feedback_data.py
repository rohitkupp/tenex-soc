"""`app.learning.feedback_data` — the shared confirmed/rejected -> label derivation consumers 1,
2, and 6 all build on. Runs against the real Postgres, like every other test in this suite.
"""

from __future__ import annotations

import uuid

from sqlalchemy.orm import Session

from app.learning.feedback_data import effective_label, labeled_examples
from tests.conftest import make_analysis, make_tenant, make_user
from tests.fixtures.learning import (
    learning_cleanup,
    learning_session,
    make_feedback,
    make_incident_with_verdict,
    make_signal,
)


class _Feedback:
    def __init__(self, corrected_disposition: str | None) -> None:
        self.corrected_disposition = corrected_disposition


def test_effective_label_confirmed_true_positive_is_positive() -> None:
    assert effective_label("true_positive", _Feedback(None)) == 1  # type: ignore[arg-type]


def test_effective_label_confirmed_false_positive_is_negative() -> None:
    assert effective_label("false_positive", _Feedback(None)) == 0  # type: ignore[arg-type]


def test_effective_label_correction_overrides_verdict_disposition() -> None:
    # Verdict said false_positive; analyst corrects it to true_positive.
    assert effective_label("false_positive", _Feedback("true_positive")) == 1  # type: ignore[arg-type]
    # Verdict said true_positive; analyst corrects it to false_positive.
    assert effective_label("true_positive", _Feedback("false_positive")) == 0  # type: ignore[arg-type]


def test_labeled_examples_one_row_per_feedback_signal_pair(
    learning_session: Session, learning_cleanup: list[uuid.UUID]
) -> None:
    tenant = make_tenant(name="Feedback Data Test Tenant")
    learning_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"fd-{uuid.uuid4()}@test.local")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)

    sig_a = make_signal(
        learning_session,
        tenant_id=tenant.id,
        analysis_id=analysis.id,
        detector_key="signal.beaconing",
    )
    sig_b = make_signal(
        learning_session, tenant_id=tenant.id, analysis_id=analysis.id, detector_key="signal.dga"
    )
    _incident, verdict = make_incident_with_verdict(
        learning_session,
        tenant_id=tenant.id,
        analysis_id=analysis.id,
        signals=[sig_a, sig_b],
        disposition="true_positive",
    )
    make_feedback(learning_session, verdict_id=verdict.id, user_id=user.id, agrees=True)
    learning_session.commit()

    examples = labeled_examples(learning_session, tenant.id)
    assert len(examples) == 2
    detector_keys = {e.detector_key for e in examples}
    assert detector_keys == {"signal.beaconing", "signal.dga"}
    assert all(e.label == 1 for e in examples)


def test_labeled_examples_incident_with_no_signal_ids_is_skipped(
    learning_session: Session, learning_cleanup: list[uuid.UUID]
) -> None:
    tenant = make_tenant(name="Feedback Data Empty Signals Tenant")
    learning_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"fd-empty-{uuid.uuid4()}@test.local")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)

    _incident, verdict = make_incident_with_verdict(
        learning_session, tenant_id=tenant.id, analysis_id=analysis.id, signals=[]
    )
    make_feedback(learning_session, verdict_id=verdict.id, user_id=user.id, agrees=True)
    learning_session.commit()

    assert labeled_examples(learning_session, tenant.id) == []
