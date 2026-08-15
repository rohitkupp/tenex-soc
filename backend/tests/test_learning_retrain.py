"""`app.learning.retrain` — consumer 6's gate (docs/08 "Retrain gate", docs/12 "Regression gate").

The load-bearing test in this file is `test_evaluate_candidate_rejects_a_deliberately_worse_
candidate`: it constructs a worse candidate on purpose and asserts the gate rejects it and names
the metric that tripped it, per this milestone's own acceptance bar. `test_run_classifier_
retrain_*` exercises the same gate wired to real `model_versions` writes, with a dependency-
injected trainer (`app.learning.classifier.train_and_evaluate`'s real LightGBM path is exercised
separately, and skipped rather than failed where the local environment can't load `lightgbm` --
see `app/learning/classifier.py`'s module docstring for why that's a real, documented risk on at
least one development machine, not a hypothetical).
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from datetime import UTC, datetime

import pytest
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.core.db import get_engine
from app.learning.classifier import TrainingRow, TrainResult, build_training_rows
from app.learning.retrain import DOCS12_TOLERANCES, evaluate_candidate, run_classifier_retrain
from app.models.model_version import ModelVersion
from tests.conftest import make_analysis, make_tenant, make_user
from tests.fixtures.learning import (  # noqa: F401
    learning_cleanup,
    learning_session,
    make_feedback,
    make_incident_with_verdict,
    make_signal,
)


@pytest.fixture
def retrain_model_key() -> Iterator[str]:
    """A run-unique `model_key`, cleaned up afterward. `model_versions` is not tenant-scoped
    (docs/02 -- see `run_classifier_retrain`'s docstring), and `app/scripts/seed_feedback.py`
    already writes a real, multi-version history under `CLASSIFIER_MODEL_KEY` ("lightgbm") --
    every retrain test uses its own key instead so `version == 1` / "no baseline" assertions hold
    regardless of what else has been seeded, and parallel test runs never collide with each
    other. `tests.fixtures.learning.learning_cleanup` cannot cover this itself (it cleans up by
    `tenant_id`, and this table has none), so this fixture is what removes the row after the test.
    """
    key = f"lightgbm-test-{uuid.uuid4().hex[:8]}"
    yield key
    with get_engine().begin() as conn:
        conn.execute(delete(ModelVersion).where(ModelVersion.model_key == key))


# ---------------------------------------------------------------------------- evaluate_candidate


def test_evaluate_candidate_promotes_first_model_when_no_baseline() -> None:
    result = evaluate_candidate({"accuracy": 0.1, "macro_f1": 0.05}, None)
    assert result.passed is True
    assert result.failed_metric is None
    assert result.comparisons == []


def test_evaluate_candidate_rejects_a_deliberately_worse_candidate() -> None:
    """The acceptance bar, verbatim: "A deliberately worse candidate model is rejected by the
    gate. Construct one and show the rejection with the metric that tripped it." """
    baseline = {"accuracy": 0.70, "macro_precision": 0.68, "macro_recall": 0.65, "macro_f1": 0.66}
    # Deliberately worse: macro_f1 drops by 0.10, far past the -0.02 tolerance
    # (`DOCS12_TOLERANCES["detection_f1"]`, which `macro_f1` is gated against).
    worse_candidate = {
        "accuracy": 0.69,  # within disposition_accuracy's -0.05 tolerance, not the trigger
        "macro_precision": 0.67,  # within detection_f1's -0.02 tolerance, not the trigger
        "macro_recall": 0.64,  # within tolerance too
        "macro_f1": 0.56,  # -0.10, beyond the -0.02 tolerance -- this is the one that trips it
    }

    result = evaluate_candidate(worse_candidate, baseline)

    assert result.passed is False
    assert result.failed_metric == "macro_f1"
    assert "macro_f1" in result.reason
    # Every checked metric is reported, not just the one that failed.
    assert {c.metric for c in result.comparisons} == {
        "accuracy",
        "macro_precision",
        "macro_recall",
        "macro_f1",
    }
    f1_comparison = next(c for c in result.comparisons if c.metric == "macro_f1")
    assert f1_comparison.regressed is True
    assert f1_comparison.baseline == 0.66
    assert f1_comparison.candidate == 0.56


def test_evaluate_candidate_promotes_an_improved_candidate() -> None:
    baseline = {"accuracy": 0.60, "macro_precision": 0.60, "macro_recall": 0.60, "macro_f1": 0.60}
    better = {"accuracy": 0.75, "macro_precision": 0.72, "macro_recall": 0.70, "macro_f1": 0.71}
    result = evaluate_candidate(better, baseline)
    assert result.passed is True
    assert result.failed_metric is None
    assert all(not c.regressed for c in result.comparisons)


def test_evaluate_candidate_tolerates_a_small_regression_within_bounds() -> None:
    baseline = {"macro_f1": 0.60}
    slightly_worse = {"macro_f1": 0.585}  # -0.015, inside the -0.02 tolerance
    result = evaluate_candidate(slightly_worse, baseline)
    assert result.passed is True


def test_evaluate_candidate_skips_metrics_missing_from_either_side() -> None:
    baseline = {"accuracy": 0.5}
    candidate = {"macro_f1": 0.9}  # no overlapping gated metric
    result = evaluate_candidate(candidate, baseline)
    assert result.passed is True
    assert result.comparisons == []


def test_docs12_tolerances_injection_resistance_has_a_hard_floor() -> None:
    tol = DOCS12_TOLERANCES["injection_resistance"]
    assert tol.hard_floor == 1.0
    result = evaluate_candidate(
        {"injection_resistance": 0.95}, {"injection_resistance": 0.95}, tolerances=DOCS12_TOLERANCES
    )
    # Delta is zero, but the hard floor still trips because 0.95 < 1.0.
    assert result.passed is False
    assert result.failed_metric == "injection_resistance"


# ---------------------------------------------------------------------------- run_classifier_retrain


def _stub_train_fn(scores: dict[str, float], *, n_train: int = 40, n_held_out: int = 10):
    def _train(_rows: list[TrainingRow]) -> TrainResult:
        return TrainResult(
            model_bytes=b"stub-model",
            label_classes=("benign", "T1071.001"),
            eval_scores=scores,
            n_train=n_train,
            n_held_out=n_held_out,
        )

    return _train


def _seed_labeled_rows(
    session: Session, tenant_id: uuid.UUID, analysis_id: uuid.UUID, user_id: uuid.UUID, n: int
) -> None:
    for i in range(n):
        sig = make_signal(session, tenant_id=tenant_id, analysis_id=analysis_id)
        _incident, verdict = make_incident_with_verdict(
            session,
            tenant_id=tenant_id,
            analysis_id=analysis_id,
            signals=[sig],
            disposition="true_positive" if i % 2 == 0 else "false_positive",
            mitre_techniques=["T1071.001"] if i % 2 == 0 else [],
        )
        make_feedback(session, verdict_id=verdict.id, user_id=user_id, agrees=True)
    session.commit()


def test_run_classifier_retrain_skips_below_the_minimum_row_threshold(
    learning_session: Session,  # noqa: F811
    learning_cleanup: list[uuid.UUID],  # noqa: F811
) -> None:
    tenant = make_tenant(name="Retrain Too Few Rows Test Tenant")
    learning_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"retrain-few-{uuid.uuid4()}@test.local")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)
    _seed_labeled_rows(learning_session, tenant.id, analysis.id, user.id, n=3)

    attempt = run_classifier_retrain(learning_session, tenant.id, min_rows=20)
    assert attempt.skipped is True
    assert attempt.skip_reason is not None
    assert "20" in attempt.skip_reason
    assert attempt.model_version_id is None


def test_run_classifier_retrain_promotes_the_first_attempt_with_no_incumbent(
    learning_session: Session,  # noqa: F811
    learning_cleanup: list[uuid.UUID],  # noqa: F811
    retrain_model_key: str,
) -> None:
    tenant = make_tenant(name="Retrain First Promotion Test Tenant")
    learning_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"retrain-first-{uuid.uuid4()}@test.local")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)
    _seed_labeled_rows(learning_session, tenant.id, analysis.id, user.id, n=20)

    model_key = retrain_model_key
    train_fn = _stub_train_fn(
        {"accuracy": 0.5, "macro_precision": 0.5, "macro_recall": 0.5, "macro_f1": 0.5}
    )
    attempt = run_classifier_retrain(
        learning_session, tenant.id, train_fn=train_fn, min_rows=20, model_key=model_key
    )

    assert attempt.skipped is False
    assert attempt.promoted is True
    assert attempt.version == 1
    assert attempt.baseline_version is None
    assert attempt.gate is not None
    assert attempt.gate.passed is True

    row = learning_session.get(ModelVersion, attempt.model_version_id)
    assert row is not None
    assert row.model_key == model_key
    assert row.promoted is True
    assert row.eval_scores["gate"]["passed"] is True


def test_run_classifier_retrain_rejects_a_deliberately_worse_second_attempt(
    learning_session: Session,  # noqa: F811
    learning_cleanup: list[uuid.UUID],  # noqa: F811
    retrain_model_key: str,
) -> None:
    """End-to-end version of the same acceptance-bar requirement: a first, decent model
    promotes; a second, deliberately worse model is rejected and the first stays live -- both
    recorded as `model_versions` rows, promoted or not (docs/08 "Retrain gate": "Record every
    attempt")."""
    tenant = make_tenant(name="Retrain Rejection Test Tenant")
    learning_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"retrain-reject-{uuid.uuid4()}@test.local")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)
    _seed_labeled_rows(learning_session, tenant.id, analysis.id, user.id, n=20)
    model_key = retrain_model_key

    good_train_fn = _stub_train_fn(
        {"accuracy": 0.75, "macro_precision": 0.72, "macro_recall": 0.70, "macro_f1": 0.71}
    )
    first = run_classifier_retrain(
        learning_session, tenant.id, train_fn=good_train_fn, min_rows=20, model_key=model_key
    )
    assert first.promoted is True
    assert first.version == 1

    worse_train_fn = _stub_train_fn(
        {"accuracy": 0.50, "macro_precision": 0.40, "macro_recall": 0.35, "macro_f1": 0.37}
    )
    second = run_classifier_retrain(
        learning_session, tenant.id, train_fn=worse_train_fn, min_rows=20, model_key=model_key
    )

    assert second.skipped is False
    assert second.promoted is False
    assert second.version == 2
    assert second.baseline_version == 1
    assert second.gate is not None
    assert second.gate.passed is False
    assert second.gate.failed_metric is not None

    # Both attempts are on record -- the rejection history is the evidence the gate works.
    rows = (
        learning_session.execute(
            select(ModelVersion)
            .where(ModelVersion.model_key == model_key)
            .order_by(ModelVersion.version)
        )
        .scalars()
        .all()
    )
    versions = {
        r.version: r for r in rows if r.id in {first.model_version_id, second.model_version_id}
    }
    assert versions[1].promoted is True
    assert versions[2].promoted is False
    assert versions[2].eval_scores["gate"]["failed_metric"] is not None

    # The incumbent (v1) is still the latest *promoted* row -- rejection did not overwrite it.
    latest_promoted = (
        learning_session.execute(
            select(ModelVersion)
            .where(ModelVersion.model_key == model_key, ModelVersion.promoted.is_(True))
            .order_by(ModelVersion.version.desc())
            .limit(1)
        )
        .scalars()
        .first()
    )
    assert latest_promoted is not None
    assert latest_promoted.version == 1


def test_run_classifier_retrain_persist_false_writes_nothing(
    learning_session: Session,  # noqa: F811
    learning_cleanup: list[uuid.UUID],  # noqa: F811
) -> None:
    tenant = make_tenant(name="Retrain No Persist Test Tenant")
    learning_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"retrain-nopersist-{uuid.uuid4()}@test.local")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)
    _seed_labeled_rows(learning_session, tenant.id, analysis.id, user.id, n=20)

    train_fn = _stub_train_fn(
        {"accuracy": 0.5, "macro_precision": 0.5, "macro_recall": 0.5, "macro_f1": 0.5}
    )
    attempt = run_classifier_retrain(
        learning_session, tenant.id, train_fn=train_fn, min_rows=20, persist=False
    )
    assert attempt.model_version_id is None
    assert attempt.version is None
    # gate/eval_scores are still computed and returned even without persisting.
    assert attempt.eval_scores is not None
    assert attempt.gate is not None


# ---------------------------------------------------------------------------- real LightGBM path


def test_build_training_rows_and_real_lightgbm_end_to_end(
    learning_session: Session,  # noqa: F811
    learning_cleanup: list[uuid.UUID],  # noqa: F811
) -> None:
    """Exercises `app.learning.classifier.train_and_evaluate`'s real (non-stubbed) LightGBM path.
    Skips, rather than fails, if `lightgbm` cannot be imported in this environment -- see
    `app/learning/classifier.py`'s module docstring."""
    try:
        import lightgbm  # noqa: F401
    except (ImportError, OSError) as exc:
        pytest.skip(f"lightgbm not loadable in this environment: {exc}")

    from app.learning.classifier import train_and_evaluate

    tenant = make_tenant(name="Retrain Real LightGBM Test Tenant")
    learning_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"retrain-real-{uuid.uuid4()}@test.local")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)
    _seed_labeled_rows(learning_session, tenant.id, analysis.id, user.id, n=30)

    rows = build_training_rows(learning_session, tenant.id)
    assert len(rows) == 30

    result = train_and_evaluate(rows)
    assert 0.0 <= result.eval_scores["accuracy"] <= 1.0
    assert result.n_train + result.n_held_out == 30
    assert "benign" in result.label_classes or "T1071.001" in result.label_classes


def test_run_classifier_retrain_real_lightgbm_writes_a_promoted_first_version(
    learning_session: Session,  # noqa: F811
    learning_cleanup: list[uuid.UUID],  # noqa: F811
    retrain_model_key: str,
) -> None:
    try:
        import lightgbm  # noqa: F401
    except (ImportError, OSError) as exc:
        pytest.skip(f"lightgbm not loadable in this environment: {exc}")

    tenant = make_tenant(name="Retrain Real LightGBM Attempt Test Tenant")
    learning_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"retrain-real-attempt-{uuid.uuid4()}@test.local")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)
    _seed_labeled_rows(learning_session, tenant.id, analysis.id, user.id, n=30)

    attempt = run_classifier_retrain(
        learning_session, tenant.id, min_rows=20, model_key=retrain_model_key
    )
    assert attempt.skipped is False
    assert attempt.promoted is True  # first attempt, nothing to regress against
    assert attempt.eval_scores is not None
    assert datetime.now(UTC) >= attempt.attempted_at
