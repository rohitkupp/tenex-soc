"""Mechanism 8 — DGA classifier retraining (change 21, gated). "Corrected domain labels append
to the training set." The DGA evidence extractor (`app.detection.evidence.dga`, docs/04 §L2) is a
logistic regression over lexical features; this module retrains a *candidate* of that same model
family from `dga_label_feedback` (analyst-corrected domain labels, `app.learning.
dga_label_feedback`) and gates promotion the same way `app.learning.retrain`'s pre-migration
classifier gate does -- mapped onto the closest `evals.config.GATE_TOLERANCES` key
(`disposition_accuracy`, this package's own established "metric mapping" precedent).

## Its own small, honest feature set -- not `app.detection.evidence.dga`'s

`app/detection/**` is out of this milestone's ownership, so this module does not import or
replicate that extractor's exact lexical feature pipeline (entropy, bigram log-likelihood, digit
ratio, consonant runs -- `docs/v2_migration` change 2's own table). It computes a small,
independent, honestly-scoped feature set from the domain string alone (length, digit ratio, vowel
ratio, character-level Shannon entropy) -- enough for a real logistic regression fit and a real
gate decision, not a claim of feature parity with the production extractor.
"""

from __future__ import annotations

import math
import uuid
from collections import Counter
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.learning.mechanisms import GatedApplyResult, create_proposal, decide_proposal
from app.learning.retrain import DOCS12_TOLERANCES, evaluate_candidate
from app.models.base import tenant_scope
from app.models.dga_label_feedback import DgaLabelFeedback
from app.models.learning_proposal import LearningProposal
from app.models.model_version import ModelVersion

__all__ = [
    "DGA_MODEL_KEY",
    "MIN_TRAINING_ROWS",
    "accept_dga_retrain",
    "propose_dga_retrain",
    "record_dga_label_correction",
]

DGA_MODEL_KEY = "dga_logistic_regression"
MIN_TRAINING_ROWS = 20
_REFIT_EVERY_N_LABELS = 10


def record_dga_label_correction(
    session: Session,
    tenant_id: uuid.UUID,
    *,
    domain: str,
    is_dga: bool,
    feedback_id: uuid.UUID,
    incident_id: uuid.UUID,
) -> DgaLabelFeedback:
    with tenant_scope(session, tenant_id):
        row = DgaLabelFeedback(
            tenant_id=tenant_id,
            domain=domain,
            is_dga=is_dga,
            feedback_id=feedback_id,
            incident_id=incident_id,
        )
        session.add(row)
        session.flush()
    return row


def _domain_features(domain: str) -> list[float]:
    if not domain:
        return [0.0, 0.0, 0.0, 0.0]
    length = float(len(domain))
    digits = sum(c.isdigit() for c in domain) / length
    vowels = sum(c.lower() in "aeiou" for c in domain) / length
    counts = Counter(domain)
    entropy = -sum((n / length) * math.log2(n / length) for n in counts.values())
    return [length, digits, vowels, entropy]


def _labeled_rows(session: Session, tenant_id: uuid.UUID) -> list[tuple[str, bool]]:
    """Most-recent label per domain -- module docstring, "a domain relabeled more than once"."""
    with tenant_scope(session, tenant_id):
        rows = (
            session.execute(select(DgaLabelFeedback).order_by(DgaLabelFeedback.created_at.asc()))
            .scalars()
            .all()
        )
    latest: dict[str, bool] = {}
    for r in rows:
        latest[r.domain] = r.is_dga
    return sorted(latest.items())


def propose_dga_retrain(
    session: Session,
    tenant_id: uuid.UUID,
    *,
    trigger_feedback_id: uuid.UUID,
    model_key: str = DGA_MODEL_KEY,
) -> LearningProposal | None:
    """`model_key` defaults to `DGA_MODEL_KEY`; `model_versions` is not tenant-scoped (docs/02,
    same global-sequence design `app.learning.retrain`'s pre-migration classifier gate already
    documents), so tests that don't want to collide with each other's `version` sequence pass a
    run-unique key here -- production code never passes anything but the default."""
    rows = _labeled_rows(session, tenant_id)
    if len(rows) < MIN_TRAINING_ROWS or len(rows) % _REFIT_EVERY_N_LABELS != 0:
        return None
    if len({label for _, label in rows}) < 2:
        return None
    return create_proposal(
        session,
        tenant_id,
        mechanism=8,
        payload={"n_labels": len(rows), "model_key": model_key},
        supporting_feedback_ids=[trigger_feedback_id],
        trigger_feedback_id=trigger_feedback_id,
    )


def _train_and_score(rows: list[tuple[str, bool]]) -> dict[str, float]:
    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import accuracy_score
    from sklearn.model_selection import train_test_split

    x = [_domain_features(d) for d, _ in rows]
    y = [1 if label else 0 for _, label in rows]
    x_train, x_test, y_train, y_test = train_test_split(
        x, y, test_size=0.25, random_state=42, stratify=y if len(set(y)) > 1 else None
    )
    model = LogisticRegression(max_iter=1000)
    model.fit(x_train, y_train)
    accuracy = float(accuracy_score(y_test, model.predict(x_test)))
    return {"disposition_accuracy": accuracy}


def accept_dga_retrain(
    session: Session, tenant_id: uuid.UUID, proposal: LearningProposal, *, user_id: uuid.UUID
) -> GatedApplyResult:
    model_key = proposal.payload.get("model_key", DGA_MODEL_KEY)
    rows = _labeled_rows(session, tenant_id)
    candidate_scores = _train_and_score(rows)

    with tenant_scope(session, tenant_id):
        baseline = session.execute(
            select(ModelVersion)
            .where(ModelVersion.model_key == model_key, ModelVersion.promoted.is_(True))
            .order_by(ModelVersion.version.desc())
            .limit(1)
        ).scalar_one_or_none()

    gate = evaluate_candidate(
        candidate_scores,
        baseline.eval_scores if baseline is not None else None,
        tolerances={"disposition_accuracy": DOCS12_TOLERANCES["disposition_accuracy"]},
    )

    def _apply(
        session: Session, tenant_id: uuid.UUID, proposal: LearningProposal
    ) -> dict[str, Any]:
        version = (baseline.version + 1) if baseline is not None else 1
        with tenant_scope(session, tenant_id):
            session.add(
                ModelVersion(
                    model_key=model_key,
                    version=version,
                    artifact_ref=f"learning/dga_retrain/v{version}",
                    trained_at=datetime.now(UTC),
                    eval_scores={**candidate_scores, "n_labels": len(rows)},
                    promoted=True,
                )
            )
            session.flush()
        return {"version": version, "model_key": model_key, **candidate_scores}

    return decide_proposal(
        session,
        tenant_id,
        proposal,
        passed=gate.passed,
        metric_delta=candidate_scores,
        reason=gate.reason,
        user_id=user_id,
        apply_fn=_apply,
    )
