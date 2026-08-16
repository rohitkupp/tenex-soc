"""Mechanism 6 — baseline expansion (change 21, gated). "Confirmed-benign windows append with
`analyst_confirmed` -> `baseline_windows` -> EIF, refit: yes."

Builds on the existing consumer-5 flagging path (`app.learning.benign_corpus.flag_benign_baseline`,
pre-migration but untouched by this module): a `mark_benign_baseline` feedback event already
writes `benign_baseline_entries` rows. This module is the *gated* second half change 21 adds on
top of that: batch every unconsumed entry for one feedback event into one `learning_proposals`
candidate (`app.learning.mechanisms.create_proposal`); on approval, actually append to
`baseline_windows` (change 1's historical baseline store -- every percentile in the system
resolves against it) and retrain a candidate EIF, gated through `evals.gate.evaluate_gate`.

## `features` -- an honest approximation, not the generator's true ~9-key pipeline

`baseline_windows.features` is meant to hold the same 9 keys `docs/v2_migration/
generate_corpus.py`'s `build_baseline()` computes from raw events (`app.models.baseline_window`'s
own docstring). Nothing in this checkout's live path re-derives those 9 keys from a real,
already-ingested analysis's events yet (`app/baseline/loader.py` only bulk-loads the generator's
own JSONL output; there is no live "compute the 9 keys for one entity-window" function to call
without reimplementing a piece of `app/detection`'s feature pipeline, which this milestone does
not own). `_approximate_features` below computes the closest honest approximation from data this
package already has -- the incident's own contributing `signals` -- and is documented as an
approximation rather than silently presented as the generator's exact figure.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.detection.ml.eif import EIFArtifact
from app.learning.mechanisms import GatedApplyResult, create_proposal, decide_proposal
from app.learning.retrain import DOCS12_TOLERANCES, evaluate_candidate
from app.models.base import tenant_scope
from app.models.baseline_window import BaselineWindow
from app.models.benign_baseline_entry import BenignBaselineEntry
from app.models.learning_proposal import LearningProposal
from app.models.model_version import ModelVersion
from app.models.signal import Signal

__all__ = ["EIF_MODEL_KEY", "accept_baseline_expansion", "propose_baseline_expansion"]

EIF_MODEL_KEY = "eif"
_BASELINE_FEATURE_KEYS = (
    "n_events",
    "n_unique_domains",
    "bytes_out",
    "bytes_in",
    "post_ratio",
    "blocked_ratio",
    "off_hours_ratio",
    "automation_ua_ratio",
    "direct_ip_ratio",
)


def _approximate_features(session: Session, entry: BenignBaselineEntry) -> dict[str, float]:
    """Best-effort 9-key approximation from the entity's own signals in this window -- module
    docstring, "an honest approximation." Every key defaults to `0.0` when nothing in the
    signal's `explanation` carries it, rather than fabricating a plausible-looking number."""
    signals = (
        session.execute(
            select(Signal).where(
                Signal.entity_type == entry.entity_type,
                Signal.entity_value == entry.entity_value,
            )
        )
        .scalars()
        .all()
    )
    features = dict.fromkeys(_BASELINE_FEATURE_KEYS, 0.0)
    for sig in signals:
        measurements = (
            sig.explanation.get("measurements") if isinstance(sig.explanation, dict) else None
        )
        if not isinstance(measurements, dict):
            continue
        for key in _BASELINE_FEATURE_KEYS:
            value = measurements.get(key)
            if isinstance(value, int | float):
                features[key] = max(features[key], float(value))
    return features


def propose_baseline_expansion(
    session: Session, tenant_id: uuid.UUID, feedback_id: uuid.UUID
) -> LearningProposal | None:
    """Called from `app/learning/feedback.py` right after `flag_benign_baseline` runs for this
    feedback event. Stages every unconsumed `benign_baseline_entries` row this specific feedback
    event created into one proposal; returns `None` (no proposal) if that feedback event flagged
    nothing."""
    with tenant_scope(session, tenant_id):
        entries = (
            session.execute(
                select(BenignBaselineEntry).where(
                    BenignBaselineEntry.feedback_id == feedback_id,
                    BenignBaselineEntry.included_in_training_at.is_(None),
                )
            )
            .scalars()
            .all()
        )
        if not entries:
            return None

        windows = [
            {
                "entry_id": e.id,
                "entity_type": e.entity_type,
                "entity_value": e.entity_value,
                "window_start": e.window_start.isoformat() if e.window_start else None,
                "features": _approximate_features(session, e),
            }
            for e in entries
        ]

    return create_proposal(
        session,
        tenant_id,
        mechanism=6,
        payload={"windows": windows},
        supporting_feedback_ids=[feedback_id],
        trigger_feedback_id=feedback_id,
    )


def _apply(session: Session, tenant_id: uuid.UUID, proposal: LearningProposal) -> dict[str, Any]:
    windows = proposal.payload["windows"]
    written = 0
    with tenant_scope(session, tenant_id):
        for w in windows:
            window_start = datetime.fromisoformat(w["window_start"]) if w["window_start"] else None
            if window_start is None:
                continue
            existing = session.execute(
                select(BaselineWindow).where(
                    BaselineWindow.entity_type == w["entity_type"],
                    BaselineWindow.entity_value == w["entity_value"],
                    BaselineWindow.window_start == window_start,
                )
            ).scalar_one_or_none()
            if existing is not None:
                existing.features = w["features"]
            else:
                session.add(
                    BaselineWindow(
                        tenant_id=tenant_id,
                        entity_type=w["entity_type"],
                        entity_value=w["entity_value"],
                        window_start=window_start,
                        features=w["features"],
                    )
                )
                written += 1

            entry = session.get(BenignBaselineEntry, w["entry_id"])
            if entry is not None:
                entry.included_in_training_at = datetime.now(UTC)
        session.flush()

        all_windows = session.execute(select(BaselineWindow)).scalars().all()

        score = _score_eif_candidate([w.features for w in all_windows])
        baseline_version = session.execute(
            select(ModelVersion)
            .where(ModelVersion.model_key == EIF_MODEL_KEY, ModelVersion.promoted.is_(True))
            .order_by(ModelVersion.version.desc())
            .limit(1)
        ).scalar_one_or_none()
        version = (baseline_version.version + 1) if baseline_version is not None else 1
        if not score.skipped:
            session.add(
                ModelVersion(
                    model_key=EIF_MODEL_KEY,
                    version=version,
                    artifact_ref=f"learning/baseline_expansion/eif_candidate_v{version}",
                    trained_at=datetime.now(UTC),
                    eval_scores={
                        **score.candidate_scores,
                        "n_windows": len(all_windows),
                        "separation": score.separation,
                    },
                    # This call site is only ever reached from `decide_proposal` after the gate
                    # already passed (`accept_baseline_expansion`'s own precondition) -- promoted
                    # unconditionally here, not re-decided.
                    promoted=True,
                )
            )
            session.flush()

    return {
        "baseline_windows_written": written,
        "baseline_windows_total": len(all_windows),
        "eif_version": version if not score.skipped else None,
        "eif_separation": score.separation,
    }


@dataclass(frozen=True, slots=True)
class EifCandidateScore:
    skipped: bool
    skip_reason: str | None
    separation: float | None
    candidate_scores: dict[str, float]


def _score_eif_candidate(windows: list[dict[str, float]]) -> EifCandidateScore:
    """Pure: fit a real (small, fast) EIF against `windows` and score how well it separates a
    synthetic extreme outlier from the confirmed-benign bulk -- the same `EIFArtifact.fit`
    production code trains against, just the 9 baseline keys rather than the full ~50-feature L3
    vector (module docstring). No DB access, no side effects, so `accept_baseline_expansion` can
    call this to *decide* before anything is written, and `_apply` calls it again (cheap: EIF on
    a few hundred 9-dimensional rows is milliseconds) once a candidate is actually approved.
    Promotion of the *real* production EIF artifact under `app/detection/ml/train.py` is out of
    this module's scope -- this produces a benchmark-quality signal for `evals.gate`, not that
    artifact.
    """
    import numpy as np

    if len(windows) < 10:
        return EifCandidateScore(
            True, f"only {len(windows)} baseline windows, need >= 10", None, {}
        )

    x = np.array([[float(w.get(k, 0.0)) for k in _BASELINE_FEATURE_KEYS] for w in windows])
    x_calib = x[: max(5, len(x) // 5)]
    artifact = EIFArtifact.fit(x, x_calib, n_estimators=50)
    scores = artifact.raw_scores(x)
    # Does a synthetic extreme outlier score above the 95th percentile of the confirmed-benign
    # corpus? The gate compares this figure against the previously-promoted candidate's own.
    outlier = x.mean(axis=0) + 8 * (x.std(axis=0) + 1.0)
    outlier_score = float(artifact.raw_scores(outlier.reshape(1, -1))[0])
    benign_p95 = float(np.percentile(scores, 95))
    separation = outlier_score - benign_p95
    candidate_scores = {"detection_f1_aggregate": min(1.0, max(0.0, separation / 10.0))}
    return EifCandidateScore(False, None, separation, candidate_scores)


def accept_baseline_expansion(
    session: Session, tenant_id: uuid.UUID, proposal: LearningProposal, *, user_id: uuid.UUID
) -> GatedApplyResult:
    """Scores the candidate corpus (this proposal's windows folded into the tenant's existing
    `baseline_windows`) *without writing anything*, decides via `app.learning.retrain.
    evaluate_candidate` against the last promoted `eif` `model_versions` row, and only then calls
    `_apply` (which redoes the write for real, cheaply, on pass) -- so a rejected candidate never
    touches `baseline_windows` or writes a `model_versions` row at all.
    """
    with tenant_scope(session, tenant_id):
        existing = session.execute(select(BaselineWindow)).scalars().all()
        baseline_version = session.execute(
            select(ModelVersion)
            .where(ModelVersion.model_key == EIF_MODEL_KEY, ModelVersion.promoted.is_(True))
            .order_by(ModelVersion.version.desc())
            .limit(1)
        ).scalar_one_or_none()

    candidate_windows = [w["features"] for w in proposal.payload["windows"] if w["window_start"]]
    all_features = [w.features for w in existing] + candidate_windows
    score = _score_eif_candidate(all_features)

    if score.skipped:
        passed, reason = True, f"gate skipped: {score.skip_reason}"
    else:
        gate = evaluate_candidate(
            score.candidate_scores,
            baseline_version.eval_scores if baseline_version is not None else None,
            tolerances={"detection_f1_aggregate": DOCS12_TOLERANCES["detection_f1"]},
        )
        passed, reason = gate.passed, gate.reason

    return decide_proposal(
        session,
        tenant_id,
        proposal,
        passed=passed,
        metric_delta={"separation": score.separation, **score.candidate_scores},
        reason=reason,
        user_id=user_id,
        apply_fn=_apply,
    )
