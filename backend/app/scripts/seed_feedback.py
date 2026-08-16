"""`make seed` -> `python -m app.scripts.seed` then `python -m app.scripts.seed_feedback`.

docs/08 "Demo honesty": *"One session cannot produce enough feedback for retraining to visibly
help... Seed a synthetic feedback history so the loop has something to consume and the curves are
demonstrable — and say so plainly in the README rather than implying the data is real."*

This script builds one coherent, backdated ~8-week feedback history under the demo tenant
(`app.scripts.seed`'s `DEFAULT_EMAIL`, which must already exist — run `seed` first) and drives it
through the *real* consumer code in `app.learning.feedback.record_feedback`, exactly as
`POST /api/incidents/{id}/feedback` would. Nothing here reimplements a consumer; every weight
change, calibration refit, suppression candidate, and benign-baseline flag comes from the same
code path a live analyst click would hit.

## Every synthetic row is marked, unmissably

Every row this script creates in a table the learning API surfaces — `analyst_feedback`
today, and any other table a future endpoint reads from — gets a matching row in
`learning_synthetic_seed` (`app.models.synthetic_seed_marker`). `GET /api/learning/metrics`,
`GET /api/learning/suppressions`, and `GET /api/models/calibration` all key off that table to set
`synthetic: true` in their responses. This script's own log output states the same thing in
plain language, and the top-level README must too (docs/08's instruction, not optional).

## Why detector precision is engineered, not random

Eleven detectors, each given a deliberate precision profile (`DETECTOR_PROFILES` below): several
start weak and *improve* over the eight weeks (so the calibration/weight-tuning "before vs.
after" story is real and visible), two (`sigma.non_browser_user_agent`, `signal.burst`) stay
persistently noisy throughout (so the weight-tuning demo has a detector that visibly gets and
*stays* down-weighted, not just one story arc). `stated_confidence` per detector is fixed
regardless of outcome — mirroring `app/detection/sigma/runner.py`'s own documented interim
policy (raw score, pass-through, not yet calibrated) — which is exactly what makes the isotonic
refit's before/after Brier score improvement genuine rather than contrived: a detector whose
stated confidence doesn't track its true precision is precisely what calibration exists to fix.
"""

from __future__ import annotations

import os
import random
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.db import get_session_factory
from app.core.logging import configure_logging, get_logger
from app.detection.fusion import anomaly_confidence_from_fused_score
from app.learning.calibration import refit_calibrators
from app.learning.feedback import FeedbackInput, record_feedback
from app.learning.retrain import run_classifier_retrain
from app.learning.weights import retune_detector_weights
from app.models.analysis import Analysis
from app.models.base import bypass_tenant_scope, tenant_scope
from app.models.incident import Incident
from app.models.signal import Signal
from app.models.synthetic_seed_marker import SyntheticSeedMarker
from app.models.triage_verdict import TriageVerdict
from app.models.upload import Upload
from app.models.user import User
from app.scripts.seed import DEFAULT_EMAIL

log = get_logger(__name__)

SEED_RNG_SEED = 1337  # CLAUDE.md rule 7: determinism where possible -- same seed, same history.
N_WEEKS = 8
SINGLE_INCIDENTS_PER_DETECTOR_PER_WEEK = 2
N_MULTI_DETECTOR_INCIDENTS = 40

_SEVERITY_THRESHOLDS = (  # docs/04 "Severity" -- reused exactly, so seeded severities are the
    (0.85, "critical"),  # same buckets a live fusion score would land in, not an invented scale.
    (0.65, "high"),
    (0.40, "medium"),
)


def _severity_for(score: float) -> str:
    for threshold, label in _SEVERITY_THRESHOLDS:
        if score >= threshold:
            return label
    return "low"


# docs/v2_migration change 3 ("two confidences, never mixed") + the "two confidences" migration's
# own backfill -- same three buckets, reused here rather than invented, so a seeded verdict's
# threat_confidence lands in the same bucket a real migration-era backfilled row would have.
_THREAT_CONFIDENCE_THRESHOLDS = (
    (0.75, "high"),
    (0.40, "moderate"),
)


def _threat_confidence_for(score: float) -> str:
    for threshold, label in _THREAT_CONFIDENCE_THRESHOLDS:
        if score >= threshold:
            return label
    return "low"


@dataclass(frozen=True, slots=True)
class DetectorProfile:
    detector_key: str
    layer: str
    entity_type: str  # docs/02 entities.type vocabulary -- must match `entity_value`'s own shape
    stated_confidence: float  # fixed, outcome-independent -- see module docstring
    precision_start: float
    precision_end: float
    technique: str  # real ATT&CK id, matching this project's own convention of never inventing one


# See module docstring, "Why detector precision is engineered, not random." `entity_type` per
# detector is a plausible real assignment (`sigma.non_browser_user_agent` -> `src_ip`, e.g.,
# matches the real worked example in `app/detection/rules/suppressions/backup-service-account-
# non-browser-ua.yml`), not arbitrary -- `_entity_value_for` below shapes `entity_value` to match.
DETECTOR_PROFILES: tuple[DetectorProfile, ...] = (
    DetectorProfile(
        "sigma.large_post_to_new_domain", "rule", "src_ip", 0.75, 0.55, 0.85, "T1567.002"
    ),
    DetectorProfile("sigma.malicious_url_category", "rule", "src_ip", 0.75, 0.85, 0.90, "T1071"),
    DetectorProfile("sigma.dlp_engine_triggered", "rule", "user", 0.75, 0.80, 0.85, "T1048.003"),
    DetectorProfile("sigma.credentials_in_url", "rule", "user", 0.55, 0.45, 0.75, "T1552.001"),
    DetectorProfile("sigma.non_browser_user_agent", "rule", "src_ip", 0.55, 0.15, 0.15, "T1105"),
    DetectorProfile("signal.beaconing", "signal", "src_ip", 0.75, 0.55, 0.92, "T1071.001"),
    DetectorProfile("signal.dga", "signal", "domain", 0.55, 0.55, 0.65, "T1568.002"),
    DetectorProfile("signal.burst", "signal", "user", 0.55, 0.20, 0.25, "T1567"),
    DetectorProfile("signal.rarity", "signal", "domain", 0.35, 0.45, 0.55, "T1078"),
    DetectorProfile("ml.iforest", "ml", "user", 0.55, 0.40, 0.50, "T1530"),
    # Was "ml.autoencoder" -- migration change 19 removed that model (`docs/v2_migration/
    # MIGRATION-01-evidence-first.md`); swapped for another still-shipping L3 baseline so this
    # stays eleven real, live detector keys rather than one that no longer produces signals.
    DetectorProfile("ml.mahalanobis", "ml", "user", 0.55, 0.35, 0.45, "T1029"),
)

_DISMISSAL_REASONS = (
    "known sanctioned automation account",
    "recurring benign SaaS integration, already reviewed last quarter",
    "corporate backup job, matches change ticket",
    "vendor-managed scanner on the allowlist request queue",
    "false positive: url category miscategorized by feed",
    "duplicate of an incident already triaged this week",
)


def _target_precision(profile: DetectorProfile, week_idx: int) -> float:
    if N_WEEKS <= 1:
        return profile.precision_end
    t = week_idx / (N_WEEKS - 1)
    return profile.precision_start + t * (profile.precision_end - profile.precision_start)


def _mark_synthetic(
    session: Session, tenant_id: uuid.UUID, table_name: str, row_id: object
) -> None:
    with tenant_scope(session, tenant_id):
        session.add(
            SyntheticSeedMarker(tenant_id=tenant_id, table_name=table_name, row_id=str(row_id))
        )


def _already_seeded(session: Session, tenant_id: uuid.UUID) -> bool:
    with tenant_scope(session, tenant_id):
        return (
            session.execute(
                select(SyntheticSeedMarker.id)
                .where(SyntheticSeedMarker.table_name == "analyst_feedback")
                .limit(1)
            ).scalar_one_or_none()
            is not None
        )


def _demo_tenant_and_user(session: Session) -> tuple[uuid.UUID, User]:
    email = os.environ.get("SEED_USER_EMAIL", DEFAULT_EMAIL)
    with bypass_tenant_scope(session):
        user = session.execute(select(User).where(User.email == email)).scalar_one_or_none()
    if user is None:
        raise RuntimeError(
            f"no user {email!r} found -- run `python -m app.scripts.seed` (or `make seed`, which "
            "runs both scripts in order) before seeding feedback history"
        )
    return user.tenant_id, user


def _seed_container(session: Session, tenant_id: uuid.UUID, user_id: uuid.UUID) -> Analysis:
    with tenant_scope(session, tenant_id):
        upload = Upload(
            tenant_id=tenant_id,
            user_id=user_id,
            filename="synthetic-feedback-seed.log",
            size_bytes=0,
            sha256="0" * 64,
            storage_ref=f"{tenant_id}/synthetic-feedback-seed",
            detected_sources=["zscaler"],
        )
        session.add(upload)
        session.flush()
        analysis = Analysis(
            tenant_id=tenant_id, upload_id=upload.id, status="complete", stage="done", progress=1.0
        )
        session.add(analysis)
        session.flush()
    _mark_synthetic(session, tenant_id, "uploads", upload.id)
    _mark_synthetic(session, tenant_id, "analyses", analysis.id)
    return analysis


@dataclass(frozen=True, slots=True)
class GeneratedIncident:
    incident_id: uuid.UUID
    verdict_id: uuid.UUID
    detector_keys: list[str]
    label: int  # the effective disposition every profile's precision curve is measured against
    dismissed: bool


def _entity_value_for(entity_type: str, week_idx: int, rng: random.Random) -> str:
    """Shapes `entity_value` to actually look like its declared `entity_type` (docs/02
    `entities.type`) -- an incident's title and the agent's eventual evidence rendering both
    read this string, and a `"user"`-typed row holding a dotted-quad would be a data-realism bug,
    not merely a cosmetic one."""
    if entity_type == "user":
        return f"user{rng.randint(1, 500)}@corp.example"
    if entity_type == "domain":
        return (
            f"{rng.choice(['xk3f', 'qz9p', 'lm2v', 'nT7c'])}{rng.randint(10, 99)}.example-cdn.net"
        )
    return f"10.{week_idx}.{rng.randint(1, 254)}.{rng.randint(1, 254)}"  # src_ip (the default)


def _make_signal(
    session: Session,
    *,
    analysis: Analysis,
    tenant_id: uuid.UUID,
    profile: DetectorProfile,
    entity_type: str,
    entity_value: str,
    created_at: datetime,
    rng: random.Random,
) -> Signal:
    jitter = rng.uniform(-0.05, 0.05)
    raw_score = max(0.05, min(0.99, profile.stated_confidence + jitter))
    signal = Signal(
        analysis_id=analysis.id,
        tenant_id=tenant_id,
        detector_key=profile.detector_key,
        detector_layer=profile.layer,
        raw_score=raw_score,
        confidence=raw_score,  # stated, pre-calibration pass-through -- see module docstring
        entity_type=entity_type,
        entity_value=entity_value,
        window_start=created_at,
        window_end=created_at + timedelta(hours=1),
        mitre_technique=profile.technique,
        evidence_event_ids=[],
        explanation={
            "synthetic": True,
            "source": "app/scripts/seed_feedback.py",
            "detector_key": profile.detector_key,
        },
        created_at=created_at,
    )
    session.add(signal)
    session.flush()
    _mark_synthetic(session, tenant_id, "signals", signal.id)
    return signal


def _make_incident_and_verdict(
    session: Session,
    *,
    analysis: Analysis,
    tenant_id: uuid.UUID,
    signals: list[Signal],
    label: int,
    primary_technique: str | None,
    created_at: datetime,
    rng: random.Random,
    embedding: list[float],
) -> tuple[Incident, TriageVerdict]:
    confidences = [s.confidence for s in signals]
    fused_score = max(confidences) if confidences else 0.0
    detector_summary = "+".join(sorted({s.detector_key for s in signals}))

    incident = Incident(
        analysis_id=analysis.id,
        tenant_id=tenant_id,
        title=f"{detector_summary} on entity {signals[0].entity_value}",
        severity=_severity_for(fused_score),
        fused_score=fused_score,
        anomaly_confidence=anomaly_confidence_from_fused_score(fused_score),
        entity_ids=[],
        signal_ids=[s.id for s in signals],
        status="closed",
        embedding=embedding,
        created_at=created_at,
    )
    session.add(incident)
    session.flush()
    _mark_synthetic(session, tenant_id, "incidents", incident.id)

    natural_disposition = "true_positive" if label == 1 else "false_positive"
    # 15% of the time, simulate the model getting it wrong so the analyst's correction path
    # (`corrected_disposition`) gets exercised too -- see module docstring.
    model_was_wrong = rng.random() < 0.15
    verdict_disposition = (
        ("false_positive" if natural_disposition == "true_positive" else "true_positive")
        if model_was_wrong
        else natural_disposition
    )

    verdict = TriageVerdict(
        incident_id=incident.id,
        disposition=verdict_disposition,
        threat_confidence=_threat_confidence_for(fused_score),
        threat_confidence_reason=(
            f"Synthetic seed judgement: evidence strength from {detector_summary} corresponds "
            f"to a fused score of {fused_score:.2f}."
        ),
        llm_severity_opinion=incident.severity,
        mitre_techniques=([primary_technique] if (label == 1 and primary_technique) else []),
        summary=f"Synthetic seed verdict for {detector_summary}.",
        narrative=[{"step": 1, "claim": "Synthetic seed narrative.", "evidence_event_ids": []}],
        recommended_actions=[],
        tool_trace=[],
        citation_valid=True,
        invalid_citations=[],
        model="synthetic-seed",
        created_at=created_at,
    )
    session.add(verdict)
    session.flush()
    _mark_synthetic(session, tenant_id, "triage_verdicts", verdict.id)
    return incident, verdict


def _feedback_for(
    label: int,
    *,
    model_was_wrong: bool,
    natural_disposition: str,
    primary_technique: str,
    created_at: datetime,
    rng: random.Random,
) -> FeedbackInput:
    agrees = not model_was_wrong
    dismissed = label == 0
    # ~25% of confirmed true positives also get an explicit `corrected_technique` -- docs/08 §6's
    # own trigger for consumer 6, exercised directly rather than only via the derived path.
    corrected_technique = (
        primary_technique if (label == 1 and agrees and rng.random() < 0.25) else None
    )
    return FeedbackInput(
        agrees=agrees,
        corrected_disposition=None if agrees else natural_disposition,
        corrected_technique=corrected_technique,
        dismissal_reason=(
            rng.choice(_DISMISSAL_REASONS) if dismissed and rng.random() < 0.7 else None
        ),
        mark_benign_baseline=dismissed and rng.random() < 0.5,
        note="Synthetic seed feedback." if label == 1 else None,
        created_at=created_at,
    )


def _embedding_for(cluster_key: str, rng: random.Random, dim: int = 1024) -> list[float]:
    """A stable base vector per `cluster_key` (technique for true positives, detector for false
    positives) plus small per-incident noise, then L2-normalized -- makes cosine similarity
    within a cluster high and across clusters lower, so `app.learning.memory`'s retrieval has
    something real to find rather than random noise that happens to rank first."""
    cluster_rng = random.Random(f"cluster:{cluster_key}")
    base = [cluster_rng.gauss(0, 1) for _ in range(dim)]
    vec = [b + rng.gauss(0, 0.15) for b in base]
    norm = sum(v * v for v in vec) ** 0.5
    return [v / norm for v in vec] if norm > 0 else vec


def _generate_incident(
    session: Session,
    *,
    analysis: Analysis,
    tenant_id: uuid.UUID,
    user_id: uuid.UUID,
    profiles: list[DetectorProfile],
    week_idx: int,
    created_at: datetime,
    rng: random.Random,
) -> GeneratedIncident:
    primary = profiles[0]
    label = 1 if rng.random() < _target_precision(primary, week_idx) else 0

    # One incident, one entity: every contributing signal (however many detectors/layers) is
    # keyed on the *primary* detector's entity dimension -- real graph correlation (docs/05) is
    # out of this milestone's scope to simulate, and this keeps `entity_type` and `entity_value`
    # mutually consistent, which a per-detector entity_type would not (see `_entity_value_for`).
    entity_type = primary.entity_type
    entity_value = _entity_value_for(entity_type, week_idx, rng)
    signals = [
        _make_signal(
            session,
            analysis=analysis,
            tenant_id=tenant_id,
            profile=p,
            entity_type=entity_type,
            entity_value=entity_value,
            created_at=created_at,
            rng=rng,
        )
        for p in profiles
    ]

    cluster_key = primary.technique if label == 1 else f"fp:{primary.detector_key}"
    incident, verdict = _make_incident_and_verdict(
        session,
        analysis=analysis,
        tenant_id=tenant_id,
        signals=signals,
        label=label,
        primary_technique=primary.technique,
        created_at=created_at,
        rng=rng,
        embedding=_embedding_for(cluster_key, rng),
    )

    natural_disposition = "true_positive" if label == 1 else "false_positive"
    model_was_wrong = verdict.disposition != natural_disposition
    feedback_input = _feedback_for(
        label,
        model_was_wrong=model_was_wrong,
        natural_disposition=natural_disposition,
        primary_technique=primary.technique,
        created_at=created_at + timedelta(hours=1),
        rng=rng,
    )

    outcome = record_feedback(
        session, tenant_id, user_id=user_id, incident_id=incident.id, data=feedback_input
    )
    _mark_synthetic(session, tenant_id, "analyst_feedback", outcome.feedback_id)
    for candidate in outcome.suppression_candidates:
        _mark_synthetic(session, tenant_id, "suppression_candidates", candidate.id)
    for entry in outcome.benign_baseline_entries:
        _mark_synthetic(session, tenant_id, "benign_baseline_entries", entry.id)

    return GeneratedIncident(
        incident_id=incident.id,
        verdict_id=verdict.id,
        detector_keys=[p.detector_key for p in profiles],
        label=label,
        dismissed=feedback_input.dismissal_reason is not None,
    )


def seed_feedback() -> None:
    session = get_session_factory()()
    try:
        tenant_id, user = _demo_tenant_and_user(session)

        if _already_seeded(session, tenant_id):
            log.info("seed_feedback.already_seeded", tenant_id=str(tenant_id))
            return

        rng = random.Random(SEED_RNG_SEED)
        analysis = _seed_container(session, tenant_id, user.id)

        now = datetime.now(UTC)
        week_starts = [now - timedelta(weeks=(N_WEEKS - w)) for w in range(N_WEEKS)]

        generated: list[GeneratedIncident] = []

        for week_idx, week_start in enumerate(week_starts):
            for profile in DETECTOR_PROFILES:
                for _ in range(SINGLE_INCIDENTS_PER_DETECTOR_PER_WEEK):
                    ts = week_start + timedelta(days=rng.uniform(0, 6), hours=rng.uniform(0, 23))
                    generated.append(
                        _generate_incident(
                            session,
                            analysis=analysis,
                            tenant_id=tenant_id,
                            user_id=user.id,
                            profiles=[profile],
                            week_idx=week_idx,
                            created_at=ts,
                            rng=rng,
                        )
                    )
            session.flush()

        for _ in range(N_MULTI_DETECTOR_INCIDENTS):
            week_idx = rng.randrange(N_WEEKS)
            week_start = week_starts[week_idx]
            ts = week_start + timedelta(days=rng.uniform(0, 6), hours=rng.uniform(0, 23))
            k = rng.choice([2, 3])
            profiles = rng.sample(DETECTOR_PROFILES, k=k)
            generated.append(
                _generate_incident(
                    session,
                    analysis=analysis,
                    tenant_id=tenant_id,
                    user_id=user.id,
                    profiles=profiles,
                    week_idx=week_idx,
                    created_at=ts,
                    rng=rng,
                )
            )
        session.flush()

        session.commit()

        n_feedback = len(generated)
        log.info(
            "seed_feedback.history_written",
            tenant_id=str(tenant_id),
            n_incidents=n_feedback,
            n_weeks=N_WEEKS,
            n_detectors=len(DETECTOR_PROFILES),
            synthetic=True,
        )

        # Final refit/retune/retrain pass over the *complete* history, plus one classifier
        # retrain attempt -- gives `make seed`'s own output a concrete before/after to show
        # (docs/08 M13 verification bar: "Show before/after numbers").
        weight_result = retune_detector_weights(session, tenant_id)
        calibration_result = refit_calibrators(session, tenant_id)
        session.commit()
        for change in weight_result.detectors:
            log.info(
                "seed_feedback.detector_weight",
                detector_key=change.detector_key,
                true_positives=change.true_positives,
                false_positives=change.false_positives,
                precision=change.precision,
                fusion_weight=change.weight_after,
            )
        log.info(
            "seed_feedback.calibration_summary",
            overall_brier_before=calibration_result.overall_brier_before,
            overall_brier_after=calibration_result.overall_brier_after,
        )

        retrain_attempt = run_classifier_retrain(session, tenant_id)
        session.commit()
        log.info(
            "seed_feedback.classifier_retrain",
            skipped=retrain_attempt.skipped,
            skip_reason=retrain_attempt.skip_reason,
            promoted=retrain_attempt.promoted,
            version=retrain_attempt.version,
            eval_scores=retrain_attempt.eval_scores,
        )
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def main() -> None:
    configure_logging()
    seed_feedback()


if __name__ == "__main__":
    main()
