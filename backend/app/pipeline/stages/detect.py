"""Detect — docs/01's `detect` stage contract, made real:

* Precondition: events anonymized (privacy pass has run — detection itself still reads the real
  values; see `app.pipeline.stages.anonymize`'s module docstring for why that is correct).
* Postcondition: `signals` rows with calibrated confidence.

Three detection layers, run in order, every one of them an *existing, tested* component this
stage only has to call:

1. **L1 — Sigma rules** (`app.detection.sigma.runner.run_rules` / `write_signals`).
2. **L2 — the six evidence extractors** (`app.detection.evidence.run.run_evidence_layer`) —
   also the one call that produces this analysis's `EvidencePayload`s, though this stage does not
   need to keep them: `app.agent.context.compute_evidence_payloads` re-derives them on demand at
   triage time (see that function's own docstring), so nothing here has to hold or pass them on.
3. **L3 — the ML model bundle** (`app.detection.ml.detect.MLModelBundle` / `score_entity_windows`).

`app.graph.pipeline_demo` (M10's own end-to-end verification tool) is the closest existing
reference for wiring all three together — its `_run_l1`/`_run_l2`/`_run_l3` are reused
conceptually here (same functions, same order), but two things differ because this is a live
queue stage, not an offline CLI:

* Layer L2 goes through `run_evidence_layer` (which owns *both* extraction and persistence,
  including the evidence-payload side pipeline_demo doesn't need), not the individual `detect_*`
  functions pipeline_demo calls directly.
* L5 (`app.graph.features`'s graph-derived anomaly signals) is **not** computed here, or in
  `correlate` — it needs the entity graph, which does not exist until `correlate` builds it, and
  wiring it in as a fourth layer was not part of this milestone's brief. `app.graph.pipeline_demo`
  folds L5 into the same run because it is a single offline script with no stage boundary; the
  live pipeline has one, and L5 sits on the wrong side of it for either stage to own cleanly.

## Calibration

Every persisted draft (L1's `write_signals`, L2's internal `persist_signals`, L3's own
`MLSignalDraft.confidence`) starts out with whatever *interim* number its own layer's module
docstring already documents as not-yet-calibrated (`clamp01(raw_score)`, or an ML model's own
percentile-rank confidence). This stage's last step recalibrates every one of this analysis's
`signals` rows in place via `app.detection.calibration.CalibratorStore` — one pass, one code path,
regardless of which layer produced the row — so what actually lands in the `signals.confidence`
column a real reader ever sees is uniformly calibrated. A detector with no fitted calibrator yet
falls back to `clamp01(raw_score)`, logged (`calibration.fallback`) — `CalibratorStore`'s own
documented, tested policy, not a gap this stage papers over.

## L3 needs the raw file, not the `events` table

`app.detection.ml.events.load_ml_events` deliberately never touches `app/pipeline`/`app/storage`
(see its own module docstring) — it re-parses a log file directly, the same way training/eval do,
so a feature computed there is provably identical to what training scored. This stage re-fetches
the same raw object `parse` already streamed out of MinIO (`uploads.storage_ref`, resolved via
`app.pipeline.state.fetch_upload_for_analysis`) into a scratch temp file for that one call — a
second download of an already-parsed object, not a second source of truth: `app/parsers/registry`
is the only parser either path uses.

## Model artifacts — fail loudly, never silently skip

`MLModelBundle.load()` and `app.detection.ml.artifacts.load_feature_manifest` are called *before*
anything else in this stage runs, and any failure (`FileNotFoundError` — an artifact file is
missing; `ValueError` — `load_feature_manifest`'s own staleness check, "written against a
different feature vector than `ENTITY_WINDOW_MODEL_FEATURES` exposes today") is re-raised as
`PermanentStageError`. That is deliberate on both counts: fail *before* L1/L2 write anything (a
clean all-or-nothing failure, not a partial signal set that quietly looks complete), and fail as
non-retryable (retrying the identical message cannot make a missing file appear — see
`app.pipeline.errors.PermanentStageError`'s own docstring). A stage that caught this and moved on
with zero L3 signals is exactly the failure mode CLAUDE.md's brief calls out by name.
"""

from __future__ import annotations

import asyncio
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.db import get_engine, get_session_factory
from app.core.logging import get_logger
from app.detection.calibration import CalibratorStore
from app.detection.evidence.run import run_evidence_layer
from app.detection.ml.artifacts import MODELS_DIR, load_feature_manifest
from app.detection.ml.detect import MLModelBundle, MLSignalDraft, score_entity_windows
from app.detection.ml.events import load_ml_events
from app.detection.ml.features import build_entity_window_features
from app.detection.sigma.runner import run_rules, write_signals
from app.models.base import tenant_scope
from app.models.event import Event
from app.models.signal import Signal
from app.pipeline import state
from app.pipeline.contracts import NEXT_QUEUE, STAGE_PROGRESS, public_counters
from app.pipeline.errors import PermanentStageError
from app.pipeline.messages import StageMessage
from app.pipeline.progress import publish_progress
from app.pipeline.redis_client import get_redis
from app.storage.client import get_s3_client

log = get_logger(__name__)


def _load_ml_bundle() -> MLModelBundle:
    """Loads and validates the L3 artifact set — see module docstring "Model artifacts"."""
    try:
        load_feature_manifest(MODELS_DIR)  # raises ValueError on a stale feature vector
        return MLModelBundle.load(MODELS_DIR)
    except (FileNotFoundError, ValueError) as exc:
        raise PermanentStageError(
            f"L3 model artifacts missing or stale in {MODELS_DIR}: {exc}. Run "
            "`python -m app.detection.ml.train` (writes a fresh feature_manifest.json and all "
            "six model artifacts) before detection can run for any analysis."
        ) from exc


def _download_raw_object(storage_ref: str) -> Path:
    settings = get_settings()
    s3 = get_s3_client()
    obj = s3.get_object(Bucket=settings.s3_bucket, Key=storage_ref)
    fd, name = tempfile.mkstemp(suffix=".log")
    tmp_path = Path(name)
    try:
        with tmp_path.open("wb") as fh:
            for chunk in obj["Body"].iter_chunks():
                fh.write(chunk)
    finally:
        import os

        os.close(fd)
    return tmp_path


def _persist_ml_signals(
    session: Session,
    *,
    analysis_id: Any,
    tenant_id: Any,
    drafts: list[MLSignalDraft],
    line_to_event_id: dict[int, int],
) -> int:
    rows: list[Signal] = []
    for d in drafts:
        evidence_ids = [
            line_to_event_id[ln] for ln in d.evidence_line_numbers if ln in line_to_event_id
        ]
        if not evidence_ids:
            continue
        rows.append(
            Signal(
                analysis_id=analysis_id,
                tenant_id=tenant_id,
                detector_key=d.detector_key,
                detector_layer=d.detector_layer,
                raw_score=d.raw_score,
                confidence=d.confidence,
                entity_type=d.entity_type,
                entity_value=d.entity_value,
                window_start=d.window_start.to_pydatetime(),
                window_end=d.window_end.to_pydatetime(),
                mitre_technique=d.mitre_technique,
                evidence_event_ids=evidence_ids,
                explanation=d.explanation,
            )
        )
    if rows:
        with tenant_scope(session, tenant_id):
            session.add_all(rows)
            session.commit()
    return len(rows)


#  `app.graph.pipeline_demo._calibration_feature`'s own documented policy, reused verbatim: L1/L2
# raw scores are otherwise already `[0, 1]`-ish, but `signal.burst`'s raw_score is a *signed*
# z-score (docs/04: flag `|z| > 3.5`), and `app.detection.features.robust_z`'s documented
# MAD==0 policy can legitimately return +/-inf. `IsotonicCalibrator.fit_calibrator` sanitizes
# its *training* input this same way (`np.nan_to_num(..., posinf=1e12, neginf=-1e12)`) but
# `IsotonicCalibrator.calibrate` — the *inference*-time call every real caller (this stage,
# pipeline_demo) actually uses — does not, so an unsanitized inf/NaN raw_score reaching it
# crashes `IsotonicRegression.predict`'s own finite-input check. Sanitizing at the call site
# (not inside `app.detection.calibration`, a package this milestone does not own) matches
# `pipeline_demo`'s own established convention for the exact same gap.
_BURST_DETECTOR_KEY: Final[str] = "signal.burst"
_INF_SENTINEL: Final[float] = 1e6


def _calibration_feature(detector_key: str, raw_score: float) -> float:
    x = raw_score
    if x != x:  # NaN
        x = 0.0
    elif x in (float("inf"), float("-inf")):
        x = _INF_SENTINEL if x > 0 else -_INF_SENTINEL
    if detector_key == _BURST_DETECTOR_KEY:
        x = abs(x)
    return x


def _recalibrate_signals(conn: Any, *, analysis_id: Any, tenant_id: Any) -> int:
    """One calibrated-confidence pass over every `signals` row this stage just wrote (any
    layer) — see module docstring "Calibration"."""
    store = CalibratorStore()
    rows = conn.execute(
        text(
            "SELECT id, detector_key, raw_score FROM signals "
            "WHERE analysis_id = :analysis_id AND tenant_id = :tenant_id"
        ),
        {"analysis_id": analysis_id, "tenant_id": tenant_id},
    ).all()
    updates = [
        {
            "id": signal_id,
            "confidence": store.calibrate(
                detector_key, _calibration_feature(detector_key, raw_score)
            ),
        }
        for signal_id, detector_key, raw_score in rows
    ]
    if updates:
        conn.execute(text("UPDATE signals SET confidence = :confidence WHERE id = :id"), updates)
    return len(updates)


def _run_detect(message: StageMessage) -> dict[str, Any]:
    bundle = _load_ml_bundle()  # fail fast, before L1/L2 write anything

    session = get_session_factory()()
    try:
        # ---- L1: Sigma rules ----
        with get_engine().connect() as raw_conn:
            l1_drafts = run_rules(raw_conn, message.analysis_id, message.tenant_id)
        write_signals(
            session, l1_drafts, analysis_id=message.analysis_id, tenant_id=message.tenant_id
        )
        n_l1 = len(l1_drafts)

        # ---- L2: the six evidence extractors ----
        try:
            summary = run_evidence_layer(
                session, analysis_id=message.analysis_id, tenant_id=message.tenant_id
            )
        except FileNotFoundError as exc:
            raise PermanentStageError(f"L2 evidence-layer artifact missing: {exc}") from exc
        session.commit()
        n_l2 = summary.total_signals

        # ---- L3: the ML model bundle ----
        with get_engine().begin() as conn:
            upload = state.fetch_upload_for_analysis(
                conn, analysis_id=message.analysis_id, tenant_id=message.tenant_id
            )
        detected_sources = list(upload["detected_sources"] or [])
        if not detected_sources:
            raise PermanentStageError(
                f"upload {upload['upload_id']} has no detected source types — cannot run L3"
            )
        source_type = detected_sources[0]

        tmp_path = _download_raw_object(upload["storage_ref"])
        try:
            ml_events = load_ml_events({source_type: tmp_path})
        finally:
            tmp_path.unlink(missing_ok=True)

        df = build_entity_window_features(ml_events)
        try:
            ml_drafts = score_entity_windows(bundle, df)
        except ValueError as exc:
            # `app.detection.ml.features.to_feature_matrix` already sanitizes every *input*
            # feature's own NaN/inf (`Z_SCORE_CLIP`) before scoring, but a handful of raw
            # features are deliberately left unclipped (large-but-finite counts/byte sums), and
            # a model fit on a large, differently-distributed training corpus can still overflow
            # scoring a genuinely tiny/degenerate window batch (few entity-hours, extreme
            # per-window ratios) — a real, data-dependent numeric edge case in `app/detection/ml`
            # (out of this stage's ownership to patch), not a bug this stage introduced. Retrying
            # the identical file cannot change its own event volume, so this is deterministic —
            # fail loudly and immediately rather than spend three retries re-learning the same
            # overflow, and never silently report zero L3 signals as if L3 had run cleanly.
            raise PermanentStageError(
                f"L3 scoring failed on a numeric edge case (likely a very small or unusually "
                f"shaped event volume for this analysis, scored against a model fit on a much "
                f"larger corpus): {exc}"
            ) from exc

        with tenant_scope(session, message.tenant_id):
            line_to_event_id = dict(
                session.execute(
                    select(Event.raw_line_no, Event.id).where(
                        Event.analysis_id == message.analysis_id
                    )
                )
                .tuples()
                .all()
            )
        n_l3 = _persist_ml_signals(
            session,
            analysis_id=message.analysis_id,
            tenant_id=message.tenant_id,
            drafts=ml_drafts,
            line_to_event_id=line_to_event_id,
        )

        # ---- calibrate every signal this stage just wrote, uniformly ----
        with get_engine().begin() as conn:
            n_recalibrated = _recalibrate_signals(
                conn, analysis_id=message.analysis_id, tenant_id=message.tenant_id
            )
            state.mark_stage(
                conn,
                analysis_id=message.analysis_id,
                tenant_id=message.tenant_id,
                stage="detect",
                progress=STAGE_PROGRESS["detect"],
            )
            counters = state.increment_counter(
                conn,
                analysis_id=message.analysis_id,
                tenant_id=message.tenant_id,
                key="signals",
                delta=n_l1 + n_l2 + n_l3,
            )
    finally:
        session.close()

    log.info(
        "detect.done",
        analysis_id=str(message.analysis_id),
        n_l1=n_l1,
        n_l2=n_l2,
        n_l3=n_l3,
        n_recalibrated=n_recalibrated,
    )
    return {"n_l1": n_l1, "n_l2": n_l2, "n_l3": n_l3, "counters": counters}


async def handle(message: StageMessage) -> list[tuple[str, StageMessage]]:
    result = await asyncio.to_thread(_run_detect, message)
    n_total = result["n_l1"] + result["n_l2"] + result["n_l3"]

    await publish_progress(
        get_redis(),
        analysis_id=message.analysis_id,
        stage="detect",
        progress=STAGE_PROGRESS["detect"],
        status="running",
        message=(
            f"Detection complete: {n_total} signal(s) — {result['n_l1']} rule (L1), "
            f"{result['n_l2']} evidence-extractor (L2), {result['n_l3']} ML model (L3) — "
            "all calibrated."
        ),
        counters=public_counters(result["counters"]),
    )

    next_queue = NEXT_QUEUE["detect"]
    assert next_queue is not None
    now = datetime.now(UTC)
    return [
        (
            next_queue,
            message.model_copy(update={"stage": next_queue, "attempt": 0, "emitted_at": now}),
        )
    ]
