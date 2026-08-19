"""Re-run calibration over stored signals and re-fuse their incidents, without re-triaging.

For after the calibrator artifacts change (they did: class-balanced isotonic replaced the
base-rate fit, and `ml.kth_nn`/`ml.eif` gained calibrators they never had). New uploads pick the
new artifacts up automatically in the detect stage; this script brings *existing* analyses to
the same state so the queue is not half old-scale, half new-scale:

1. `_recalibrate_signals` — the detect stage's own pass, imported, not reimplemented — rewrites
   every signal's `confidence` (and `calibrated` provenance) from the current store.
2. Every incident is re-fused from its member signals through the same `score_incident` the
   correlate stage uses, refreshing `fused_score`, `severity`, and `anomaly_confidence`.

**One deliberate approximation.** `score_incident` takes `community_signal_density`, a
formation-time graph statistic that was never persisted on the incident row. It enters only
through `apply_graph_bonus`, weighted `GRAPH_BONUS_COMMUNITY_DENSITY_WEIGHT = 0.10`, so passing
`0.0` understates a re-fused score by at most ~10% relative — it can round a borderline severity
down, never up, and never reorders two incidents whose evidence differs more than that. Storing
the density would need a migration; a ≤10% conservative haircut on eight demo analyses does not.

**Triage verdicts are untouched.** Dispositions, narratives, and `evidence_confidence` were all
computed from evidence content, not from these scores; re-fusing does not invalidate them
(CLAUDE.md rule 5 — the LLM never consumed the fused score as anything but context).

    python -m app.scripts.rescore_signals [--dry-run]
"""

from __future__ import annotations

import argparse
import json

from sqlalchemy import text

from app.core.db import get_engine
from app.core.logging import get_logger
from app.detection.fusion import FusionInput, score_incident
from app.pipeline.stages.correlate import _fusion_weight
from app.pipeline.stages.detect import _recalibrate_signals

log = get_logger(__name__)


def rescore(*, dry_run: bool = False) -> dict[str, int]:
    engine = get_engine()
    with engine.begin() as conn:
        analyses = conn.execute(
            text("SELECT id, tenant_id FROM analyses WHERE status = 'complete'")
        ).all()

    n_signals = n_incidents = n_severity_changed = 0
    from app.core.db import get_session_factory

    session = get_session_factory()()
    try:
        for analysis_id, tenant_id in analyses:
            with engine.begin() as conn:
                if not dry_run:
                    n_signals += _recalibrate_signals(
                        conn, analysis_id=analysis_id, tenant_id=tenant_id
                    )
                incidents = conn.execute(
                    text(
                        "SELECT id, signal_ids, severity, fused_score FROM incidents "
                        "WHERE analysis_id = :a AND tenant_id = :t"
                    ),
                    {"a": analysis_id, "t": tenant_id},
                ).all()

                for incident_id, signal_ids, old_severity, old_fused in incidents:
                    if not signal_ids:
                        continue
                    rows = conn.execute(
                        text(
                            "SELECT detector_key, detector_layer, confidence FROM signals "
                            "WHERE id = ANY(:ids) AND tenant_id = :t"
                        ),
                        {"ids": list(signal_ids), "t": tenant_id},
                    ).all()
                    if not rows:
                        continue
                    inputs = [
                        FusionInput(
                            detector_key=key,
                            detector_layer=layer,
                            confidence=float(conf),
                            fusion_weight=_fusion_weight(session, tenant_id, key),
                        )
                        for key, layer, conf in rows
                    ]
                    scored = score_incident(inputs, community_signal_density=0.0)
                    n_incidents += 1
                    if scored.severity != old_severity:
                        n_severity_changed += 1
                    log.info(
                        "rescore.incident",
                        incident_id=str(incident_id),
                        fused=f"{old_fused:.3f}->{scored.fused_score:.3f}",
                        severity=f"{old_severity}->{scored.severity}",
                    )
                    if not dry_run:
                        conn.execute(
                            text(
                                "UPDATE incidents SET fused_score = :f, severity = :s, "
                                "anomaly_confidence = :c WHERE id = :id"
                            ),
                            {
                                "f": scored.fused_score,
                                "s": scored.severity,
                                "c": scored.anomaly_confidence,
                                "id": incident_id,
                            },
                        )
    finally:
        session.close()

    summary = {
        "analyses": len(analyses),
        "signals_recalibrated": n_signals,
        "incidents_refused": n_incidents,
        "severity_changed": n_severity_changed,
    }
    log.info("rescore.done", dry_run=dry_run, **summary)
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    print(json.dumps(rescore(dry_run=args.dry_run)))


if __name__ == "__main__":
    main()
