"""`app.pipeline.stages.detect` — real work: Sigma (L1) + the six evidence extractors (L2) + the
ML model bundle (L3), all calibrated, over a real uploaded/parsed scenario file. Also proves the
"fail loudly on missing model artifacts" requirement — a stage that silently produced zero L3
signals because a `.joblib` was missing is exactly the failure this test guards against."""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import text

from app.agent.context import compute_evidence_payloads
from app.core.db import get_engine, get_session_factory
from app.pipeline.errors import PermanentStageError
from app.pipeline.messages import StageMessage
from app.pipeline.stages import detect
from tests.conftest import make_analysis, make_tenant, make_user
from tests.fixtures.agent import make_event
from tests.fixtures.pipeline_corpus import upload_and_parse_scenario


def _message(analysis_id: uuid.UUID, tenant_id: uuid.UUID) -> StageMessage:
    return StageMessage(
        analysis_id=analysis_id,
        tenant_id=tenant_id,
        stage="detect",
        storage_ref=None,
        source_type=None,
        attempt=0,
        emitted_at=datetime.now(UTC),
    )


def test_detect_produces_calibrated_signals_and_evidence_from_a_real_scenario(
    tenant_cleanup: list[uuid.UUID], tmp_path: Path
) -> None:
    tenant = make_tenant()
    tenant_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"detect-real-{uuid.uuid4()}@test.local")

    uploaded = upload_and_parse_scenario(
        tenant=tenant,
        user=user,
        out_dir=tmp_path / "scenario",
        name="c2_beaconing",
        seed=101,
        events=50_000,
    )

    forwarded = asyncio.run(detect.handle(_message(uploaded.analysis.id, tenant.id)))
    assert len(forwarded) == 1
    assert forwarded[0][0] == "correlate"

    with get_engine().begin() as conn:
        signal_rows = conn.execute(
            text("SELECT detector_layer, confidence FROM signals WHERE analysis_id = :aid"),
            {"aid": uploaded.analysis.id},
        ).all()
        counters = conn.execute(
            text("SELECT counters FROM analyses WHERE id = :aid"), {"aid": uploaded.analysis.id}
        ).scalar_one()

    assert len(signal_rows) > 0, "a real c2_beaconing scenario must produce at least one signal"
    assert counters["signals"] == len(signal_rows)
    for _layer, confidence in signal_rows:
        assert 0.0 <= confidence <= 1.0

    # The six evidence extractors produced real EvidencePayloads for this analysis (docs/v2_
    # migration change 2's own contract) -- recomputed the same way `app.agent.orchestrator.
    # triage_top_incidents_for_analysis` does, since detect does not persist them separately.
    session = get_session_factory()()
    try:
        evidence = compute_evidence_payloads(
            session, analysis_id=uploaded.analysis.id, tenant_id=tenant.id
        )
    finally:
        session.close()
    assert len(evidence) > 0
    assert all(e.evidence_id.startswith("EVIDENCE-") for e in evidence)


def test_detect_fails_loudly_when_model_artifacts_are_missing(
    tenant_cleanup: list[uuid.UUID], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tenant = make_tenant()
    tenant_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"detect-missing-{uuid.uuid4()}@test.local")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)
    make_event(
        tenant_id=tenant.id,
        analysis_id=analysis.id,
        ts=datetime.now(UTC),
        raw_line_no=1,
        domain="whatever.example",
    )

    monkeypatch.setattr(detect, "MODELS_DIR", tmp_path / "no_such_models_dir")

    with pytest.raises(PermanentStageError, match="model artifacts"):
        asyncio.run(detect.handle(_message(analysis.id, tenant.id)))

    with get_engine().begin() as conn:
        n_signals = conn.execute(
            text("SELECT count(*) FROM signals WHERE analysis_id = :aid"), {"aid": analysis.id}
        ).scalar_one()
    # Fails *before* L1/L2 write anything -- no partial, silently-incomplete signal set.
    assert n_signals == 0
