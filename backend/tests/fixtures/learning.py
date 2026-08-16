"""Shared builders for `tests/test_learning_*.py`. Mirrors `tests/conftest.py`'s
`make_tenant`/`make_user`/`make_analysis` pattern (a real row via a tenant-bound session, not a
mock) one layer further down the schema: `signals` -> `incidents` -> `triage_verdicts` ->
`analyst_feedback`, none of which `conftest.py` itself needed before this milestone.

Lives under `tests/fixtures/` rather than a new `test_learning_*.py` module, matching
`tests/fixtures/rules/events.py`'s own precedent: shared, non-test support code for a family of
test modules belongs here, not duplicated across them or awkwardly named to satisfy pytest's
`test_*.py` collection glob.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from datetime import datetime

import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.db import get_engine, get_session_factory
from app.detection.fusion import anomaly_confidence_from_fused_score
from app.models.analyst_feedback import AnalystFeedback
from app.models.base import tenant_scope
from app.models.incident import Incident
from app.models.signal import Signal
from app.models.triage_verdict import TriageVerdict
from app.models.user import User


@pytest.fixture
def learning_session(learning_cleanup: list[uuid.UUID]) -> Iterator[Session]:
    """A plain, unscoped `Session` -- `tests/test_learning_*.py`'s equivalent of the ad hoc
    `get_session_factory()()` every other test file in this suite constructs inline
    (`tests/test_ops_dead_letters.py`, e.g.), just factored out once since so many learning tests
    need one.

    **Why this depends on `learning_cleanup` even though it never reads it.** pytest tears fixtures
    down in reverse setup order, and a test that lists `learning_session` before `learning_cleanup`
    in its own signature therefore used to have cleanup run *first* -- issuing `DELETE FROM
    analyst_feedback` on a fresh pooled connection while this session still held row locks from an
    uncommitted `INSERT`. Neither side could proceed: the delete waited on the lock, and the
    session could not release it because its own teardown was queued behind the delete. That is not
    a slow test, it is a permanent hang -- it wedged the suite for hours before it was diagnosed.
    Declaring the dependency here forces `learning_cleanup` to be set up first and therefore torn
    down last, so this session is always closed (and its transaction released) before any DELETE
    runs. Ordering now comes from the dependency graph rather than from each test's parameter
    order, which no test author should have to remember.
    """
    s = get_session_factory()()
    try:
        yield s
    finally:
        s.close()


@pytest.fixture
def learning_cleanup(tenant_cleanup: list[uuid.UUID]) -> Iterator[list[uuid.UUID]]:
    """Extends `tests.conftest.tenant_cleanup` for the tables this milestone owns.
    `tenant_cleanup`'s own teardown deletes `analyses`/`uploads`/`users`/`tenants`; cascading
    from `analyses` reaches `incidents`/`signals`/`triage_verdicts` (`ON DELETE CASCADE`, docs/02)
    but **not** `analyst_feedback` (docs/02 gives it no cascade -- "a durable analyst record, not
    a row meant to vanish on cascade," per `app.models.analyst_feedback`'s docstring) or any of
    this milestone's own tables, several of which reference `analyst_feedback`/`incidents` in
    turn. Deleting them here first is what keeps `tenant_cleanup`'s own
    `DELETE FROM analyses ...` from failing on a live foreign key -- pytest tears fixtures down in
    reverse dependency order, so declaring `tenant_cleanup` as this fixture's own dependency
    guarantees this teardown runs *before* `tenant_cleanup`'s.

    `detector_stats` gets the same treatment for a sharper reason than FK safety:
    `detector_key` is docs/02's own primary key, *not* a `(tenant_id, detector_key)` composite
    (see `app.models.detector_stats`'s docstring -- a real, documented data-model limitation, not
    an oversight this fixture should paper over silently). A `detector_key` a test doesn't clean
    up leaks past that single test and collides with the next test (or the next full run) that
    reuses the same key, with no foreign key to catch it -- this fixture is what keeps
    `tests/test_learning_weights.py` and `tests/test_learning_feedback.py`'s synthetic detector
    keys from colliding across runs.
    """
    tenant_ids = tenant_cleanup
    yield tenant_ids
    if not tenant_ids:
        return
    with get_engine().begin() as conn:
        # A backstop for the failure mode `learning_session`'s docstring describes: if some future
        # fixture ordering again leaves a transaction open while these DELETEs run, this makes the
        # suite fail in five seconds with a lock timeout rather than hang indefinitely. A test-only
        # teardown has no legitimate reason to wait on a lock at all.
        conn.execute(text("SET LOCAL lock_timeout = '5s'"))
        conn.execute(
            text("DELETE FROM learning_synthetic_seed WHERE tenant_id = ANY(:ids)"),
            {"ids": tenant_ids},
        )
        conn.execute(
            text("DELETE FROM suppression_candidates WHERE tenant_id = ANY(:ids)"),
            {"ids": tenant_ids},
        )
        conn.execute(
            text("DELETE FROM benign_baseline_entries WHERE tenant_id = ANY(:ids)"),
            {"ids": tenant_ids},
        )
        conn.execute(
            text("DELETE FROM detector_stats WHERE tenant_id = ANY(:ids)"), {"ids": tenant_ids}
        )
        # docs/v2_migration change 21's own tables: every one of these either FKs to
        # `analyst_feedback` directly (which has no cascade of its own -- see that model's
        # docstring) or is tenant-scoped state this milestone owns. All deleted before the
        # `analyst_feedback` DELETE below for the same reason as the tables above it.
        for table in (
            "claim_feedback",
            "evidence_relevance_feedback",
            "reference_set_exclusions",
            "dga_label_feedback",
            "exemplar_bank_entries",
            "learning_proposals",
            "entity_threshold_overrides",
            "entity_cohorts",
            "retrieval_priors",
            "evidence_profile_state",
            "baseline_windows",
        ):
            conn.execute(
                text(f"DELETE FROM {table} WHERE tenant_id = ANY(:ids)"),
                {"ids": tenant_ids},
            )
        conn.execute(
            text(
                "DELETE FROM learning_events WHERE trigger_feedback_id IN "
                "(SELECT af.id FROM analyst_feedback af "
                "JOIN triage_verdicts tv ON af.verdict_id = tv.id "
                "JOIN incidents i ON tv.incident_id = i.id WHERE i.tenant_id = ANY(:ids))"
            ),
            {"ids": tenant_ids},
        )
        conn.execute(
            text(
                "DELETE FROM analyst_feedback WHERE verdict_id IN "
                "(SELECT tv.id FROM triage_verdicts tv JOIN incidents i "
                "ON tv.incident_id = i.id WHERE i.tenant_id = ANY(:ids))"
            ),
            {"ids": tenant_ids},
        )


def make_signal(
    session: Session,
    *,
    tenant_id: uuid.UUID,
    analysis_id: uuid.UUID,
    detector_key: str | None = None,
    detector_layer: str = "signal",
    raw_score: float = 0.7,
    confidence: float = 0.7,
    entity_type: str = "src_ip",
    entity_value: str = "10.0.0.1",
    mitre_technique: str | None = "T1071.001",
    window_start: datetime | None = None,
    window_end: datetime | None = None,
    explanation: dict[str, object] | None = None,
) -> Signal:
    """`detector_key` defaults to a fresh, call-unique value (`signal.beaconing.<hex>`), not a
    fixed literal. `detector_stats.detector_key` is a *global* primary key (docs/02, no
    `tenant_id` in the uniqueness constraint -- see `app.models.detector_stats`'s docstring), so
    any two tests that both accept a fixed default and both flow through `app.learning.weights.
    retune_detector_weights` (directly, or via `app.learning.feedback.record_feedback`) would
    contend for the *same* global row -- which, run concurrently with this project's other test
    suites and `app/scripts/seed_feedback.py` against one shared Postgres instance, produced a
    genuine multi-minute lock wait in practice, not a hypothetical. Pass an explicit
    `detector_key` only when a test's own assertions need a specific, known value."""
    with tenant_scope(session, tenant_id):
        signal = Signal(
            analysis_id=analysis_id,
            tenant_id=tenant_id,
            detector_key=detector_key or f"signal.beaconing.{uuid.uuid4().hex[:8]}",
            detector_layer=detector_layer,
            raw_score=raw_score,
            confidence=confidence,
            entity_type=entity_type,
            entity_value=entity_value,
            mitre_technique=mitre_technique,
            window_start=window_start,
            window_end=window_end,
            evidence_event_ids=[],
            explanation=explanation if explanation is not None else {"test": True},
        )
        session.add(signal)
        session.flush()
    return signal


def make_incident_with_verdict(
    session: Session,
    *,
    tenant_id: uuid.UUID,
    analysis_id: uuid.UUID,
    signals: list[Signal],
    disposition: str = "true_positive",
    fused_score: float = 0.7,
    severity: str = "high",
    threat_confidence: str = "high",
    mitre_techniques: list[str] | None = None,
    embedding: list[float] | None = None,
    created_at: datetime | None = None,
) -> tuple[Incident, TriageVerdict]:
    """One incident carrying `signals` (already-created `Signal` rows, same `analysis_id`), plus
    the one `TriageVerdict` `analyst_feedback.verdict_id` needs to reference (docs/02:
    `analyst_feedback` cannot exist without a verdict).

    `threat_confidence` (docs/v2_migration change 3) is the verdict's own low/moderate/high
    hypothesis-evaluation judgment -- independent of `incident.anomaly_confidence`, which this
    helper always derives from `fused_score` (`app.detection.fusion.
    anomaly_confidence_from_fused_score`), the same way every real incident-persisting code path
    does."""
    with tenant_scope(session, tenant_id):
        incident = Incident(
            analysis_id=analysis_id,
            tenant_id=tenant_id,
            title="Test incident",
            severity=severity,
            fused_score=fused_score,
            anomaly_confidence=anomaly_confidence_from_fused_score(fused_score),
            entity_ids=[],
            signal_ids=[s.id for s in signals],
            embedding=embedding,
            **({"created_at": created_at} if created_at is not None else {}),
        )
        session.add(incident)
        session.flush()

        verdict = TriageVerdict(
            incident_id=incident.id,
            disposition=disposition,
            threat_confidence=threat_confidence,
            threat_confidence_reason="Test verdict threat-confidence reason.",
            mitre_techniques=mitre_techniques or [],
            summary="Test verdict.",
            narrative=[{"step": 1, "claim": "test", "evidence_event_ids": []}],
            recommended_actions=[],
            tool_trace=[],
            citation_valid=True,
            invalid_citations=[],
            model="test-fixture",
            **({"created_at": created_at} if created_at is not None else {}),
        )
        session.add(verdict)
        session.flush()
    return incident, verdict


def make_feedback(
    session: Session,
    *,
    verdict_id: uuid.UUID,
    user_id: uuid.UUID,
    agrees: bool = True,
    corrected_disposition: str | None = None,
    corrected_technique: str | None = None,
    dismissal_reason: str | None = None,
    mark_benign_baseline: bool = False,
    note: str | None = None,
) -> AnalystFeedback:
    """`analyst_feedback` has no `tenant_id` column (docs/02) so no `tenant_scope` is needed to
    write one directly -- isolation is transitive through `verdict_id` (see
    `app.models.analyst_feedback`'s docstring)."""
    feedback = AnalystFeedback(
        verdict_id=verdict_id,
        user_id=user_id,
        agrees=agrees,
        corrected_disposition=corrected_disposition,
        corrected_technique=corrected_technique,
        dismissal_reason=dismissal_reason,
        mark_benign_baseline=mark_benign_baseline,
        note=note,
    )
    session.add(feedback)
    session.flush()
    return feedback


def unit_embedding(seed_text: str, dim: int = 1024) -> list[float]:
    """A deterministic, roughly-unit-norm pseudo-embedding for tests that need `incidents.
    embedding` populated (few-shot memory retrieval) without pulling in a real model. Same
    `seed_text` -> same vector; different `seed_text` -> a materially different one."""
    import random

    rng = random.Random(seed_text)
    vec = [rng.gauss(0, 1) for _ in range(dim)]
    norm = sum(v * v for v in vec) ** 0.5
    return [v / norm for v in vec] if norm > 0 else vec


__all__ = [
    "User",
    "make_feedback",
    "make_incident_with_verdict",
    "make_signal",
    "unit_embedding",
]
