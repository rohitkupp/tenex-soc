"""Mechanism 12 — RAG document enrichment (change 21, gated). "Repeated mis-mapping means a
technique's `evidence_that_weakens` is thin. Dismissal reasons become proposed KB additions. The
knowledge base itself learns."

Targets `backend/data/kb/mitre/techniques/<technique>.yml`'s `evidence_that_weakens` list
(`docs/v2_migration` change 4's own KB document schema). Mirrors `app.learning.suppression`'s
"never auto-apply" discipline exactly: this module only ever proposes; the only code path that
writes the YAML file is `accept_kb_enrichment`, reached solely through a human clicking Accept.
"""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any

import yaml
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.learning.mechanisms import GatedApplyResult, create_proposal, decide_proposal
from app.learning.retrain import MetricTolerance, evaluate_candidate
from app.models.analyst_feedback import AnalystFeedback
from app.models.base import tenant_scope
from app.models.incident import Incident
from app.models.learning_proposal import LearningProposal
from app.models.triage_verdict import TriageVerdict

__all__ = ["KB_TECHNIQUES_DIR", "MIN_REPEATS", "accept_kb_enrichment", "propose_kb_enrichment"]

# app/learning/kb_enrichment.py -> learning -> app -> backend
_BACKEND_ROOT = Path(__file__).resolve().parents[2]
KB_TECHNIQUES_DIR: Path = _BACKEND_ROOT / "data" / "kb" / "mitre" / "techniques"
MIN_REPEATS = 2
_SUPPORT_TOLERANCE = MetricTolerance("higher_is_better", 0.0)


def _technique_id(verdict: TriageVerdict) -> str | None:
    techniques = verdict.mitre_techniques
    if not isinstance(techniques, list) or not techniques:
        return None
    first = techniques[0]
    if isinstance(first, str):
        return first
    if isinstance(first, dict):
        tid = first.get("technique") or first.get("id")
        return tid if isinstance(tid, str) else None
    return None


def propose_kb_enrichment(
    session: Session,
    tenant_id: uuid.UUID,
    feedback: AnalystFeedback,
    verdict: TriageVerdict,
    *,
    techniques_dir: Path = KB_TECHNIQUES_DIR,
) -> LearningProposal | None:
    """A Dismiss (or a corrected-to-benign Override) that named a specific reason for a verdict
    that had mapped to a technique is a candidate weakening-evidence phrase. Proposes once at
    least `MIN_REPEATS` feedback events for the same `(technique, reason)` pair have accumulated
    -- a single dismissal is too little evidence to edit a shared knowledge-base document over.
    `techniques_dir` defaults to the real KB directory; tests point it at a `tmp_path` copy so
    they never mutate the repository's own KB files.
    """
    if feedback.agrees or not feedback.dismissal_reason:
        return None
    technique_id = _technique_id(verdict)
    if technique_id is None or technique_id == "NO_KNOWN_MAPPING":
        return None
    yaml_path = techniques_dir / f"{technique_id}.yml"
    if not yaml_path.exists():
        return None

    with tenant_scope(session, tenant_id):
        rows = session.execute(
            select(AnalystFeedback, TriageVerdict, Incident)
            .join(TriageVerdict, AnalystFeedback.verdict_id == TriageVerdict.id)
            .join(Incident, TriageVerdict.incident_id == Incident.id)
            .where(AnalystFeedback.dismissal_reason == feedback.dismissal_reason)
        ).all()
    matching_ids = [f.id for f, v, _i in rows if _technique_id(v) == technique_id]
    if len(matching_ids) < MIN_REPEATS or matching_ids[-1] != feedback.id:
        return None

    return create_proposal(
        session,
        tenant_id,
        mechanism=12,
        payload={
            "technique_id": technique_id,
            "proposed_phrase": feedback.dismissal_reason,
            "n_repeats": len(matching_ids),
        },
        supporting_feedback_ids=matching_ids,
        trigger_feedback_id=feedback.id,
    )


def _apply_kb_write(proposal: LearningProposal, techniques_dir: Path) -> dict[str, Any]:
    technique_id = proposal.payload["technique_id"]
    phrase = proposal.payload["proposed_phrase"]
    path = techniques_dir / f"{technique_id}.yml"
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    weakens = doc.setdefault("evidence_that_weakens", [])
    if phrase not in weakens:
        weakens.append(phrase)
        path.write_text(
            yaml.safe_dump(doc, sort_keys=False, default_flow_style=False), encoding="utf-8"
        )
    return {"technique_id": technique_id, "evidence_that_weakens": weakens}


def accept_kb_enrichment(
    session: Session,
    tenant_id: uuid.UUID,
    proposal: LearningProposal,
    *,
    user_id: uuid.UUID,
    techniques_dir: Path = KB_TECHNIQUES_DIR,
) -> GatedApplyResult:
    gate = evaluate_candidate({"support": 1.0}, None, tolerances={"support": _SUPPORT_TOLERANCE})
    return decide_proposal(
        session,
        tenant_id,
        proposal,
        passed=gate.passed,
        metric_delta={"n_repeats": proposal.payload["n_repeats"]},
        reason=gate.reason,
        user_id=user_id,
        apply_fn=lambda s, t, p: _apply_kb_write(p, techniques_dir),
    )
