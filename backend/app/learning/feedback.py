"""`POST /api/incidents/{id}/feedback` is the single entry point into every "no retrain" consumer
this milestone builds, plus the trigger for the retrain-triggering ones. This module is that
entry point's implementation, kept separate from `app/api/learning.py` so the orchestration logic
(which consumer runs when, in what order, on what cadence) is unit-testable without going through
FastAPI/HTTP at all.

## Two generations of consumers, one entry point

The six pre-migration consumers (docs/08 Part 2, this module's original M13 shape) still run
exactly as before -- calibration refit, detector weight tuning, verdict-memory retrieval (a pure
read side, `app.learning.memory`, unaffected by anything here), suppression rule generation, and
benign-corpus flagging are all untouched, and every existing test in `tests/test_learning_*.py`
still exercises the same behavior. `docs/v2_migration/MIGRATION-01-evidence-first.md` change 21
adds fifteen numbered mechanisms on top; where a pre-migration consumer already *is* one of the
fifteen (calibration = mechanism 1, weight tuning = mechanism 2, verdict memory = mechanism 9),
this module logs a `learning_events` row for it here rather than duplicating the consumer itself.
Every genuinely new mechanism (3-8, 10-15) lives in its own `app/learning/<mechanism>.py` module
(see `app.learning.mechanisms.MECHANISMS` for the full map) and is invoked from here.

## Change 22's feedback taxonomy, mapped onto docs/02's existing columns

`analyst_feedback` (docs/02) is not altered by this migration -- change 22's UI maps onto its
existing columns rather than growing the schema: `dismissal_reason` now carries one of
`DISMISSAL_REASON_CATEGORIES` (a constrained vocabulary, not free text) and `note` carries the
free-text elaboration change 22 asks for separately. `corrected_technique` is validated against
`valid_technique_choices(verdict)` -- the verdict's own retrieved candidate set plus
`NO_KNOWN_MAPPING` -- so the override dropdown's constraint is enforced server-side, not only by
the frontend control leaving off the other options.

## Order of operations

1. Insert the `analyst_feedback` row itself.
2. Pre-migration consumers 1-5 (weight tuning always; calibration + classifier retrain at the
   50-event cadence; suppression + benign-baseline flagging on their own triggers) -- unchanged.
3. Mechanisms 1, 2, 9 -- `learning_events` logged for the pre-migration consumers above.
4. Mechanism 3 -- entity threshold adaptation, every call.
5. Mechanisms 4/5 -- reference set curation/exclusion, gated on the feedback's own disposition
   (see `_reference_set_action`); silently skipped (no `learning_events` row) when no feature
   vector can be found for this window -- see `app.learning.reference_sets`'s module docstring.
6. Mechanism 6 -- baseline expansion, proposed whenever consumer 5 flagged something.
7. Mechanism 7 -- cohort re-derivation, proposed every 10th feedback event.
8. Mechanism 8 -- DGA classifier retraining, proposed when `corrected_domain_labels` crosses the
   refit cadence.
9. Mechanisms 10/11/12/13 -- exemplar bank, judge rubric, KB enrichment, retrieval prior tuning.

Mechanisms 14 and 15 are **not** triggered from here -- their source signals (per-claim thumbs,
evidence relevance) are separate feedback tiers change 22 defines as their own controls, not part
of the primary Confirm/Override/Dismiss bar. See `record_claim_feedback` and
`record_evidence_relevance_toggle` below.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.learning.baseline_expansion import propose_baseline_expansion
from app.learning.benign_corpus import flag_benign_baseline
from app.learning.calibration import CalibrationRefitResult, refit_calibrators, should_refit_now
from app.learning.cohorts import propose_cohort_re_derivation
from app.learning.dga_retrain import propose_dga_retrain, record_dga_label_correction
from app.learning.exemplars import propose_exemplar
from app.learning.kb_enrichment import propose_kb_enrichment
from app.learning.mechanisms import record_event
from app.learning.reference_sets import (
    ReferenceSetMutation,
    add_to_reference_set,
    exclude_from_reference_set,
    feature_row_for_incident,
)
from app.learning.retrain import RetrainAttempt, run_classifier_retrain
from app.learning.retrieval_priors import RetrievalPriorChange, record_retrieval_outcome
from app.learning.rubric import propose_rubric_item
from app.learning.suppression import generate_suppression_candidates
from app.learning.weights import WeightTuningResult, retune_detector_weights
from app.models.analyst_feedback import AnalystFeedback
from app.models.base import get_scoped, tenant_scope
from app.models.benign_baseline_entry import BenignBaselineEntry
from app.models.claim_feedback import ClaimFeedback
from app.models.evidence_relevance_feedback import EvidenceRelevanceFeedback
from app.models.incident import Incident
from app.models.learning_proposal import LearningProposal
from app.models.suppression_candidate import SuppressionCandidate
from app.models.triage_verdict import TriageVerdict

__all__ = [
    "COHORT_RE_DERIVATION_EVERY_N_FEEDBACK",
    "DISMISSAL_REASON_CATEGORIES",
    "NO_KNOWN_MAPPING",
    "DomainLabelCorrection",
    "FeedbackInput",
    "FeedbackOutcome",
    "IncidentNotFoundError",
    "IncidentNotTriagedError",
    "InvalidCorrectedTechniqueError",
    "record_claim_feedback",
    "record_evidence_relevance_toggle",
    "record_feedback",
    "valid_technique_choices",
]


class IncidentNotFoundError(Exception):
    """No incident with this id exists for this tenant."""


class IncidentNotTriagedError(Exception):
    """The incident exists but has no `triage_verdicts` row yet — feedback needs a verdict to
    attach to (docs/02: `analyst_feedback.verdict_id` is `NOT NULL`)."""


class InvalidCorrectedTechniqueError(Exception):
    """`corrected_technique` was not one of `verdict.mitre_techniques`' own ids, nor
    `NO_KNOWN_MAPPING` — change 22's override dropdown is "limited to retrieved candidates plus
    NO_KNOWN_MAPPING," enforced here, not only by the frontend leaving other options out."""


# Change 22's Dismiss reason-category vocabulary, verbatim. Not free text — `analyst_feedback.
# dismissal_reason` (docs/02) carries one of these; the accompanying free-text elaboration goes
# in `note` (a genuinely separate column, per change 22: "reason category ... free text").
DISMISSAL_REASON_CATEGORIES: tuple[str, ...] = (
    "sanctioned_automation",
    "known_business_process",
    "expected_for_this_entity",
    "insufficient_evidence",
    "other",
)

# Change 5's mandatory "no forced attribution" value, reused verbatim as the one extra option
# change 22's Override technique dropdown adds on top of the verdict's own retrieved candidates.
NO_KNOWN_MAPPING = "NO_KNOWN_MAPPING"

COHORT_RE_DERIVATION_EVERY_N_FEEDBACK = 10


def _technique_ids(mitre_techniques: object) -> set[str]:
    if not isinstance(mitre_techniques, list):
        return set()
    out: set[str] = set()
    for item in mitre_techniques:
        if isinstance(item, str):
            out.add(item)
        elif isinstance(item, dict):
            tid = item.get("technique") or item.get("id") or item.get("mitre_technique")
            if isinstance(tid, str):
                out.add(tid)
    return out


def valid_technique_choices(verdict: TriageVerdict) -> set[str]:
    """Change 22: "dropdown limited to retrieved candidates plus `NO_KNOWN_MAPPING`." The
    retrieved candidate set is `verdict.mitre_techniques` — every technique the Analyst stage
    evaluated for this incident (docs/v2_migration change 5), not just the one it ultimately
    chose."""
    return _technique_ids(verdict.mitre_techniques) | {NO_KNOWN_MAPPING}


@dataclass(frozen=True, slots=True)
class DomainLabelCorrection:
    domain: str
    is_dga: bool


@dataclass(frozen=True, slots=True)
class FeedbackInput:
    agrees: bool
    corrected_disposition: str | None = None
    corrected_technique: str | None = None
    dismissal_reason: str | None = None
    mark_benign_baseline: bool = False
    note: str | None = None
    # Not part of the real HTTP request body -- an override hook so `app/scripts/
    # seed_feedback.py` can backdate synthetic feedback across a multi-week synthetic history.
    created_at: datetime | None = None
    # Mechanism 8 input: domains the analyst confirmed or corrected as (not) DGA-generated on
    # this incident, e.g. via a per-domain control in the evidence section.
    corrected_domain_labels: tuple[DomainLabelCorrection, ...] = ()


@dataclass(slots=True)
class FeedbackOutcome:
    feedback_id: uuid.UUID
    weight_tuning: WeightTuningResult
    calibration_refit: CalibrationRefitResult | None
    suppression_candidates: list[SuppressionCandidate]
    benign_baseline_entries: list[BenignBaselineEntry]
    retrain_attempt: RetrainAttempt | None
    # docs/v2_migration change 21 additions -- every field below is additive; nothing above this
    # line changed shape, so every pre-migration test keeps passing unmodified.
    reference_set_mechanism: int | None = None  # 4 (add) or 5 (exclude), or None if skipped
    reference_set_mutations: list[ReferenceSetMutation] = field(default_factory=list)
    baseline_expansion_proposal: LearningProposal | None = None
    cohort_proposal: LearningProposal | None = None
    dga_retrain_proposal: LearningProposal | None = None
    exemplar_proposal: LearningProposal | None = None
    rubric_proposal: LearningProposal | None = None
    kb_enrichment_proposal: LearningProposal | None = None
    retrieval_prior_changes: list[RetrievalPriorChange] = field(default_factory=list)


def _tenant_feedback_count(session: Session, tenant_id: uuid.UUID) -> int:
    """**A real, pre-existing tenant-isolation gap found and fixed while building this
    milestone**, in the same spirit as this codebase's own precedent (git history: "fix a real
    tenant-isolation leak"). `app.models.base`'s automatic `with_loader_criteria(TenantScopedMixin,
    ...)` hook only reaches entities that are part of a query's top-level selected columns; it does
    **not** reach `Incident` here, since this query only ever joins it in to reach `analyst_feedback`
    (which itself carries no `tenant_id`) -- `select(func.count(AnalystFeedback.id)).join(...).
    join(Incident, ...)` compiled, in production, with no `WHERE incidents.tenant_id = ...` clause
    at all, silently counting **every tenant's** feedback. On a single-tenant demo database this was
    invisible (the unscoped count and the correctly-scoped count happen to be equal when only one
    tenant has any feedback); it surfaced once more than one tenant's feedback existed at once. Kept
    inside `tenant_scope(...)` for defense in depth (it costs nothing) but no longer *relies on* it —
    the explicit `.where(Incident.tenant_id == tenant_id)` below is what actually enforces scoping.
    """
    with tenant_scope(session, tenant_id):
        return session.execute(
            select(func.count(AnalystFeedback.id))
            .join(TriageVerdict, AnalystFeedback.verdict_id == TriageVerdict.id)
            .join(Incident, TriageVerdict.incident_id == Incident.id)
            .where(Incident.tenant_id == tenant_id)
        ).scalar_one()


def _reference_set_action(feedback: AnalystFeedback, verdict: TriageVerdict) -> str | None:
    """`"add"` (mechanism 4) on a confirmed-benign window (a Dismiss with `mark_benign_baseline`);
    `"exclude"` (mechanism 5) on a confirmed true positive (a plain Confirm of an already-
    true_positive verdict, or an Override that corrects the disposition *to* true_positive);
    `None` otherwise -- most feedback (e.g. confirming a benign verdict, or a dismissal that does
    not mark the baseline) triggers neither."""
    if not feedback.agrees and feedback.mark_benign_baseline:
        return "add"
    effective = feedback.corrected_disposition or verdict.disposition
    if effective == "true_positive":
        return "exclude"
    return None


def record_feedback(
    session: Session,
    tenant_id: uuid.UUID,
    *,
    user_id: uuid.UUID,
    incident_id: uuid.UUID,
    data: FeedbackInput,
) -> FeedbackOutcome:
    with tenant_scope(session, tenant_id):
        incident = get_scoped(session, Incident, incident_id)
        if incident is None:
            raise IncidentNotFoundError(f"no incident {incident_id} for tenant {tenant_id}")

        verdict = session.execute(
            select(TriageVerdict)
            .where(TriageVerdict.incident_id == incident_id)
            .order_by(TriageVerdict.created_at.desc())
            .limit(1)
        ).scalar_one_or_none()
        if verdict is None:
            raise IncidentNotTriagedError(f"incident {incident_id} has no triage verdict yet")

        if data.corrected_technique is not None:
            allowed = valid_technique_choices(verdict)
            if data.corrected_technique not in allowed:
                raise InvalidCorrectedTechniqueError(
                    f"{data.corrected_technique!r} is not a retrieved candidate for this "
                    f"verdict (allowed: {sorted(allowed)})"
                )
        # `dismissal_reason` is deliberately *not* hard-validated against
        # `DISMISSAL_REASON_CATEGORIES` here: `analyst_feedback.dismissal_reason` (docs/02) is a
        # plain TEXT column that pre-migration code (`app.learning.suppression`'s free-text
        # reason, `app/scripts/seed_feedback.py`'s synthetic history, every existing test in
        # `tests/test_learning_*.py`) already writes arbitrary strings into. Change 22's
        # constrained dropdown is enforced by the frontend control offering only the five
        # categories; mechanisms 11/12 (`app.learning.rubric`/`app.learning.kb_enrichment`)
        # already degrade a non-category string to `"other"`/no-op respectively rather than
        # assuming every row is one of the five. Rejecting free text here would break every
        # caller that predates change 22's UI, for a validation the UI layer already provides.

        feedback_kwargs: dict[str, object] = {
            "verdict_id": verdict.id,
            "user_id": user_id,
            "agrees": data.agrees,
            "corrected_disposition": data.corrected_disposition,
            "corrected_technique": data.corrected_technique,
            "dismissal_reason": data.dismissal_reason,
            "mark_benign_baseline": data.mark_benign_baseline,
            "note": data.note,
        }
        if data.created_at is not None:
            feedback_kwargs["created_at"] = data.created_at
        feedback = AnalystFeedback(**feedback_kwargs)
        session.add(feedback)
        session.flush()  # assign feedback.id before any consumer reads it back

    # --- Pre-migration consumers 1-5 (unchanged) --------------------------------------------
    weight_result = retune_detector_weights(session, tenant_id)
    total_feedback = _tenant_feedback_count(session, tenant_id)
    calibration_result = (
        refit_calibrators(session, tenant_id) if should_refit_now(total_feedback) else None
    )
    suppression_candidates = generate_suppression_candidates(session, tenant_id, feedback)
    benign_entries = flag_benign_baseline(session, tenant_id, feedback)
    retrain_attempt = (
        run_classifier_retrain(session, tenant_id) if should_refit_now(total_feedback) else None
    )

    # --- Mechanisms 1, 2 -- learning_events for the pre-migration consumers above ------------
    record_event(
        session,
        mechanism=2,
        applied=True,
        trigger_feedback_id=feedback.id,
        after_state={
            "detectors_changed": [c.detector_key for c in weight_result.detectors if c.changed]
        },
        metric_delta={"prior_precision": weight_result.prior_precision},
    )
    if calibration_result is not None:
        record_event(
            session,
            mechanism=1,
            applied=True,
            trigger_feedback_id=feedback.id,
            before_state={"overall_brier": calibration_result.overall_brier_before},
            after_state={"overall_brier": calibration_result.overall_brier_after},
            metric_delta={
                "brier_improvement": (
                    (calibration_result.overall_brier_before or 0)
                    - (calibration_result.overall_brier_after or 0)
                )
                if calibration_result.overall_brier_before is not None
                and calibration_result.overall_brier_after is not None
                else None
            },
        )

    # --- Mechanism 9 -- this feedback event makes its incident retrievable as a prior decision
    if incident.embedding is not None:
        record_event(
            session,
            mechanism=9,
            applied=True,
            trigger_feedback_id=feedback.id,
            after_state={"incident_id": str(incident.id), "disposition": verdict.disposition},
        )

    # --- Mechanism 3 -- entity threshold adaptation, every call ------------------------------
    from app.learning.entity_thresholds import adapt_entity_threshold

    adapt_entity_threshold(session, tenant_id, feedback, trigger_feedback_id=feedback.id)

    # --- Mechanisms 4/5 -- reference set curation / contamination exclusion ------------------
    reference_set_mechanism: int | None = None
    reference_set_mutations: list[ReferenceSetMutation] = []
    action = _reference_set_action(feedback, verdict)
    if action is not None:
        located = feature_row_for_incident(session, tenant_id, incident_id)
        if located is not None:
            window, feature_row = located
            if action == "add":
                reference_set_mechanism = 4
                reference_set_mutations = add_to_reference_set(
                    session,
                    tenant_id,
                    window=window,
                    feature_row=feature_row,
                    trigger_feedback_id=feedback.id,
                )
            else:
                reference_set_mechanism = 5
                reference_set_mutations = exclude_from_reference_set(
                    session,
                    tenant_id,
                    window=window,
                    feature_row=feature_row,
                    feedback=feedback,
                    trigger_feedback_id=feedback.id,
                )

    # --- Mechanism 6 -- baseline expansion, proposed once consumer 5 flagged something --------
    baseline_expansion_proposal = (
        propose_baseline_expansion(session, tenant_id, feedback.id) if benign_entries else None
    )

    # --- Mechanism 7 -- cohort re-derivation, every 10th feedback event -----------------------
    cohort_proposal = (
        propose_cohort_re_derivation(session, tenant_id, trigger_feedback_id=feedback.id)
        if total_feedback % COHORT_RE_DERIVATION_EVERY_N_FEEDBACK == 0
        else None
    )

    # --- Mechanism 8 -- DGA classifier retraining ---------------------------------------------
    for correction in data.corrected_domain_labels:
        record_dga_label_correction(
            session,
            tenant_id,
            domain=correction.domain,
            is_dga=correction.is_dga,
            feedback_id=feedback.id,
            incident_id=incident_id,
        )
    dga_retrain_proposal = (
        propose_dga_retrain(session, tenant_id, trigger_feedback_id=feedback.id)
        if data.corrected_domain_labels
        else None
    )

    # --- Mechanism 10 -- curated exemplar bank -------------------------------------------------
    exemplar_proposal = propose_exemplar(session, tenant_id, feedback, verdict)

    # --- Mechanism 11 -- judge rubric evolution -------------------------------------------------
    rubric_proposal = propose_rubric_item(session, tenant_id, trigger_feedback_id=feedback.id)

    # --- Mechanism 12 -- RAG document enrichment ------------------------------------------------
    kb_enrichment_proposal = propose_kb_enrichment(session, tenant_id, feedback, verdict)

    # --- Mechanism 13 -- retrieval prior tuning -------------------------------------------------
    retrieval_prior_changes = record_retrieval_outcome(
        session, tenant_id, verdict, feedback, trigger_feedback_id=feedback.id
    )

    # No explicit commit here -- `app.core.db.get_db`'s request-scoped session commits once at
    # end of request; `app/scripts/seed_feedback.py` commits explicitly on its own schedule.

    return FeedbackOutcome(
        feedback_id=feedback.id,
        weight_tuning=weight_result,
        calibration_refit=calibration_result,
        suppression_candidates=suppression_candidates,
        benign_baseline_entries=benign_entries,
        retrain_attempt=retrain_attempt,
        reference_set_mechanism=reference_set_mechanism,
        reference_set_mutations=reference_set_mutations,
        baseline_expansion_proposal=baseline_expansion_proposal,
        cohort_proposal=cohort_proposal,
        dga_retrain_proposal=dga_retrain_proposal,
        exemplar_proposal=exemplar_proposal,
        rubric_proposal=rubric_proposal,
        kb_enrichment_proposal=kb_enrichment_proposal,
        retrieval_prior_changes=retrieval_prior_changes,
    )


def record_claim_feedback(
    session: Session,
    tenant_id: uuid.UUID,
    *,
    user_id: uuid.UUID,
    incident_id: uuid.UUID,
    step: int,
    helpful: bool,
    note: str | None = None,
) -> ClaimFeedback:
    """Change 22: "Per-claim thumbs on narrative claims, hover-revealed." Independent of the
    primary Confirm/Override/Dismiss bar -- an analyst can thumbs-down one claim in an otherwise-
    confirmed incident. Feeds mechanism 14 (`app.learning.verifier_rules.propose_verifier_rule`),
    invoked here immediately after the row is written."""
    with tenant_scope(session, tenant_id):
        incident = get_scoped(session, Incident, incident_id)
        if incident is None:
            raise IncidentNotFoundError(f"no incident {incident_id} for tenant {tenant_id}")
        verdict = session.execute(
            select(TriageVerdict)
            .where(TriageVerdict.incident_id == incident_id)
            .order_by(TriageVerdict.created_at.desc())
            .limit(1)
        ).scalar_one_or_none()
        if verdict is None:
            raise IncidentNotTriagedError(f"incident {incident_id} has no triage verdict yet")

        claim = ClaimFeedback(
            tenant_id=tenant_id,
            incident_id=incident_id,
            verdict_id=verdict.id,
            step=step,
            helpful=helpful,
            note=note,
            user_id=user_id,
        )
        session.add(claim)
        session.flush()

    from app.learning.verifier_rules import propose_verifier_rule

    propose_verifier_rule(session, tenant_id, claim)
    return claim


def record_evidence_relevance_toggle(
    session: Session,
    tenant_id: uuid.UUID,
    *,
    user_id: uuid.UUID,
    incident_id: uuid.UUID,
    evidence_id: str,
    extractor: str,
    relevant: bool,
) -> EvidenceRelevanceFeedback:
    """Change 16/22's "per-evidence relevance toggle." Feeds mechanism 15 (`app.learning.
    evidence_profiles.record_evidence_relevance`) -- see that module's docstring for a documented
    reading of change 16's own cross-reference to "mechanism 13"."""
    with tenant_scope(session, tenant_id):
        row = EvidenceRelevanceFeedback(
            tenant_id=tenant_id,
            incident_id=incident_id,
            evidence_id=evidence_id,
            extractor=extractor,
            relevant=relevant,
            user_id=user_id,
        )
        session.add(row)
        session.flush()

    from app.learning.evidence_profiles import record_evidence_relevance

    record_evidence_relevance(session, tenant_id, extractor=extractor, relevant=relevant)
    return row
