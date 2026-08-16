"""Change 21's fifteen mechanisms (`app.learning.mechanisms.MECHANISMS`), and change 25's test
plan for them: "each of the 15 mechanisms has a test asserting its specific state change" plus
the auto/gated split enforcement and the gated golden-set gate (including rejection history).

Mechanisms 4 and 5 have their own dedicated, more extensive module:
`tests/test_learning_reference_sets.py` — see that file for the contamination-exclusion test
change 25 calls out by name.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.learning.baseline_expansion import accept_baseline_expansion
from app.learning.cohorts import accept_cohort_re_derivation, propose_cohort_re_derivation
from app.learning.dga_retrain import (
    DGA_MODEL_KEY,
    accept_dga_retrain,
    propose_dga_retrain,
    record_dga_label_correction,
)
from app.learning.entity_thresholds import MIN_THRESHOLD, adapt_entity_threshold
from app.learning.evidence_profiles import (
    MIN_SAMPLES_TO_PROPOSE,
    accept_evidence_profile_widening,
)
from app.learning.exemplars import accept_exemplar, propose_exemplar
from app.learning.feedback import (
    FeedbackInput,
    InvalidCorrectedTechniqueError,
    record_claim_feedback,
    record_evidence_relevance_toggle,
    record_feedback,
)
from app.learning.kb_enrichment import accept_kb_enrichment, propose_kb_enrichment
from app.learning.mechanisms import MECHANISMS
from app.learning.rubric import accept_rubric_item
from app.learning.verifier_rules import propose_verifier_rule
from app.models.base import tenant_scope
from app.models.baseline_window import BaselineWindow
from app.models.entity_cohort import EntityCohort
from app.models.entity_threshold_override import EntityThresholdOverride
from app.models.evidence_profile_state import EvidenceProfileState
from app.models.exemplar_bank_entry import ExemplarBankEntry
from app.models.learning_event import LearningEvent
from app.models.learning_proposal import STATUS_APPROVED, STATUS_REJECTED, LearningProposal
from app.models.model_version import ModelVersion
from app.models.retrieval_prior import RetrievalPrior
from tests.conftest import make_analysis, make_tenant, make_user
from tests.fixtures.learning import (  # noqa: F401
    learning_cleanup,
    learning_session,
    make_feedback,
    make_incident_with_verdict,
    make_signal,
)


def _seed_incident(
    session,
    *,
    tenant_id,
    user_id,
    disposition="true_positive",
    mitre_techniques=None,
    detector_key=None,
    window_start=None,
    window_end=None,
):
    analysis = make_analysis(tenant_id=tenant_id, user_id=user_id)
    sig = make_signal(
        session,
        tenant_id=tenant_id,
        analysis_id=analysis.id,
        detector_key=detector_key,
        window_start=window_start,
        window_end=window_end,
    )
    return make_incident_with_verdict(
        session,
        tenant_id=tenant_id,
        analysis_id=analysis.id,
        signals=[sig],
        disposition=disposition,
        mitre_techniques=mitre_techniques,
    )


def test_mechanism_registry_matches_change_21_auto_gated_split() -> None:
    auto = {m for m, spec in MECHANISMS.items() if spec.mode == "auto"}
    gated = {m for m, spec in MECHANISMS.items() if spec.mode == "gated"}
    assert auto == {1, 2, 3, 4, 5, 9, 13}
    assert gated == {6, 7, 8, 10, 11, 12, 14, 15}
    assert auto | gated == set(range(1, 16))


# --------------------------------------------------------------------------- mechanism 3


def test_mechanism_3_raises_entity_threshold_on_repeated_dismissals(
    learning_session: Session,  # noqa: F811
    learning_cleanup: list[uuid.UUID],  # noqa: F811
) -> None:
    tenant = make_tenant(name="Mechanism 3 Test Tenant")
    learning_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"m3-{uuid.uuid4()}@test.local")

    stable_detector_key = f"signal.beaconing.m3-{uuid.uuid4().hex[:8]}"
    last = None
    for _ in range(2):
        _incident, verdict = _seed_incident(
            learning_session,
            tenant_id=tenant.id,
            user_id=user.id,
            disposition="false_positive",
            detector_key=stable_detector_key,
        )
        learning_session.commit()
        fb = make_feedback(learning_session, verdict_id=verdict.id, user_id=user.id, agrees=False)
        learning_session.commit()
        last = adapt_entity_threshold(learning_session, tenant.id, fb, trigger_feedback_id=fb.id)
        learning_session.commit()

    assert last is not None
    assert last.dismiss_count == 2
    assert last.threshold_after > MIN_THRESHOLD
    assert last.changed is True

    with tenant_scope(learning_session, tenant.id):
        row = learning_session.execute(select(EntityThresholdOverride)).scalars().one()
    assert row.threshold_percentile == last.threshold_after

    event = (
        learning_session.execute(select(LearningEvent).where(LearningEvent.mechanism == 3))
        .scalars()
        .all()
    )
    assert len(event) == 2
    assert all(e.applied for e in event)


# --------------------------------------------------------------------------- mechanism 9


def test_mechanism_9_logs_verdict_retrieval_when_incident_is_embedded(
    learning_session: Session,  # noqa: F811
    learning_cleanup: list[uuid.UUID],  # noqa: F811
) -> None:
    tenant = make_tenant(name="Mechanism 9 Test Tenant")
    learning_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"m9-{uuid.uuid4()}@test.local")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)
    sig = make_signal(learning_session, tenant_id=tenant.id, analysis_id=analysis.id)
    from tests.fixtures.learning import unit_embedding

    incident, _verdict = make_incident_with_verdict(
        learning_session,
        tenant_id=tenant.id,
        analysis_id=analysis.id,
        signals=[sig],
        embedding=unit_embedding("mechanism-9"),
    )
    learning_session.commit()

    record_feedback(
        learning_session,
        tenant.id,
        user_id=user.id,
        incident_id=incident.id,
        data=FeedbackInput(agrees=True),
    )
    learning_session.commit()

    event = (
        learning_session.execute(select(LearningEvent).where(LearningEvent.mechanism == 9))
        .scalars()
        .one()
    )
    assert event.applied is True
    assert event.after_state["incident_id"] == str(incident.id)


# --------------------------------------------------------------------------- mechanism 13


def test_mechanism_13_down_weights_a_technique_retrieved_but_never_supported(
    learning_session: Session,  # noqa: F811
    learning_cleanup: list[uuid.UUID],  # noqa: F811
) -> None:
    tenant = make_tenant(name="Mechanism 13 Test Tenant")
    learning_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"m13-{uuid.uuid4()}@test.local")

    for _ in range(3):
        _incident, _verdict = _seed_incident(
            learning_session,
            tenant_id=tenant.id,
            user_id=user.id,
            disposition="false_positive",
            mitre_techniques=["T1071.001"],
        )
        learning_session.commit()
        record_feedback(
            learning_session,
            tenant.id,
            user_id=user.id,
            incident_id=_incident.id,
            data=FeedbackInput(agrees=False, dismissal_reason="insufficient_evidence"),
        )
        learning_session.commit()

    with tenant_scope(learning_session, tenant.id):
        row = learning_session.execute(select(RetrievalPrior)).scalars().one()
    assert row.retrieved_count == 3
    assert row.supported_count == 0
    assert row.weight < 1.0


def test_override_dropdown_is_limited_to_retrieved_candidates_plus_no_known_mapping(
    learning_session: Session,  # noqa: F811
    learning_cleanup: list[uuid.UUID],  # noqa: F811
) -> None:
    tenant = make_tenant(name="Technique Dropdown Test Tenant")
    learning_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"dropdown-{uuid.uuid4()}@test.local")
    incident, _verdict = _seed_incident(
        learning_session, tenant_id=tenant.id, user_id=user.id, mitre_techniques=["T1071.001"]
    )
    learning_session.commit()

    with pytest.raises(InvalidCorrectedTechniqueError):
        record_feedback(
            learning_session,
            tenant.id,
            user_id=user.id,
            incident_id=incident.id,
            data=FeedbackInput(agrees=False, corrected_technique="T1567.002"),
        )

    # A retrieved candidate is accepted.
    record_feedback(
        learning_session,
        tenant.id,
        user_id=user.id,
        incident_id=incident.id,
        data=FeedbackInput(agrees=False, corrected_technique="T1071.001"),
    )
    # NO_KNOWN_MAPPING is always accepted, retrieved or not.
    incident2, _v2 = _seed_incident(
        learning_session, tenant_id=tenant.id, user_id=user.id, mitre_techniques=["T1071.001"]
    )
    learning_session.commit()
    record_feedback(
        learning_session,
        tenant.id,
        user_id=user.id,
        incident_id=incident2.id,
        data=FeedbackInput(agrees=False, corrected_technique="NO_KNOWN_MAPPING"),
    )


# --------------------------------------------------------------------------- mechanism 6


def test_mechanism_6_baseline_expansion_writes_baseline_windows_on_accept(
    learning_session: Session,  # noqa: F811
    learning_cleanup: list[uuid.UUID],  # noqa: F811
) -> None:
    tenant = make_tenant(name="Mechanism 6 Test Tenant")
    learning_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"m6-{uuid.uuid4()}@test.local")
    incident, _verdict = _seed_incident(
        learning_session,
        tenant_id=tenant.id,
        user_id=user.id,
        disposition="false_positive",
        window_start=datetime(2026, 1, 1, tzinfo=UTC),
        window_end=datetime(2026, 1, 1, 1, tzinfo=UTC),
    )
    learning_session.commit()

    outcome = record_feedback(
        learning_session,
        tenant.id,
        user_id=user.id,
        incident_id=incident.id,
        data=FeedbackInput(
            agrees=False, dismissal_reason="sanctioned_automation", mark_benign_baseline=True
        ),
    )
    learning_session.commit()
    assert outcome.baseline_expansion_proposal is not None
    proposal = outcome.baseline_expansion_proposal
    assert proposal.mechanism == 6

    result = accept_baseline_expansion(learning_session, tenant.id, proposal, user_id=user.id)
    learning_session.commit()
    assert result.passed is True
    assert proposal.status == STATUS_APPROVED

    with tenant_scope(learning_session, tenant.id):
        windows = learning_session.execute(select(BaselineWindow)).scalars().all()
    assert len(windows) >= 1


# --------------------------------------------------------------------------- mechanism 7


def test_mechanism_7_cohort_re_derivation_writes_entity_cohorts_on_accept(
    learning_session: Session,  # noqa: F811
    learning_cleanup: list[uuid.UUID],  # noqa: F811
) -> None:
    tenant = make_tenant(name="Mechanism 7 Test Tenant")
    learning_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"m7-{uuid.uuid4()}@test.local")

    with tenant_scope(learning_session, tenant.id):
        for i in range(8):
            learning_session.add(
                BaselineWindow(
                    tenant_id=tenant.id,
                    entity_type="user",
                    entity_value=f"user{i}@example.com",
                    window_start=datetime(2026, 1, 1, tzinfo=UTC),
                    features={"n_events": float(i * 10), "bytes_out": float(i * 1000)},
                )
            )
        learning_session.flush()
    learning_session.commit()

    fb_id = uuid.uuid4()
    proposal = propose_cohort_re_derivation(learning_session, tenant.id, trigger_feedback_id=fb_id)
    learning_session.commit()
    assert proposal is not None
    assert proposal.mechanism == 7

    result = accept_cohort_re_derivation(learning_session, tenant.id, proposal, user_id=user.id)
    learning_session.commit()
    assert result.passed is True

    with tenant_scope(learning_session, tenant.id):
        cohorts = learning_session.execute(select(EntityCohort)).scalars().all()
    assert len(cohorts) == 8


# --------------------------------------------------------------------------- mechanism 8


def test_mechanism_8_dga_retrain_writes_a_promoted_model_version_on_accept(
    learning_session: Session,  # noqa: F811
    learning_cleanup: list[uuid.UUID],  # noqa: F811
) -> None:
    tenant = make_tenant(name="Mechanism 8 Test Tenant")
    learning_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"m8-{uuid.uuid4()}@test.local")
    incident, verdict = _seed_incident(learning_session, tenant_id=tenant.id, user_id=user.id)
    learning_session.commit()
    fb = make_feedback(learning_session, verdict_id=verdict.id, user_id=user.id, agrees=True)
    learning_session.commit()

    import random

    rng = random.Random(8)
    for i in range(20):
        domain = f"benign-site-{i}.com" if i % 2 == 0 else f"{rng.randbytes(8).hex()}.biz"
        record_dga_label_correction(
            learning_session,
            tenant.id,
            domain=domain,
            is_dga=(i % 2 == 1),
            feedback_id=fb.id,
            incident_id=incident.id,
        )
    learning_session.commit()

    model_key = f"{DGA_MODEL_KEY}.test.{uuid.uuid4().hex[:8]}"
    proposal = propose_dga_retrain(
        learning_session, tenant.id, trigger_feedback_id=fb.id, model_key=model_key
    )
    learning_session.commit()
    assert proposal is not None
    assert proposal.mechanism == 8

    result = accept_dga_retrain(learning_session, tenant.id, proposal, user_id=user.id)
    learning_session.commit()
    assert result.passed is True

    version = (
        learning_session.execute(select(ModelVersion).where(ModelVersion.model_key == model_key))
        .scalars()
        .one()
    )
    assert version.promoted is True


# --------------------------------------------------------------------------- mechanism 10


def test_mechanism_10_curated_exemplar_written_on_accept(
    learning_session: Session,  # noqa: F811
    learning_cleanup: list[uuid.UUID],  # noqa: F811
) -> None:
    tenant = make_tenant(name="Mechanism 10 Test Tenant")
    learning_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"m10-{uuid.uuid4()}@test.local")
    _incident, verdict = _seed_incident(
        learning_session, tenant_id=tenant.id, user_id=user.id, mitre_techniques=["T1071.001"]
    )
    learning_session.commit()
    fb = make_feedback(
        learning_session,
        verdict_id=verdict.id,
        user_id=user.id,
        agrees=False,
        corrected_technique="T1567.002",
        note="This was a scheduled backup, not C2.",
    )
    learning_session.commit()

    proposal = propose_exemplar(learning_session, tenant.id, fb, verdict)
    learning_session.commit()
    assert proposal is not None
    assert proposal.mechanism == 10

    result = accept_exemplar(learning_session, tenant.id, proposal, user_id=user.id)
    learning_session.commit()
    assert result.passed is True

    with tenant_scope(learning_session, tenant.id):
        entries = learning_session.execute(select(ExemplarBankEntry)).scalars().all()
    assert len(entries) == 1
    assert entries[0].error_mode == "technique_misattribution"


# --------------------------------------------------------------------------- mechanism 11


def test_mechanism_11_judge_rubric_item_proposed_after_cluster_of_dismissals() -> None:
    pass  # exercised end-to-end below, via record_feedback


def test_mechanism_11_rubric_evolution_end_to_end(
    learning_session: Session,  # noqa: F811
    learning_cleanup: list[uuid.UUID],  # noqa: F811
) -> None:
    tenant = make_tenant(name="Mechanism 11 Test Tenant")
    learning_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"m11-{uuid.uuid4()}@test.local")

    proposal = None
    for _ in range(3):
        incident, _verdict = _seed_incident(learning_session, tenant_id=tenant.id, user_id=user.id)
        learning_session.commit()
        outcome = record_feedback(
            learning_session,
            tenant.id,
            user_id=user.id,
            incident_id=incident.id,
            data=FeedbackInput(agrees=False, dismissal_reason="sanctioned_automation"),
        )
        learning_session.commit()
        if outcome.rubric_proposal is not None:
            proposal = outcome.rubric_proposal

    assert proposal is not None
    assert proposal.mechanism == 11
    assert proposal.payload["n_misses"] == 3

    result = accept_rubric_item(learning_session, tenant.id, proposal, user_id=user.id)
    learning_session.commit()
    assert result.passed is True
    assert "service account" in result.after_state["rubric_item"]


# --------------------------------------------------------------------------- mechanism 12


def test_mechanism_12_kb_enrichment_appends_evidence_that_weakens_on_accept(
    tmp_path,
    learning_session: Session,  # noqa: F811
    learning_cleanup: list[uuid.UUID],  # noqa: F811
) -> None:
    import shutil

    from app.learning.kb_enrichment import KB_TECHNIQUES_DIR

    techniques_dir = tmp_path / "techniques"
    shutil.copytree(KB_TECHNIQUES_DIR, techniques_dir)

    tenant = make_tenant(name="Mechanism 12 Test Tenant")
    learning_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"m12-{uuid.uuid4()}@test.local")

    proposal = None
    for _ in range(2):
        _incident, verdict = _seed_incident(
            learning_session, tenant_id=tenant.id, user_id=user.id, mitre_techniques=["T1071.001"]
        )
        learning_session.commit()
        fb = make_feedback(
            learning_session,
            verdict_id=verdict.id,
            user_id=user.id,
            agrees=False,
            dismissal_reason="known_business_process",
        )
        learning_session.commit()
        proposal = propose_kb_enrichment(
            learning_session, tenant.id, fb, verdict, techniques_dir=techniques_dir
        )
        learning_session.commit()

    assert proposal is not None
    assert proposal.mechanism == 12

    result = accept_kb_enrichment(
        learning_session, tenant.id, proposal, user_id=user.id, techniques_dir=techniques_dir
    )
    learning_session.commit()
    assert result.passed is True

    import yaml

    doc = yaml.safe_load((techniques_dir / "T1071.001.yml").read_text())
    assert "known_business_process" in doc["evidence_that_weakens"]


# --------------------------------------------------------------------------- mechanism 14


def test_mechanism_14_verifier_rule_proposed_from_clustered_claim_thumbs(
    learning_session: Session,  # noqa: F811
    learning_cleanup: list[uuid.UUID],  # noqa: F811
) -> None:
    tenant = make_tenant(name="Mechanism 14 Test Tenant")
    learning_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"m14-{uuid.uuid4()}@test.local")

    proposal = None
    for _ in range(3):
        incident, _verdict = _seed_incident(learning_session, tenant_id=tenant.id, user_id=user.id)
        learning_session.commit()
        claim = record_claim_feedback(
            learning_session,
            tenant.id,
            user_id=user.id,
            incident_id=incident.id,
            step=1,
            helpful=False,
            note="This claim swaps bytes_in and bytes_out for this host.",
        )
        learning_session.commit()
        p = propose_verifier_rule(learning_session, tenant.id, claim)
        if p is not None:
            proposal = p

    assert proposal is not None
    assert proposal.mechanism == 14
    assert proposal.payload["pattern"] == "bytes_in_out_confusion"


# --------------------------------------------------------------------------- mechanism 15


def test_mechanism_15_evidence_profile_widening_proposed_then_accepted(
    learning_session: Session,  # noqa: F811
    learning_cleanup: list[uuid.UUID],  # noqa: F811
) -> None:
    tenant = make_tenant(name="Mechanism 15 Test Tenant")
    learning_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"m15-{uuid.uuid4()}@test.local")
    incident, _verdict = _seed_incident(learning_session, tenant_id=tenant.id, user_id=user.id)
    learning_session.commit()

    for i in range(MIN_SAMPLES_TO_PROPOSE):
        record_evidence_relevance_toggle(
            learning_session,
            tenant.id,
            user_id=user.id,
            incident_id=incident.id,
            evidence_id=f"EVIDENCE-{i}",
            extractor="beaconing",
            relevant=False,
        )
        learning_session.commit()

    with tenant_scope(learning_session, tenant.id):
        state = learning_session.execute(select(EvidenceProfileState)).scalars().one()
    assert state.total_count == MIN_SAMPLES_TO_PROPOSE
    assert state.expand_count == MIN_SAMPLES_TO_PROPOSE
    assert state.widened is False

    with tenant_scope(learning_session, tenant.id):
        pending = (
            learning_session.execute(
                select(LearningProposal).where(LearningProposal.mechanism == 15)
            )
            .scalars()
            .one()
        )
    result = accept_evidence_profile_widening(learning_session, tenant.id, pending, user_id=user.id)
    learning_session.commit()
    assert result.passed is True

    with tenant_scope(learning_session, tenant.id):
        state = learning_session.execute(select(EvidenceProfileState)).scalars().one()
    assert state.widened is True


# --------------------------------------------------------------------------- gate rejection


def test_gated_candidate_regressing_a_metric_is_rejected_and_incumbent_stays_live(
    learning_session: Session,  # noqa: F811
    learning_cleanup: list[uuid.UUID],  # noqa: F811
) -> None:
    """change 21: "a candidate regressing precision, recall, hallucination rate or injection
    resistance is rejected and the incumbent stays live." Exercised on mechanism 8 (DGA
    retraining): seed a first promoted model, then a deliberately unlearnable (near-random)
    label set, and assert the second attempt is rejected and the first model_versions row stays
    the only *promoted* one.
    """
    tenant = make_tenant(name="Gate Rejection Test Tenant")
    learning_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"gate-reject-{uuid.uuid4()}@test.local")
    incident, verdict = _seed_incident(learning_session, tenant_id=tenant.id, user_id=user.id)
    learning_session.commit()
    fb = make_feedback(learning_session, verdict_id=verdict.id, user_id=user.id, agrees=True)
    learning_session.commit()

    model_key = f"{DGA_MODEL_KEY}.test.{uuid.uuid4().hex[:8]}"
    with tenant_scope(learning_session, tenant.id):
        learning_session.add(
            ModelVersion(
                model_key=model_key,
                version=1,
                artifact_ref="test/incumbent",
                trained_at=datetime.now(UTC),
                eval_scores={"disposition_accuracy": 0.99},
                promoted=True,
            )
        )
        learning_session.flush()
    learning_session.commit()

    # 20 distinct domains, same shape (same length/digit/vowel/entropy profile), labels assigned
    # with no relationship to that shape at all -- a logistic regression over exactly those four
    # features cannot separate them meaningfully better than chance.
    for i in range(20):
        record_dga_label_correction(
            learning_session,
            tenant.id,
            domain=f"abcdxyz{i:02d}.com",
            is_dga=bool((i * 7 + 3) % 2),
            feedback_id=fb.id,
            incident_id=incident.id,
        )
    learning_session.commit()

    proposal = propose_dga_retrain(
        learning_session, tenant.id, trigger_feedback_id=fb.id, model_key=model_key
    )
    learning_session.commit()
    assert proposal is not None

    result = accept_dga_retrain(learning_session, tenant.id, proposal, user_id=user.id)
    learning_session.commit()

    assert result.passed is False
    assert proposal.status == STATUS_REJECTED

    with tenant_scope(learning_session, tenant.id):
        versions = (
            learning_session.execute(
                select(ModelVersion).where(ModelVersion.model_key == model_key)
            )
            .scalars()
            .all()
        )
    promoted = [v for v in versions if v.promoted]
    assert len(promoted) == 1
    assert promoted[0].version == 1  # the incumbent -- rejection did not touch it

    # Rejection history retained: the learning_events row stays applied=False, not deleted.
    event = learning_session.get(LearningEvent, proposal.learning_event_id)
    assert event is not None
    assert event.applied is False
    assert event.after_state["status"] == "rejected"
