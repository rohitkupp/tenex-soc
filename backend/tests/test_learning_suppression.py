"""`app.learning.suppression` — consumer 4, "Suppression rule generation" (docs/08 Part 2, §4).

docs/08 is explicit that this consumer must never auto-apply. The load-bearing assertion in this
file is `test_generate_suppression_candidates_never_writes_to_the_suppressions_directory`: it
proves the generator's only effect is a `suppression_candidates` row, never a file on disk.
"""

from __future__ import annotations

import uuid
from pathlib import Path

import yaml
from sqlalchemy.orm import Session

from app.detection.sigma.rule import load_rule_file
from app.detection.sigma.runner import SUPPRESSIONS_DIR
from app.learning.suppression import generate_suppression_candidates
from app.models.suppression_candidate import STATUS_PENDING, SuppressionCandidate
from tests.conftest import make_analysis, make_tenant, make_user
from tests.fixtures.learning import (  # noqa: F401
    learning_cleanup,
    learning_session,
    make_feedback,
    make_incident_with_verdict,
    make_signal,
)


def test_generate_suppression_candidates_requires_a_dismissal_reason(
    learning_session: Session,  # noqa: F811
    learning_cleanup: list[uuid.UUID],  # noqa: F811
) -> None:
    tenant = make_tenant(name="Suppression No Reason Test Tenant")
    learning_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"suppress-noreason-{uuid.uuid4()}@test.local")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)

    sig = make_signal(learning_session, tenant_id=tenant.id, analysis_id=analysis.id)
    _incident, verdict = make_incident_with_verdict(
        learning_session, tenant_id=tenant.id, analysis_id=analysis.id, signals=[sig]
    )
    feedback = make_feedback(
        learning_session, verdict_id=verdict.id, user_id=user.id, agrees=False
    )  # no dismissal_reason
    learning_session.commit()

    candidates = generate_suppression_candidates(learning_session, tenant.id, feedback)
    assert candidates == []


def test_generate_suppression_candidates_one_per_distinct_detector_entity(
    learning_session: Session,  # noqa: F811
    learning_cleanup: list[uuid.UUID],  # noqa: F811
) -> None:
    tenant = make_tenant(name="Suppression Multi Detector Test Tenant")
    learning_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"suppress-multi-{uuid.uuid4()}@test.local")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)

    sig_a = make_signal(
        learning_session,
        tenant_id=tenant.id,
        analysis_id=analysis.id,
        detector_key="sigma.non_browser_user_agent",
        entity_type="src_ip",
        entity_value="10.10.5.5",
        mitre_technique="T1105",
    )
    sig_b = make_signal(
        learning_session,
        tenant_id=tenant.id,
        analysis_id=analysis.id,
        detector_key="sigma.large_post_to_new_domain",
        entity_type="src_ip",
        entity_value="10.10.5.5",
        mitre_technique="T1567",
    )
    _incident, verdict = make_incident_with_verdict(
        learning_session, tenant_id=tenant.id, analysis_id=analysis.id, signals=[sig_a, sig_b]
    )
    feedback = make_feedback(
        learning_session,
        verdict_id=verdict.id,
        user_id=user.id,
        agrees=False,
        dismissal_reason="known sanctioned backup job",
    )
    learning_session.commit()

    candidates = generate_suppression_candidates(learning_session, tenant.id, feedback)
    assert len(candidates) == 2
    detector_keys = {c.detector_key for c in candidates}
    assert detector_keys == {"sigma.non_browser_user_agent", "sigma.large_post_to_new_domain"}
    for c in candidates:
        assert c.entity_type == "src_ip"
        assert c.entity_value == "10.10.5.5"
        assert c.status == STATUS_PENDING
        assert c.reason == "known sanctioned backup job"
        assert c.synthetic is False


def test_generate_suppression_candidates_reuses_existing_pending_candidate(
    learning_session: Session,  # noqa: F811
    learning_cleanup: list[uuid.UUID],  # noqa: F811
) -> None:
    tenant = make_tenant(name="Suppression Reuse Test Tenant")
    learning_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"suppress-reuse-{uuid.uuid4()}@test.local")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)

    def _dismiss_once() -> list[SuppressionCandidate]:
        sig = make_signal(
            learning_session,
            tenant_id=tenant.id,
            analysis_id=analysis.id,
            detector_key="sigma.non_browser_user_agent",
            entity_type="src_ip",
            entity_value="10.10.5.5",
        )
        _incident, verdict = make_incident_with_verdict(
            learning_session, tenant_id=tenant.id, analysis_id=analysis.id, signals=[sig]
        )
        fb = make_feedback(
            learning_session,
            verdict_id=verdict.id,
            user_id=user.id,
            agrees=False,
            dismissal_reason="known sanctioned backup job, again",
        )
        learning_session.commit()
        return generate_suppression_candidates(learning_session, tenant.id, fb)

    first = _dismiss_once()
    second = _dismiss_once()
    assert len(first) == 1
    assert len(second) == 1
    assert first[0].id == second[0].id  # same pending candidate reused, not duplicated


def test_generated_rule_yaml_round_trips_through_the_real_sigma_loader(
    learning_session: Session,  # noqa: F811
    learning_cleanup: list[uuid.UUID],  # noqa: F811
    tmp_path: Path,
) -> None:
    """The generated candidate must actually be a well-formed Sigma rule (the same schema
    `app.detection.sigma.rule.load_rule_file` parses) *before* any human ever accepts it -- this
    test writes the candidate's `rule_yaml` to a throwaway path (not `SUPPRESSIONS_DIR`) purely
    to validate it parses, proving structural correctness without touching the real suppressions
    directory."""
    tenant = make_tenant(name="Suppression YAML Test Tenant")
    learning_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"suppress-yaml-{uuid.uuid4()}@test.local")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)

    sig = make_signal(
        learning_session,
        tenant_id=tenant.id,
        analysis_id=analysis.id,
        detector_key="signal.beaconing",
        entity_type="domain",
        entity_value="xk3f42.example-cdn.net",
        mitre_technique="T1071.001",
    )
    _incident, verdict = make_incident_with_verdict(
        learning_session, tenant_id=tenant.id, analysis_id=analysis.id, signals=[sig]
    )
    feedback = make_feedback(
        learning_session,
        verdict_id=verdict.id,
        user_id=user.id,
        agrees=False,
        dismissal_reason="vendor CDN, already allowlisted upstream",
    )
    learning_session.commit()

    candidates = generate_suppression_candidates(learning_session, tenant.id, feedback)
    assert len(candidates) == 1
    candidate = candidates[0]

    parsed = yaml.safe_load(candidate.rule_yaml)
    assert parsed["applies_to"] == ["signal.beaconing"]

    path = tmp_path / f"{parsed['id']}.yml"
    path.write_text(candidate.rule_yaml, encoding="utf-8")
    rule = load_rule_file(path)  # raises RuleLoadError if malformed
    assert rule.entity.type == "domain"
    assert rule.entity.by == "domain"


def test_generate_suppression_candidates_never_writes_to_the_suppressions_directory(
    learning_session: Session,  # noqa: F811
    learning_cleanup: list[uuid.UUID],  # noqa: F811
) -> None:
    """docs/08: "Never auto-apply." The only assertion that actually matters in this file --
    generating candidates must never touch the real filesystem location detection reads from."""
    tenant = make_tenant(name="Suppression No Auto Apply Test Tenant")
    learning_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"suppress-noauto-{uuid.uuid4()}@test.local")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)

    before = set(SUPPRESSIONS_DIR.glob("*.yml"))

    sig = make_signal(learning_session, tenant_id=tenant.id, analysis_id=analysis.id)
    _incident, verdict = make_incident_with_verdict(
        learning_session, tenant_id=tenant.id, analysis_id=analysis.id, signals=[sig]
    )
    feedback = make_feedback(
        learning_session,
        verdict_id=verdict.id,
        user_id=user.id,
        agrees=False,
        dismissal_reason="should never touch disk",
    )
    learning_session.commit()
    candidates = generate_suppression_candidates(learning_session, tenant.id, feedback)
    assert len(candidates) == 1

    after = set(SUPPRESSIONS_DIR.glob("*.yml"))
    assert before == after, "generating a candidate must never write a file to SUPPRESSIONS_DIR"
