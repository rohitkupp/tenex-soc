"""`app.learning.memory` — consumer 3, "Agent few-shot memory" (docs/08 Part 2, §3)."""

from __future__ import annotations

import uuid

from sqlalchemy.orm import Session

from app.learning.memory import (
    get_prior_analyst_decisions_for_incident,
    render_prior_analyst_decisions_block,
    retrieve_prior_analyst_decisions,
)
from tests.conftest import make_analysis, make_tenant, make_user
from tests.fixtures.learning import (  # noqa: F401
    learning_cleanup,
    learning_session,
    make_feedback,
    make_incident_with_verdict,
    make_signal,
    unit_embedding,
)


def test_retrieve_returns_nearest_confirmed_incidents_first(
    learning_session: Session,  # noqa: F811
    learning_cleanup: list[uuid.UUID],  # noqa: F811
) -> None:
    tenant = make_tenant(name="Memory Retrieval Test Tenant")
    learning_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"memory-{uuid.uuid4()}@test.local")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)

    def _confirmed_incident(cluster: str, reason: str) -> uuid.UUID:
        sig = make_signal(learning_session, tenant_id=tenant.id, analysis_id=analysis.id)
        incident, verdict = make_incident_with_verdict(
            learning_session,
            tenant_id=tenant.id,
            analysis_id=analysis.id,
            signals=[sig],
            disposition="false_positive",
            embedding=unit_embedding(cluster),
        )
        make_feedback(
            learning_session,
            verdict_id=verdict.id,
            user_id=user.id,
            agrees=True,
            dismissal_reason=reason,
        )
        return incident.id

    near_a = _confirmed_incident("backup-jobs", "Sanctioned nightly backup to corporate S3 bucket.")
    near_b = _confirmed_incident("backup-jobs", "Same backup job, different night.")
    near_c = _confirmed_incident("backup-jobs", "Third instance of the same backup job.")
    far = _confirmed_incident("unrelated-c2-beacon", "Confirmed malicious beacon, unrelated.")
    learning_session.commit()

    decisions = retrieve_prior_analyst_decisions(
        learning_session,
        tenant_id=tenant.id,
        query_embedding=unit_embedding("backup-jobs"),
        k=3,
    )

    assert len(decisions) == 3
    returned_ids = {d.incident_id for d in decisions}
    assert returned_ids == {near_a, near_b, near_c}
    assert far not in returned_ids
    # Nearest first.
    assert decisions[0].similarity >= decisions[1].similarity >= decisions[2].similarity
    for d in decisions:
        assert d.disposition == "false_positive"
        assert "backup" in d.reason.lower()


def test_retrieve_excludes_incidents_with_no_feedback(
    learning_session: Session,  # noqa: F811
    learning_cleanup: list[uuid.UUID],  # noqa: F811
) -> None:
    tenant = make_tenant(name="Memory No Feedback Test Tenant")
    learning_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"memory-nofb-{uuid.uuid4()}@test.local")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)

    # An incident with an embedding but *no* analyst feedback -- must never surface as a "prior
    # analyst decision" since there is no decision recorded on it yet.
    sig = make_signal(learning_session, tenant_id=tenant.id, analysis_id=analysis.id)
    make_incident_with_verdict(
        learning_session,
        tenant_id=tenant.id,
        analysis_id=analysis.id,
        signals=[sig],
        embedding=unit_embedding("no-feedback-cluster"),
    )
    learning_session.commit()

    decisions = retrieve_prior_analyst_decisions(
        learning_session,
        tenant_id=tenant.id,
        query_embedding=unit_embedding("no-feedback-cluster"),
        k=3,
    )
    assert decisions == []


def test_get_prior_analyst_decisions_for_incident_excludes_itself(
    learning_session: Session,  # noqa: F811
    learning_cleanup: list[uuid.UUID],  # noqa: F811
) -> None:
    tenant = make_tenant(name="Memory Self Exclusion Test Tenant")
    learning_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"memory-self-{uuid.uuid4()}@test.local")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)

    sig1 = make_signal(learning_session, tenant_id=tenant.id, analysis_id=analysis.id)
    incident1, verdict1 = make_incident_with_verdict(
        learning_session,
        tenant_id=tenant.id,
        analysis_id=analysis.id,
        signals=[sig1],
        disposition="true_positive",
        embedding=unit_embedding("self-exclusion-cluster"),
    )
    make_feedback(learning_session, verdict_id=verdict1.id, user_id=user.id, agrees=True)

    sig2 = make_signal(learning_session, tenant_id=tenant.id, analysis_id=analysis.id)
    incident2, verdict2 = make_incident_with_verdict(
        learning_session,
        tenant_id=tenant.id,
        analysis_id=analysis.id,
        signals=[sig2],
        disposition="true_positive",
        embedding=unit_embedding("self-exclusion-cluster"),
    )
    make_feedback(learning_session, verdict_id=verdict2.id, user_id=user.id, agrees=True)
    learning_session.commit()

    decisions = get_prior_analyst_decisions_for_incident(
        learning_session, tenant_id=tenant.id, incident_id=incident1.id, k=3
    )
    assert len(decisions) == 1
    assert decisions[0].incident_id == incident2.id


def test_get_prior_analyst_decisions_returns_empty_for_incident_without_embedding(
    learning_session: Session,  # noqa: F811
    learning_cleanup: list[uuid.UUID],  # noqa: F811
) -> None:
    tenant = make_tenant(name="Memory No Embedding Test Tenant")
    learning_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"memory-noembed-{uuid.uuid4()}@test.local")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)

    sig = make_signal(learning_session, tenant_id=tenant.id, analysis_id=analysis.id)
    incident, verdict = make_incident_with_verdict(
        learning_session,
        tenant_id=tenant.id,
        analysis_id=analysis.id,
        signals=[sig],
        embedding=None,
    )
    make_feedback(learning_session, verdict_id=verdict.id, user_id=user.id, agrees=True)
    learning_session.commit()

    decisions = get_prior_analyst_decisions_for_incident(
        learning_session, tenant_id=tenant.id, incident_id=incident.id
    )
    assert decisions == []


def test_render_prior_analyst_decisions_block_matches_docs08_format(
    learning_session: Session,  # noqa: F811
    learning_cleanup: list[uuid.UUID],  # noqa: F811
) -> None:
    tenant = make_tenant(name="Memory Render Test Tenant")
    learning_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"memory-render-{uuid.uuid4()}@test.local")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)

    sig = make_signal(learning_session, tenant_id=tenant.id, analysis_id=analysis.id)
    _incident, verdict = make_incident_with_verdict(
        learning_session,
        tenant_id=tenant.id,
        analysis_id=analysis.id,
        signals=[sig],
        disposition="false_positive",
        embedding=unit_embedding("render-cluster"),
    )
    make_feedback(
        learning_session,
        verdict_id=verdict.id,
        user_id=user.id,
        agrees=True,
        dismissal_reason="Sanctioned nightly backup to corporate S3 bucket.",
    )
    learning_session.commit()

    decisions = retrieve_prior_analyst_decisions(
        learning_session, tenant_id=tenant.id, query_embedding=unit_embedding("render-cluster"), k=1
    )
    block = render_prior_analyst_decisions_block(decisions)
    assert block.startswith("<prior_analyst_decisions>\n")
    assert block.endswith("\n</prior_analyst_decisions>")
    assert "analyst disposition: false_positive" in block
    assert 'Reason: "Sanctioned nightly backup to corporate S3 bucket."' in block


def test_render_prior_analyst_decisions_block_empty_list_still_wraps() -> None:
    block = render_prior_analyst_decisions_block([])
    assert block == "<prior_analyst_decisions>\n</prior_analyst_decisions>"
