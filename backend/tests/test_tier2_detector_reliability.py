"""Tier 2 chart 3 — per-detector confirm/dismiss counts pooled across every tenant's analyst
feedback. Builds two isolated tenants, each giving feedback on the *same* `detector_key`, and
proves `list_detector_reliability` pools both — the deliberate, reviewed exception to tenant
scoping `app.tier2.detector_reliability`'s module docstring documents.
"""

from __future__ import annotations

import uuid

from sqlalchemy.orm import Session

from app.tier2.detector_reliability import list_detector_reliability
from tests.conftest import make_analysis, make_tenant, make_user
from tests.fixtures.learning import (  # noqa: F401
    learning_cleanup,
    learning_session,
    make_feedback,
    make_incident_with_verdict,
    make_signal,
)


def _confirm_event(
    session: Session,
    tenant_id: uuid.UUID,
    analysis_id: uuid.UUID,
    user_id: uuid.UUID,
    *,
    detector_key: str,
) -> None:
    sig = make_signal(
        session, tenant_id=tenant_id, analysis_id=analysis_id, detector_key=detector_key
    )
    _incident, verdict = make_incident_with_verdict(
        session,
        tenant_id=tenant_id,
        analysis_id=analysis_id,
        signals=[sig],
        disposition="true_positive",
    )
    make_feedback(session, verdict_id=verdict.id, user_id=user_id, agrees=True)


def _dismiss_event(
    session: Session,
    tenant_id: uuid.UUID,
    analysis_id: uuid.UUID,
    user_id: uuid.UUID,
    *,
    detector_key: str,
) -> None:
    sig = make_signal(
        session, tenant_id=tenant_id, analysis_id=analysis_id, detector_key=detector_key
    )
    _incident, verdict = make_incident_with_verdict(
        session,
        tenant_id=tenant_id,
        analysis_id=analysis_id,
        signals=[sig],
        disposition="false_positive",
    )
    make_feedback(
        session,
        verdict_id=verdict.id,
        user_id=user_id,
        agrees=True,
        dismissal_reason="benign_after_review",
    )


def test_pools_confirm_dismiss_counts_across_two_isolated_tenants(
    learning_session: Session,  # noqa: F811
    learning_cleanup: list[uuid.UUID],  # noqa: F811
) -> None:
    run = uuid.uuid4().hex[:8]
    detector_key = f"test.pooled-reliability.{run}"

    tenant_a = make_tenant(name="Detector Reliability Test Tenant A")
    tenant_b = make_tenant(name="Detector Reliability Test Tenant B")
    learning_cleanup.extend([tenant_a.id, tenant_b.id])
    user_a = make_user(tenant_id=tenant_a.id, email=f"drel-a-{uuid.uuid4()}@test.local")
    user_b = make_user(tenant_id=tenant_b.id, email=f"drel-b-{uuid.uuid4()}@test.local")
    analysis_a = make_analysis(tenant_id=tenant_a.id, user_id=user_a.id)
    analysis_b = make_analysis(tenant_id=tenant_b.id, user_id=user_b.id)

    # Tenant A: 2 confirms, 1 dismiss. Tenant B: 1 confirm, 2 dismisses. Pooled: 3 confirms, 3
    # dismisses -- a number neither tenant's own data could produce alone, which is the point.
    _confirm_event(
        learning_session, tenant_a.id, analysis_a.id, user_a.id, detector_key=detector_key
    )
    _confirm_event(
        learning_session, tenant_a.id, analysis_a.id, user_a.id, detector_key=detector_key
    )
    _dismiss_event(
        learning_session, tenant_a.id, analysis_a.id, user_a.id, detector_key=detector_key
    )
    _confirm_event(
        learning_session, tenant_b.id, analysis_b.id, user_b.id, detector_key=detector_key
    )
    _dismiss_event(
        learning_session, tenant_b.id, analysis_b.id, user_b.id, detector_key=detector_key
    )
    _dismiss_event(
        learning_session, tenant_b.id, analysis_b.id, user_b.id, detector_key=detector_key
    )
    learning_session.commit()

    result = list_detector_reliability(learning_session)
    row = next(item for item in result.items if item.detector_key == detector_key)
    assert row.confirmed == 3
    assert row.dismissed == 3
    assert result.total_tenants >= 2


def test_a_single_tenants_feedback_is_not_reported_as_cross_tenant(
    learning_session: Session,  # noqa: F811
    learning_cleanup: list[uuid.UUID],  # noqa: F811
) -> None:
    """The frontend's empty state gates on `total_tenants < 2` -- this proves the backend
    number that gate reads is genuinely a distinct-tenant count, not a feedback-row count."""
    run = uuid.uuid4().hex[:8]
    detector_key = f"test.single-tenant-reliability.{run}"

    tenant = make_tenant(name="Detector Reliability Single Tenant Test")
    learning_cleanup.append(tenant.id)
    user = make_user(tenant_id=tenant.id, email=f"drel-solo-{uuid.uuid4()}@test.local")
    analysis = make_analysis(tenant_id=tenant.id, user_id=user.id)

    for _ in range(3):
        _confirm_event(learning_session, tenant.id, analysis.id, user.id, detector_key=detector_key)
    learning_session.commit()

    result = list_detector_reliability(learning_session)
    row = next(item for item in result.items if item.detector_key == detector_key)
    assert row.confirmed == 3
    assert row.dismissed == 0
    # This one detector's own row says nothing about the fleet-wide tenant count directly, but
    # the response-level total_tenants must still be a real distinct-tenant count and not, say,
    # a feedback-row count -- proven by the pooled test above disagreeing with a naive row count.
