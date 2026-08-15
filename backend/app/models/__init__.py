"""Importing this package registers every ORM model on `Base.metadata`, which is what
`alembic/env.py` relies on for autogeneration. M1 shipped Core only (docs/02); `events`
(M3, app/models/event.py) and `dead_letters` (M4, app/models/dead_letter.py) followed.
This module adds the rest of docs/02 verbatim: detection (`signals`), graph & incidents
(`entities`, `entity_edges`, `incidents`), triage & response (`triage_verdicts`,
`response_plans`), the enforcement plane (`enforcement_state`, `enforcement_journal`),
learning (`analyst_feedback`, `detector_stats`, `model_versions`), and ops/eval
(`tier2_signatures`, `eval_runs`)."""

from __future__ import annotations

from app.models.analysis import Analysis
from app.models.analyst_feedback import AnalystFeedback
from app.models.base import (
    MissingTenantScopeError,
    TenantScopedMixin,
    bypass_tenant_scope,
    tenant_scope,
    tenant_session,
)
from app.models.dead_letter import DeadLetter
from app.models.detector_stats import DetectorStats
from app.models.enforcement_journal import EnforcementJournal
from app.models.enforcement_state import EnforcementState
from app.models.entity import Entity
from app.models.entity_edge import EntityEdge
from app.models.eval_run import EvalRun
from app.models.event import Event
from app.models.incident import Incident
from app.models.model_version import ModelVersion
from app.models.response_plan import ResponsePlan
from app.models.signal import Signal
from app.models.tenant import Tenant
from app.models.tier2_signature import Tier2Signature
from app.models.triage_verdict import TriageVerdict
from app.models.upload import Upload
from app.models.user import User

__all__ = [
    "Analysis",
    "AnalystFeedback",
    "DeadLetter",
    "DetectorStats",
    "EnforcementJournal",
    "EnforcementState",
    "Entity",
    "EntityEdge",
    "EvalRun",
    "Event",
    "Incident",
    "MissingTenantScopeError",
    "ModelVersion",
    "ResponsePlan",
    "Signal",
    "Tenant",
    "TenantScopedMixin",
    "Tier2Signature",
    "TriageVerdict",
    "Upload",
    "User",
    "bypass_tenant_scope",
    "tenant_scope",
    "tenant_session",
]
