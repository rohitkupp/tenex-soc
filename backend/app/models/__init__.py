"""Importing this package registers every ORM model on `Base.metadata`, which is what
`alembic/env.py` relies on for autogeneration. M1 shipped Core only (docs/02); `events`
(M3, app/models/event.py) and `dead_letters` (M4, app/models/dead_letter.py) followed.
This module adds the rest of docs/02 verbatim: detection (`signals`), graph & incidents
(`entities`, `entity_edges`, `incidents`), triage (`triage_verdicts`),
learning (`analyst_feedback`, `detector_stats`, `model_versions`), and ops/eval
(`tier2_signatures`, `eval_runs`). M13 (`app/learning`) adds three tables of its own that sit
outside docs/02's literal SQL -- `suppression_candidates`, `benign_baseline_entries`, and
`learning_synthetic_seed` -- see each model's own docstring for why they exist and why they are
additive rather than changes to an existing table.

`response_plans`, `enforcement_state`, and `enforcement_journal` (the response action graph and
simulated enforcement plane) were removed in docs/v2_migration change 20 -- see the migration
alembic revision for the drop, and docs/08-RESPONSE-AND-LEARNING.md, Part 1 (deleted).

docs/v2_migration change 1 ("Historical baseline store") adds `baseline_windows`,
`baseline_profiles`, and `baseline_contacts` -- the persistent per-tenant history every
percentile and rarity lookup resolves against from here on, never the uploaded file. Loaded by
`app.baseline.loader`, queried by `app.baseline.resolve`; see `app/models/baseline_window.py`
for why none of the three carry a `tenants` FK.

docs/v2_migration change 21 ("Continuous learning") adds `learning_events` (the ledger, matched
verbatim to the task brief's schema) plus eight small supporting tables the 15 mechanisms need
and docs/02 does not define: `entity_threshold_overrides` (3), `reference_set_exclusions` (5),
`entity_cohorts` (7), `dga_label_feedback` (8), `exemplar_bank_entries` (10),
`retrieval_priors` (13), `evidence_profile_state` (15), and `learning_proposals` (the shared
staging table for every gated mechanism's propose/approve/reject cycle). See each model's own
docstring and `app/learning/mechanisms.py` for the full 1-15 mapping."""

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
from app.models.baseline_contact import BaselineContact
from app.models.baseline_profile import BaselineProfile
from app.models.baseline_window import BaselineWindow
from app.models.benign_baseline_entry import BenignBaselineEntry
from app.models.claim_feedback import ClaimFeedback
from app.models.dead_letter import DeadLetter
from app.models.detector_stats import DetectorStats
from app.models.dga_label_feedback import DgaLabelFeedback
from app.models.entity import Entity
from app.models.entity_cohort import EntityCohort
from app.models.entity_edge import EntityEdge
from app.models.entity_threshold_override import ALL_DETECTORS, EntityThresholdOverride
from app.models.eval_run import EvalRun
from app.models.event import Event
from app.models.evidence_profile_state import EvidenceProfileState
from app.models.evidence_relevance_feedback import EvidenceRelevanceFeedback
from app.models.exemplar_bank_entry import ExemplarBankEntry
from app.models.incident import Incident
from app.models.learning_event import LearningEvent
from app.models.learning_proposal import (
    STATUS_APPROVED,
    STATUS_PENDING,
    STATUS_REJECTED,
    LearningProposal,
)
from app.models.model_version import ModelVersion
from app.models.reference_set_exclusion import ReferenceSetExclusion
from app.models.retrieval_prior import RetrievalPrior
from app.models.signal import Signal
from app.models.suppression_candidate import SuppressionCandidate
from app.models.synthetic_seed_marker import SyntheticSeedMarker
from app.models.tenant import LIVE_TENANT_NAME, Tenant, get_or_create_live_tenant
from app.models.tier2_signature import Tier2Signature
from app.models.triage_verdict import TriageVerdict
from app.models.upload import Upload
from app.models.user import User

__all__ = [
    "ALL_DETECTORS",
    "LIVE_TENANT_NAME",
    "STATUS_APPROVED",
    "STATUS_PENDING",
    "STATUS_REJECTED",
    "Analysis",
    "AnalystFeedback",
    "BaselineContact",
    "BaselineProfile",
    "BaselineWindow",
    "BenignBaselineEntry",
    "ClaimFeedback",
    "DeadLetter",
    "DetectorStats",
    "DgaLabelFeedback",
    "Entity",
    "EntityCohort",
    "EntityEdge",
    "EntityThresholdOverride",
    "EvalRun",
    "Event",
    "EvidenceProfileState",
    "EvidenceRelevanceFeedback",
    "ExemplarBankEntry",
    "Incident",
    "LearningEvent",
    "LearningProposal",
    "MissingTenantScopeError",
    "ModelVersion",
    "ReferenceSetExclusion",
    "RetrievalPrior",
    "Signal",
    "SuppressionCandidate",
    "SyntheticSeedMarker",
    "Tenant",
    "TenantScopedMixin",
    "Tier2Signature",
    "TriageVerdict",
    "Upload",
    "User",
    "bypass_tenant_scope",
    "get_or_create_live_tenant",
    "tenant_scope",
    "tenant_session",
]
