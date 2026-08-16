"""Pydantic v2 schemas for changes 8, 9, 10 and 14 Path A (docs/v2_migration/MIGRATION-01-
evidence-first.md):

    GET  /api/analyses/{id}/overview   change 9's deterministic log overview, always produced,
                                        plus notable users / notable destinations (change 9) and
                                        change 8's (not-yet-wired, see below) semantic findings
    POST /api/analyses/{id}/narrate    change 14 Path A — the Narrator LLM call, wired here for
                                        the first time (`app.agent.orchestrator.narrate_analysis`
                                        exists and is unit-tested, but nothing before this called
                                        it from an API surface — its own module docstring: "wiring
                                        this into `analyses`/an API response is out of `app/agent`'s
                                        ownership")

Both routes live in `app.api.analyses`. Split into two routes, not one, on purpose:

- `GET /overview` is pure SQL + deterministic composition (CLAUDE.md rule 1: "do not ask a model
  to count 83,241 rows") — cheap, idempotent, safe to call on every page load, and correct even
  mid-run or for an analysis with zero incidents (change 9: "on every upload, whether or not
  anything is flagged").
- `POST /narrate` costs a real LLM call (change 12: "cost is real per upload"). Unlike
  `POST /api/incidents/{id}/triage`, this cannot be made idempotent-by-persistence — `app.agent.
  orchestrator.NarrationResult` is explicitly "not persisted to any table by this module" (no
  schema for one exists; adding one is `app/models`' call, out of this milestone's ownership
  boundary). Keeping it a distinct, explicit POST — mirroring the triage endpoints' own POST-not-
  GET shape for the same cost reason — means the expensive call only fires when an analyst (or
  the frontend, once, on first render) actually asks for a narrative, not on every dashboard
  refresh. A future milestone that owns `app/models` should add a persistence column and make
  this idempotent the same way triage already is; until then, callers are responsible for not
  re-requesting it needlessly.
"""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import Any, Final, Literal

from pydantic import BaseModel, ConfigDict

__all__ = [
    "ML_ANOMALY_LABEL",
    "SEMANTIC_INSIGHT_LABEL",
    "AnalysisNarrateResponse",
    "AnalysisOverviewResponse",
    "BaselineComparisonOut",
    "DomainSemanticFinding",
    "LogOverview",
    "NotableDestination",
    "NotableUser",
    "PeriodicityOut",
]


class LogOverview(BaseModel):
    """change 9's JSON shape, verbatim field-for-field:

        { "period": [...], "events": 83241, "users": 127, "src_ips": 139,
          "unique_domains": 4921, "allowed": 78201, "blocked": 5040,
          "bytes_out": ..., "bytes_in": ..., "parse_failure_rate": 0.0021 }

    `period_start`/`period_end` replace the doc's `period: [start, end]` pair (Pydantic has no
    tuple-as-array-of-two convenience over JSON that's nicer than two named fields; the wire
    array shape is illustrative, this is the same information). Both are `None` only when the
    analysis has zero events — an empty file is a valid, reportable overview, not an error.
    """

    model_config = ConfigDict(frozen=True)

    period_start: datetime | None
    period_end: datetime | None
    events: int
    users: int
    src_ips: int
    unique_domains: int
    allowed: int
    blocked: int
    bytes_out: int
    bytes_in: int
    parse_failure_rate: float | None


class BaselineComparisonOut(BaseModel):
    """`app.baseline.resolve.PercentileResult`, serialised. Cold start must stay visible
    (CLAUDE.md: "a percentile from four windows must not look like one from six months") —
    `percentile` is `None` and `baseline_status == "insufficient_history"` together whenever
    `n_windows` is too thin to trust, exactly as `app.baseline.resolve.percentile_for` already
    guarantees; this schema does not add a second way to hide that."""

    model_config = ConfigDict(frozen=True)

    metric: str
    value: float
    baseline_status: Literal["ok", "insufficient_history"]
    n_windows: int
    percentile: float | None
    p50: float | None
    p95: float | None
    p99: float | None


class NotableUser(BaseModel):
    """change 9: "notable users (anomalous windows, volume vs. baseline, first-seen domain
    count, top anomaly score)". Computed deterministically in `app.api.analyses` from `entities`,
    `signals`, `entity_edges` and the baseline store (`app.baseline.resolve`) — no LLM
    involvement, see this module's own docstring on why `GET /overview` is a plain SQL route."""

    model_config = ConfigDict(frozen=True)

    value: str
    # Distinct detector windows (`signals.window_start`) in this analysis where this user's
    # signal confidence exceeded `app.api.analyses.ANOMALOUS_WINDOW_CONFIDENCE_THRESHOLD`.
    anomalous_windows: int
    volume_vs_baseline: BaselineComparisonOut
    # Domains this user contacted in this analysis that `app.baseline.resolve.contact_counts`
    # reports as a first contact at user scope (`ScopeContactCount.is_first_contact`) — "zero
    # for Alice" made countable.
    first_seen_domain_count: int
    # MAX(signals.confidence) across every signal naming this user as its entity, this analysis.
    # `None` when the user has no signal at all (still notable enough to be listed by volume).
    top_anomaly_score: float | None


class PeriodicityOut(BaseModel):
    model_config = ConfigDict(frozen=True)

    dominant_period_s: float
    spectral_strength: float


class NotableDestination(BaseModel):
    """change 9: "notable destinations (first-observed flag, distinct users, DGA score,
    connection count, periodicity)"."""

    model_config = ConfigDict(frozen=True)

    value: str
    # `app.baseline.resolve.contact_counts(...).org.is_first_contact` — never contacted by this
    # tenant's baseline before, org-wide.
    first_observed: bool
    # Distinct users this analysis connects to this domain via an `accessed` entity edge.
    distinct_users: int
    # The DGA classifier's own probability (`signal.dga`'s `explanation["score"]`, `app.
    # detection.evidence.dga`) — this is `ML_ANOMALY_LABEL` territory, never relabelled here.
    # `None` when no `signal.dga` fired for this domain in this analysis.
    dga_score: float | None
    connection_count: int
    # `signal.beaconing`'s own `dominant_period_s`/`spectral_strength`
    # (`app.detection.evidence.beaconing`), when a beaconing signal named this domain. `None`
    # when it did not.
    periodicity: PeriodicityOut | None


# change 8: "findings from this pass are labelled differently in the UI, and this is not
# cosmetic ... never let a semantic judgement inherit the statistical backing of a calibrated
# classifier." Both labels are exported as constants specifically so nothing in this codebase
# can construct a semantic finding carrying the ML label by a typo — `DomainSemanticFinding.
# label` below is additionally pinned to a `Literal` of exactly `SEMANTIC_INSIGHT_LABEL`, making
# the mistake this change exists to prevent a type error, not a code-review nit.
ML_ANOMALY_LABEL: Final = "ML anomaly — high confidence"
SEMANTIC_INSIGHT_LABEL: Final = "Analyst insight — requires validation"


class DomainSemanticFinding(BaseModel):
    """change 8's LLM semantic domain-analysis pass: brand impersonation, typosquatting intent,
    and contextual relevance for destinations flagged rare or first-seen — the half the DGA
    classifier's lexical-randomness model cannot catch (`microsoft-security-login-support.com`
    is linguistically ordinary).

    **Not produced by this endpoint.** The judgement itself is an LLM call, and every LLM call
    in this codebase lives in `app/agent` (prompts, verifier, citation infrastructure) — building
    a second, parallel LLM call site inside `app/api` would duplicate that infrastructure outside
    the module that owns it, which is exactly what the milestone's package boundaries (`app/api`,
    `app/schemas` only) are meant to prevent. This schema is change 8's plumbing on this side of
    that boundary: `AnalysisOverviewResponse.domain_semantic_findings` always returns `[]` today.
    Once an `app/agent` owner adds the semantic pass, wiring it in is exactly "populate this
    field from that call's output" — the `Literal` on `label` already makes mislabelling it as
    `ML_ANOMALY_LABEL` a type error, not a future code-review nit, and the frontend badge
    component already renders whichever label this schema sends.
    """

    model_config = ConfigDict(frozen=True)

    domain: str
    label: Literal["Analyst insight — requires validation"] = SEMANTIC_INSIGHT_LABEL
    assessment: str
    rationale: str
    evidence_id: str | None = None


class AnalysisOverviewResponse(BaseModel):
    """`GET /api/analyses/{id}/overview` — change 10 Level 1 ("what happened"): overview stats +
    executive summary + anomaly count. `executive_summary` is always `null` here — see this
    module's own docstring for why the Narrator call is a separate `POST /narrate`, not inlined
    into this GET."""

    overview: LogOverview
    anomaly_count: int
    notable_users: list[NotableUser]
    notable_destinations: list[NotableDestination]
    domain_semantic_findings: list[DomainSemanticFinding]


class AnalysisNarrateResponse(BaseModel):
    """`POST /api/analyses/{id}/narrate` — `app.agent.orchestrator.NarrationResult`, serialised.
    Not persisted (see module docstring); every call re-runs the Narrator and re-spends."""

    executive_summary: str
    phase_narratives: list[dict[str, Any]]
    citation_valid: bool
    invalid_citations: list[dict[str, Any]]
    model: str
    tokens_in: int
    tokens_out: int
    cost_usd: Decimal
    latency_ms: int
