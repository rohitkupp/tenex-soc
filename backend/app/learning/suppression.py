"""Consumer 4 — Suppression rule generation (docs/08 Part 2, §4). No retraining.

On dismissal with a reason, generate a candidate Sigma exception rule (the "entity allowlist"
form docs/08 names) and present it to the analyst for review. **Never auto-apply.**

## Why this never writes to `app/detection/rules/suppressions/` itself

docs/08, verbatim: *"Never auto-apply. Analyst review is the gate — that is how tuning works in a
real SOC, and auto-suppression is how you miss a breach."* This module only ever inserts a
`suppression_candidates` row with `status='pending'` (`app.models.suppression_candidate`) — an
inert record an analyst can inspect, edit their mind about, and reject. The *only* code path that
writes a `.yml` file under `app/detection/rules/suppressions/` is
`POST /api/learning/suppressions/{id}/accept` (`app/api/learning.py`), and only after a human
clicks accept. If a bug ever made this module write the file directly, that would be the
auto-suppression failure mode docs/08 is warning against, not a shortcut — this paragraph exists
so a future edit does not casually add that call.

## What a candidate targets

Grounded directly in the dismissed incident's own `signals` rows, not re-derived: for every
distinct `(detector_key, entity_type, entity_value)` a dismissed incident's contributing signals
touched, one candidate is generated, scoped to exactly that detector and that entity value — the
literal, minimal claim implied by "this specific value tripped this specific detector and an
analyst says it shouldn't have," never widened to "this detector in general" (that would suppress
true positives from other entities) or narrowed by a cross-field trick the analyst didn't ask for.
An already-pending candidate for the same `(detector_key, entity_type, entity_value)` is reused
rather than duplicated — a detector an analyst dismisses on the same entity twice should not pile
up two near-identical candidates waiting for review.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from typing import Any

import yaml
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.analyst_feedback import AnalystFeedback
from app.models.base import tenant_scope
from app.models.incident import Incident
from app.models.signal import Signal
from app.models.suppression_candidate import STATUS_PENDING, SuppressionCandidate
from app.models.triage_verdict import TriageVerdict

__all__ = [
    "ENTITY_TYPE_TO_EVENT_FIELD",
    "generate_suppression_candidates",
    "render_sigma_suppression_yaml",
]

# docs/02 `events`' hot columns vs. `entities.type`'s vocabulary (`user|src_ip|domain|dst_ip|
# asn|session`) — the same mapping `app.detection.signal.constants`' module docstring describes
# ("'user', not 'principal', even though the column on events is named principal"). `asn`/
# `session` have no hot column of their own; falling back to the entity_type string itself is a
# documented best effort, not a silent guess dressed up as certainty.
ENTITY_TYPE_TO_EVENT_FIELD: dict[str, str] = {
    "user": "principal",
    "src_ip": "src_ip",
    "domain": "domain",
    "dst_ip": "dst_ip",
}

_SIGMA_LEVEL = "informational"  # unreviewed candidate; never inherits the source rule's level


@dataclass(frozen=True, slots=True)
class SuppressionTarget:
    detector_key: str
    entity_type: str
    entity_value: str


def _event_field_for(entity_type: str) -> str:
    return ENTITY_TYPE_TO_EVENT_FIELD.get(entity_type, entity_type)


def _slugify(value: str, *, max_len: int = 40) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug[:max_len].strip("-") or "value"


def render_sigma_suppression_yaml(
    *, target: SuppressionTarget, reason: str, mitre_techniques: list[str], rule_id: str
) -> str:
    """A Sigma rule file (`app.detection.sigma.rule.load_rule_file`'s schema) plus the
    `applies_to` key `app.detection.sigma.runner.load_suppressions` requires — the exact format
    of every hand-authored file already under `app/detection/rules/suppressions/`. Rendered with
    `yaml.safe_dump`, not string-templated, so the output is guaranteed parseable YAML rather
    than "usually fine as long as no value has a colon in it."
    """
    field = _event_field_for(target.entity_type)
    block_name = "dismissed_entity"
    payload: dict[str, Any] = {
        "title": f"Suppress {target.detector_key} for {target.entity_type}={target.entity_value}",
        "id": rule_id,
        "status": "experimental",  # unreviewed candidate -- an analyst may edit before accepting
        "applies_to": [target.detector_key],
        "reason": reason,
        "logsource": {"product": "zscaler", "service": "web"},
        "detection": {
            block_name: {field: target.entity_value},
            "condition": block_name,
        },
        "level": _SIGMA_LEVEL,
        "tags": [f"attack.t{t.lower()}" for t in mitre_techniques] if mitre_techniques else [],
        "entity": {"type": target.entity_type, "by": field},
    }
    return yaml.safe_dump(payload, sort_keys=False, default_flow_style=False)


def _extract_technique_ids(mitre_techniques: Any) -> list[str]:
    """`triage_verdicts.mitre_techniques` is JSONB with no schema pinned tighter than "the LLM's
    structured technique list" (`app.models.triage_verdict`'s docstring) -- handles the two
    reasonable shapes (a bare list of technique-id strings, or a list of `{"technique": ...}`-
    style dicts) rather than assuming one."""
    if not isinstance(mitre_techniques, list):
        return []
    out: list[str] = []
    for item in mitre_techniques:
        if isinstance(item, str):
            out.append(item)
        elif isinstance(item, dict):
            tid = item.get("technique") or item.get("id") or item.get("mitre_technique")
            if isinstance(tid, str):
                out.append(tid)
    return out


def _targets_for_incident(session: Session, incident: Incident) -> list[SuppressionTarget]:
    if not incident.signal_ids:
        return []
    signals = (
        session.execute(select(Signal).where(Signal.id.in_(incident.signal_ids))).scalars().all()
    )
    seen: set[tuple[str, str, str]] = set()
    targets: list[SuppressionTarget] = []
    for sig in signals:
        key = (sig.detector_key, sig.entity_type, sig.entity_value)
        if key in seen:
            continue
        seen.add(key)
        targets.append(
            SuppressionTarget(
                detector_key=sig.detector_key,
                entity_type=sig.entity_type,
                entity_value=sig.entity_value,
            )
        )
    return targets


def generate_suppression_candidates(
    session: Session, tenant_id: uuid.UUID, feedback: AnalystFeedback, *, synthetic: bool = False
) -> list[SuppressionCandidate]:
    """docs/08 §4 trigger: "on dismissal with a reason." Gated purely on
    `dismissal_reason` being set (docs/02's own comment on that column: "feeds suppression rule
    generation") -- independent of `agrees`, since an analyst can attach a dismissal reason on any
    disagreement with a verdict, not only a `false_positive` one. Returns the created (or reused
    pending) candidates; writes nothing outside `suppression_candidates` (see module docstring).
    """
    reason = (feedback.dismissal_reason or "").strip()
    if not reason:
        return []

    with tenant_scope(session, tenant_id):
        verdict = session.get(TriageVerdict, feedback.verdict_id)
        if verdict is None:
            return []
        incident = session.get(Incident, verdict.incident_id)
        if incident is None:
            return []

        targets = _targets_for_incident(session, incident)
        if not targets:
            return []

        techniques = _extract_technique_ids(verdict.mitre_techniques)

        results: list[SuppressionCandidate] = []
        for target in targets:
            existing = session.execute(
                select(SuppressionCandidate).where(
                    SuppressionCandidate.detector_key == target.detector_key,
                    SuppressionCandidate.entity_type == target.entity_type,
                    SuppressionCandidate.entity_value == target.entity_value,
                    SuppressionCandidate.status == STATUS_PENDING,
                )
            ).scalar_one_or_none()
            if existing is not None:
                results.append(existing)
                continue

            rule_id = f"auto-{_slugify(target.detector_key)}-{_slugify(target.entity_value)}-{uuid.uuid4().hex[:8]}"
            rule_yaml = render_sigma_suppression_yaml(
                target=target, reason=reason, mitre_techniques=techniques, rule_id=rule_id
            )
            candidate = SuppressionCandidate(
                tenant_id=tenant_id,
                feedback_id=feedback.id,
                detector_key=target.detector_key,
                entity_type=target.entity_type,
                entity_value=target.entity_value,
                reason=reason,
                rule_yaml=rule_yaml,
                status=STATUS_PENDING,
                synthetic=synthetic,
            )
            session.add(candidate)
            session.flush()
            results.append(candidate)

    return results
