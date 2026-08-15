"""Load every `*.yml` rule (and suppression) in `app/detection/rules/`, evaluate each against
one analysis's `events`, and turn the matches into `signals` rows (docs/02).

This is the one place score/`explanation` construction happens — `app.detection.sigma.compiler`
only returns raw `Match`es (entity, window, evidence, a rule-specific `detail` dict); nothing
about scoring is baked into a rule's SQL.

## Scoring — an honest placeholder, not a calibrator

docs/04 "Fusion & calibration": `signals.confidence` is "always post-calibration", via isotonic
regression fit on held-out labeled data — that calibrator, and the eval set it is fit on, belong
to the fusion milestone (`app/detection/fusion.py`, M10), which is out of this package's scope
(`app/detection/rules/**` and `app/detection/sigma/**` only, per this task's ownership). Until
that calibrator exists, `confidence` cannot honestly be "calibrated" — so this module does not
pretend it is. `raw_score` is a level-anchored, rule-agnostic heuristic (`_LEVEL_BASE_SCORE`,
nudged by how far a threshold-based match cleared its threshold); `confidence` is currently a
direct pass-through of `raw_score`, clamped to `[0, 1]`, with `calibrated: false` recorded
alongside it in `explanation` so a reviewer (or the fusion milestone's own code) can tell at a
glance that this number has not been through isotonic regression yet. Both the module docstring
and the M6 verification report say this in the same words — nothing is hidden in a comment nobody
reads.

## Suppressions (docs/08 "Suppression rule generation")

A suppression is a normal `SigmaRule` YAML file (same loader, same compiler — no second format to
maintain) under `app/detection/rules/suppressions/`, plus one extra top-level key: `applies_to`,
a detector key or list of detector keys (or `"*"` for all of them) the suppression subtracts
from. `run_rules` evaluates every suppression the same way it evaluates a detection rule, then
drops any detection match whose `entity_value` coincides with a suppression match's
`entity_value` for a rule the suppression applies to — "entity allowlist", the simpler of the two
docs/08 describes, expressed as data (a Sigma condition), not a second code path. Suppressions are
never auto-generated or auto-applied by this module; they are read from whatever an analyst
already accepted and committed to that directory (docs/08: "Accepted rules go to
`detection/rules/suppressions/`... Never auto-apply[d]" — the human-review gate is upstream of
this code, in whatever writes the file).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from sqlalchemy import Connection
from sqlalchemy.orm import Session

from app.detection.sigma.compiler import Match, evaluate_rule
from app.detection.sigma.rule import RuleLoadError, SigmaRule, load_rule_file
from app.models.base import tenant_scope
from app.models.signal import Signal

__all__ = [
    "RULES_DIR",
    "SUPPRESSIONS_DIR",
    "SignalDraft",
    "SuppressionRule",
    "load_rules",
    "load_suppressions",
    "run_rules",
    "signal_drafts_to_rows",
    "write_signals",
]

RULES_DIR = Path(__file__).resolve().parents[2] / "detection" / "rules"
SUPPRESSIONS_DIR = RULES_DIR / "suppressions"

_LEVEL_BASE_SCORE: dict[str, float] = {
    "informational": 0.20,
    "low": 0.35,
    "medium": 0.55,
    "high": 0.75,
    "critical": 0.90,
}


@dataclass(frozen=True, slots=True)
class SignalDraft:
    """Everything `app.models.signal.Signal` needs except the ids `INSERT` assigns."""

    detector_key: str
    detector_layer: str
    raw_score: float
    confidence: float
    entity_type: str
    entity_value: str
    window_start: Any
    window_end: Any
    mitre_technique: str | None
    evidence_event_ids: list[int]
    explanation: dict[str, Any]


@dataclass(frozen=True, slots=True)
class SuppressionRule:
    rule: SigmaRule
    applies_to: frozenset[str]  # detector keys, or {"*"}
    reason: str

    def covers(self, detector_key: str) -> bool:
        return "*" in self.applies_to or detector_key in self.applies_to


# ---------------------------------------------------------------------------- loading


def load_rules(rules_dir: Path = RULES_DIR) -> list[SigmaRule]:
    """Every `*.yml` directly under `rules_dir` — `suppressions/` is a subdirectory, not a glob
    match, so it is never loaded as a detection rule by accident."""
    rules = [load_rule_file(p) for p in sorted(rules_dir.glob("*.yml"))]
    _check_unique_ids(rules)
    return rules


def _check_unique_ids(rules: list[SigmaRule]) -> None:
    seen: dict[str, Path] = {}
    for r in rules:
        if r.id in seen:
            raise RuleLoadError(f"duplicate rule id {r.id!r}: {seen[r.id]} and {r.path}")
        seen[r.id] = r.path or Path(r.id)


def load_suppressions(suppressions_dir: Path = SUPPRESSIONS_DIR) -> list[SuppressionRule]:
    if not suppressions_dir.exists():
        return []
    out: list[SuppressionRule] = []
    for path in sorted(suppressions_dir.glob("*.yml")):
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        applies_to_raw = raw.get("applies_to")
        if applies_to_raw is None:
            raise RuleLoadError(f"{path}: suppression rule missing required key 'applies_to'")
        applies_to = (
            frozenset({applies_to_raw})
            if isinstance(applies_to_raw, str)
            else frozenset(applies_to_raw)
        )
        rule = load_rule_file(path)
        out.append(
            SuppressionRule(rule=rule, applies_to=applies_to, reason=str(raw.get("reason", "")))
        )
    return out


# ---------------------------------------------------------------------------- scoring


def _score_match(rule: SigmaRule, match: Match) -> tuple[float, float]:
    """`(raw_score, confidence)` — see module docstring for why `confidence` is currently a
    direct, documented pass-through of `raw_score` rather than a calibrated probability."""
    base = _LEVEL_BASE_SCORE.get(rule.level, 0.5)
    bonus = 0.0
    threshold = match.detail.get("threshold")
    observed = match.detail.get("agg_block_count") or match.detail.get("speed_kmh")
    if isinstance(threshold, (int, float)) and isinstance(observed, (int, float)) and threshold:
        excess = max(0.0, (observed - threshold) / threshold)
        bonus = min(0.25, 0.1 * excess)
    raw_score = min(0.99, base + bonus)
    return raw_score, raw_score


def _build_explanation(rule: SigmaRule, match: Match) -> dict[str, Any]:
    return {
        "rule_id": rule.id,
        "title": rule.title,
        "description": rule.description,
        "condition": rule.condition,
        "level": rule.level,
        "logsource": {"product": rule.logsource.product, "service": rule.logsource.service},
        "tags": list(rule.tags),
        "match": match.detail,
        "calibrated": False,
    }


def _draft_from_match(rule: SigmaRule, match: Match) -> SignalDraft:
    raw_score, confidence = _score_match(rule, match)
    return SignalDraft(
        detector_key=rule.detector_key,
        detector_layer="rule",
        raw_score=raw_score,
        confidence=confidence,
        entity_type=rule.entity.type,
        entity_value=match.entity_value,
        window_start=match.window_start,
        window_end=match.window_end,
        mitre_technique=rule.primary_mitre_technique,
        evidence_event_ids=list(match.evidence_event_ids),
        explanation=_build_explanation(rule, match),
    )


# ---------------------------------------------------------------------------- running


@dataclass(slots=True)
class _RunStats:
    matches_by_rule: dict[str, int] = field(default_factory=dict)
    suppressed_by_rule: dict[str, int] = field(default_factory=dict)


def run_rules(
    conn: Connection,
    analysis_id: uuid.UUID,
    tenant_id: uuid.UUID,
    *,
    rules: list[SigmaRule] | None = None,
    suppressions: list[SuppressionRule] | None = None,
) -> list[SignalDraft]:
    """Evaluate every loaded rule against one analysis's `events`, apply suppressions, and return
    one `SignalDraft` per surviving match. Read-only — does not write `signals`; pair with
    `write_signals` for that (kept separate so a caller can inspect/filter drafts first, and so
    this function only ever needs a `Connection`, not a tenant-bound ORM `Session`)."""
    rules = rules if rules is not None else load_rules()
    suppressions = suppressions if suppressions is not None else load_suppressions()

    suppression_cache: dict[str, frozenset[str]] = {}

    def suppressed_entities(detector_key: str) -> frozenset[str]:
        applicable = [s for s in suppressions if s.covers(detector_key)]
        cache_key = "|".join(sorted(s.rule.id for s in applicable))
        if cache_key not in suppression_cache:
            values: set[str] = set()
            for s in applicable:
                for m in evaluate_rule(conn, s.rule, analysis_id, tenant_id):
                    values.add(m.entity_value)
            suppression_cache[cache_key] = frozenset(values)
        return suppression_cache[cache_key]

    drafts: list[SignalDraft] = []
    for rule in rules:
        matches = evaluate_rule(conn, rule, analysis_id, tenant_id)
        blocked = suppressed_entities(rule.detector_key)
        for m in matches:
            if m.entity_value in blocked:
                continue
            drafts.append(_draft_from_match(rule, m))
    return drafts


def signal_drafts_to_rows(
    drafts: list[SignalDraft], *, analysis_id: uuid.UUID, tenant_id: uuid.UUID
) -> list[Signal]:
    return [
        Signal(
            analysis_id=analysis_id,
            tenant_id=tenant_id,
            detector_key=d.detector_key,
            detector_layer=d.detector_layer,
            raw_score=d.raw_score,
            confidence=d.confidence,
            entity_type=d.entity_type,
            entity_value=d.entity_value,
            window_start=d.window_start,
            window_end=d.window_end,
            mitre_technique=d.mitre_technique,
            evidence_event_ids=d.evidence_event_ids,
            explanation=d.explanation,
        )
        for d in drafts
    ]


def write_signals(
    session: Session, drafts: list[SignalDraft], *, analysis_id: uuid.UUID, tenant_id: uuid.UUID
) -> list[Signal]:
    """Insert `drafts` as `signals` rows on a tenant-bound `session` (`app.models.base.
    tenant_scope`/`tenant_session`) and return the inserted ORM objects (ids populated)."""
    rows = signal_drafts_to_rows(drafts, analysis_id=analysis_id, tenant_id=tenant_id)
    with tenant_scope(session, tenant_id):
        session.add_all(rows)
        session.commit()
        for row in rows:
            session.refresh(row)
    return rows
