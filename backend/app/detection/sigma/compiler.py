"""Compiles a parsed `SigmaRule` (`app.detection.sigma.rule`) + its `condition` AST
(`app.detection.sigma.grammar`) into SQL executed over `events`, and returns the matches.

**Everything here runs as SQL against Postgres.** No rule evaluation pulls `events` rows into
Python to filter/aggregate/window them there — every predicate, `count()`/`not_seen_before()`/
`speed_kmh()` aggregation, and sliding/gap-clustered time window is a SQLAlchemy Core query
(CTEs, window functions, correlated subqueries) executed via `conn.execute(...)`. Python only
ever sees the *matches* — already reduced to one row per (entity, window) — never the underlying
event rows. `tests/test_sigma_compiler.py::test_every_strategy_compiles_to_a_single_round_trip`
asserts this by counting `conn.execute` calls.

## Condition shapes supported

Exactly the shapes `app.detection.sigma.grammar`'s docstring describes, dispatched by the shape
of the parsed AST root:

* A boolean combination (`and`/`or`/`not`/parens) of bare block references, with no aggregation
  anywhere in it — a "presence" rule. Every matching row is a candidate; rows for the same entity
  within `rule.timeframe_s` (default 30 minutes) of each other are gap-clustered into one signal,
  so a hundred-event burst that trips a presence rule on every line becomes one signal with a
  hundred-row evidence array, not a hundred near-duplicate signals.
* A single `count()`/`not_seen_before()`/`speed_kmh()` aggregation term, standalone. Brute force
  and password spray are this shape.
* `and` of exactly one aggregation term and exactly one bare block reference (in either order) —
  the docs/04 worked example's own shape (`failures | count() by principal >= 5 and success`).
  The block reference is the *anchor*: for every row matching it, count/check the aggregation
  block's rows in the trailing `timeframe` window ending at the anchor's own timestamp, grouped
  by the aggregation's `by` fields (matched against the anchor row's own values for those same
  field names). MFA fatigue, blocked-then-allowed, and both upload-side cross-source rules are
  this shape.

Deeper nesting (aggregation `and` aggregation, `or` of aggregations, ...) is not implemented —
no rule in the docs/04 inventory needs it, and raising `UnsupportedConditionError` at rule-load
time for anything else is safer than silently mishandling a shape nobody exercised.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from sqlalchemy import (
    ColumnElement,
    Connection,
    and_,
    case,
    func,
    literal,
    not_,
    or_,
    select,
)
from sqlalchemy.orm import aliased

from app.detection.sigma import fields
from app.detection.sigma.grammar import (
    And,
    BlockRef,
    ConditionNode,
    CountAgg,
    Not,
    NotSeenBefore,
    Or,
    SpeedKmh,
    parse_condition,
)
from app.detection.sigma.rule import FieldValue, RuleLoadError, SigmaRule
from app.models.event import Event

__all__ = ["Match", "UnsupportedConditionError", "evaluate_rule"]

# Default gap for clustering a "presence" rule's individually-matching rows into one signal, for
# rules whose YAML sets no `detection.timeframe` (the timeframe otherwise doubles as the gap).
_DEFAULT_CLUSTER_GAP_S = 1800  # 30 minutes


class UnsupportedConditionError(ValueError):
    """A condition parses (`app.detection.sigma.grammar`) but its shape is not one of the
    evaluator's supported strategies — see this module's docstring."""


@dataclass(frozen=True, slots=True)
class Match:
    """One `signals` row's worth of evaluation output, before scoring/explanation are attached
    (`app.detection.sigma.runner` does that; docs/02's `signals` table is the target shape)."""

    entity_value: str
    window_start: Any
    window_end: Any
    evidence_event_ids: tuple[int, ...]
    detail: dict[str, Any] = field(default_factory=dict)


EventAlias = type[Event]

# ---------------------------------------------------------------------------- filter compilation

_NUMERIC_MODIFIERS = frozenset({"gte", "gt", "lte", "lt"})
_TEXT_MODIFIERS = frozenset({"contains", "startswith", "endswith", "re"})


def _escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _wildcard_to_like(value: str) -> str:
    """Sigma bare-value wildcard glob (`*`, `?`) -> a SQL `LIKE` pattern (`%`, `_`)."""
    return _escape_like(value).replace("*", "%").replace("?", "_")


def _value_predicate(
    field_name: str, modifier: str | None, value: FieldValue, entity: EventAlias
) -> ColumnElement[bool]:
    if field_name in fields.BOOLEAN_FIELDS:
        if modifier is not None:
            raise RuleLoadError(f"boolean field {field_name!r} does not take a |modifier")
        if not isinstance(value, bool):
            raise RuleLoadError(f"boolean field {field_name!r} needs true/false, got {value!r}")
        expr = fields.resolve_bool_field(field_name, entity)
        return expr if value else not_(expr)

    if modifier in _NUMERIC_MODIFIERS:
        col = fields.resolve_numeric_field(field_name, entity)
        threshold = float(value)
        if modifier == "gte":
            return col >= threshold
        if modifier == "gt":
            return col > threshold
        if modifier == "lte":
            return col <= threshold
        return col < threshold  # "lt"

    col = fields.resolve_field(field_name, entity)
    if modifier == "contains":
        return col.ilike(f"%{_escape_like(str(value))}%")
    if modifier == "startswith":
        return col.ilike(f"{_escape_like(str(value))}%")
    if modifier == "endswith":
        return col.ilike(f"%{_escape_like(str(value))}")
    if modifier == "re":
        return col.op("~")(str(value))
    if modifier in (None, "eq"):
        if isinstance(value, str) and ("*" in value or "?" in value):
            return col.ilike(_wildcard_to_like(value))
        return col == value
    raise RuleLoadError(
        f"unhandled field modifier {modifier!r} on {field_name!r}"
    )  # pragma: no cover


def compile_block_predicate(
    rule: SigmaRule, block_name: str, entity: EventAlias
) -> ColumnElement[bool]:
    if block_name not in rule.blocks:
        raise RuleLoadError(
            f"{rule.id}: condition references block {block_name!r}, not defined under 'detection'"
        )
    block = rule.blocks[block_name]
    filter_preds: list[ColumnElement[bool]] = []
    for f in block.filters:
        value_preds = [_value_predicate(f.field, f.modifier, v, entity) for v in f.values]
        filter_preds.append(value_preds[0] if len(value_preds) == 1 else or_(*value_preds))
    return filter_preds[0] if len(filter_preds) == 1 else and_(*filter_preds)


# ---------------------------------------------------------------------------- shape detection


def _is_aggregation(node: ConditionNode) -> bool:
    return isinstance(node, CountAgg | NotSeenBefore | SpeedKmh)


def _contains_aggregation(node: ConditionNode) -> bool:
    if _is_aggregation(node):
        return True
    if isinstance(node, Not):
        return _contains_aggregation(node.term)
    if isinstance(node, And | Or):
        return any(_contains_aggregation(t) for t in node.terms)
    return False


def _base_predicate(
    rule: SigmaRule, node: ConditionNode, entity: EventAlias
) -> ColumnElement[bool]:
    """Compile a presence-shaped node (no aggregation anywhere in it) to one WHERE predicate."""
    if isinstance(node, BlockRef):
        return compile_block_predicate(rule, node.name, entity)
    if isinstance(node, Not):
        return not_(_base_predicate(rule, node.term, entity))
    if isinstance(node, And):
        return and_(*(_base_predicate(rule, t, entity) for t in node.terms))
    if isinstance(node, Or):
        return or_(*(_base_predicate(rule, t, entity) for t in node.terms))
    raise UnsupportedConditionError(  # pragma: no cover - reached only via _contains_aggregation
        f"{rule.id}: aggregation node {node!r} found where a plain predicate was expected"
    )


def _analysis_scope(
    entity: EventAlias, analysis_id: uuid.UUID, tenant_id: uuid.UUID
) -> ColumnElement[bool]:
    return and_(entity.analysis_id == analysis_id, entity.tenant_id == tenant_id)


# ---------------------------------------------------------------------------- strategy: presence


def _run_presence(
    conn: Connection,
    rule: SigmaRule,
    root: ConditionNode,
    analysis_id: uuid.UUID,
    tenant_id: uuid.UUID,
) -> list[Match]:
    e = aliased(Event, name="e")
    predicate = _base_predicate(rule, root, e)
    entity_expr = fields.resolve_text_field(rule.entity.by, e)

    matched = (
        select(e.id.label("id"), e.ts.label("ts"), entity_expr.label("entity_value"))
        .where(_analysis_scope(e, analysis_id, tenant_id), predicate, entity_expr.is_not(None))
        .cte("matched")
    )

    gap_s = rule.timeframe_s or _DEFAULT_CLUSTER_GAP_S
    prev_ts = func.lag(matched.c.ts).over(
        partition_by=matched.c.entity_value, order_by=matched.c.ts
    )
    gap_seconds = func.extract("epoch", matched.c.ts - prev_ts)
    is_new_episode = case((or_(prev_ts.is_(None), gap_seconds > gap_s), 1), else_=0)
    gapped = select(
        matched.c.id, matched.c.ts, matched.c.entity_value, is_new_episode.label("is_new")
    ).cte("gapped")

    episode_id = func.sum(gapped.c.is_new).over(
        partition_by=gapped.c.entity_value, order_by=gapped.c.ts
    )
    episodes = select(
        gapped.c.id, gapped.c.ts, gapped.c.entity_value, episode_id.label("episode_id")
    ).cte("episodes")

    final = (
        select(
            episodes.c.entity_value,
            episodes.c.episode_id,
            func.min(episodes.c.ts).label("window_start"),
            func.max(episodes.c.ts).label("window_end"),
            func.array_agg(episodes.c.id).label("evidence_ids"),
        )
        .group_by(episodes.c.entity_value, episodes.c.episode_id)
        .order_by(func.min(episodes.c.ts))
    )

    rows = conn.execute(final).all()
    return [
        Match(
            entity_value=row.entity_value,
            window_start=row.window_start,
            window_end=row.window_end,
            evidence_event_ids=tuple(sorted(row.evidence_ids)),
            detail={"matched_events": len(row.evidence_ids)},
        )
        for row in rows
    ]


# ---------------------------------------------------------------------------- shared: `by` group key


def _group_key(by_cols: Sequence[ColumnElement[Any]]) -> ColumnElement[str]:
    """Multiple `by` fields collapse to one text grouping key (`\\x1f`-joined — a control
    character no real field value contains) so every downstream join/partition operates on a
    single column regardless of how many fields a rule groups by. `by_cols` are already text
    (`_by_columns` resolves through `fields.resolve_text_field`), so no further cast is needed here."""
    if len(by_cols) == 1:
        return by_cols[0]
    return func.concat_ws(literal("\x1f"), *by_cols)


def _by_columns(by: tuple[str, ...], entity: EventAlias) -> list[ColumnElement[Any]]:
    """Text-coerced (`fields.resolve_text_field`) so both grouping (`_group_key`) and the
    `entity_value` a caller slices out of these by index (`_entity_by_index`) get the same clean
    text representation — e.g. `host(src_ip)` rather than `src_ip::text`'s `/32`-suffixed form."""
    return [fields.resolve_text_field(name, entity) for name in by]


def _entity_by_index(rule: SigmaRule, by: tuple[str, ...]) -> int:
    if rule.entity.by not in by:
        raise RuleLoadError(
            f"{rule.id}: entity.by={rule.entity.by!r} must be one of the aggregation's 'by' "
            f"fields {by!r}"
        )
    return by.index(rule.entity.by)


# ---------------------------------------------------------------------------- strategy: standalone count()


def _run_standalone_count(
    conn: Connection,
    rule: SigmaRule,
    agg: CountAgg,
    analysis_id: uuid.UUID,
    tenant_id: uuid.UUID,
) -> list[Match]:
    if rule.timeframe_s is None:
        raise RuleLoadError(f"{rule.id}: a count() aggregation requires 'detection.timeframe'")
    timeframe = timedelta(seconds=rule.timeframe_s)
    entity_idx = _entity_by_index(rule, agg.by)

    e = aliased(Event, name="e")
    predicate = compile_block_predicate(rule, agg.block, e)
    by_cols = _by_columns(agg.by, e)
    grp = _group_key(by_cols)
    entity_col = by_cols[entity_idx]

    b = (
        select(
            e.id.label("id"),
            e.ts.label("ts"),
            grp.label("grp"),
            entity_col.label("entity_value"),
        )
        .where(_analysis_scope(e, analysis_id, tenant_id), predicate, grp.is_not(None))
        .cte("b")
    )

    if agg.distinct_field is None:
        # Plain rolling COUNT(*) — e.g. brute force.
        b2 = b.alias("b2")
        rolling = (
            select(func.count())
            .select_from(b2)
            .where(b2.c.grp == b.c.grp, b2.c.ts.between(b.c.ts - timeframe, b.c.ts))
            .correlate(b)
            .scalar_subquery()
        )
    else:
        # Distinct-count with an optional per-value cap — password spray's "≥10 distinct
        # principals, ≤3 attempts each": count *values* of `distinct_field` whose own rolling
        # count (within the same window, against the same group) does not exceed `max_each`.
        distinct_expr_e = fields.resolve_text_field(agg.distinct_field, e)
        b = (
            select(
                e.id.label("id"),
                e.ts.label("ts"),
                grp.label("grp"),
                entity_col.label("entity_value"),
                distinct_expr_e.label("distinct_value"),
            )
            .where(_analysis_scope(e, analysis_id, tenant_id), predicate, grp.is_not(None))
            .cte("b")
        )
        b2 = b.alias("b2")
        own_count = (
            select(func.count())
            .select_from(b2)
            .where(
                b2.c.grp == b.c.grp,
                b2.c.distinct_value == b.c.distinct_value,
                b2.c.ts.between(b.c.ts - timeframe, b.c.ts),
            )
            .correlate(b)
            .scalar_subquery()
        )
        eligible = select(b.c.id, b.c.ts, b.c.grp, b.c.entity_value, b.c.distinct_value).where(
            (own_count <= agg.max_each) if agg.max_each is not None else literal(True)
        )
        eligible_cte = eligible.cte("eligible")
        b = eligible_cte
        b2d = b.alias("b2d")
        rolling = (
            select(func.count(func.distinct(b2d.c.distinct_value)))
            .select_from(b2d)
            .where(b2d.c.grp == b.c.grp, b2d.c.ts.between(b.c.ts - timeframe, b.c.ts))
            .correlate(b)
            .scalar_subquery()
        )

    rolled = select(b.c.id, b.c.ts, b.c.grp, b.c.entity_value, rolling.label("rolling_count")).cte(
        "rolled"
    )

    comparator = agg.comparator
    threshold = agg.value
    crossed = _compare(rolled.c.rolling_count, comparator, threshold)
    trigger = (
        select(rolled.c.grp, func.min(rolled.c.ts).label("trigger_ts"))
        .where(crossed)
        .group_by(rolled.c.grp)
        .cte("trigger")
    )

    b3 = b.alias("b3")
    final = (
        select(
            trigger.c.grp,
            trigger.c.trigger_ts,
            func.array_agg(b3.c.id).label("evidence_ids"),
            func.min(b3.c.ts).label("window_start"),
            func.max(func.coalesce(b3.c.entity_value, "")).label("entity_value_sample"),
        )
        .select_from(
            trigger.join(
                b3,
                and_(
                    b3.c.grp == trigger.c.grp,
                    b3.c.ts.between(trigger.c.trigger_ts - timeframe, trigger.c.trigger_ts),
                ),
            )
        )
        .group_by(trigger.c.grp, trigger.c.trigger_ts)
    )
    rows = conn.execute(final).all()
    return [
        Match(
            entity_value=row.entity_value_sample,
            window_start=row.window_start,
            window_end=row.trigger_ts,
            evidence_event_ids=tuple(sorted(row.evidence_ids)),
            detail={
                "aggregation": "count" if agg.distinct_field is None else "count_distinct",
                "distinct_field": agg.distinct_field,
                "max_each": agg.max_each,
                "by": list(agg.by),
                "threshold": threshold,
                "comparator": comparator,
                "n_evidence": len(row.evidence_ids),
            },
        )
        for row in rows
    ]


def _compare(col: ColumnElement[Any], comparator: str, value: float) -> ColumnElement[bool]:
    if comparator == ">=":
        return col >= value
    if comparator == ">":
        return col > value
    if comparator == "<=":
        return col <= value
    if comparator == "<":
        return col < value
    return col == value  # "==" / "="


# ---------------------------------------------------------------------------- strategy: anchored count()


def _run_anchored_count(
    conn: Connection,
    rule: SigmaRule,
    agg: CountAgg,
    anchor_block: str,
    analysis_id: uuid.UUID,
    tenant_id: uuid.UUID,
) -> list[Match]:
    """`agg_block | count(...) by f... >= N and anchor_block` — docs/04's worked example shape.

    For every row matching `anchor_block`, count/distinct-count `agg_block` rows sharing the same
    `by` field values within the trailing `timeframe` window ending at the anchor row's own
    timestamp; keep the anchor if the count clears `N`.
    """
    if rule.timeframe_s is None:
        raise RuleLoadError(f"{rule.id}: an anchored count() requires 'detection.timeframe'")
    timeframe = timedelta(seconds=rule.timeframe_s)
    entity_idx = _entity_by_index(rule, agg.by)

    ea = aliased(Event, name="ea")  # aggregation-block rows
    en = aliased(Event, name="en")  # anchor-block rows
    agg_predicate = compile_block_predicate(rule, agg.block, ea)
    anchor_predicate = compile_block_predicate(rule, anchor_block, en)

    agg_by_cols = _by_columns(agg.by, ea)
    anchor_by_cols = _by_columns(agg.by, en)  # same field *names*, resolved on the anchor row
    agg_grp = _group_key(agg_by_cols)
    anchor_grp = _group_key(anchor_by_cols)
    anchor_entity_col = anchor_by_cols[entity_idx]

    count_field_expr = (
        fields.resolve_text_field(agg.distinct_field, ea) if agg.distinct_field else None
    )

    b_cols: list[ColumnElement[Any]] = [ea.id.label("id"), ea.ts.label("ts"), agg_grp.label("grp")]
    if count_field_expr is not None:
        b_cols.append(count_field_expr.label("distinct_value"))
    b = (
        select(*b_cols)
        .where(_analysis_scope(ea, analysis_id, tenant_id), agg_predicate, agg_grp.is_not(None))
        .cte("agg_rows")
    )

    anchors = (
        select(
            en.id.label("id"),
            en.ts.label("ts"),
            anchor_grp.label("grp"),
            anchor_entity_col.label("entity_value"),
        )
        .where(
            _analysis_scope(en, analysis_id, tenant_id), anchor_predicate, anchor_grp.is_not(None)
        )
        .cte("anchors")
    )

    if agg.distinct_field is None:
        agg_count = (
            select(func.count())
            .select_from(b)
            .where(b.c.grp == anchors.c.grp, b.c.ts.between(anchors.c.ts - timeframe, anchors.c.ts))
            .correlate(anchors)
            .scalar_subquery()
        )
    else:
        agg_count = (
            select(func.count(func.distinct(b.c.distinct_value)))
            .select_from(b)
            .where(b.c.grp == anchors.c.grp, b.c.ts.between(anchors.c.ts - timeframe, anchors.c.ts))
            .correlate(anchors)
            .scalar_subquery()
        )

    scored = select(
        anchors.c.id,
        anchors.c.ts,
        anchors.c.grp,
        anchors.c.entity_value,
        agg_count.label("agg_count"),
    ).cte("scored")
    qualifying = (
        select(scored)
        .where(_compare(scored.c.agg_count, agg.comparator, agg.value))
        .cte("qualifying")
    )

    b2 = b.alias("b2")
    evidence = (
        select(func.array_agg(b2.c.id))
        .select_from(b2)
        .where(
            b2.c.grp == qualifying.c.grp,
            b2.c.ts.between(qualifying.c.ts - timeframe, qualifying.c.ts),
        )
        .correlate(qualifying)
        .scalar_subquery()
    )
    final = select(
        qualifying.c.id,
        qualifying.c.ts,
        qualifying.c.entity_value,
        qualifying.c.agg_count,
        evidence.label("agg_evidence_ids"),
    ).order_by(qualifying.c.ts)

    rows = conn.execute(final).all()
    matches: list[Match] = []
    for row in rows:
        evidence_ids = tuple(sorted({*(row.agg_evidence_ids or []), row.id}))
        matches.append(
            Match(
                entity_value=row.entity_value,
                window_start=row.ts - timeframe,
                window_end=row.ts,
                evidence_event_ids=evidence_ids,
                detail={
                    "aggregation": "count" if agg.distinct_field is None else "count_distinct",
                    "by": list(agg.by),
                    "threshold": agg.value,
                    "comparator": agg.comparator,
                    "agg_block_count": row.agg_count,
                    "anchor_block": anchor_block,
                    "anchor_event_id": row.id,
                },
            )
        )
    return matches


# ---------------------------------------------------------------------------- strategy: not_seen_before


def _run_not_seen_before(
    conn: Connection,
    rule: SigmaRule,
    agg: NotSeenBefore,
    analysis_id: uuid.UUID,
    tenant_id: uuid.UUID,
) -> list[Match]:
    ea = aliased(Event, name="anchor")
    eh = aliased(Event, name="history")
    anchor_predicate = compile_block_predicate(rule, agg.block, ea)
    history_predicate = compile_block_predicate(rule, agg.other_block, eh)

    anchor_field_cols = _by_columns(agg.fields, ea)
    history_field_cols = _by_columns(agg.fields, eh)
    entity_expr = fields.resolve_text_field(rule.entity.by, ea)

    anchors = (
        select(
            ea.id.label("id"),
            ea.ts.label("ts"),
            entity_expr.label("entity_value"),
            *[c.label(f"f{i}") for i, c in enumerate(anchor_field_cols)],
        )
        .where(_analysis_scope(ea, analysis_id, tenant_id), anchor_predicate)
        .cte("nsb_anchors")
    )

    history = select(
        eh.ts.label("ts"), *[c.label(f"f{i}") for i, c in enumerate(history_field_cols)]
    ).where(_analysis_scope(eh, analysis_id, tenant_id), history_predicate)
    history_sub = history.subquery("nsb_history")

    exists_earlier = (
        select(literal(1))
        .select_from(history_sub)
        .where(
            history_sub.c.ts < anchors.c.ts,
            *[history_sub.c[f"f{i}"] == anchors.c[f"f{i}"] for i in range(len(agg.fields))],
        )
        .correlate(anchors)
        .exists()
    )
    # A baseline must actually exist: by convention (documented on `NotSeenBefore` in
    # app.detection.sigma.grammar) the *first* field in `fields` is the "who" this rule tracks a
    # history for (`principal`, in every rule that uses this primitive) — without this check, a
    # principal's very first-ever row would trivially satisfy "no earlier row shares these field
    # values" and "first login from new country" would fire on every principal's first login in
    # the file, which is a missing baseline, not a novel one.
    has_baseline = (
        select(literal(1))
        .select_from(history_sub)
        .where(history_sub.c.ts < anchors.c.ts, history_sub.c.f0 == anchors.c.f0)
        .correlate(anchors)
        .exists()
    )

    final = (
        select(anchors.c.id, anchors.c.ts, anchors.c.entity_value)
        .where(has_baseline, ~exists_earlier, anchors.c.entity_value.is_not(None))
        .order_by(anchors.c.ts)
    )
    rows = conn.execute(final).all()
    return [
        Match(
            entity_value=row.entity_value,
            window_start=row.ts,
            window_end=row.ts,
            evidence_event_ids=(row.id,),
            detail={"fields": list(agg.fields), "other_block": agg.other_block},
        )
        for row in rows
    ]


# ---------------------------------------------------------------------------- strategy: speed_kmh

_EARTH_RADIUS_KM = 6371.0088


def _haversine_km(
    lat1: ColumnElement[Any],
    lon1: ColumnElement[Any],
    lat2: ColumnElement[Any],
    lon2: ColumnElement[Any],
) -> ColumnElement[Any]:
    rlat1, rlat2 = func.radians(lat1), func.radians(lat2)
    dlat = func.radians(lat2 - lat1)
    dlon = func.radians(lon2 - lon1)
    a = func.sin(dlat / 2) * func.sin(dlat / 2) + func.cos(rlat1) * func.cos(rlat2) * func.sin(
        dlon / 2
    ) * func.sin(dlon / 2)
    return 2 * _EARTH_RADIUS_KM * func.asin(func.sqrt(a))


def _run_speed_kmh(
    conn: Connection,
    rule: SigmaRule,
    agg: SpeedKmh,
    analysis_id: uuid.UUID,
    tenant_id: uuid.UUID,
) -> list[Match]:
    e = aliased(Event, name="e")
    predicate = compile_block_predicate(rule, agg.block, e)
    by_cols = _by_columns(agg.by, e)
    grp = _group_key(by_cols)
    entity_idx = _entity_by_index(rule, agg.by)
    entity_col = by_cols[entity_idx]
    lat = fields.resolve_numeric_field(agg.lat_field, e)
    lon = fields.resolve_numeric_field(agg.lon_field, e)

    b = (
        select(
            e.id.label("id"),
            e.ts.label("ts"),
            grp.label("grp"),
            entity_col.label("entity_value"),
            lat.label("lat"),
            lon.label("lon"),
        )
        .where(
            _analysis_scope(e, analysis_id, tenant_id),
            predicate,
            grp.is_not(None),
            lat.is_not(None),
            lon.is_not(None),
        )
        .cte("geo")
    )

    prev_id = func.lag(b.c.id).over(partition_by=b.c.grp, order_by=b.c.ts)
    prev_ts = func.lag(b.c.ts).over(partition_by=b.c.grp, order_by=b.c.ts)
    prev_lat = func.lag(b.c.lat).over(partition_by=b.c.grp, order_by=b.c.ts)
    prev_lon = func.lag(b.c.lon).over(partition_by=b.c.grp, order_by=b.c.ts)
    pairs = select(
        b.c.id,
        b.c.ts,
        b.c.grp,
        b.c.entity_value,
        b.c.lat,
        b.c.lon,
        prev_id.label("prev_id"),
        prev_ts.label("prev_ts"),
        prev_lat.label("prev_lat"),
        prev_lon.label("prev_lon"),
    ).cte("geo_pairs")

    distance = _haversine_km(pairs.c.prev_lat, pairs.c.prev_lon, pairs.c.lat, pairs.c.lon)
    elapsed_h = func.extract("epoch", pairs.c.ts - pairs.c.prev_ts) / 3600.0
    speed = case(
        (elapsed_h <= 0, case((distance > 1.0, literal(10_000_000.0)), else_=literal(0.0))),
        else_=distance / elapsed_h,
    )
    scored = (
        select(
            pairs.c.id,
            pairs.c.ts,
            pairs.c.entity_value,
            pairs.c.prev_id,
            pairs.c.prev_ts,
            distance.label("distance_km"),
            elapsed_h.label("elapsed_h"),
            speed.label("speed_kmh"),
        )
        .where(pairs.c.prev_ts.is_not(None))
        .cte("geo_scored")
    )

    final = (
        select(scored)
        .where(
            _compare(scored.c.speed_kmh, agg.comparator, agg.value),
            scored.c.distance_km >= agg.min_km,
        )
        .order_by(scored.c.ts)
    )
    rows = conn.execute(final).all()
    return [
        Match(
            entity_value=row.entity_value,
            window_start=row.prev_ts,
            window_end=row.ts,
            evidence_event_ids=tuple(sorted({row.prev_id, row.id})),
            detail={
                "distance_km": round(float(row.distance_km), 1),
                "elapsed_h": round(float(row.elapsed_h), 3),
                "speed_kmh": round(float(row.speed_kmh), 1),
                "threshold_kmh": agg.value,
                "min_km": agg.min_km,
            },
        )
        for row in rows
    ]


# ---------------------------------------------------------------------------- dispatcher


def evaluate_rule(
    conn: Connection, rule: SigmaRule, analysis_id: uuid.UUID, tenant_id: uuid.UUID
) -> list[Match]:
    """Run one rule's `condition` against `events` for one analysis. Returns its raw matches —
    `app.detection.sigma.runner` turns these into scored, explained `signals` rows."""
    root = parse_condition(rule.condition)

    if not _contains_aggregation(root):
        return _run_presence(conn, rule, root, analysis_id, tenant_id)

    if _is_aggregation(root):
        if isinstance(root, CountAgg):
            return _run_standalone_count(conn, rule, root, analysis_id, tenant_id)
        if isinstance(root, NotSeenBefore):
            return _run_not_seen_before(conn, rule, root, analysis_id, tenant_id)
        if isinstance(root, SpeedKmh):
            return _run_speed_kmh(conn, rule, root, analysis_id, tenant_id)

    if isinstance(root, And) and len(root.terms) == 2:
        agg_terms = [t for t in root.terms if isinstance(t, CountAgg)]
        block_terms = [t for t in root.terms if isinstance(t, BlockRef)]
        if len(agg_terms) == 1 and len(block_terms) == 1:
            return _run_anchored_count(
                conn, rule, agg_terms[0], block_terms[0].name, analysis_id, tenant_id
            )

    raise UnsupportedConditionError(
        f"{rule.id}: condition {rule.condition!r} is not one of the evaluator's supported "
        "shapes — see app.detection.sigma.compiler's module docstring"
    )
