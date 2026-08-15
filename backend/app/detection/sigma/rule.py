"""The Sigma rule schema: what a `*.yml` file in `app/detection/rules/` must contain, and how it
loads into the small typed model `app.detection.sigma.compiler` compiles to SQL.

docs/04's worked example is the schema this follows, field for field:

```yaml
title: Okta MFA fatigue
id: okta-mfa-fatigue
status: experimental
logsource:
  product: okta
  service: system
detection:
  failures:
    activity_name: 'user.authentication.auth_via_mfa'
    status: 'FAILURE'
  success:
    activity_name: 'user.authentication.auth_via_mfa'
    status: 'SUCCESS'
  timeframe: 15m
  condition: failures | count() by principal >= 5 and success
level: high
tags:
  - attack.credential_access
  - attack.t1621
```

Two keys this pipeline adds on top of upstream Sigma, because docs/02's `signals` table needs
information real Sigma (a detection-only format with no opinion on storage) has no field for:

* `entity` — which grouping field becomes `signals.entity_value`, and its `entity_type`
  (docs/02's `user | src_ip | domain | dst_ip | asn | session`). Sigma's own spec never says what
  to *do* with a match; this pipeline's evaluator has to.
* `sources` — informational only (which `datagen` sources the rule is meant to see; validated
  loosely, never required for the rule to run) — lets a rule's YAML self-document whether it is a
  proxy, identity, or cross-source rule without a human having to read its `detection` block to
  tell.

A field filter (`activity_name: 'user.authentication.auth_via_mfa'`) supports Sigma's own
modifier suffix syntax (`field|modifier: value`) for the handful of modifiers the rule inventory
actually needs: `contains`, `startswith`, `endswith`, `re`, and — beyond stock Sigma, which has no
numeric comparators — `gte`/`gt`/`lte`/`lt` for the numeric-threshold fields (`bytes_out`,
`hour_utc`, ...). A bare value containing `*`/`?` is treated as a Sigma wildcard glob. A list
value is an OR across its members, matching Sigma's own "a list means any of these" convention.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

import yaml

__all__ = [
    "DetectionBlock",
    "EntitySpec",
    "FieldFilter",
    "LogSource",
    "RuleLoadError",
    "SigmaRule",
    "load_rule_file",
]


class RuleLoadError(ValueError):
    """A `*.yml` rule file is missing a required key or fails schema validation."""


_MODIFIERS = frozenset({"contains", "startswith", "endswith", "re", "gte", "gt", "lte", "lt", "eq"})
_RESERVED_DETECTION_KEYS = frozenset({"condition", "timeframe"})
FieldValue = str | int | float | bool
EntityType = Literal["user", "src_ip", "domain", "dst_ip", "asn", "session"]


@dataclass(frozen=True, slots=True)
class FieldFilter:
    """One `field[|modifier]: value` entry. `value` is a single scalar or a list (OR)."""

    field: str
    modifier: str | None
    values: tuple[FieldValue, ...]

    @classmethod
    def parse(cls, raw_key: str, raw_value: Any) -> FieldFilter:
        if "|" in raw_key:
            field_name, _, modifier = raw_key.partition("|")
            if modifier not in _MODIFIERS:
                raise RuleLoadError(
                    f"unknown field modifier {modifier!r} on {raw_key!r}; known: "
                    f"{sorted(_MODIFIERS)}"
                )
        else:
            field_name, modifier = raw_key, None
        values = tuple(raw_value) if isinstance(raw_value, list) else (raw_value,)
        if not values:
            raise RuleLoadError(f"field filter {raw_key!r} has an empty value list")
        return cls(field=field_name, modifier=modifier, values=values)


@dataclass(frozen=True, slots=True)
class DetectionBlock:
    """A named group of field filters (docs/04's `failures:`, `success:`, ...). All ANDed."""

    name: str
    filters: tuple[FieldFilter, ...]

    @classmethod
    def parse(cls, name: str, raw: dict[str, Any]) -> DetectionBlock:
        if not raw:
            raise RuleLoadError(f"detection block {name!r} has no field filters")
        return cls(name=name, filters=tuple(FieldFilter.parse(k, v) for k, v in raw.items()))


@dataclass(frozen=True, slots=True)
class LogSource:
    product: str  # "okta" | "zscaler" | "okta+zscaler" (cross-source)
    service: str | None = None


@dataclass(frozen=True, slots=True)
class EntitySpec:
    """Which value becomes `signals.entity_value`/`entity_type` for a match (docs/02)."""

    type: EntityType
    by: str  # a field name resolvable on the row/group the match reports


_TIMEFRAME_UNITS: dict[str, int] = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def parse_timeframe(raw: str) -> int:
    """`"15m"` -> `900` (seconds). Sigma's own timeframe suffix set, no more."""
    raw = raw.strip()
    if len(raw) < 2 or raw[-1] not in _TIMEFRAME_UNITS:
        raise RuleLoadError(f"unparseable timeframe {raw!r}; expected e.g. '15m', '1h', '30s'")
    try:
        amount = int(raw[:-1])
    except ValueError as exc:
        raise RuleLoadError(f"unparseable timeframe {raw!r}") from exc
    return amount * _TIMEFRAME_UNITS[raw[-1]]


@dataclass(frozen=True, slots=True)
class SigmaRule:
    id: str
    title: str
    status: str
    logsource: LogSource
    blocks: dict[str, DetectionBlock]
    condition: str
    timeframe_s: int | None
    level: str
    tags: tuple[str, ...]
    entity: EntitySpec
    description: str = ""
    path: Path | None = field(default=None, compare=False)

    @property
    def detector_key(self) -> str:
        """`signals.detector_key` (docs/02): `sigma.<rule_id with '-' -> '_'>`.

        Matches `datagen.types.sigma_key` byte for byte (asserted independently in
        `tests/test_sigma_rule_ids.py` rather than imported — detection code does not depend on
        the synthetic-data generator package, see `app/detection/features.py`'s docstring for the
        same rule applied to a different shared formula).
        """
        return f"sigma.{self.id.strip().lower().replace('-', '_')}"

    @property
    def mitre_techniques(self) -> tuple[str, ...]:
        return tuple(t.removeprefix("attack.t").upper() for t in self.tags if _is_technique(t))

    @property
    def primary_mitre_technique(self) -> str | None:
        techniques = self.mitre_techniques
        return techniques[0] if techniques else None


def _is_technique(tag: str) -> bool:
    return tag.startswith("attack.t") and tag.removeprefix("attack.t")[:1].isdigit()


def load_rule_file(path: Path) -> SigmaRule:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise RuleLoadError(f"{path}: rule file must be a YAML mapping")

    def require(key: str) -> Any:
        if key not in raw:
            raise RuleLoadError(f"{path}: missing required key {key!r}")
        return raw[key]

    rule_id = str(require("id"))
    title = str(require("title"))
    status = str(raw.get("status", "experimental"))

    logsource_raw = require("logsource")
    if not isinstance(logsource_raw, dict) or "product" not in logsource_raw:
        raise RuleLoadError(f"{path}: 'logsource' must be a mapping with a 'product' key")
    logsource = LogSource(
        product=str(logsource_raw["product"]), service=logsource_raw.get("service")
    )

    detection_raw = require("detection")
    if not isinstance(detection_raw, dict):
        raise RuleLoadError(f"{path}: 'detection' must be a mapping")
    condition = detection_raw.get("condition")
    if not isinstance(condition, str) or not condition.strip():
        raise RuleLoadError(f"{path}: 'detection.condition' is required and must be a string")
    timeframe_raw = detection_raw.get("timeframe")
    timeframe_s = parse_timeframe(str(timeframe_raw)) if timeframe_raw is not None else None

    blocks: dict[str, DetectionBlock] = {}
    for name, body in detection_raw.items():
        if name in _RESERVED_DETECTION_KEYS:
            continue
        if not isinstance(body, dict):
            raise RuleLoadError(f"{path}: detection block {name!r} must be a mapping")
        blocks[name] = DetectionBlock.parse(name, body)
    if not blocks:
        raise RuleLoadError(f"{path}: 'detection' defines no blocks")

    level = str(raw.get("level", "medium"))
    tags = tuple(str(t) for t in raw.get("tags", ()))

    entity_raw = require("entity")
    if not isinstance(entity_raw, dict) or "type" not in entity_raw or "by" not in entity_raw:
        raise RuleLoadError(f"{path}: 'entity' must be a mapping with 'type' and 'by'")
    entity = EntitySpec(type=entity_raw["type"], by=str(entity_raw["by"]))

    description = str(raw.get("description", "")).strip()

    rule = SigmaRule(
        id=rule_id,
        title=title,
        status=status,
        logsource=logsource,
        blocks=blocks,
        condition=condition,
        timeframe_s=timeframe_s,
        level=level,
        tags=tags,
        entity=entity,
        description=description,
        path=path,
    )
    return rule
