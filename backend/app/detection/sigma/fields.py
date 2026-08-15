"""Sigma field name -> SQL expression, over `events` (docs/02) plus `events.enrichment` (docs/03
M5) and `events.ocsf` (docs/03 mappers).

A rule's `detection` blocks reference *logical* field names (`principal`, `status`,
`url_category`, `country`, ...), not raw SQL — the whole point of Sigma is that a rule author
writes what they mean, not a JSONB path. This module is the one place that translation happens,
so every rule gets it for free and no rule file ever embeds a `->>'foo'` operator itself.

Three tiers, cheapest first:

1. **Hot columns** (`app.models.event.Event`) — indexed, and several OCSF fields are already
   projected onto one by `hot_columns()` at parse time (docs/03): `action` carries the ZScaler
   `disposition` (allowed/blocked/...) — and, before Okta was removed, carried its `status`
   (SUCCESS/FAILURE/...) the same way, which is why `status`/`disposition` still both resolve to
   `action` below rather than a slower `ocsf->>'status'` lookup, and why the mapping stays
   name-for-name rather than collapsed to a single alias now that only one source feeds it.
2. **`ocsf` JSONB paths** — anything docs/03's mappers put in the OCSF-fidelity blob but not in a
   hot column: geo coordinates, the malware/threat block, `unmapped.*` (ZScaler's
   `url_supercategory`, which is exactly what the "malicious URL category" rule keys on per
   `datagen/emitters/zscaler.py`'s own comment).
3. **`enrichment` JSONB paths** — M5's offline enrichment payload
   (`app.enrichment.enrich_event`'s docstring documents the exact shape:
   `{src_ip, dst_ip, domain, user_agent, tags}`, each a small dict or `None`).

Plus a handful of **computed fields** that are not a single JSON path — a regex test or an hour
extraction — each documented at its definition below with the rule that needs it and why it
can't just be a path lookup.

Every resolver takes an `entity` — the mapped class (or `sqlalchemy.orm.aliased` alias of it) the
expression should be built against. `app.detection.sigma.compiler` needs this: the cross-source
rules and `not_seen_before`/`speed_kmh` aggregations self-join or correlate `events` against
itself (a different alias per side of the join), and a resolver hardcoded to the bare `Event`
class could only ever build one side of that.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Final

from sqlalchemy import ColumnElement, Numeric, Text, cast, func, literal, select
from sqlalchemy.orm import aliased

from app.models.event import Event

__all__ = [
    "BOOLEAN_FIELDS",
    "FieldResolutionError",
    "resolve_bool_field",
    "resolve_field",
    "resolve_numeric_field",
    "resolve_text_field",
]

EventLike = type[Event]
# `ColumnElement[Any]`, not `ColumnElement[object]`: SQLAlchemy's `ColumnElement` is invariant in
# its type parameter, so a `Callable[..., ColumnElement[bool]]` is not a subtype of
# `Callable[..., ColumnElement[object]]` even though `bool` is a subtype of `object` — every
# resolver in this module returns a differently-typed `ColumnElement` (`bool`, `float`, a JSONB
# scalar, ...) and is stored in one dict, so the common type has to be `Any`, which (unlike
# `object`) suppresses variance checking instead of tripping it.
FieldFn = Callable[[EventLike], ColumnElement[Any]]


class FieldResolutionError(ValueError):
    """A rule references a field name this evaluator does not know how to translate to SQL."""


# ---------------------------------------------------------------------------- hot columns

# Sigma field name -> `Event` attribute, for the fields that are already a projected, indexed
# column (docs/02 "hot columns"). `status`/`disposition` both land on `action` — see module
# docstring point 1.
_HOT_COLUMNS: Final[dict[str, str]] = {
    "principal": "principal",
    "src_ip": "src_ip",
    "dst_ip": "dst_ip",
    "domain": "domain",
    "url_path": "url_path",
    "action": "action",
    "status": "action",
    "disposition": "action",
    "http_method": "http_method",
    "status_code": "status_code",
    "bytes_in": "bytes_in",
    "bytes_out": "bytes_out",
    "user_agent": "user_agent",
    "event_key": "event_key",
    "source_type": "source_type",
    "ts": "ts",
}

# ---------------------------------------------------------------------------- ocsf JSONB paths

# Sigma field name -> path segments into `Event.ocsf` (a `model_dump(mode="json")` of the
# Pydantic OCSF event — see app/ocsf/base.py, app/ocsf/http_activity.py). A few of these paths
# (`auth_protocol`, `status_detail`, and the geo/ASN fields) were populated only by Okta's now-
# removed Authentication (3002) mapping; ZScaler's HTTPActivity never sets them, so they resolve
# to SQL `NULL` today rather than being pruned -- a future identity source can repopulate them
# without this table changing shape.
_OCSF_TEXT_PATHS: Final[dict[str, tuple[str, ...]]] = {
    "activity_name": ("activity_name",),
    "status_detail": ("status_detail",),
    "auth_protocol": ("auth_protocol",),
    "country": ("src_endpoint", "location", "country"),
    "city": ("src_endpoint", "location", "city"),
    "asn": ("src_endpoint", "autonomous_system", "number"),
    "url_supercategory": ("unmapped", "url_supercategory"),
    "url_category": ("http_request", "url", "category_ids", "0"),
    # First entry of `malware[]` (docs/03 ZScaler mapping; at most one entry is ever appended —
    # `app/parsers/zscaler.py` only creates a `Malware` record when `threatname` is present).
    "threat_name": ("malware", "0", "name"),
    "threat_category": ("malware", "0", "classification_ids", "0"),
    # docs/03's ZScaler field table: `dlpengine` / `dlpdictionaries` -> `unmapped.dlp_*`
    # (`app/parsers/zscaler.py` only populates these keys when the source field is non-`None`).
    # Added for the docs/04 §L1 "DLP engine trigger on an outbound request" rule (T1048.003) — a
    # field the surviving seven rules never used.
    "dlp_engine": ("unmapped", "dlp_engine"),
    "dlp_dictionaries": ("unmapped", "dlp_dictionaries"),
}

_OCSF_NUMERIC_PATHS: Final[dict[str, tuple[str, ...]]] = {
    "lat": ("src_endpoint", "location", "coordinates", "lat"),
    "lon": ("src_endpoint", "location", "coordinates", "lon"),
    # docs/03's ZScaler field table: `riskscore` -> `risk_score`, a top-level `HTTPActivity` field
    # (`app/ocsf/http_activity.py`), not a hot column — so it lives in `events.ocsf` at the
    # single-segment path `risk_score`, not nested under `http_request`/`unmapped`. Added for the
    # docs/04 §L1 "ZScaler risk score >= 80 on an otherwise-allowed request" rule (T1071).
    "risk_score": ("risk_score",),
}

# ---------------------------------------------------------------------------- enrichment JSONB

# `app.enrichment.enrich_event`'s docstring: "{src_ip, dst_ip, domain, user_agent, tags}".
_ENRICHMENT_BOOL_PATHS: Final[dict[str, tuple[str, ...]]] = {
    "is_automation_tool": ("user_agent", "is_automation_tool"),
    "is_newly_registered_domain": ("domain", "newly_registered"),
    "is_hosting_src_ip": ("src_ip", "is_hosting"),
    "is_hosting_dst_ip": ("dst_ip", "is_hosting"),
}
_ENRICHMENT_TEXT_PATHS: Final[dict[str, tuple[str, ...]]] = {
    "domain_risk_tier": ("domain", "tld_risk_tier"),
    "registrable_domain": ("domain", "registrable_domain"),
}

# Fields whose resolved expression is *already* a boolean condition (an enrichment/computed
# predicate), as opposed to a value column compared against a filter value. `app.detection.sigma.
# compiler` needs to tell the two apart: `direct_to_ip: true` uses the expression as-is (or
# negated for `false`); `principal: 'jdoe@corp.example'` compares a value column with `==`.
BOOLEAN_FIELDS: Final[frozenset[str]] = frozenset(_ENRICHMENT_BOOL_PATHS) | frozenset(
    {"direct_to_ip", "has_download_extension"}
)


def _path_segment(segment: str) -> str | int:
    """A pure-digit path segment (`"0"`) means "the first element of a JSON array" (`malware[0]`,
    `category_ids[0]` — docs/03's list-valued OCSF fields) and must be bound as an *integer*, not
    text: Postgres's `jsonb -> text` operator only indexes object keys and silently returns `NULL`
    for an array (there is no such thing as an array "keyed" by the string `"0"`); `jsonb ->
    integer` is the separate operator overload that indexes by array position. Any other segment
    is a real object key and stays a string."""
    return int(segment) if segment.isdigit() else segment


def _jsonb_text_path(column: Any, path: tuple[str, ...]) -> ColumnElement[str]:
    """`col->'a'->'b'->>'c'` — every segment but the last with `->`, the last with `->>`.

    `column` is typed `Any`, not `ColumnElement[Any]`: the two JSONB columns callers pass
    (`Event.ocsf`, `Event.enrichment`) are ORM `InstrumentedAttribute`s, which structurally
    support the same `.op()` protocol at runtime (SQLAlchemy resolves them to their underlying
    `ColumnElement` via `__clause_element__`) but are not one in the type system, and mypy's
    invariant generics mean nothing short of `Any` accepts both that and the plain
    `ColumnElement[str]` this function also feeds itself in its own multi-segment loop below.
    """
    expr = column
    for segment in path[:-1]:
        expr = expr.op("->")(_path_segment(segment))
    return expr.op("->>")(_path_segment(path[-1]))  # type: ignore[no-any-return]


def _jsonb_bool_path(column: Any, path: tuple[str, ...]) -> ColumnElement[bool]:
    """`->>` always yields JSON's text rendering of a scalar, so a JSON `true` reads back as the
    literal string `"true"` — comparing against that string is simpler and just as correct as
    round-tripping through a second JSONB cast."""
    return _jsonb_text_path(column, path) == literal("true")


# ---------------------------------------------------------------------------- computed fields

# `direct_to_ip` (docs/04 proxy rule "Direct-to-IP HTTP request", T1071.001): the ZScaler `host`
# field (-> `domain` hot column, docs/03) is itself a dotted-quad IPv4 literal rather than a
# hostname — no DNS resolution happened. A plain regex test on the indexed hot column, not a
# dependency on `enrichment.domain` (which reports "unknown" for an IP just as honestly as it
# would for any un-enriched hostname, per `app/enrichment/domain_enrichment.py`'s own docstring,
# and is not guaranteed to have run yet — the enricher worker is still a skeleton, docs/13 M5 vs
# the M4 pipeline wiring).
_IPV4_RE: Final[str] = (
    r"^(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])"
    r"(\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}$"
)


def _direct_to_ip(entity: EventLike) -> ColumnElement[bool]:
    return entity.domain.op("~")(literal(_IPV4_RE))


# `hour_utc` — fractional UTC hour of day, for `api_token_created_off_hours` (docs/04 identity
# rule, T1098.001). Deliberately a fixed, global UTC band rather than the L3 canonical per-user
# local-time `is_off_hours` (`app/detection/features.py`): that function needs a per-user
# `WorkHours` (timezone offset + local start/end hour) which is a `datagen` construct with no
# home in `events` or any docs/02 table — OCSF carries a login's *geolocation*, not the
# principal's *employment* timezone, and the two differ for travel, VPNs and remote work by
# construction. `app/detection/features.py`'s own docstring reserves per-user local-hours scoring
# for L3 (M8); see `api-token-created-off-hours.yml` for the derivation of the UTC band this
# resolves against (the intersection of "off hours" across all three simulated offices, docs/11
# "Simulated org": US-CA, US-NY, IE-DU).
def _hour_utc(entity: EventLike) -> ColumnElement[float]:
    # Postgres has no `numeric % double precision` (or `double precision % double precision`)
    # overload of the `%` operator — only `numeric % numeric` and the integer types. Casting the
    # divisor literal to `numeric` too (rather than leaving it an untyped Python float bind, which
    # psycopg sends as `double precision`) keeps both operands the same type.
    hours = cast(func.extract("epoch", entity.ts), Numeric) / cast(literal(3600.0), Numeric)
    return func.mod(hours, cast(literal(24.0), Numeric))


# `domain_event_count` — how many events in *this analysis* (any principal, any source) touched
# the same `domain` as the current row. A cheap, self-contained proxy for the L2 `signal.rarity`
# formula (docs/04: `1 / (1 + org_wide_event_count(domain))`) for the one rule that needs a rarity
# *predicate* at L1 rather than L2's own scored signal — the cross-source
# "auth failure burst ... contacting a rare domain" rule
# (`xsrc-auth-burst-and-rare-domain.yml`) needs *some* notion of rare available inside a single SQL
# query, and duplicating L2's full org-wide statistic here (owned by a different package,
# `app/detection/signal/`, per this task's ownership split) would be exactly the kind of
# second, silently-different definition `app/detection/features.py`'s docstring warns about. This
# is deliberately coarser and stated as such in that rule's YAML.
def _domain_event_count(entity: EventLike) -> ColumnElement[Any]:
    other = aliased(Event)
    return (
        select(func.count())
        .select_from(other)
        .where(other.analysis_id == entity.analysis_id, other.domain == entity.domain)
        .correlate(entity)
        .scalar_subquery()
    )


# `has_download_extension` (docs/04 §L1 "Executable/archive download from an uncategorized or
# newly-registered domain", T1105 — another field the surviving seven rules never used, per
# docs/04's own note: "file extension on `url_path`"). A regex test on the already-indexed
# `url_path` hot column (docs/03: ZScaler's `url` field, "path and query only") for a filename
# extension associated with an executable payload or an archive commonly used to smuggle one,
# immediately before the query string or the end of the path — same "test the syntactic fact on
# the hot column directly, don't wait on enrichment" reasoning as `_direct_to_ip` above. Matched
# case-insensitively (`~*`, not `~`): a real download URL's extension case is not a meaningful
# signal here and treating `.EXE` as a miss would just be a free evasion.
_DOWNLOAD_EXTENSION_RE: Final[str] = (
    r"\.(exe|msi|dll|bat|cmd|ps1|vbs|scr|jar|apk|zip|rar|7z|tar\.gz|tgz|tar|gz|iso)(\?|$)"
)


def _has_download_extension(entity: EventLike) -> ColumnElement[bool]:
    return entity.url_path.op("~*")(literal(_DOWNLOAD_EXTENSION_RE))


_COMPUTED: Final[dict[str, FieldFn]] = {
    "direct_to_ip": _direct_to_ip,
    "hour_utc": _hour_utc,
    "domain_event_count": _domain_event_count,
    "has_download_extension": _has_download_extension,
}


def resolve_field(name: str, entity: EventLike = Event) -> ColumnElement[Any]:
    """Sigma field name -> a SQLAlchemy Core column expression usable in a `WHERE`/`SELECT`,
    built against `entity` (defaults to the bare `Event` mapped class; pass an
    `sqlalchemy.orm.aliased(Event)` alias when the compiler needs a second, independent
    reference to `events` in the same query — a self-join or correlated subquery).

    Raises `FieldResolutionError` for any name none of the tiers above recognize — a rule with a
    typo'd field name fails loudly at load time (`app.detection.sigma.compiler`), not silently at
    zero-recall at runtime.
    """
    if name in _HOT_COLUMNS:
        return getattr(entity, _HOT_COLUMNS[name])  # type: ignore[no-any-return]
    if name in _COMPUTED:
        return _COMPUTED[name](entity)
    if name in _OCSF_TEXT_PATHS:
        return _jsonb_text_path(entity.ocsf, _OCSF_TEXT_PATHS[name])
    if name in _OCSF_NUMERIC_PATHS:
        return cast(_jsonb_text_path(entity.ocsf, _OCSF_NUMERIC_PATHS[name]), Numeric)
    if name in _ENRICHMENT_BOOL_PATHS:
        return _jsonb_bool_path(entity.enrichment, _ENRICHMENT_BOOL_PATHS[name])
    if name in _ENRICHMENT_TEXT_PATHS:
        return _jsonb_text_path(entity.enrichment, _ENRICHMENT_TEXT_PATHS[name])
    raise FieldResolutionError(
        f"unknown Sigma field {name!r}; add it to app.detection.sigma.fields if the field is "
        "real, or fix the typo in the rule YAML"
    )


def resolve_numeric_field(name: str, entity: EventLike = Event) -> ColumnElement[Any]:
    """Like `resolve_field`, cast to `numeric` — for a field compared against a numeric literal
    (`hour_utc`, `bytes_out`, ...) that might be resolved from a JSONB text path rather than an
    already-numeric hot column."""
    if name in _HOT_COLUMNS or name in _COMPUTED:
        return resolve_field(name, entity)
    return cast(resolve_field(name, entity), Numeric)


def resolve_bool_field(name: str, entity: EventLike = Event) -> ColumnElement[bool]:
    """Like `resolve_field`, for a field in `BOOLEAN_FIELDS` — whose resolved expression is
    already a boolean condition (`direct_to_ip`, `enrichment.*` flags), not a value column. The
    only caller is `app.detection.sigma.compiler._value_predicate`'s boolean-field branch, which
    checks membership in `BOOLEAN_FIELDS` first — this does not re-check it, so calling it on a
    non-boolean field name would return whatever `resolve_field` gives back, mistyped."""
    return resolve_field(name, entity)


# `src_ip`/`dst_ip` are `INET`-typed hot columns (docs/02). Postgres's plain `::text` cast on an
# `inet` value keeps the netmask suffix (`'198.51.100.9'::inet::text` -> `'198.51.100.9/32'`) —
# correct, but not what a `signals.entity_value` or a grouping key should look like. `host()` is
# the same cast without the surprise suffix.
_INET_FIELDS: Final[frozenset[str]] = frozenset({"src_ip", "dst_ip"})


def resolve_text_field(name: str, entity: EventLike = Event) -> ColumnElement[str]:
    """Like `resolve_field`, coerced to a clean `text` representation — for building a grouping
    key or an `entity_value` out of a field that might be a non-text column type."""
    col = resolve_field(name, entity)
    if name in _INET_FIELDS:
        return func.host(col)
    return cast(col, Text)
