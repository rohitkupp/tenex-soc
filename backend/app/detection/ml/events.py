"""Raw log file -> flat `MLEvent` records, the input `features.py` builds entity-window vectors
from (docs/04 §L3: "the step that turns categorical logs into the continuous numeric regime
these models need").

## Why this module exists, and why it does not touch `app/pipeline`/`app/storage`

The rest of the pipeline's event store is a live Postgres table populated by an upload flowing
through `app/parsers` -> `app/storage` -> `app/workers` (all out of this milestone's ownership,
per the M8 task brief). Training and evaluating the L3 models does not need that path: `docs/11`'s
benign corpus and labeled scenarios are plain files on disk (`python -m datagen benign`/`scenario`),
and `docs/12`'s eval harness scores against `malicious_line_numbers` from `.labels.json`, not
against a `signals` row's `analysis_id`. This module reads those files directly through the same
parser contract the real ingestion path uses (`app.parsers.registry.iter_events`), so a feature
computed here is provably the same feature a live analysis would get — no second parsing path to
drift out of sync with `docs/03`.

`app.detection.ml` does not import `datagen` anywhere (matching the boundary
`app/detection/features.py` states: "Detection code must not depend on the synthetic-data
generator"). Producing the corpus/scenario files is a CLI invocation
(`python -m datagen ...`, run out-of-process by `train.py`/`evaluate.py`), not a Python import —
this module only ever reads the resulting log files, the same as it would read a real customer
upload.

## Enrichment

`app.enrichment.enrich_event` runs per line (ASN/org/country/hosting for IPs, registrable
domain/TLD-risk/age/popularity for domains, family/is_browser/is_automation_tool for user
agents) — the same offline, network-free datasets the real ingestion path uses (docs/03
"Enrichment").

## Department (the `*_z_vs_cohort` family's own baseline)

`MLEvent.department` feeds `features.py`'s department-cohort z-score family (docs/04 §L3 "Peer-
group cohorts": "the cohort variants ... against the entity's department"). See
`_department_from_groups` below for how it is recovered from `actor.user.groups` without this
package importing `app.parsers`/`datagen` internals beyond what it already does.

## Identity events

`EntityKind` still carries an `"identity"` variant and `features.py` still computes
`IDENTITY_FEATURES` from it, even though no registered parser produces one anymore — Okta (the
only identity source) was removed along with CloudTrail, narrowing this project to ZScaler web
proxy logs only. Left in place rather than pruned: `MLEvent.kind` and the identity feature block
are generic ("does this pipeline have an identity source" is a fact about what is registered, not
something `features.py`'s aggregation needs to know), so a future identity parser plugs back in
here — set `kind="identity"` on the `MLEvent`s it produces — without this module or `features.py`
changing shape. Today every `MLEvent` this module yields has `kind="proxy"`, so `IDENTITY_FEATURES`
is simply always zero.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Literal

from app.enrichment import enrich_event
from app.ocsf import HTTPActivity
from app.parsers.base import ParseFailure
from app.parsers.registry import ParseStats, iter_events, make_parser

__all__ = ["MLEvent", "iter_ml_events", "load_ml_events"]

EntityKind = Literal["proxy", "identity"]


@dataclass(frozen=True, slots=True)
class MLEvent:
    """One parsed, enriched log line — the unit `features.py`'s bucketing pass groups by
    `(entity, hour)`. Deliberately wider than `app.detection.signal.events_dao.EventRow`: L2's
    four detectors need five columns between them, but the ~50 L3 features (docs/04) span
    volume, timing, domains, transfer, HTTP, device, and identity, so this row carries
    everything at least one category reads.
    """

    line_no: int
    ts: datetime
    source_type: str  # "zscaler" (datagen.types.SourceType's only registered value)
    kind: EntityKind
    principal: str | None
    src_ip: str | None
    domain: str | None
    registrable_domain: str | None
    url_path: str | None
    http_method: str | None
    status_code: int | None
    bytes_in: int | None
    bytes_out: int | None
    user_agent: str | None
    action: str | None  # ZScaler: allowed/blocked/other (docs/03)
    activity_name: str | None  # ZScaler's own literal action string
    event_key: str | None
    country: str | None
    asn: int | None
    is_hosting: bool
    is_automation_ua: bool
    is_browser_ua: bool
    domain_newly_registered: bool
    domain_high_risk_tld: bool
    domain_is_top_site: bool
    threat_present: bool  # ZScaler `malware[]` non-empty
    is_direct_ip: bool = False  # host is a bare IP literal (docs/04 "Direct-to-IP" rule)
    # An identity source's `target[]` type strings (docs/03) -- always empty today, see module
    # docstring's "Identity events" note.
    resources: tuple[str, ...] = field(default_factory=tuple)
    # Best-effort department label -- see `_department_from_groups` below. `None` when the
    # source event carried no `actor.user.groups` at all (e.g. a service account with neither
    # `location` nor `department` populated).
    department: str | None = None
    # `http_request.referrer`, verbatim -- same "no hot-column home, read straight off the parsed
    # OCSF object" pattern `department` above already uses. Not a docs/02 hot column (see
    # `app/models/event.py`); this is the one place in the detection package that can see it, and
    # `app.detection.ml.navigation` (migration change 18, "navigation chain extractor") is the
    # reason it was added -- see that module's docstring, "Referer field availability."
    referrer: str | None = None


def _department_from_groups(groups: Sequence[str]) -> str | None:
    """Best-effort `department` extraction from `actor.user.groups` (docs/03: "`location` /
    `department` -> `actor.user.groups`", with no further OCSF field to keep the two apart).

    `app/parsers/zscaler.py` (out of this milestone's ownership) builds that list as
    `[g for g in (location, department) if g is not None]` — i.e. it preserves `(location,
    department)` order while dropping whichever side is absent. That means: whenever `department`
    is present, it is always the *last* entry, regardless of whether `location` also is. Every
    `datagen` emitter (`datagen/org.py`'s `User.department` is a required, non-optional field)
    populates both together for every human and service-account principal, so this resolves
    unambiguously against the corpus this package trains and evaluates against — see
    `app.detection.ml.features`'s module docstring for what this feeds (the docs/04 §L3
    department-cohort feature family).

    Ambiguous only in the case this project's own corpus never produces: a real deployment where
    a principal has a `location` but genuinely no `department` on file — that lone entry would be
    misread as a department. Documented rather than silently assumed away, matching this
    package's existing convention for a heuristic that is correct on the corpus it can be
    verified against (`estimate_work_hours`'s own module docstring states the same kind of
    caveat for its self-inclusive baseline).
    """
    return groups[-1] if groups else None


def _hostname_is_ip(hostname: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _from_http_activity(event: HTTPActivity) -> MLEvent:
    hot = event.hot_columns()
    enrichment = enrich_event(
        {
            "src_ip": hot["src_ip"],
            "domain": hot["domain"],
            "user_agent": hot["user_agent"],
        }
    )
    domain_info = enrichment["domain"]
    src_info = enrichment["src_ip"]
    ua_info = enrichment["user_agent"]

    domain = hot["domain"]
    registrable = domain_info["registrable_domain"] if domain_info else domain
    is_direct_ip = bool(domain) and _hostname_is_ip(domain)

    return MLEvent(
        line_no=event.line_no,
        ts=event.time,
        source_type=event.source_type,
        kind="proxy",
        principal=hot["principal"],
        src_ip=hot["src_ip"],
        domain=domain,
        registrable_domain=(registrable if not is_direct_ip else domain),
        url_path=hot["url_path"],
        http_method=hot["http_method"],
        status_code=hot["status_code"],
        bytes_in=hot["bytes_in"],
        bytes_out=hot["bytes_out"],
        user_agent=hot["user_agent"],
        action=hot["action"],
        activity_name=event.activity_name,
        event_key=hot["event_key"],
        country=src_info["country"] if src_info else None,
        asn=src_info["asn"] if src_info else None,
        is_hosting=bool(src_info and src_info["is_hosting"]),
        is_automation_ua=bool(ua_info and ua_info["is_automation_tool"]),
        is_browser_ua=bool(ua_info and ua_info["is_browser"]),
        domain_newly_registered=bool(domain_info and domain_info["newly_registered"]),
        domain_high_risk_tld=bool(domain_info and domain_info["tld_risk_tier"] == "high"),
        domain_is_top_site=bool(domain_info and domain_info["is_top_site"]),
        threat_present=bool(event.malware),
        is_direct_ip=is_direct_ip,
        department=_department_from_groups(event.actor.user.groups),
        referrer=event.http_request.referrer if event.http_request else None,
    )


def iter_ml_events(
    path: Path, source_type: str, *, stats: ParseStats | None = None
) -> Iterator[MLEvent]:
    """Parse one log file into `MLEvent`s, in file order. `line_no` on each result is 1-based and
    matches `GroundTruth.malicious_line_numbers` exactly (same contract `iter_events` documents),
    which is what lets the eval harness (docs/12) join a scored entity-window back to labeled
    malicious lines.

    Every parsed result is an `HTTPActivity` today (ZScaler is the only registered source), so
    this always yields exactly one `MLEvent` per successfully-parsed line via
    `_from_http_activity`. Kept as an `isinstance` dispatch rather than collapsed into a single
    unconditional call so a future identity-source parser (module docstring, "Identity events")
    only has to add its own `_from_<source>` branch here, not restructure this function.
    """
    parser = make_parser(source_type)
    with path.open("r", encoding="utf-8") as fh:
        for result in iter_events(source_type, fh, parser=parser):
            if stats is not None:
                stats.record(result)
            if isinstance(result, ParseFailure):
                continue
            if isinstance(result, HTTPActivity):
                yield _from_http_activity(result)


def load_ml_events(paths: dict[str, Path], *, stats: ParseStats | None = None) -> list[MLEvent]:
    """Parse every `{source_type: path}` pair and return one time-ordered list.

    `paths` keys are `datagen.types.SourceType` values (`"zscaler"`, the only one registered);
    callers build this dict from whatever files `python -m datagen` wrote (see `train.py`/
    `evaluate.py`), which is the only place this module's caller needs to know the datagen output
    naming convention — this function itself takes plain paths and never touches `datagen`.
    """
    events: list[MLEvent] = []
    for source_type, path in paths.items():
        events.extend(iter_ml_events(path, source_type, stats=stats))
    events.sort(key=lambda e: (e.ts, e.line_no))
    return events
