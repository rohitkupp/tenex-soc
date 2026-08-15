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
"Enrichment"). Okta's own `src_endpoint.location.country` / `.autonomous_system.number` (present
on the OCSF object, not proxy IP-range-derived) are preferred over IP enrichment for identity
events, since Okta ships genuine client geolocation and ZScaler's `HTTPActivity` does not
(docs/03's mapping tables).
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Literal

from app.enrichment import enrich_event
from app.ocsf import Authentication, HTTPActivity
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
    source_type: str  # "zscaler" | "okta" | "cloudtrail" (datagen.types.SourceType values)
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
    action: str | None  # ZScaler: allowed/blocked/other. Okta: SUCCESS/FAILURE/... (docs/03)
    activity_name: str | None  # Okta eventType (docs/03); ZScaler's own literal action string
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
    resources: tuple[str, ...] = field(default_factory=tuple)  # Okta target[] type strings


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
    )


def _from_authentication(event: Authentication) -> MLEvent:
    hot = event.hot_columns()
    enrichment = enrich_event(
        {"src_ip": hot["src_ip"], "domain": None, "user_agent": hot["user_agent"]}
    )
    src_info = enrichment["src_ip"]
    ua_info = enrichment["user_agent"]

    # Okta's own geolocation (docs/03) wins over IP-range enrichment when present — it is real
    # client-reported geo, not a CIDR-block guess.
    okta_country = event.src_endpoint.location.country if event.src_endpoint.location else None
    okta_asn = (
        event.src_endpoint.autonomous_system.number
        if event.src_endpoint.autonomous_system
        else None
    )

    return MLEvent(
        line_no=event.line_no,
        ts=event.time,
        source_type=event.source_type,
        kind="identity",
        principal=hot["principal"],
        src_ip=hot["src_ip"],
        domain=None,
        registrable_domain=None,
        url_path=None,
        http_method=None,
        status_code=None,
        bytes_in=None,
        bytes_out=None,
        user_agent=hot["user_agent"],
        action=hot["action"],
        activity_name=event.activity_name,
        event_key=hot["event_key"],
        country=okta_country or (src_info["country"] if src_info else None),
        asn=okta_asn if okta_asn is not None else (src_info["asn"] if src_info else None),
        is_hosting=bool(src_info and src_info["is_hosting"]),
        is_automation_ua=bool(ua_info and ua_info["is_automation_tool"]),
        is_browser_ua=bool(ua_info and ua_info["is_browser"]),
        domain_newly_registered=False,
        domain_high_risk_tld=False,
        domain_is_top_site=False,
        threat_present=False,
        resources=tuple(r.type for r in event.resources if r.type),
    )


def iter_ml_events(
    path: Path, source_type: str, *, stats: ParseStats | None = None
) -> Iterator[MLEvent]:
    """Parse one log file into `MLEvent`s, in file order. `line_no` on each result is 1-based and
    matches `GroundTruth.malicious_line_numbers` exactly (same contract `iter_events` documents),
    which is what lets the eval harness (docs/12) join a scored entity-window back to labeled
    malicious lines.

    CloudTrail is parsed (so a mixed-source corpus round-trips cleanly) but produces no `MLEvent`
    rows — docs/04's L3 feature vector is scoped to proxy + identity sources (Volume/Temporal/
    Domains/Transfer/HTTP/Device from ZScaler, Identity from Okta); CloudTrail "exists mainly to
    prove the parser interface generalizes" (docs/03) and is not one of the two entity sources
    (`principal`, `src_ip`) docs/04's L3 section scopes this milestone to.
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
            elif isinstance(result, Authentication):
                yield _from_authentication(result)
            # APIActivity (CloudTrail) intentionally produces no MLEvent — see docstring.


def load_ml_events(paths: dict[str, Path], *, stats: ParseStats | None = None) -> list[MLEvent]:
    """Parse every `{source_type: path}` pair and return one time-ordered list.

    `paths` keys are `datagen.types.SourceType` values (`"zscaler"`, `"okta"`, `"cloudtrail"`);
    callers build this dict from whatever files `python -m datagen` wrote (see `train.py`/
    `evaluate.py`), which is the only place this module's caller needs to know the datagen output
    naming convention — this function itself takes plain paths and never touches `datagen`.
    """
    events: list[MLEvent] = []
    for source_type, path in paths.items():
        events.extend(iter_ml_events(path, source_type, stats=stats))
    events.sort(key=lambda e: (e.ts, e.line_no))
    return events
