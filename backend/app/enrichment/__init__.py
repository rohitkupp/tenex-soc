"""Offline enrichment (docs/03-PARSERS-OCSF.md "Enrichment", docs/13-MILESTONES.md M5).

Runs after parse, before anonymization, "so enrichment sees real values" (docs/03) -- this
package must only ever be called with *unpseudonymized* IPs/domains/user-agents. No network
calls anywhere in this package; every dataset is bundled under `backend/data/enrichment/`,
`backend/data/tags/`, or reused from `backend/datagen/data/` (see each submodule's
docstring for exact provenance and honestly-stated coverage limitations).

Public surface -- what `app/workers`' enricher worker (owned by a concurrent agent, out of
this package's scope) is expected to call:

    enrich_ip(ip: str | None) -> IPEnrichment | None
    enrich_domain(domain: str | None, *, as_of: date | None = None) -> DomainEnrichment | None
    enrich_user_agent(user_agent: str | None) -> UserAgentEnrichment | None
    match_tags(*, registrable_domain=None, tld=None, user_agent=None, is_hosting=None) -> list[str]

    enrich_event(event: Mapping[str, Any]) -> dict[str, Any]
    enrich_events(events: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]

`enrich_event`/`enrich_events` are the one-call convenience the worker most likely wants:
they read exactly four keys off whatever mapping is handed in -- `src_ip`, `dst_ip`,
`domain`, `user_agent` (the same names as the docs/02 `events` hot columns and
`OCSFEventBase.hot_columns()`'s output) -- via `.get`, so a full `Event` row, an
OCSF-mapper's hot-columns dict, or a bare `dict` with just those four keys all work
identically; every other key on the input is ignored. The returned dict is exactly what
belongs in `events.enrichment` (docs/02's JSONB column).
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import fields, is_dataclass
from typing import Any

from app.enrichment.domain_enrichment import DomainEnrichment, enrich_domain
from app.enrichment.ip_enrichment import IPEnrichment, enrich_ip
from app.enrichment.tags import match_tags
from app.enrichment.user_agent_enrichment import UserAgentEnrichment, enrich_user_agent

__all__ = [
    "DomainEnrichment",
    "IPEnrichment",
    "UserAgentEnrichment",
    "enrich_domain",
    "enrich_event",
    "enrich_events",
    "enrich_ip",
    "enrich_user_agent",
    "match_tags",
]


def _as_dict(obj: object) -> dict[str, Any] | None:
    if obj is None:
        return None
    assert is_dataclass(obj) and not isinstance(obj, type)  # narrows for mypy; always true here
    return {f.name: getattr(obj, f.name) for f in fields(obj)}


def enrich_event(event: Mapping[str, Any]) -> dict[str, Any]:
    """Build the docs/02 `events.enrichment` payload for one event. See module docstring
    for the exact input contract."""
    src = enrich_ip(event.get("src_ip"))
    dst = enrich_ip(event.get("dst_ip"))
    domain = enrich_domain(event.get("domain"))
    ua = enrich_user_agent(event.get("user_agent"))

    is_hosting = bool(src and src.is_hosting) or bool(dst and dst.is_hosting)
    tags = match_tags(
        registrable_domain=domain.registrable_domain if domain else None,
        tld=domain.tld if domain else None,
        user_agent=event.get("user_agent"),
        is_hosting=is_hosting,
    )

    return {
        "src_ip": _as_dict(src),
        "dst_ip": _as_dict(dst),
        "domain": _as_dict(domain),
        "user_agent": _as_dict(ua),
        "tags": tags,
    }


def enrich_events(events: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Batch convenience. Same order as `events`; independent per event (no shared state
    across the batch beyond the module-level cached datasets)."""
    return [enrich_event(event) for event in events]
