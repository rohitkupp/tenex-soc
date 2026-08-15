"""Tag bank matching (docs/03-PARSERS-OCSF.md "Enrichment": "all -> tag bank match").

Rules loaded from `data/tags/tag_bank.yml` -- see that file's header comment for the schema
and the reasoning behind each category. Distinct from the structured ip/domain/user_agent
enrichment: those answer "what is this value"; tags answer "what kind of thing is this
traffic," for fast event-explorer filtering (docs/13 M3) without reading raw JSON.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache

import yaml

from app.enrichment.loader import DATA_TAGS_DIR

TAG_BANK_YML = DATA_TAGS_DIR / "tag_bank.yml"


@dataclass(frozen=True, slots=True)
class _Rule:
    tag: str
    domain_in: frozenset[str]
    domain_regex: re.Pattern[str] | None
    tld_in: frozenset[str]
    ua_contains: tuple[str, ...]
    is_hosting: bool | None

    @property
    def is_empty(self) -> bool:
        """A rule with no conditions at all would match every event -- guarded against
        explicitly so a malformed YAML entry fails loud (via `match_tags` skipping it,
        proven by a dedicated test) rather than silently tagging everything."""
        return not (
            self.domain_in
            or self.domain_regex is not None
            or self.tld_in
            or self.ua_contains
            or self.is_hosting is not None
        )


@lru_cache(maxsize=1)
def _rules() -> tuple[_Rule, ...]:
    if not TAG_BANK_YML.exists():
        return ()
    data = yaml.safe_load(TAG_BANK_YML.read_text(encoding="utf-8")) or {}
    out: list[_Rule] = []
    for raw in data.get("rules") or []:
        match = raw.get("match") or {}
        domain_regex = (
            re.compile(match["domain_regex"], re.IGNORECASE) if "domain_regex" in match else None
        )
        out.append(
            _Rule(
                tag=raw["tag"],
                domain_in=frozenset(str(d).lower() for d in match.get("domain_in") or []),
                domain_regex=domain_regex,
                tld_in=frozenset(str(t).lower() for t in match.get("tld_in") or []),
                ua_contains=tuple(str(s).lower() for s in match.get("ua_contains") or []),
                is_hosting=match.get("is_hosting"),
            )
        )
    return tuple(out)


def match_tags(
    *,
    registrable_domain: str | None = None,
    tld: str | None = None,
    user_agent: str | None = None,
    is_hosting: bool | None = None,
) -> list[str]:
    """Every present condition on a rule must match (AND); a condition the rule doesn't
    declare is not evaluated at all. Returns tags in `tag_bank.yml` declaration order;
    an event can match any number, including zero."""
    domain_l = (registrable_domain or "").lower()
    tld_l = (tld or "").lower()
    ua_l = (user_agent or "").lower()

    matched: list[str] = []
    for rule in _rules():
        if rule.is_empty:
            continue
        if rule.domain_in and domain_l not in rule.domain_in:
            continue
        if rule.domain_regex is not None and not rule.domain_regex.search(domain_l):
            continue
        if rule.tld_in and tld_l not in rule.tld_in:
            continue
        if rule.ua_contains and not any(kw in ua_l for kw in rule.ua_contains):
            continue
        if rule.is_hosting is not None and bool(is_hosting) != rule.is_hosting:
            continue
        matched.append(rule.tag)
    return matched
