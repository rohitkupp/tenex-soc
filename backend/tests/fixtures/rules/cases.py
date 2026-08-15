"""One `FixtureCase` per rule in `app/detection/rules/*.yml` — docs/04: "Each rule needs a
positive and a negative fixture in tests/fixtures/rules/." `tests/test_rules_fixtures.py` drives
every case in `CASES` through the real evaluator against the real Postgres `events` table.

Each `positive` list is built to clear its rule's threshold with a small, legible margin — not
buried in a mountain of incidental rows — and each `negative` list is built to *almost* fire
(same shape, one axis kept just under the rule's own threshold) rather than being unrelated
traffic that would trivially not match anything. A rule that only tests "empty input doesn't
fire" has not tested its own boundary.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

from app.storage.event_writer import SimpleEventRecord
from tests.fixtures.rules.events import T0, zscaler_event

__all__ = ["CASES", "FixtureCase"]


@dataclass(frozen=True, slots=True)
class FixtureCase:
    rule_id: str
    positive: list[SimpleEventRecord]
    negative: list[SimpleEventRecord]


CASES: dict[str, FixtureCase] = {}


def _register(
    rule_id: str, positive: list[SimpleEventRecord], negative: list[SimpleEventRecord]
) -> None:
    CASES[rule_id] = FixtureCase(rule_id=rule_id, positive=positive, negative=negative)


# ---------------------------------------------------------------------------- proxy rules

_register(
    "malicious-url-category",
    positive=[
        zscaler_event(
            "vic@corp.example",
            T0,
            "badsite.top",
            disposition="blocked",
            url_supercategory="Security",
            url_category="Botnet Callback",
        ),
    ],
    negative=[
        zscaler_event(
            "vic@corp.example",
            T0,
            "docs.google.com",
            disposition="allowed",
            url_supercategory="Business and Economy",
            url_category="Web-based Productivity Apps",
        ),
    ],
)

_register(
    "threat-name-present",
    positive=[
        zscaler_event(
            "vic@corp.example",
            T0,
            "badc2.top",
            disposition="blocked",
            threat_name="Backdoor.Generic.C2",
            threat_category="Botnet",
        ),
    ],
    negative=[
        zscaler_event("vic@corp.example", T0, "example.com", disposition="allowed"),
    ],
)

_register(
    "credentials-in-url",
    positive=[
        zscaler_event(
            "vic@corp.example",
            T0,
            "legacyapp.example",
            url_path="/api/v1/login?user=vic&password=hunter2",
        ),
    ],
    negative=[
        zscaler_event(
            "vic@corp.example", T0, "legacyapp.example", url_path="/api/v1/login?user=vic"
        ),
    ],
)

_register(
    "blocked-then-allowed",
    positive=[
        zscaler_event(
            "vic@corp.example", T0, "evasion.example", disposition="blocked", src_ip="203.0.113.9"
        ),
        zscaler_event(
            "vic@corp.example",
            T0 + timedelta(minutes=2),
            "evasion.example",
            disposition="allowed",
            src_ip="203.0.113.9",
        ),
    ],
    negative=[
        # Same shape, but the block is 20 minutes before the allow -- outside the 5m timeframe.
        zscaler_event(
            "vic@corp.example", T0, "evasion.example", disposition="blocked", src_ip="203.0.113.9"
        ),
        zscaler_event(
            "vic@corp.example",
            T0 + timedelta(minutes=20),
            "evasion.example",
            disposition="allowed",
            src_ip="203.0.113.9",
        ),
    ],
)

_register(
    "non-browser-user-agent",
    positive=[
        zscaler_event("vic@corp.example", T0, "example.com", user_agent="curl/8.4.0"),
    ],
    negative=[
        zscaler_event("vic@corp.example", T0, "example.com"),  # default browser UA
    ],
)

_register(
    "large-post-to-new-domain",
    positive=[
        zscaler_event(
            "vic@corp.example",
            T0,
            "freshly-registered.top",
            http_method="POST",
            bytes_out=15_000_000,
            url_category="Newly Registered and Revived Domains",
        ),
    ],
    negative=[
        # Large upload, but to a well-known, categorized SaaS destination.
        zscaler_event(
            "vic@corp.example",
            T0,
            "drive.google.com",
            http_method="POST",
            bytes_out=15_000_000,
            url_category="Web-based Productivity Apps",
        ),
    ],
)

_register(
    "direct-to-ip-request",
    positive=[
        zscaler_event("vic@corp.example", T0, "198.51.100.77"),
    ],
    negative=[
        zscaler_event("vic@corp.example", T0, "example.com"),
    ],
)

assert set(CASES) == {
    "malicious-url-category",
    "threat-name-present",
    "credentials-in-url",
    "blocked-then-allowed",
    "non-browser-user-agent",
    "large-post-to-new-domain",
    "direct-to-ip-request",
}, "every rule id in app/detection/rules/*.yml must have a fixture case"
