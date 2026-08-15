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
from tests.fixtures.rules.events import T0, okta_event, zscaler_event

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

# ---------------------------------------------------------------------------- identity rules


def _mfa_burst(
    principal: str, n_failures: int, *, interval_s: float = 60.0, src_ip: str = "203.0.113.5"
) -> list[SimpleEventRecord]:
    events = []
    t = T0
    for _ in range(n_failures):
        events.append(
            okta_event(principal, t, "user.authentication.auth_via_mfa", "FAILURE", src_ip=src_ip)
        )
        t += timedelta(seconds=interval_s)
    events.append(
        okta_event(principal, t, "user.authentication.auth_via_mfa", "SUCCESS", src_ip=src_ip)
    )
    return events


_register(
    "okta-mfa-fatigue",
    positive=_mfa_burst("fatigue.pos@corp.example", 6),
    negative=_mfa_burst("fatigue.neg@corp.example", 3),
)

_register(
    "brute-force",
    positive=[
        okta_event(
            "brute.pos@corp.example",
            T0 + timedelta(seconds=30 * i),
            "user.session.start",
            "FAILURE",
        )
        for i in range(22)
    ],
    negative=[
        okta_event(
            "brute.neg@corp.example",
            T0 + timedelta(seconds=30 * i),
            "user.session.start",
            "FAILURE",
        )
        for i in range(10)
    ],
)


def _spray(
    n_principals: int, attempts_each: int, *, prefix: str, src_ip: str
) -> list[SimpleEventRecord]:
    events = []
    t = T0
    for _ in range(attempts_each):
        for i in range(n_principals):
            events.append(
                okta_event(
                    f"{prefix}{i}@corp.example", t, "user.session.start", "FAILURE", src_ip=src_ip
                )
            )
            t += timedelta(seconds=30)
    return events


_register(
    "password-spray",
    positive=_spray(18, 2, prefix="spray.pos", src_ip="198.51.100.20"),
    # Pen-test shaped: fewer than 10 distinct principals.
    negative=_spray(8, 2, prefix="spray.neg", src_ip="198.51.100.21"),
)

_register(
    "impossible-travel",
    positive=[
        okta_event(
            "travel.pos@corp.example",
            T0,
            "user.session.start",
            "SUCCESS",
            src_ip="203.0.113.10",
            country="US",
            lat=37.77,
            lon=-122.42,
        ),
        okta_event(
            "travel.pos@corp.example",
            T0 + timedelta(hours=1),
            "user.session.start",
            "SUCCESS",
            src_ip="198.51.100.44",
            country="RU",
            lat=55.75,
            lon=37.62,
        ),
    ],
    negative=[
        # Same two endpoints, but 20 hours apart -- a physically plausible flight.
        okta_event(
            "travel.neg@corp.example",
            T0,
            "user.session.start",
            "SUCCESS",
            src_ip="203.0.113.10",
            country="US",
            lat=37.77,
            lon=-122.42,
        ),
        okta_event(
            "travel.neg@corp.example",
            T0 + timedelta(hours=20),
            "user.session.start",
            "SUCCESS",
            src_ip="198.51.100.44",
            country="RU",
            lat=55.75,
            lon=37.62,
        ),
    ],
)

_register(
    "first-login-new-country",
    positive=[
        okta_event("geo.pos@corp.example", T0, "user.session.start", "SUCCESS", country="US"),
        okta_event(
            "geo.pos@corp.example",
            T0 + timedelta(days=1),
            "user.session.start",
            "SUCCESS",
            country="US",
        ),
        okta_event(
            "geo.pos@corp.example",
            T0 + timedelta(days=2),
            "user.session.start",
            "SUCCESS",
            country="RU",
        ),
    ],
    negative=[
        okta_event("geo.neg@corp.example", T0, "user.session.start", "SUCCESS", country="US"),
        okta_event(
            "geo.neg@corp.example",
            T0 + timedelta(days=1),
            "user.session.start",
            "SUCCESS",
            country="US",
        ),
    ],
)

_register(
    "mfa-factor-deactivated",
    positive=[
        okta_event("deact.pos@corp.example", T0, "user.mfa.factor.deactivate", "SUCCESS"),
    ],
    negative=[
        okta_event("deact.neg@corp.example", T0, "user.mfa.factor.activate", "SUCCESS"),
    ],
)

_register(
    "api-token-created-off-hours",
    positive=[
        # 04:00 UTC -- inside the [01:30, 09:00) off-hours-for-everyone band.
        okta_event(
            "token.pos@corp.example",
            T0.replace(hour=4, minute=0),
            "system.api_token.create",
            "SUCCESS",
        ),
    ],
    negative=[
        # 15:00 UTC -- on-hours for every simulated office.
        okta_event(
            "token.neg@corp.example",
            T0.replace(hour=15, minute=0),
            "system.api_token.create",
            "SUCCESS",
        ),
    ],
)

_register(
    "privilege-grant",
    positive=[
        okta_event("grant.pos@corp.example", T0, "user.account.privilege.grant", "SUCCESS"),
    ],
    negative=[
        okta_event("grant.neg@corp.example", T0, "application.user_membership.add", "SUCCESS"),
    ],
)

# ---------------------------------------------------------------------------- cross-source rules

_register(
    "xsrc-auth-burst-and-rare-domain",
    positive=[
        # 12 distinct principals, <=3 attempts each, one src_ip -- clears the same
        # >=10-distinct-principal spray threshold `password-spray.yml` uses.
        *[
            okta_event(
                f"xsrc.pos{i}@corp.example",
                T0 + timedelta(seconds=20 * i),
                "user.session.start",
                "FAILURE",
                src_ip="198.51.100.30",
            )
            for i in range(12)
        ],
        zscaler_event(
            "xsrc.pos0@corp.example",
            T0 + timedelta(minutes=5),
            "raretail.example",
            src_ip="198.51.100.30",
        ),
    ],
    negative=[
        # Pen-test shaped: only 8 distinct principals (like s10_benign_but_weird's negative
        # control) from that src_ip -- well over 5 *raw* failure events, but under the
        # >=10-distinct-principal threshold this rule actually keys on -- and the proxy hit from
        # that src_ip is a popular, heavily-trafficked domain (simulated by many *other*
        # principals also hitting it, so its in-analysis event count clears the rarity
        # threshold too; either gap alone is enough to keep this negative).
        *[
            okta_event(
                f"xsrc.neg{i}@corp.example",
                T0 + timedelta(seconds=20 * i),
                "user.session.start",
                "FAILURE",
                src_ip="198.51.100.31",
            )
            for i in range(8)
        ],
        zscaler_event(
            "xsrc.neg0@corp.example",
            T0 + timedelta(minutes=5),
            "popular.example",
            src_ip="198.51.100.31",
        ),
        *[
            zscaler_event(
                f"other.user{i}@corp.example",
                T0 + timedelta(minutes=6, seconds=i),
                "popular.example",
            )
            for i in range(30)
        ],
    ],
)

_register(
    "xsrc-login-without-proxy-history",
    positive=[
        # Baseline: this principal has proxy history from their own usual address.
        zscaler_event(
            "nohist.pos@corp.example", T0 - timedelta(days=2), "saas.example", src_ip="203.0.113.50"
        ),
        # Compromise: a successful login from a *different* address with no proxy history of
        # its own for this principal.
        okta_event(
            "nohist.pos@corp.example", T0, "user.session.start", "SUCCESS", src_ip="198.51.100.60"
        ),
    ],
    negative=[
        # Login from the same address the principal's own proxy history already shows.
        zscaler_event(
            "nohist.neg@corp.example", T0 - timedelta(days=2), "saas.example", src_ip="203.0.113.51"
        ),
        okta_event(
            "nohist.neg@corp.example", T0, "user.session.start", "SUCCESS", src_ip="203.0.113.51"
        ),
    ],
)

_register(
    "xsrc-credential-reset-then-upload",
    positive=[
        okta_event("reset.pos@corp.example", T0, "user.account.reset_password", "SUCCESS"),
        zscaler_event(
            "reset.pos@corp.example",
            T0 + timedelta(minutes=20),
            "exfil-target.example",
            http_method="POST",
            bytes_out=12_000_000,
        ),
    ],
    negative=[
        # Reset happens, but the large upload is well outside the 1h window.
        okta_event("reset.neg@corp.example", T0, "user.account.reset_password", "SUCCESS"),
        zscaler_event(
            "reset.neg@corp.example",
            T0 + timedelta(hours=5),
            "exfil-target.example",
            http_method="POST",
            bytes_out=12_000_000,
        ),
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
    "impossible-travel",
    "password-spray",
    "brute-force",
    "okta-mfa-fatigue",
    "first-login-new-country",
    "mfa-factor-deactivated",
    "api-token-created-off-hours",
    "privilege-grant",
    "xsrc-auth-burst-and-rare-domain",
    "xsrc-login-without-proxy-history",
    "xsrc-credential-reset-then-upload",
}, "every rule id in app/detection/rules/*.yml must have a fixture case"
