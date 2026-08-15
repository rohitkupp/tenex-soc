"""The simulated org (docs/11 "Simulated org").

An `Org` is a pure function of its seed. Everything a scenario or emitter needs about a
principal — where they sit, when they work, what they browse, what device they carry — is fixed
at construction so that the benign corpus and an injected attack agree about the same person.

The service accounts are the load-bearing part. They are twelve principals out of 262 but they
produce most of the traffic, on regular intervals, from automation user agents, at volumes no
human matches. Every one of those properties is also an attack indicator, which is precisely the
point: they are the dominant source of realistic false positives, scenario 10 is built from
them, and a model that has not learned them as normal will fail its false-positive budget.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from typing import Any

from .realism import (
    DEFAULT_OFFICE_CODES,
    OFFICE_CATALOG,
    RESIDENTIAL_ASNS,
    GeoPoint,
    Office,
    RealismModels,
    UserAgentSpec,
    WorkHours,
    build_models,
    load_first_names,
    load_last_names,
)
from .rng import SeededRandom, stable_hash

__all__ = [
    "DEFAULT_DEPARTMENTS",
    "DEFAULT_SAAS_APPS",
    "SERVICE_ACCOUNT_CATALOG",
    "DeviceFingerprint",
    "Org",
    "SaasApp",
    "ServiceAccountSpec",
    "User",
]

DEFAULT_DEPARTMENTS: tuple[tuple[str, float], ...] = (
    ("Engineering", 0.30),
    ("Sales", 0.17),
    ("Customer Success", 0.11),
    ("Marketing", 0.09),
    ("Finance", 0.08),
    ("Operations", 0.08),
    ("IT", 0.07),
    ("People", 0.05),
    ("Legal", 0.02),
    ("Security", 0.02),
    ("Product", 0.01),
)


@dataclass(frozen=True, slots=True)
class SaasApp:
    name: str
    domain: str
    category: str


DEFAULT_SAAS_APPS: tuple[SaasApp, ...] = (
    # A workforce identity provider the org's employees browse to over the proxy (SSO landing
    # pages, MFA prompts) — modeling that this org *uses* an IdP as a SaaS destination, not that
    # this pipeline *ingests* one as a log source. Named "OneLogin" rather than "Okta" on purpose:
    # this project narrowed to ZScaler web proxy logs only, and Okta is no longer a source this
    # codebase parses (`app/parsers/`, `datagen/emitters/`) — nothing here should read as if it
    # still is.
    SaasApp("OneLogin", "onelogin.com", "identity"),
    SaasApp("Google Workspace", "google.com", "productivity"),
    SaasApp("Slack", "slack.com", "collaboration"),
    SaasApp("Salesforce", "salesforce.com", "crm"),
    SaasApp("Workday", "workday.com", "hr"),
    SaasApp("GitHub", "github.com", "engineering"),
    SaasApp("Atlassian", "atlassian.net", "engineering"),
    SaasApp("Zoom", "zoom.us", "collaboration"),
    SaasApp("Box", "box.com", "storage"),
    SaasApp("AWS Console", "amazonaws.com", "cloud"),
    SaasApp("Snowflake", "snowflakecomputing.com", "data"),
    SaasApp("Datadog", "datadoghq.com", "observability"),
)


@dataclass(frozen=True, slots=True)
class ServiceAccountSpec:
    """Catalogue entry for a machine principal: what it does and how regularly."""

    name: str
    purpose: str
    interval_s: int
    events_per_day: int
    ua_family: str
    apps: tuple[str, ...] = ()


SERVICE_ACCOUNT_CATALOG: tuple[ServiceAccountSpec, ...] = (
    ServiceAccountSpec(
        "svc-backup-s3", "Nightly object-store backup", 3600, 4800, "rclone", ("AWS Console", "Box")
    ),
    ServiceAccountSpec(
        "svc-etl-airflow",
        "Airflow warehouse ETL",
        300,
        12000,
        "python-requests",
        ("Snowflake", "AWS Console"),
    ),
    ServiceAccountSpec(
        "svc-monitoring",
        "Infrastructure monitoring agent",
        60,
        20000,
        "Datadog Agent",
        ("Datadog",),
    ),
    ServiceAccountSpec(
        "svc-ci-runner", "CI build and artifact fetch", 120, 9000, "curl", ("GitHub", "AWS Console")
    ),
    ServiceAccountSpec(
        "svc-scim-sync", "Directory SCIM provisioning", 900, 2400, "okhttp", ("OneLogin", "Workday")
    ),
    ServiceAccountSpec(
        "svc-siem-forwarder", "SIEM log forwarder", 60, 18000, "Go-http-client", ("Datadog",)
    ),
    ServiceAccountSpec(
        "svc-vuln-scanner", "Authenticated vulnerability scan", 1800, 3000, "python-requests", ()
    ),
    ServiceAccountSpec(
        "svc-license-audit",
        "SaaS license reconciliation",
        3600,
        800,
        "Java",
        ("OneLogin", "Workday"),
    ),
    ServiceAccountSpec(
        "svc-crm-sync", "CRM bidirectional sync", 600, 5200, "axios", ("Salesforce",)
    ),
    ServiceAccountSpec("svc-patch-mgmt", "Endpoint patch management", 1800, 2600, "PowerShell", ()),
    ServiceAccountSpec(
        "svc-dns-telemetry", "DNS telemetry export", 300, 7200, "aws-cli", ("AWS Console",)
    ),
    ServiceAccountSpec(
        "svc-doc-indexer",
        "Document store indexer",
        240,
        6400,
        "Apache-HttpClient",
        ("Box", "Google Workspace"),
    ),
)


@dataclass(frozen=True, slots=True)
class DeviceFingerprint:
    """Stable UA + OS per principal. Real users do not change browser between requests."""

    device_id: str
    user_agent: str
    browser_family: str
    os_family: str
    device_type: str
    is_automation: bool = False

    @classmethod
    def from_spec(cls, spec: UserAgentSpec, device_id: str) -> DeviceFingerprint:
        return cls(
            device_id=device_id,
            user_agent=spec.user_agent,
            browser_family=spec.browser_family,
            os_family=spec.os_family,
            device_type=spec.device_type,
            is_automation=spec.is_automation,
        )


@dataclass(frozen=True, slots=True)
class User:
    """A principal — human or machine. `is_service_account` is the only branch emitters need."""

    username: str
    email: str
    display_name: str
    user_id: str
    department: str
    office: Office
    home_country: str
    home_asn: int
    home_asn_org: str
    home_geo: GeoPoint
    office_ip: str
    work_hours: WorkHours
    device: DeviceFingerprint
    domain_affinity: tuple[str, ...]
    saas_apps: tuple[str, ...]
    activity_weight: float
    remote_ratio: float
    events_per_day: int
    is_service_account: bool = False
    interval_s: int | None = None
    purpose: str = ""

    @property
    def key(self) -> str:
        """Sub-stream key. `rng.substream(user.key)` is this user's independent stream."""
        return f"user:{self.username}"

    @property
    def principal(self) -> str:
        """What lands in `events.principal` before pseudonymization."""
        return self.email

    @property
    def tz_offset_h(self) -> float:
        return self.work_hours.tz_offset_h

    def source_ip(self, rng: SeededRandom) -> str:
        """Office egress or home broadband, at this user's remote-working rate."""
        if self.is_service_account:
            return self.office_ip
        if rng.chance(self.remote_ratio):
            return self.home_geo.ip
        return self.office_ip

    def geo(self, ip: str) -> GeoPoint:
        """Resolve one of this user's own addresses back to a location."""
        if ip == self.home_geo.ip:
            return self.home_geo
        return GeoPoint(
            ip=ip,
            country=self.office.country,
            city=self.office.city,
            latitude=self.office.latitude,
            longitude=self.office.longitude,
            asn=self.office.asn,
            asn_org=self.office.asn_org,
        )


@dataclass(frozen=True, slots=True)
class _OrgConfig:
    n_users: int
    n_departments: int
    offices: tuple[str, ...]
    n_service_accounts: int
    saas_apps: tuple[str, ...]
    seed: int
    email_domain: str
    name: str


class Org:
    """A seeded simulated organisation.

    Two orgs built from the same seed are equal; two built from different seeds are not. The
    benign corpus and the eval scenarios deliberately use different seeds *and* different orgs
    (docs/11) — sharing either is how synthetic benchmarks fake good numbers.
    """

    def __init__(
        self,
        n_users: int = 250,
        n_departments: int = 8,
        offices: Sequence[str] = DEFAULT_OFFICE_CODES,
        n_service_accounts: int = 12,
        saas_apps: Sequence[str] | None = None,
        seed: int = 1337,
        *,
        email_domain: str = "corp.example",
        name: str = "Northwind Trading",
    ) -> None:
        if n_users < 1:
            raise ValueError("n_users must be >= 1")
        if not 1 <= n_departments <= len(DEFAULT_DEPARTMENTS):
            raise ValueError(f"n_departments must be 1..{len(DEFAULT_DEPARTMENTS)}")
        if not offices:
            raise ValueError("offices must not be empty")

        unknown = [code for code in offices if code not in OFFICE_CATALOG]
        if unknown:
            raise ValueError(f"unknown office codes: {unknown}; known: {sorted(OFFICE_CATALOG)}")

        app_names = (
            tuple(saas_apps) if saas_apps is not None else tuple(a.name for a in DEFAULT_SAAS_APPS)
        )
        self.config = _OrgConfig(
            n_users=n_users,
            n_departments=n_departments,
            offices=tuple(offices),
            n_service_accounts=n_service_accounts,
            saas_apps=app_names,
            seed=int(seed),
            email_domain=email_domain,
            name=name,
        )

        self.seed = int(seed)
        self.name = name
        self.email_domain = email_domain
        self.offices: tuple[Office, ...] = tuple(
            OFFICE_CATALOG[code].with_egress() for code in offices
        )
        self.departments: tuple[str, ...] = tuple(d for d, _ in DEFAULT_DEPARTMENTS[:n_departments])
        self._department_weights: tuple[float, ...] = _normalized(
            [w for _, w in DEFAULT_DEPARTMENTS[:n_departments]]
        )
        self.saas_apps: tuple[SaasApp, ...] = tuple(_resolve_apps(app_names))
        self.models: RealismModels = build_models(self.offices)

        root = SeededRandom(self.seed, ("org",))
        self.users: tuple[User, ...] = self._build_users(root.substream("humans"), n_users)
        self.service_accounts: tuple[User, ...] = self._build_service_accounts(
            root.substream("service"), n_service_accounts
        )
        self.principals: tuple[User, ...] = (*self.users, *self.service_accounts)
        self._by_username = {u.username: u for u in self.principals}
        self._by_email = {u.email: u for u in self.principals}
        self._by_department: dict[str, tuple[User, ...]] = {
            dept: tuple(u for u in self.users if u.department == dept) for dept in self.departments
        }
        self._fingerprint: str | None = None

    # ---------------------------------------------------------------- construction

    def _build_users(self, rng: SeededRandom, n: int) -> tuple[User, ...]:
        first_names, last_names = load_first_names(), load_last_names()
        taken: dict[str, int] = {}
        users: list[User] = []

        for i in range(n):
            # Keyed by index, never by draw order: inserting a user does not reshuffle the rest.
            r = rng.substream(f"i:{i}")
            first = r.choice(first_names)
            last = r.choice(last_names)
            base = f"{first[0]}{last}".lower()
            seq = taken.get(base, 0)
            taken[base] = seq + 1
            username = base if seq == 0 else f"{base}{seq + 1}"

            office = self.models.geo.pick_office(r)
            department = r.weighted_choice(self.departments, self._department_weights)
            residential = self.models.geo.residential_point(r, office)
            asn_pool = RESIDENTIAL_ASNS.get(office.country, RESIDENTIAL_ASNS["US"])
            home_asn, home_asn_org = r.choice(asn_pool)
            hours = WorkHours(
                tz_offset_h=office.tz_offset_h,
                start_h=r.clamped_normal(9.0, 0.9, 6.5, 11.0),
                end_h=r.clamped_normal(17.5, 1.0, 15.0, 21.0),
                weekend_activity=round(r.uniform(0.01, 0.18), 4),
                phase_shift_h=round(r.normal(0.0, 0.6), 4),
            )
            device = DeviceFingerprint.from_spec(
                self.models.user_agents.sample_desktop(r), f"dev-{r.hex_token(6)}"
            )
            affinity_count = r.randint(12, 45)
            affinity = tuple(
                dict.fromkeys(
                    [
                        *self.models.domains.sample_unique(r, affinity_count),
                        *(app.domain for app in self.saas_apps),
                    ]
                )
            )
            # Log-normal per-user volume: a handful of heavy users, most of them light. Flat
            # volume would make `n_events_z_vs_cohort` fire on anyone slightly above average.
            weight = round(r.lognormal(0.0, 0.55), 4)

            users.append(
                User(
                    username=username,
                    email=f"{username}@{self.email_domain}",
                    display_name=f"{first} {last}",
                    user_id=f"00u{r.hex_token(8)}",
                    department=department,
                    office=office,
                    home_country=office.country,
                    home_asn=home_asn,
                    home_asn_org=home_asn_org,
                    home_geo=residential,
                    office_ip=r.choice(office.egress_ips),
                    work_hours=hours,
                    device=device,
                    domain_affinity=affinity,
                    saas_apps=tuple(a.name for a in self.saas_apps if a.category == "identity")
                    + tuple(r.sample([a.name for a in self.saas_apps], r.randint(3, 7))),
                    activity_weight=weight,
                    remote_ratio=round(r.uniform(0.10, 0.55), 4),
                    events_per_day=max(40, round(320 * weight)),
                )
            )
        return tuple(users)

    def _build_service_accounts(self, rng: SeededRandom, n: int) -> tuple[User, ...]:
        accounts: list[User] = []
        catalog = SERVICE_ACCOUNT_CATALOG
        datacenter = self.offices[0]

        for i in range(n):
            spec = catalog[i % len(catalog)]
            suffix = "" if i < len(catalog) else f"-{i // len(catalog) + 1}"
            username = f"{spec.name}{suffix}"
            r = rng.substream(f"svc:{username}")
            ua = self.models.user_agents.by_family(spec.ua_family)
            app_domains = tuple(a.domain for a in self.saas_apps if a.name in spec.apps) or tuple(
                a.domain for a in self.saas_apps[:3]
            )
            host = f"{datacenter.ip_prefix}.{200 + (i % 50)}"

            accounts.append(
                User(
                    username=username,
                    email=f"{username}@{self.email_domain}",
                    display_name=spec.purpose,
                    user_id=f"00u{r.hex_token(8)}",
                    department="IT" if "IT" in self.departments else self.departments[0],
                    office=datacenter,
                    home_country=datacenter.country,
                    home_asn=datacenter.asn,
                    home_asn_org=datacenter.asn_org,
                    home_geo=GeoPoint(
                        ip=host,
                        country=datacenter.country,
                        city=datacenter.city,
                        latitude=datacenter.latitude,
                        longitude=datacenter.longitude,
                        asn=datacenter.asn,
                        asn_org=datacenter.asn_org,
                    ),
                    office_ip=host,
                    # Machines do not keep office hours. `always_on` short-circuits the diurnal
                    # curve, which is what makes their inter-arrival CV near zero.
                    work_hours=WorkHours(
                        tz_offset_h=datacenter.tz_offset_h,
                        start_h=0.0,
                        end_h=24.0,
                        weekend_activity=1.0,
                        always_on=True,
                    ),
                    device=DeviceFingerprint.from_spec(ua, f"host-{username}"),
                    domain_affinity=app_domains,
                    saas_apps=spec.apps,
                    activity_weight=round(spec.events_per_day / 320.0, 4),
                    remote_ratio=0.0,
                    events_per_day=spec.events_per_day,
                    is_service_account=True,
                    interval_s=spec.interval_s,
                    purpose=spec.purpose,
                )
            )
        return tuple(accounts)

    # ---------------------------------------------------------------- lookup

    def by_username(self, username: str) -> User:
        return self._by_username[username]

    def by_email(self, email: str) -> User:
        return self._by_email[email]

    def get(self, principal: str) -> User:
        """Accepts either a username or an email."""
        if principal in self._by_email:
            return self._by_email[principal]
        return self._by_username[principal]

    def department_members(self, department: str) -> tuple[User, ...]:
        return self._by_department.get(department, ())

    def peers(self, user: User) -> tuple[User, ...]:
        """Same-department humans, excluding the user. The peer-group baseline for scenario 7."""
        return tuple(u for u in self._by_department.get(user.department, ()) if u != user)

    def office(self, code: str) -> Office:
        for o in self.offices:
            if o.code == code:
                return o
        raise KeyError(code)

    # ---------------------------------------------------------------- sampling

    def pick_user(self, rng: SeededRandom, *, include_service_accounts: bool = False) -> User:
        """Activity-weighted: heavy users appear more often, as they do in a real corpus."""
        pool = self.principals if include_service_accounts else self.users
        return rng.weighted_choice(pool, [u.activity_weight for u in pool])

    def pick_users(
        self, rng: SeededRandom, k: int, *, include_service_accounts: bool = False
    ) -> list[User]:
        """Distinct users. Order is the sampled order, which is stable for a given rng."""
        pool = self.principals if include_service_accounts else self.users
        return rng.sample(pool, k)

    def user_stream(self, rng: SeededRandom, user: User) -> SeededRandom:
        """This user's independent sub-stream under `rng`."""
        return rng.substream(user.key)

    # ---------------------------------------------------------------- identity

    def fingerprint(self) -> str:
        """Content hash. Two orgs are equal iff their fingerprints match."""
        if self._fingerprint is None:
            payload = json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))
            self._fingerprint = hashlib.blake2b(payload.encode(), digest_size=16).hexdigest()
        return self._fingerprint

    def to_dict(self) -> dict[str, Any]:
        return {
            "config": asdict(self.config),
            "offices": [asdict(o) for o in self.offices],
            "departments": list(self.departments),
            "saas_apps": [asdict(a) for a in self.saas_apps],
            "principals": [asdict(u) for u in self.principals],
        }

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Org):
            return NotImplemented
        return self.fingerprint() == other.fingerprint()

    def __hash__(self) -> int:
        # `hash()` is PYTHONHASHSEED-salted for `str` (see rng.py's own docstring on why keys go
        # through `stable_hash`, not `hash()`) -- using it here would make any future `set`/dict-key/
        # `lru_cache` use of `Org` silently non-reproducible across processes and machines.
        return stable_hash(self.fingerprint())

    def __len__(self) -> int:
        return len(self.principals)

    def __repr__(self) -> str:
        return (
            f"Org(name={self.name!r}, seed={self.seed}, users={len(self.users)}, "
            f"service_accounts={len(self.service_accounts)}, "
            f"offices={[o.code for o in self.offices]})"
        )


def _normalized(weights: Sequence[float]) -> tuple[float, ...]:
    total = sum(weights)
    return tuple(w / total for w in weights)


def _resolve_apps(names: Sequence[str]) -> list[SaasApp]:
    known = {a.name: a for a in DEFAULT_SAAS_APPS}
    out: list[SaasApp] = []
    for n in names:
        app = known.get(n)
        if app is None:
            slug = "".join(ch for ch in n.lower() if ch.isalnum())
            app = SaasApp(name=n, domain=f"{slug}.com", category="other")
        out.append(app)
    return out
