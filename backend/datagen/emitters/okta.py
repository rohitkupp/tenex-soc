"""Okta System Log emitter — JSON Lines as exported by `/api/v1/logs` (docs/03).

Two properties of this file are load-bearing and neither is obvious from the field table.

**Sessions are generated from a grammar, not sampled from the event vocabulary.** docs/04 §L4
trains Markov and LogBERT on Okta sessions and justifies doing so on the claim that per-principal
identity sessions are *genuinely grammatical*. If this emitter drew independent samples from
`OktaEventMix`, that claim would be false in our own corpus: every transition would be equally
likely, the Markov baseline would have nothing to learn, and the LogBERT-vs-Markov benchmark
would be measuring noise. So a benign session here is a real sign-on flow — policy evaluation,
optional password failures, session start, optional MFA step, app launches, optional logout — and
the marginal event mix falls out of the grammar's rates rather than being imposed on top of it.
`MIX_TARGETS` records what those marginals are supposed to be so a test can assert the grammar
still reproduces the documented tenant proportions.

**The line is the contract.** `serialize` emits the vendor-native JSON that `app/parsers/okta.py`
reads back; `EventRecord.fields` therefore holds Okta's own key names, nested exactly as Okta
nests them. Scenarios must not hand-roll that structure — they call `build_event` /
`inject_sequence` here, which is also why those are public.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, ClassVar

from ..realism import GeoPoint
from ..rng import stable_hash
from ..types import EventRecord, SourceType

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator, Sequence

    from ..org import User
    from ..rng import SeededRandom
    from ..types import BenignContext, ScenarioContext

__all__ = [
    "ADMIN_DEPARTMENTS",
    "MIX_TARGETS",
    "OktaClient",
    "OktaEmitter",
    "OktaStep",
    "app_target",
    "factor_target",
    "okta_event_key",
    "policy_target",
    "token_target",
    "user_target",
]

# Departments whose members perform tenant administration. Confining `system.api_token.create`,
# `user.account.privilege.grant` and friends to them is what makes those events discriminative:
# a privilege grant from Sales is an anomaly only if privilege grants normally come from IT.
ADMIN_DEPARTMENTS: frozenset[str] = frozenset({"IT", "Security"})

_SESSION_START = "user.session.start"
_SESSION_END = "user.session.end"
_SSO = "user.authentication.sso"
_MFA = "user.authentication.auth_via_mfa"
_VERIFY = "user.authentication.verify"
_POLICY_EVAL = "policy.evaluate_sign_on"
_TOKEN_GRANT = "app.oauth2.token.grant"  # noqa: S105 — an Okta eventType, not a secret
_ACCOUNT_LOCK = "user.account.lock"
_ACCOUNT_UNLOCK = "user.account.unlock"

# (displayMessage, legacyEventType) per event type. Okta ships both alongside `eventType`; some
# tenants' downstream tooling keys off the legacy name, so a realistic export carries it.
_EVENT_META: dict[str, tuple[str, str]] = {
    _SESSION_START: ("User login to Okta", "core.user_auth.login"),
    _SESSION_END: ("User logout from Okta", "core.user_auth.logout_success"),
    _SSO: ("User single sign on to app", "app.auth.sso"),
    _MFA: ("Authentication of user via MFA", "core.user.factor.attempt"),
    _VERIFY: ("User verification", "core.user_auth.verify"),
    _POLICY_EVAL: ("Evaluation of sign-on policy", "core.policy.sign_on.evaluate"),
    _TOKEN_GRANT: ("OAuth2 access token is granted", "app.oauth2.token.grant.access_token"),
    _ACCOUNT_LOCK: ("Max sign in attempts exceeded", "core.user_auth.account_locked"),
    _ACCOUNT_UNLOCK: ("Unlock user account", "core.user.account_unlock"),
    "user.account.update_profile": ("Update user profile", "core.user.config.user_profile.update"),
    "application.user_membership.add": (
        "Add user to application membership",
        "app.generic.provision.assign_user_to_app",
    ),
    "user.mfa.factor.activate": ("Activate factor for user", "core.user.factor.activate"),
    "user.mfa.factor.deactivate": ("Deactivate factor for user", "core.user.factor.deactivate"),
    "system.api_token.create": ("Create API token", "core.api_token.create"),
    "user.account.privilege.grant": (
        "Grant user privilege",
        "core.user.admin_privilege.granted",
    ),
    "policy.lifecycle.update": ("Update policy", "core.policy.lifecycle.update"),
    "user.session.impersonation.initiate": (
        "Initiate impersonation session",
        "core.user.impersonation.session.initiated",
    ),
}

_CREDENTIAL_TYPES: dict[str, str] = {
    _SESSION_START: "PASSWORD",
    _MFA: "OTP",
    _VERIFY: "OTP",
    _TOKEN_GRANT: "API_TOKEN",
}

_FAILURE_REASONS: dict[tuple[str, str], str] = {
    (_SESSION_START, "FAILURE"): "INVALID_CREDENTIALS",
    (_MFA, "FAILURE"): "INVALID_CREDENTIALS",
    (_VERIFY, "FAILURE"): "INVALID_CREDENTIALS",
    (_SSO, "FAILURE"): "App assignment missing",
    (_POLICY_EVAL, "DENY"): "Sign-on policy evaluation resulted in DENY",
    (_POLICY_EVAL, "CHALLENGE"): "Sign-on policy evaluation resulted in CHALLENGE",
    (_ACCOUNT_LOCK, "SUCCESS"): "LOCKED_OUT",
}

_MFA_FACTORS: tuple[str, ...] = ("OKTA_VERIFY_PUSH", "TOKEN:SOFTWARE:TOTP", "WEBAUTHN", "SMS")

# Self-service events any principal can produce, and the admin-only events. Weights are the
# docs/11 tenant proportions renormalised within each group; the absolute rates live on the
# emitter as knobs so a test can assert the grammar reproduces `_MIX_TARGETS`.
_SELF_SERVICE_EVENTS: tuple[tuple[str, float], ...] = (
    ("user.account.update_profile", 0.674),
    ("user.mfa.factor.activate", 0.231),
    ("user.mfa.factor.deactivate", 0.095),
)
_ADMIN_EVENTS: tuple[tuple[str, float], ...] = (
    ("application.user_membership.add", 0.694),
    ("system.api_token.create", 0.111),
    ("user.account.privilege.grant", 0.083),
    ("policy.lifecycle.update", 0.083),
    ("user.session.impersonation.initiate", 0.029),
)

# Expected share of the emitted corpus per `{eventType}:{outcome}`, from OktaEventMix.EVENTS
# normalised to 1.0. The grammar's rates are chosen to land here; tests assert it still does.
MIX_TARGETS: dict[str, float] = {
    f"{event}:{outcome}": weight / 99.69
    for event, outcome, weight in (
        (_SESSION_START, "SUCCESS", 22.0),
        (_SESSION_START, "FAILURE", 2.2),
        (_SSO, "SUCCESS", 31.0),
        (_MFA, "SUCCESS", 16.0),
        (_MFA, "FAILURE", 1.1),
        (_POLICY_EVAL, "ALLOW", 12.0),
        (_POLICY_EVAL, "CHALLENGE", 3.0),
        (_SESSION_END, "SUCCESS", 8.0),
        (_TOKEN_GRANT, "SUCCESS", 2.4),
        (_VERIFY, "SUCCESS", 1.0),
    )
}


def okta_event_key(record: EventRecord) -> str:
    """`{eventType}:{outcome.result}` — the discrete token docs/03 defines for this source."""
    fields = record.fields
    return f"{fields.get('eventType')}:{fields.get('outcome', {}).get('result')}"


def _okta_ts(ts: datetime) -> str:
    """Okta stamps `published` to the millisecond with a literal `Z`, never an offset."""
    aware = ts.astimezone(UTC)
    return f"{aware.strftime('%Y-%m-%dT%H:%M:%S')}.{aware.microsecond // 1000:03d}Z"


def _oid(prefix: str, value: str, width: int = 17) -> str:
    """Okta-shaped object id derived from a name, so the same app keeps the same id everywhere."""
    return f"{prefix}{stable_hash(value):0{width}x}"[: len(prefix) + width]


def app_target(app_name: str, domain: str | None = None) -> dict[str, Any]:
    """`target[]` entry for an application instance — what an SSO event points at."""
    return {
        "id": _oid("0oa", f"app:{app_name}"),
        "type": "AppInstance",
        "alternateId": domain or app_name,
        "displayName": app_name,
        "detailEntry": {"signOnModeType": "SAML_2_0"},
    }


def user_target(user: User) -> dict[str, Any]:
    """`target[]` entry for a principal — an admin event names the user it acted on."""
    return {
        "id": user.user_id,
        "type": "User",
        "alternateId": user.email,
        "displayName": user.display_name,
        "detailEntry": None,
    }


def factor_target(factor: str, user: User) -> dict[str, Any]:
    return {
        "id": _oid("ufs", f"factor:{user.username}:{factor}"),
        "type": "UserFactor",
        "alternateId": user.email,
        "displayName": factor,
        "detailEntry": None,
    }


def token_target(name: str) -> dict[str, Any]:
    return {
        "id": _oid("00T", f"token:{name}"),
        "type": "Token",
        "alternateId": name,
        "displayName": name,
        "detailEntry": None,
    }


def policy_target(name: str) -> dict[str, Any]:
    return {
        "id": _oid("00p", f"policy:{name}"),
        "type": "PolicyEntity",
        "alternateId": "unknown",
        "displayName": name,
        "detailEntry": None,
    }


@dataclass(frozen=True, slots=True)
class OktaClient:
    """The network identity attached to every event of one session.

    Held constant for a session on purpose: a principal whose IP, ASN and user agent change
    mid-session is exactly what the impossible-travel and new-country rules look for, so benign
    traffic must never do it by accident.
    """

    ip: str
    geo: GeoPoint
    user_agent: str
    browser_family: str
    os_family: str
    device_type: str = "desktop"
    is_proxy: bool = False

    @property
    def device_label(self) -> str:
        return {"desktop": "Computer", "mobile": "Mobile", "server": "Unknown"}.get(
            self.device_type, "Unknown"
        )

    def geo_block(self) -> dict[str, Any]:
        return {
            "city": self.geo.city,
            "country": self.geo.country,
            "geolocation": {
                "lat": round(self.geo.latitude, 4),
                "lon": round(self.geo.longitude, 4),
            },
        }

    def moved_to(self, geo: GeoPoint) -> OktaClient:
        """Same device, different location — the shape scenarios 3/4/5 need."""
        return replace(self, ip=geo.ip, geo=geo)


@dataclass(frozen=True, slots=True)
class OktaStep:
    """One step of a crafted sequence: what happened, and how long after the previous step.

    `delay_s` is `None` rather than `0.0` by default so that an explicit zero — two events in the
    same second, which a real burst does produce — stays distinguishable from "unspecified".
    """

    event_type: str
    outcome: str = "SUCCESS"
    delay_s: float | None = None
    reason: str | None = None
    targets: tuple[dict[str, Any], ...] = ()
    auth_step: int = 0


class OktaEmitter:
    """Okta System Log source. Implements `datagen.types.LogEmitter`.

    Constructor arguments are the grammar's rates. They are per-session probabilities, calibrated
    so the resulting marginal mix matches `MIX_TARGETS`; changing one shifts both the grammar and
    the marginals, which is the point — they are one model, not two.
    """

    source: ClassVar[SourceType] = SourceType.OKTA
    file_suffix: ClassVar[str] = ".jsonl"

    def __init__(
        self,
        *,
        service_account_share: float = 0.04,
        policy_eval_rate: float = 0.68,
        policy_challenge_rate: float = 0.20,
        failed_login_rate: float = 0.050,
        lockout_rate: float = 0.140,
        unlock_rate: float = 0.83,
        mfa_rate: float = 0.727,
        mfa_failure_rate: float = 0.069,
        extra_sso_lambda: float = 0.378,
        oauth_grant_rate: float = 0.005,
        verify_rate: float = 0.045,
        session_end_rate: float = 0.364,
        self_service_rate: float = 0.0236,
        admin_event_rate: float = 0.0164,
        service_jitter_pct: float = 0.03,
    ) -> None:
        self.service_account_share = service_account_share
        self.policy_eval_rate = policy_eval_rate
        self.policy_challenge_rate = policy_challenge_rate
        self.failed_login_rate = failed_login_rate
        self.lockout_rate = lockout_rate
        self.unlock_rate = unlock_rate
        self.mfa_rate = mfa_rate
        self.mfa_failure_rate = mfa_failure_rate
        self.extra_sso_lambda = extra_sso_lambda
        self.oauth_grant_rate = oauth_grant_rate
        self.verify_rate = verify_rate
        self.session_end_rate = session_end_rate
        self.self_service_rate = self_service_rate
        self.admin_event_rate = admin_event_rate
        self.service_jitter_pct = service_jitter_pct

    # ------------------------------------------------------------------ LogEmitter

    def header(self) -> str | None:
        """JSON Lines has no header row."""
        return None

    def serialize(self, record: EventRecord) -> str:
        """`published` is re-derived from `record.ts` so a mutated timestamp cannot desync it."""
        payload = dict(record.fields)
        payload["published"] = _okta_ts(record.ts)
        return json.dumps(payload, separators=(",", ":"), ensure_ascii=False)

    @property
    def mean_session_events(self) -> float:
        """Expected events per human session — the divisor that turns a budget into sessions."""
        failures = self.failed_login_rate * 2.0
        # Only a three-failure run can lock the account, and `randint(1, 3)` picks three a third
        # of the time — the term is tiny but leaving it out biases every user's session count.
        locked = self.failed_login_rate / 3.0 * self.lockout_rate
        return (
            self.policy_eval_rate
            + failures
            + locked * (1.0 + self.unlock_rate)
            + 1.0
            + self.mfa_rate * (1.0 + self.mfa_failure_rate)
            + 1.0
            + self.extra_sso_lambda
            + self.oauth_grant_rate
            + self.verify_rate
            + self.self_service_rate
            + self.admin_event_rate
            + self.session_end_rate
        )

    def generate_benign(self, ctx: BenignContext) -> Iterator[EventRecord]:
        """Yield ~`ctx.n_events` records. Streams per principal; nothing is accumulated."""
        humans = [u for u in ctx.org.principals if not u.is_service_account]
        services = [u for u in ctx.org.principals if u.is_service_account]
        if not humans and not services:
            return

        svc_budget = int(ctx.n_events * self.service_account_share) if services else 0
        human_budget = max(0, ctx.n_events - svc_budget)

        weights = [max(u.activity_weight, 1e-6) for u in humans]
        total_weight = sum(weights) or 1.0
        admin_weight = sum(
            w for u, w in zip(humans, weights, strict=True) if u.department in ADMIN_DEPARTMENTS
        )
        # Admin events are org-wide rates but only admins emit them, so the per-admin-session
        # rate is scaled up by the inverse of the admins' share of all sessions.
        admin_share = admin_weight / total_weight
        admin_rate = min(1.0, self.admin_event_rate / admin_share) if admin_share > 0 else 0.0

        for user, weight in zip(humans, weights, strict=True):
            budget = human_budget * weight / total_weight
            n_sessions = max(1, round(budget / self.mean_session_events))
            yield from self._human_sessions(ctx, user, n_sessions, admin_rate)

        if services:
            per_service = max(1, svc_budget // len(services))
            for svc in services:
                yield from self._service_ticks(ctx, svc, per_service)

    # ------------------------------------------------------------------ construction

    def client_for(
        self,
        user: User,
        rng: SeededRandom,
        *,
        geo: GeoPoint | None = None,
        ip: str | None = None,
        user_agent: str | None = None,
        is_proxy: bool = False,
    ) -> OktaClient:
        """Resolve one session's network identity, defaulting to the user's own device and egress."""
        if geo is None:
            resolved_ip = ip or user.source_ip(rng)
            geo = user.geo(resolved_ip)
        point = geo if ip is None else replace(geo, ip=ip)
        return OktaClient(
            ip=point.ip,
            geo=point,
            user_agent=user_agent or user.device.user_agent,
            browser_family=user.device.browser_family,
            os_family=user.device.os_family,
            device_type=user.device.device_type,
            is_proxy=is_proxy,
        )

    def build_event(
        self,
        *,
        user: User,
        ts: datetime,
        event_type: str,
        rng: SeededRandom,
        outcome: str = "SUCCESS",
        client: OktaClient | None = None,
        reason: str | None = None,
        targets: Sequence[dict[str, Any]] = (),
        session_id: str | None = None,
        auth_step: int = 0,
        transaction_type: str = "WEB",
        debug: dict[str, Any] | None = None,
        tags: tuple[str, ...] = (),
    ) -> EventRecord:
        """Build one fully-formed System Log record. The only supported way to make an Okta event.

        Scenarios call this rather than assembling `fields` themselves: every key docs/03 maps is
        produced here, so a crafted attack event and a benign one are indistinguishable to the
        parser and differ only in content.
        """
        resolved = client or self.client_for(user, rng)
        message, legacy = _EVENT_META.get(event_type, (event_type, event_type))
        resolved_reason = (
            reason if reason is not None else _FAILURE_REASONS.get((event_type, outcome))
        )
        geo_block = resolved.geo_block()
        fields: dict[str, Any] = {
            "uuid": rng.uuid(),
            "published": _okta_ts(ts),
            "eventType": event_type,
            "version": "0",
            "severity": _severity(event_type, outcome),
            "legacyEventType": legacy,
            "displayMessage": message,
            "actor": {
                "id": user.user_id,
                "type": "User",
                "alternateId": user.email,
                "displayName": user.display_name,
                "detailEntry": None,
            },
            "client": {
                "userAgent": {
                    "rawUserAgent": resolved.user_agent,
                    "os": resolved.os_family,
                    "browser": resolved.browser_family.upper(),
                },
                "zone": "null",
                "device": resolved.device_label,
                "id": None,
                "ipAddress": resolved.ip,
                "geographicalContext": geo_block,
            },
            "outcome": {"result": outcome, "reason": resolved_reason},
            "target": list(targets),
            "transaction": {
                "type": transaction_type,
                "id": _oid("tx", f"{user.username}:{_okta_ts(ts)}:{event_type}", 16),
                "detail": {},
            },
            "debugContext": {
                "debugData": {
                    "requestId": rng.hex_token(10),
                    "requestUri": _REQUEST_URIS.get(event_type, "/api/v1/authn"),
                    "url": _REQUEST_URIS.get(event_type, "/api/v1/authn"),
                    "threatSuspected": "false",
                    "deviceFingerprint": user.device.device_id,
                    **(debug or {}),
                }
            },
            "authenticationContext": {
                "authenticationProvider": "OKTA_AUTHENTICATION_PROVIDER",
                "authenticationStep": auth_step,
                "credentialProvider": None,
                "credentialType": _CREDENTIAL_TYPES.get(event_type),
                "issuer": None,
                "externalSessionId": session_id or "unknown",
                "interface": None,
            },
            "securityContext": {
                "asNumber": resolved.geo.asn,
                "asOrg": resolved.geo.asn_org,
                "isp": resolved.geo.asn_org,
                "domain": None,
                "isProxy": resolved.is_proxy,
            },
            "request": {
                "ipChain": [
                    {
                        "ip": resolved.ip,
                        "geographicalContext": geo_block,
                        "version": "V4",
                        "source": None,
                    }
                ]
            },
        }
        return EventRecord(
            ts=ts,
            source=self.source,
            principal=user.principal,
            fields=fields,
            src_ip=resolved.ip,
            tags=tags,
        )

    def login_session(
        self,
        user: User,
        *,
        start: datetime,
        rng: SeededRandom,
        client: OktaClient | None = None,
        session_id: str | None = None,
        mfa: bool | None = None,
        n_sso: int | None = None,
        failures: int | None = None,
        end_session: bool | None = None,
        admin_rate: float = 0.0,
        admin_subjects: Sequence[User] = (),
    ) -> list[EventRecord]:
        """One grammatical sign-on flow, in order, as a list of unlabelled records.

        The explicit keyword overrides exist for scenarios: an account-takeover chain wants a
        session that looks exactly like this one apart from the geography and the trailing
        factor-deactivate, and hand-building the benign prefix would drift from the real grammar.
        """
        resolved = client or self.client_for(user, rng)
        sid = session_id or f"trs{rng.hex_token(12)}"
        out: list[EventRecord] = []
        t = start

        def emit(event_type: str, outcome: str = "SUCCESS", **kwargs: Any) -> None:
            out.append(
                self.build_event(
                    user=user,
                    ts=t,
                    event_type=event_type,
                    outcome=outcome,
                    rng=rng,
                    client=resolved,
                    session_id=sid,
                    **kwargs,
                )
            )

        if rng.chance(self.policy_eval_rate):
            emit(
                _POLICY_EVAL,
                "CHALLENGE" if rng.chance(self.policy_challenge_rate) else "ALLOW",
            )
            t += timedelta(seconds=rng.uniform(0.2, 2.0))

        n_failures = (
            failures
            if failures is not None
            else (rng.randint(1, 3) if rng.chance(self.failed_login_rate) else 0)
        )
        for _ in range(n_failures):
            emit(_SESSION_START, "FAILURE")
            t += timedelta(seconds=rng.uniform(3.0, 25.0))

        if n_failures >= 3 and rng.chance(self.lockout_rate):
            emit(_ACCOUNT_LOCK, targets=(user_target(user),))
            if rng.chance(self.unlock_rate):
                t += timedelta(seconds=rng.uniform(120.0, 1800.0))
                emit(_ACCOUNT_UNLOCK, targets=(user_target(user),))
            return out

        emit(_SESSION_START)
        t += timedelta(seconds=rng.uniform(0.5, 4.0))

        do_mfa = mfa if mfa is not None else rng.chance(self.mfa_rate)
        if do_mfa:
            factor = rng.choice(_MFA_FACTORS)
            if rng.chance(self.mfa_failure_rate):
                emit(_MFA, "FAILURE", auth_step=1, targets=(factor_target(factor, user),))
                t += timedelta(seconds=rng.uniform(4.0, 40.0))
            emit(_MFA, auth_step=1, targets=(factor_target(factor, user),))
            t += timedelta(seconds=rng.uniform(0.5, 5.0))

        apps = user.saas_apps or ("Okta",)
        count = n_sso if n_sso is not None else 1 + rng.poisson(self.extra_sso_lambda)
        for _ in range(count):
            app = rng.choice(apps)
            emit(_SSO, targets=(app_target(app),))
            t += timedelta(seconds=rng.uniform(1.0, 240.0))
            if rng.chance(self.oauth_grant_rate):
                emit(_TOKEN_GRANT, targets=(app_target(app),))
                t += timedelta(seconds=rng.uniform(0.2, 3.0))

        if rng.chance(self.verify_rate):
            emit(_VERIFY, auth_step=1)
            t += timedelta(seconds=rng.uniform(1.0, 20.0))

        if rng.chance(self.self_service_rate):
            event_type = rng.weighted_choice(
                [e for e, _ in _SELF_SERVICE_EVENTS], [w for _, w in _SELF_SERVICE_EVENTS]
            )
            targets: tuple[dict[str, Any], ...] = (user_target(user),)
            if event_type.startswith("user.mfa.factor."):
                targets = (factor_target(rng.choice(_MFA_FACTORS), user),)
            emit(event_type, targets=targets)
            t += timedelta(seconds=rng.uniform(2.0, 60.0))

        if admin_rate > 0 and rng.chance(admin_rate):
            subject = rng.choice(admin_subjects) if admin_subjects else user
            event_type, admin_targets = _admin_event(rng, subject)
            emit(event_type, targets=admin_targets)
            t += timedelta(seconds=rng.uniform(2.0, 90.0))

        close = rng.chance(self.session_end_rate) if end_session is None else end_session
        if close:
            t += timedelta(seconds=rng.uniform(60.0, 5400.0))
            emit(_SESSION_END)

        return out

    # ------------------------------------------------------------------ scenario injection

    def inject(
        self,
        ctx: ScenarioContext,
        records: Iterable[EventRecord],
        *,
        malicious: bool = True,
    ) -> list[EventRecord]:
        """Append crafted records to the benign stream. Thin wrapper over `ScenarioContext.add`.

        Returned in emission order; hold onto them and call `line_numbers` after the driver has
        merged and numbered the file to learn where they landed.
        """
        return ctx.add_many(records, malicious=malicious)

    def inject_sequence(
        self,
        ctx: ScenarioContext,
        user: User,
        *,
        start: datetime,
        steps: Sequence[OktaStep | tuple[str, str]],
        rng: SeededRandom | None = None,
        client: OktaClient | None = None,
        session_id: str | None = None,
        default_gap_s: float = 30.0,
        malicious: bool = True,
        tags: tuple[str, ...] = (),
    ) -> list[EventRecord]:
        """Inject an ordered, crafted event sequence — the shape scenarios 3 to 6 are made of.

        `OktaStep.delay_s` is measured from the previous step, so a caller writes the chain as it
        reads in a report ("MFA deactivated four minutes after the login") without doing timestamp
        arithmetic and getting the ordering subtly wrong.
        """
        r = rng or ctx.user_rng(user)
        resolved = client or self.client_for(user, r)
        sid = session_id or f"trs{r.hex_token(12)}"
        ts = start
        built: list[EventRecord] = []
        for raw in steps:
            step = raw if isinstance(raw, OktaStep) else OktaStep(raw[0], raw[1])
            ts += timedelta(seconds=default_gap_s if step.delay_s is None else step.delay_s)
            built.append(
                self.build_event(
                    user=user,
                    ts=ts,
                    event_type=step.event_type,
                    outcome=step.outcome,
                    rng=r,
                    client=resolved,
                    reason=step.reason,
                    targets=step.targets,
                    session_id=sid,
                    auth_step=step.auth_step,
                    tags=tags,
                )
            )
        return self.inject(ctx, built, malicious=malicious)

    @staticmethod
    def line_numbers(records: Iterable[EventRecord]) -> list[int]:
        """Where the given records landed in the file. Requires `assign_line_numbers` to have run."""
        numbers: list[int] = []
        for record in records:
            if record.line_no is None:
                raise ValueError(
                    "line numbers are only known after assign_line_numbers(); "
                    f"record at {record.ts.isoformat()} is unnumbered"
                )
            numbers.append(record.line_no)
        return sorted(numbers)

    # ------------------------------------------------------------------ benign internals

    def _human_sessions(
        self, ctx: BenignContext, user: User, n_sessions: int, admin_rate: float
    ) -> Iterator[EventRecord]:
        rng = ctx.user_rng(user)
        starts = ctx.models.diurnal.sample_timestamps(
            rng, ctx.window.start, ctx.window.end, user.work_hours, n_sessions
        )
        rate = admin_rate if user.department in ADMIN_DEPARTMENTS else 0.0
        previous_end: datetime | None = None
        for start in starts:
            # Sessions of one principal must not interleave: the sequence models read a
            # principal's timeline in file order and overlapping flows would look ungrammatical.
            begin = start
            if previous_end is not None and begin <= previous_end:
                begin = previous_end + timedelta(seconds=rng.uniform(5.0, 120.0))
            if begin >= ctx.window.end:
                break
            client = self.client_for(user, rng)
            records = self.login_session(
                user,
                start=begin,
                rng=rng,
                client=client,
                admin_rate=rate,
                admin_subjects=ctx.org.users,
            )
            previous_end = records[-1].ts
            yield from records

    def _service_ticks(self, ctx: BenignContext, svc: User, budget: int) -> Iterator[EventRecord]:
        """Machine principals: the same call, on the same period, forever.

        Two choices here are deliberate and both exist to serve the false-positive budget.
        The emitted period is an integer multiple of the account's own `interval_s` rather than an
        arbitrary number, so the traffic keeps the harmonic look of a real scheduler even when the
        corpus budget forces a coarser cadence. And the tick *shape* is fixed per account instead
        of drawn per tick: a scheduler that alternated between three different call patterns would
        have an inter-arrival CV in the same range as a human, and the L3 models would have no way
        to learn machine principals as normal — which is the one thing docs/11 says they must do.
        """
        rng = ctx.user_rng(svc)
        base = svc.interval_s or 900
        natural_ticks = max(1, int(ctx.window.duration_s // base))
        multiple = max(1, math.ceil(natural_ticks / max(budget, 1)))
        interval = base * multiple
        client = self.client_for(svc, rng)
        session_id = f"trs{rng.hex_token(12)}"
        apps = svc.saas_apps or ("Okta",)
        app = rng.choice(apps)
        shape = rng.weighted_choice(_SERVICE_SHAPES, _SERVICE_SHAPE_WEIGHTS)

        t = ctx.window.start + timedelta(seconds=rng.uniform(0.0, interval))
        while t < ctx.window.end:
            at = t
            for event_type in shape:
                yield self.build_event(
                    user=svc,
                    ts=at,
                    event_type=event_type,
                    rng=rng,
                    client=client,
                    session_id=session_id,
                    targets=() if event_type == _SESSION_START else (app_target(app),),
                    transaction_type="JOB",
                )
                at += timedelta(seconds=rng.uniform(0.1, 2.0))
            t += timedelta(seconds=rng.jitter(interval, self.service_jitter_pct))


# What one scheduler tick looks like. Chosen once per service account, then repeated unchanged.
_SERVICE_SHAPES: tuple[tuple[str, ...], ...] = (
    (_TOKEN_GRANT,),
    (_SSO,),
    (_SESSION_START, _SSO),
)
_SERVICE_SHAPE_WEIGHTS: tuple[float, ...] = (0.55, 0.35, 0.10)

_REQUEST_URIS: dict[str, str] = {
    _SESSION_START: "/api/v1/authn",
    _SESSION_END: "/api/v1/sessions/me",
    _SSO: "/app/template_saml_2_0/sso/saml",
    _MFA: "/api/v1/authn/factors/verify",
    _VERIFY: "/api/v1/authn/factors/verify",
    _POLICY_EVAL: "/api/v1/authn",
    _TOKEN_GRANT: "/oauth2/v1/token",
    "system.api_token.create": "/api/v1/api-tokens",
    "user.account.privilege.grant": "/api/v1/users",
    "policy.lifecycle.update": "/api/v1/policies",
    "application.user_membership.add": "/api/v1/apps",
    "user.mfa.factor.activate": "/api/v1/users/factors",
    "user.mfa.factor.deactivate": "/api/v1/users/factors",
    "user.session.impersonation.initiate": "/admin/impersonation",
}


def _severity(event_type: str, outcome: str) -> str:
    if outcome in {"FAILURE", "DENY"}:
        return "WARN"
    if event_type in {_ACCOUNT_LOCK, "user.mfa.factor.deactivate"}:
        return "WARN"
    return "INFO"


def _admin_event(rng: SeededRandom, subject: User) -> tuple[str, tuple[dict[str, Any], ...]]:
    """Pick an admin event type and the `target[]` it acts on."""
    event_type = rng.weighted_choice([e for e, _ in _ADMIN_EVENTS], [w for _, w in _ADMIN_EVENTS])
    if event_type == "system.api_token.create":
        return event_type, (token_target(f"automation-{rng.hex_token(3)}"),)
    if event_type == "policy.lifecycle.update":
        return event_type, (policy_target(rng.choice(_POLICY_NAMES)),)
    if event_type == "application.user_membership.add":
        return event_type, (user_target(subject), app_target(rng.choice(_ADMIN_APPS)))
    return event_type, (user_target(subject),)


_POLICY_NAMES: tuple[str, ...] = (
    "Default Sign-On Policy",
    "MFA Enrollment Policy",
    "Contractor Access Policy",
    "Password Policy",
)
_ADMIN_APPS: tuple[str, ...] = ("Salesforce", "Workday", "GitHub", "Box", "Snowflake")
