"""Scenario 5 — account-takeover chain (docs/11 #5; T1556.006 primary, T1098.001 secondary).

This scenario exists to prove that L4 earns its slot (docs/13 M9: "detected by a sequence model
and **not** by L3 features"), so every design choice here is subtractive — the job is to *remove*
every signal except the ordering.

Three properties do that work, and none of them is obvious from the event list:

**The victim is an Okta administrator.** `system.api_token.create` and `user.mfa.factor.*` are
anomalies only relative to a baseline. Fired from Sales they are a rate anomaly the L3 vector's
`privilege_events` feature catches for free; fired from IT they sit inside that principal's own
normal distribution, which is what "each event is individually legitimate" actually requires.

**The whole chain lands inside one UTC hour that the victim is otherwise silent in.** L3's unit
of analysis is `(entity, 1-hour window)`. Sharing an hour with a genuine office session would put
two countries and two ASNs in one vector and `n_distinct_geos` / `n_unique_asns` would flag it
without any sequence model. `_hour_slot` searches for an empty hour instead, so the attack hour's
feature vector is a single-geo, ~10-event, business-hours session — indistinguishable from any
other login the victim makes.

**The hostile source is a residential ISP by default, not a VPS.** `hosting_provider_ratio` is an
L3 feature; renting the attack from a hosting ASN hands the flat models the answer.

What is left is the transition `user.mfa.factor.activate -> system.api_token.create`, which the
benign grammar in `emitters/okta.py` emits at most once per session and never in that order — a
bigram probability near zero and nothing else. `n_decoy_chains` injects the honest version of the
same story (a phone upgrade: deactivate then re-enroll, from the user's own device) labelled
**benign**, so the eval measures whether a detector learned the ordering or just the vocabulary.

**A fourth property, added after an independent audit found the attack hour's own `n_events`
sitting at a robust z of 3.37 against docs/04's 3.5 threshold — a 4% margin, one bad seed from a
volumetric rule contaminating the L4-only benchmark this scenario exists to run:**

* `interleave_benign_sso` now defaults to `False`. The step it adds sat *between*
  `user.mfa.factor.activate` and `system.api_token.create`, so the sequence actually emitted with
  it on was `activate -> sso -> token_create`, not the adjacent bigram this file's own docstring
  claims is the whole signal. Dropping it sharpens the claim to what it says and, incidentally,
  removes one non-technique-critical event from the attack hour.
* `_shape_baseline_variance` injects a handful of genuine, `malicious=False` multi-app sessions
  elsewhere in the window (never the attack hour, never a recon hour) so the victim's own
  per-hour `n_events` history has real spread — an admin who occasionally has a busy multi-SSO
  hour is more realistic than one whose history is a flat, narrow band the ~8-event chain then
  reads as an outlier against by construction.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import TYPE_CHECKING

from datagen.emitters.okta import (
    ADMIN_DEPARTMENTS,
    OktaEmitter,
    OktaStep,
    app_target,
    factor_target,
    token_target,
    user_target,
)
from datagen.scenarios import register_scenario
from datagen.types import (
    SEQUENCE_LOGBERT,
    SEQUENCE_MARKOV,
    SIGMA_API_TOKEN_OFF_HOURS,
    SIGMA_MFA_DEACTIVATED,
    SIGMA_NEW_COUNTRY,
    SIGMA_PRIVILEGE_GRANT,
    EntityRef,
    GroundTruth,
    Scenario,
    ScenarioContext,
    SourceType,
)

if TYPE_CHECKING:
    from datagen.org import User
    from datagen.rng import SeededRandom
    from datagen.types import EventRecord

_POLICY_EVAL = "policy.evaluate_sign_on"
_SESSION_START = "user.session.start"
_SESSION_END = "user.session.end"
_MFA = "user.authentication.auth_via_mfa"
_SSO = "user.authentication.sso"
_FACTOR_DEACTIVATE = "user.mfa.factor.deactivate"
_FACTOR_ACTIVATE = "user.mfa.factor.activate"
_API_TOKEN_CREATE = "system.api_token.create"  # noqa: S105 — an Okta eventType, not a secret
_PRIVILEGE_GRANT = "user.account.privilege.grant"

# Same set the benign emitter enrolls from; a crafted factor name would be a free giveaway.
_FACTORS: tuple[str, ...] = ("OKTA_VERIFY_PUSH", "TOKEN:SOFTWARE:TOTP", "WEBAUTHN", "SMS")

# Okta stamps an admin console sign-on against its own app instance.
_ADMIN_APP = "Okta"

# `_shape_baseline_variance`'s session count — see that method's docstring for why this is an
# empirically-checked constant, not a derived one.
_BASELINE_SESSION_COUNT = 8


@register_scenario
class AccountTakeoverChainScenario(Scenario):
    key = "account_takeover_chain"
    technique = "T1556.006"
    sources = (SourceType.OKTA,)
    expected_detectors = (SEQUENCE_MARKOV, SEQUENCE_LOGBERT, SIGMA_MFA_DEACTIVATED)
    expected_disposition = "true_positive"
    must_correlate_into_one_incident = True
    description = (
        "Session from an unfamiliar country, then MFA factor deactivate, re-enroll, and API "
        "token creation. Every event is individually legitimate; the ordering is the attack."
    )

    def __init__(
        self,
        *,
        victim_is_admin: bool = True,
        foreign_geo: bool = True,
        hosting_asn: bool = False,
        n_prior_sessions: int = 1,
        prior_lead_h: float = 3.0,
        deactivate_factor: bool = True,
        enroll_new_factor: bool = True,
        create_api_token: bool = True,
        grant_privilege: bool = False,
        interleave_benign_sso: bool = False,
        off_hours: bool = False,
        step_gap_s: float = 95.0,
        step_jitter_pct: float = 0.45,
        hijack_fraction: float = 0.62,
        max_placement_days: int = 10,
        n_decoy_chains: int = 2,
    ) -> None:
        self.victim_is_admin = victim_is_admin
        self.foreign_geo = foreign_geo
        self.hosting_asn = hosting_asn
        self.n_prior_sessions = n_prior_sessions
        self.prior_lead_h = prior_lead_h
        self.deactivate_factor = deactivate_factor
        self.enroll_new_factor = enroll_new_factor
        self.create_api_token = create_api_token
        self.grant_privilege = grant_privilege
        self.interleave_benign_sso = interleave_benign_sso
        self.off_hours = off_hours
        self.step_gap_s = step_gap_s
        self.step_jitter_pct = step_jitter_pct
        self.hijack_fraction = hijack_fraction
        self.max_placement_days = max_placement_days
        self.n_decoy_chains = n_decoy_chains
        self._emitter = OktaEmitter()

    # ------------------------------------------------------------------ injection

    def inject(self, ctx: ScenarioContext) -> GroundTruth:
        em = self._emitter
        victim = self._pick_victim(ctx)
        rng = ctx.user_rng(victim)

        steps, detail = self._chain_steps(victim, rng)
        span_s = sum(step.delay_s or 0.0 for step in steps)
        start = self._hour_slot(ctx, victim, rng, span_s=span_s, avoid_benign=True)

        if self.foreign_geo:
            geo = ctx.models.geo.foreign_point(
                rng, exclude_country=victim.home_country, hosting=self.hosting_asn
            )
        else:
            geo = victim.home_geo
        hostile = em.client_for(victim, rng, geo=geo)

        # Reconnaissance logins first: the attacker validates the stolen password and looks
        # around before touching anything. They are part of the scenario and must correlate into
        # the same incident, but on their own they are an ordinary sign-on flow.
        recon: list[EventRecord] = []
        for i in range(self.n_prior_sessions):
            begin = start - timedelta(hours=self.prior_lead_h * (i + 1))
            if not ctx.window.contains(begin):
                continue
            recon.extend(
                em.login_session(victim, start=begin, rng=rng, client=hostile, mfa=True, failures=0)
            )
        em.inject(ctx, recon)

        chain = em.inject_sequence(ctx, victim, start=start, steps=steps, rng=rng, client=hostile)

        self._inject_decoys(ctx, victim)

        attack_hour = start.replace(minute=0, second=0, microsecond=0)
        recon_hours = {r.ts.replace(minute=0, second=0, microsecond=0) for r in recon}
        n_shaped = self._shape_baseline_variance(
            ctx, victim, rng, avoid_hours={attack_hour} | recon_hours
        )

        return self.make_ground_truth(
            ctx,
            primary_entity=EntityRef(type="user", value=victim.principal),
            expected_detectors=self._detectors(),
            notes=(
                f"victim={victim.principal} dept={victim.department}; "
                f"src={hostile.ip} ({hostile.geo.city}, {hostile.geo.country}, "
                f"AS{hostile.geo.asn}); chain={'->'.join(s.event_type for s in steps)}; "
                f"factors {detail['old_factor']}->{detail['new_factor']}; "
                f"{len(recon)} recon + {len(chain)} chain events in "
                f"{span_s / 60.0:.1f} min starting {start.isoformat()}; "
                f"{n_shaped} benign (malicious=False) baseline events elsewhere in the window "
                "widen the victim's own n_events history; "
                "secondary technique T1098.001 (API token persistence)"
            ),
        )

    # ------------------------------------------------------------------ chain shape

    def _chain_steps(
        self, victim: User, rng: SeededRandom
    ) -> tuple[list[OktaStep], dict[str, str]]:
        """The ordering under test. Delays are drawn up front so the caller can size the slot."""
        apps = victim.saas_apps or (_ADMIN_APP,)
        old_factor = rng.choice(_FACTORS)
        new_factor = rng.choice([f for f in _FACTORS if f != old_factor])
        token_name = f"automation-{rng.hex_token(3)}"

        def gap() -> float:
            return rng.jitter(self.step_gap_s, self.step_jitter_pct)

        steps = [
            OktaStep(_POLICY_EVAL, "ALLOW", delay_s=0.0),
            OktaStep(_SESSION_START, delay_s=rng.uniform(0.5, 4.0)),
            OktaStep(
                _MFA,
                delay_s=rng.uniform(4.0, 30.0),
                auth_step=1,
                targets=(factor_target(old_factor, victim),),
            ),
            OktaStep(
                _SSO,
                delay_s=gap(),
                targets=(app_target(_ADMIN_APP if _ADMIN_APP in apps else apps[0]),),
            ),
        ]
        if self.deactivate_factor:
            steps.append(
                OktaStep(
                    _FACTOR_DEACTIVATE, delay_s=gap(), targets=(factor_target(old_factor, victim),)
                )
            )
        if self.enroll_new_factor:
            steps.append(
                OktaStep(
                    _FACTOR_ACTIVATE, delay_s=gap(), targets=(factor_target(new_factor, victim),)
                )
            )
        if self.interleave_benign_sso:
            steps.append(OktaStep(_SSO, delay_s=gap(), targets=(app_target(rng.choice(apps)),)))
        if self.create_api_token:
            steps.append(
                OktaStep(_API_TOKEN_CREATE, delay_s=gap(), targets=(token_target(token_name),))
            )
        if self.grant_privilege:
            steps.append(OktaStep(_PRIVILEGE_GRANT, delay_s=gap(), targets=(user_target(victim),)))
        steps.append(OktaStep(_SESSION_END, delay_s=gap()))
        return steps, {"old_factor": old_factor, "new_factor": new_factor, "token": token_name}

    def _inject_decoys(self, ctx: ScenarioContext, victim: User) -> None:
        """Honest phone upgrades, labelled benign — the false-positive half of the measurement."""
        if self.n_decoy_chains <= 0:
            return
        em = self._emitter
        pool = [u for u in ctx.org.pick_users(ctx.rng, self.n_decoy_chains + 2) if u != victim]
        for i, user in enumerate(pool[: self.n_decoy_chains]):
            rng = ctx.user_rng(user)
            old_factor = rng.choice(_FACTORS)
            new_factor = rng.choice([f for f in _FACTORS if f != old_factor])
            apps = user.saas_apps or (_ADMIN_APP,)
            steps = [
                OktaStep(_POLICY_EVAL, "ALLOW", delay_s=0.0),
                OktaStep(_SESSION_START, delay_s=rng.uniform(0.5, 4.0)),
                OktaStep(
                    _MFA,
                    delay_s=rng.uniform(4.0, 30.0),
                    auth_step=1,
                    targets=(factor_target(old_factor, user),),
                ),
                OktaStep(
                    _FACTOR_DEACTIVATE,
                    delay_s=rng.uniform(60.0, 400.0),
                    targets=(factor_target(old_factor, user),),
                ),
                OktaStep(
                    _FACTOR_ACTIVATE,
                    delay_s=rng.uniform(30.0, 260.0),
                    targets=(factor_target(new_factor, user),),
                ),
                OktaStep(_SSO, delay_s=rng.uniform(20.0, 200.0), targets=(app_target(apps[0]),)),
            ]
            span_s = sum(s.delay_s or 0.0 for s in steps)
            fraction = min(0.92, max(0.05, self.hijack_fraction - 0.25 + 0.11 * i))
            begin = self._hour_slot(
                ctx, user, rng, span_s=span_s, avoid_benign=False, fraction=fraction
            )
            em.inject_sequence(ctx, user, start=begin, steps=steps, rng=rng, malicious=False)

    # ------------------------------------------------------------------ baseline shaping

    def _shape_baseline_variance(
        self,
        ctx: ScenarioContext,
        victim: User,
        rng: SeededRandom,
        *,
        avoid_hours: set[datetime],
    ) -> int:
        """A handful of genuine, `malicious=False` multi-app sessions elsewhere in the window —
        never the attack hour, never a recon hour — so the victim's own per-hour `n_events`
        history has real spread.

        Without this, a quiet admin's own history clusters tightly around a low `n_events` value
        (median 4, MAD 1 in the run that surfaced this defect), and the chain's own ~8-event hour
        reads as a volumetric outlier by construction — not because the chain is actually loud,
        which would contaminate the L4-only benchmark this scenario exists to run (module
        docstring). `_BASELINE_SESSION_COUNT` is sized empirically against real generated output
        by `tests/test_datagen_s08_marginals.py`'s scenario-5 check, not derived from a formula:
        MAD is an order statistic, not a smooth function of sample size, so "how many extra
        sessions is enough" has to be checked against actual data.

        Returns the number of events added, for the ground-truth notes.
        """
        em = self._emitter
        shape_rng = rng.substream("baseline-variance")
        client = em.client_for(victim, shape_rng)
        used = set(avoid_hours)
        added = 0
        for i in range(_BASELINE_SESSION_COUNT):
            srng = shape_rng.substream(f"session:{i}")
            start = self._sample_baseline_timestamp(ctx, srng, victim, avoid=used)
            if start is None:
                continue
            used.add(start.replace(minute=0, second=0, microsecond=0))
            records = em.login_session(
                victim,
                start=start,
                rng=srng,
                client=client,
                mfa=True,
                n_sso=3,
                failures=0,
                end_session=False,
            )
            em.inject(ctx, records, malicious=False)
            added += len(records)
        return added

    def _sample_baseline_timestamp(
        self, ctx: ScenarioContext, rng: SeededRandom, victim: User, *, avoid: set[datetime]
    ) -> datetime | None:
        """One on-hours timestamp for `victim`, retried a few times to dodge `avoid` — a plain
        diurnal draw, not `_hour_slot`'s empty-hour search: these sessions are supposed to look
        like ordinary extra activity, not another isolated, silent hour.
        """
        for _ in range(10):
            candidates = ctx.models.diurnal.sample_timestamps(
                rng, ctx.window.start, ctx.window.end, victim.work_hours, 1
            )
            if not candidates:
                continue
            ts = candidates[0]
            if ts.replace(minute=0, second=0, microsecond=0) not in avoid:
                return ts
        return None

    # ------------------------------------------------------------------ placement

    def _hour_slot(
        self,
        ctx: ScenarioContext,
        user: User,
        rng: SeededRandom,
        *,
        span_s: float,
        avoid_benign: bool,
        fraction: float | None = None,
    ) -> datetime:
        """Find a UTC hour the chain fits inside, optionally one the principal is silent in.

        Aligning to a UTC hour boundary is not cosmetic: it is the same bucketing L3 uses, so an
        empty bucket here is exactly the guarantee that the attack hour's feature vector carries
        one geo, one ASN and one user agent.
        """
        tz = user.tz_offset_h
        low, high = self._local_hour_range(user)
        occupied = {r.ts.replace(minute=0, second=0, microsecond=0) for r in ctx.benign_for(user)}
        lead = timedelta(hours=self.prior_lead_h * max(self.n_prior_sessions, 0) + 1.0)
        base = ctx.window.fraction(self.hijack_fraction if fraction is None else fraction)
        base_day = base.replace(hour=0, minute=0, second=0, microsecond=0)

        for day_offset in range(self.max_placement_days):
            day = base_day + timedelta(days=day_offset)
            for utc_h in rng.shuffled(range(24)):
                hour_start = day + timedelta(hours=utc_h)
                local = hour_start + timedelta(hours=tz)
                local_h = local.hour + local.minute / 60.0
                if not low <= local_h <= high:
                    continue
                if not self.off_hours and local.weekday() >= 5:
                    continue
                if hour_start - lead < ctx.window.start:
                    continue
                if hour_start + timedelta(seconds=span_s + 60.0) >= ctx.window.end:
                    continue
                if avoid_benign and hour_start in occupied:
                    continue
                slack = max(60.0, 3600.0 - span_s - 60.0)
                return hour_start + timedelta(seconds=rng.uniform(0.0, slack))

        return ctx.window.clamp(base)

    def _local_hour_range(self, user: User) -> tuple[float, float]:
        hours = user.work_hours
        if self.off_hours:
            return (1.0, 4.5)
        return (hours.start_h + 1.0, max(hours.end_h - 1.0, hours.start_h + 2.0))

    # ------------------------------------------------------------------ labelling

    def _pick_victim(self, ctx: ScenarioContext) -> User:
        if not self.victim_is_admin:
            return ctx.org.pick_user(ctx.rng)
        pool = [u for dept in sorted(ADMIN_DEPARTMENTS) for u in ctx.org.department_members(dept)]
        if not pool:
            return ctx.org.pick_user(ctx.rng)
        return ctx.rng.weighted_choice(pool, [u.activity_weight for u in pool])

    def _detectors(self) -> list[str]:
        """Only the rules this configuration actually trips, so a sweep reports honest recall."""
        keys: list[str] = [SEQUENCE_MARKOV, SEQUENCE_LOGBERT]
        if self.deactivate_factor:
            keys.append(SIGMA_MFA_DEACTIVATED)
        if self.foreign_geo:
            keys.append(SIGMA_NEW_COUNTRY)
        if self.create_api_token and self.off_hours:
            keys.append(SIGMA_API_TOKEN_OFF_HOURS)
        if self.grant_privilege:
            keys.append(SIGMA_PRIVILEGE_GRANT)
        return keys
