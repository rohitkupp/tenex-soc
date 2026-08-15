"""Scenario 6 — MFA fatigue / push bombing (docs/11 #6, T1621).

The attacker already holds the password; what they do not hold is the second factor, so they
replay the push prompt until the victim taps accept to make it stop. In the System Log that is a
run of `user.authentication.auth_via_mfa:FAILURE` closed by a `:SUCCESS` — which is precisely the
Sigma rule in docs/04 (">=5 MFA failures then success, 15m") *and* a self-loop the benign grammar
never produces, since a benign session emits at most one MFA failure before its success.

Two things here are deliberately *not* distinctive, and both matter:

**The failure reason is Okta's default.** A push denial could plausibly carry its own
`outcome.reason`, but the benign corpus stamps `INVALID_CREDENTIALS` on every MFA failure, and a
bespoke string would let any detector separate attack from noise on one field lookup — leaking the
label into the data instead of measuring detection.

**The burst is timed to fit the rule, not to beat it.** `burst_window_s` and `n_failures` are the
sweep axes docs/11 asks for: below five failures, or spread past the rule's 15-minute timeframe,
the rule is *supposed* to go silent and only the sequence model should survive. `_detectors`
therefore reports what this configuration actually trips rather than the scenario's best case, so
the detection curve degrades honestly instead of manufacturing false misses.

`n_decoy_bursts` adds the benign twin — a user fumbling their authenticator three times before
succeeding — labelled non-malicious, so the eval can see a threshold that fires too eagerly.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import TYPE_CHECKING

from datagen.emitters.okta import OktaEmitter, OktaStep, app_target, factor_target
from datagen.scenarios import register_scenario
from datagen.types import (
    SEQUENCE_LOGBERT,
    SEQUENCE_MARKOV,
    SIGMA_BRUTE_FORCE,
    SIGMA_MFA_FATIGUE,
    SIGMA_NEW_COUNTRY,
    EntityRef,
    GroundTruth,
    Scenario,
    ScenarioContext,
    SourceType,
)

if TYPE_CHECKING:
    from datagen.org import User
    from datagen.rng import SeededRandom

_POLICY_EVAL = "policy.evaluate_sign_on"
_SESSION_START = "user.session.start"
_SESSION_END = "user.session.end"
_MFA = "user.authentication.auth_via_mfa"
_SSO = "user.authentication.sso"

_FACTORS: tuple[str, ...] = ("OKTA_VERIFY_PUSH", "TOKEN:SOFTWARE:TOTP", "WEBAUTHN", "SMS")

# docs/04 rule inventory: MFA fatigue is >=5 failures then a success inside 15 minutes, brute
# force is >=20 failures for one principal inside 15 minutes. Both windows are the same 900s.
_RULE_WINDOW_S: float = 900.0
_FATIGUE_MIN_FAILURES: int = 5
_BRUTE_FORCE_MIN_FAILURES: int = 20


@register_scenario
class MfaFatigueScenario(Scenario):
    key = "mfa_fatigue"
    technique = "T1621"
    sources = (SourceType.OKTA,)
    expected_detectors = (SIGMA_MFA_FATIGUE, SEQUENCE_MARKOV, SEQUENCE_LOGBERT)
    expected_disposition = "true_positive"
    must_correlate_into_one_incident = True
    description = (
        "Repeated MFA push prompts against one principal until the victim accepts one — "
        ">=5 auth_via_mfa failures followed by a success inside 15 minutes."
    )

    def __init__(
        self,
        *,
        n_failures: int = 9,
        burst_window_s: float = 540.0,
        jitter_pct: float = 0.35,
        succeeds: bool = True,
        success_delay_s: float = 40.0,
        from_new_country: bool = True,
        hosting_asn: bool = False,
        n_prior_password_failures: int = 0,
        n_post_sso: int = 2,
        attack_fraction: float = 0.48,
        off_hours: bool = True,
        max_placement_days: int = 10,
        n_decoy_bursts: int = 1,
        decoy_failures: int = 3,
    ) -> None:
        self.n_failures = n_failures
        self.burst_window_s = burst_window_s
        self.jitter_pct = jitter_pct
        self.succeeds = succeeds
        self.success_delay_s = success_delay_s
        self.from_new_country = from_new_country
        self.hosting_asn = hosting_asn
        self.n_prior_password_failures = n_prior_password_failures
        self.n_post_sso = n_post_sso
        self.attack_fraction = attack_fraction
        self.off_hours = off_hours
        self.max_placement_days = max_placement_days
        self.n_decoy_bursts = n_decoy_bursts
        self.decoy_failures = decoy_failures
        self._emitter = OktaEmitter()

    # ------------------------------------------------------------------ injection

    def inject(self, ctx: ScenarioContext) -> GroundTruth:
        em = self._emitter
        victim = ctx.org.pick_user(ctx.rng)
        rng = ctx.user_rng(victim)

        factor = rng.choice(_FACTORS)
        steps = self._burst_steps(victim, rng, factor)
        span_s = sum(step.delay_s or 0.0 for step in steps)
        start = self._start_time(ctx, victim, rng, span_s=span_s)

        if self.from_new_country:
            geo = ctx.models.geo.foreign_point(
                rng, exclude_country=victim.home_country, hosting=self.hosting_asn
            )
        else:
            geo = victim.home_geo
        attacker = em.client_for(victim, rng, geo=geo)

        injected = em.inject_sequence(
            ctx, victim, start=start, steps=steps, rng=rng, client=attacker
        )
        self._inject_decoys(ctx, victim)

        pressure_s = self._pressure_span_s(steps)
        return self.make_ground_truth(
            ctx,
            primary_entity=EntityRef(type="user", value=victim.principal),
            expected_detectors=self._detectors(pressure_s),
            notes=(
                f"victim={victim.principal}; src={attacker.ip} ({attacker.geo.city}, "
                f"{attacker.geo.country}, AS{attacker.geo.asn}); factor={factor}; "
                f"{self.n_failures} auth_via_mfa FAILURE over {pressure_s / 60.0:.1f} min "
                f"{'then a SUCCESS' if self.succeeds else 'with no success'}; "
                f"{len(injected)} events from {start.isoformat()}"
            ),
        )

    # ------------------------------------------------------------------ burst shape

    def _burst_steps(self, victim: User, rng: SeededRandom, factor: str) -> list[OktaStep]:
        """Password accepted, then the push loop. Ordered exactly as the benign grammar orders it.

        Matching the benign prefix is the point: if the attack session opened differently the
        sequence models would separate it on the prefix and the run of failures — the thing being
        measured — would never be tested.
        """
        target = (factor_target(factor, victim),)
        apps = victim.saas_apps or ("Okta",)
        interval = self.burst_window_s / max(self.n_failures, 1)

        steps = [OktaStep(_POLICY_EVAL, "CHALLENGE", delay_s=0.0)]
        for _ in range(self.n_prior_password_failures):
            steps.append(OktaStep(_SESSION_START, "FAILURE", delay_s=rng.uniform(3.0, 25.0)))
        steps.append(OktaStep(_SESSION_START, delay_s=rng.uniform(0.5, 4.0)))

        for i in range(self.n_failures):
            # The first prompt follows the password immediately; the rest are the attacker
            # re-triggering on a cadence, which is what makes the run look like pressure.
            delay = rng.uniform(2.0, 8.0) if i == 0 else rng.jitter(interval, self.jitter_pct)
            steps.append(OktaStep(_MFA, "FAILURE", delay_s=delay, auth_step=1, targets=target))

        if self.succeeds:
            steps.append(
                OktaStep(
                    _MFA,
                    delay_s=rng.jitter(self.success_delay_s, self.jitter_pct),
                    auth_step=1,
                    targets=target,
                )
            )
            for _ in range(self.n_post_sso):
                steps.append(
                    OktaStep(
                        _SSO,
                        delay_s=rng.uniform(2.0, 90.0),
                        targets=(app_target(rng.choice(apps)),),
                    )
                )
            steps.append(OktaStep(_SESSION_END, delay_s=rng.uniform(120.0, 1800.0)))
        return steps

    def _pressure_span_s(self, steps: list[OktaStep]) -> float:
        """Seconds from the first MFA failure to the closing success — what the rule times."""
        elapsed = 0.0
        first: float | None = None
        last = 0.0
        for step in steps:
            elapsed += step.delay_s or 0.0
            if step.event_type != _MFA:
                continue
            if first is None:
                first = elapsed
            last = elapsed
        return 0.0 if first is None else last - first

    def _inject_decoys(self, ctx: ScenarioContext, victim: User) -> None:
        """Sub-threshold fumbles from the user's own device, labelled benign."""
        if self.n_decoy_bursts <= 0 or self.decoy_failures <= 0:
            return
        em = self._emitter
        pool = [u for u in ctx.org.pick_users(ctx.rng, self.n_decoy_bursts + 2) if u != victim]
        for i, user in enumerate(pool[: self.n_decoy_bursts]):
            rng = ctx.user_rng(user)
            factor = rng.choice(_FACTORS)
            target = (factor_target(factor, user),)
            apps = user.saas_apps or ("Okta",)
            steps = [
                OktaStep(_POLICY_EVAL, "CHALLENGE", delay_s=0.0),
                OktaStep(_SESSION_START, delay_s=rng.uniform(0.5, 4.0)),
            ]
            for _ in range(self.decoy_failures):
                steps.append(
                    OktaStep(
                        _MFA, "FAILURE", delay_s=rng.uniform(8.0, 45.0), auth_step=1, targets=target
                    )
                )
            steps.append(
                OktaStep(_MFA, delay_s=rng.uniform(4.0, 30.0), auth_step=1, targets=target)
            )
            steps.append(
                OktaStep(_SSO, delay_s=rng.uniform(2.0, 60.0), targets=(app_target(apps[0]),))
            )
            span_s = sum(s.delay_s or 0.0 for s in steps)
            fraction = min(0.9, max(0.05, self.attack_fraction + 0.17 * (i + 1)))
            begin = self._start_time(ctx, user, rng, span_s=span_s, fraction=fraction, quiet=False)
            em.inject_sequence(ctx, user, start=begin, steps=steps, rng=rng, malicious=False)

    # ------------------------------------------------------------------ placement

    def _start_time(
        self,
        ctx: ScenarioContext,
        user: User,
        rng: SeededRandom,
        *,
        span_s: float,
        fraction: float | None = None,
        quiet: bool = True,
    ) -> datetime:
        """A UTC hour inside the window with room for the whole burst.

        Push bombing works when the victim is half asleep, so the default local range is late
        evening rather than mid-afternoon; `off_hours=False` moves it into the working day, which
        is the harder variant because the failures then blend with genuine fumbles.
        """
        tz = user.tz_offset_h
        low, high = (22.0, 23.5) if self.off_hours else (10.0, 16.0)
        occupied = {r.ts.replace(minute=0, second=0, microsecond=0) for r in ctx.benign_for(user)}
        base = ctx.window.fraction(self.attack_fraction if fraction is None else fraction)
        base_day = base.replace(hour=0, minute=0, second=0, microsecond=0)

        for day_offset in range(self.max_placement_days):
            day = base_day + timedelta(days=day_offset)
            for utc_h in rng.shuffled(range(24)):
                hour_start = day + timedelta(hours=utc_h)
                local = hour_start + timedelta(hours=tz)
                local_h = local.hour + local.minute / 60.0
                if not low <= local_h <= high:
                    continue
                if hour_start < ctx.window.start:
                    continue
                if hour_start + timedelta(seconds=span_s + 3600.0) >= ctx.window.end:
                    continue
                if quiet and hour_start in occupied:
                    continue
                return hour_start + timedelta(seconds=rng.uniform(0.0, 600.0))

        return ctx.window.clamp(base)

    # ------------------------------------------------------------------ labelling

    def _detectors(self, pressure_s: float) -> list[str]:
        """What this configuration genuinely trips — the sweep needs real misses, not assumed ones."""
        keys: list[str] = [SEQUENCE_MARKOV, SEQUENCE_LOGBERT]
        in_window = pressure_s <= _RULE_WINDOW_S
        if self.succeeds and self.n_failures >= _FATIGUE_MIN_FAILURES and in_window:
            keys.insert(0, SIGMA_MFA_FATIGUE)
        if self.n_failures >= _BRUTE_FORCE_MIN_FAILURES and in_window:
            keys.append(SIGMA_BRUTE_FORCE)
        if self.from_new_country:
            keys.append(SIGMA_NEW_COUNTRY)
        return keys
