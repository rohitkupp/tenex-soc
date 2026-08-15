"""Scenario 10 — benign-but-weird, the false-positive control (docs/11 row 10).

Every other scenario in this package answers "can the pipeline find the attack". This one
answers the question docs/11 says matters just as much: "does the pipeline leave sanctioned,
merely-unusual behavior alone". `expected_detectors` is empty and `expected_disposition` is
`false_positive` on purpose — the eval's `fp_rate` (docs/12) is measured against exactly this
kind of traffic, and a detection stack that cannot tell it apart from the other nine scenarios
has not learned the attack, it has learned "unusual == malicious".

Three independent, unrelated motifs are bundled into one scenario because each one targets a
different layer and none of them should correlate with either of the others:

* **Regular-interval backup job** — machine-regular interval, automation user agent, large
  outbound transfer to one host, anchored at a nightly start hour. That is the *literal* feature
  vector L2 beaconing and the L3 peer-group / autoencoder models key on. The only thing that
  makes it benign is context the volumetric detectors do not see on their own: it is one of the
  org's own catalogued service accounts (`datagen.org.SERVICE_ACCOUNT_CATALOG`), talking to a
  SaaS app already in its own affinity set, at the cadence its `interval_s` already advertises in
  the benign corpus — the burst's actual span is `(backup_events - 1) * account.interval_s`, not
  an independent knob, so it is not necessarily a single night for a many-chunk job against a
  slow-cadence account. If a detector needs the destination to be rare or the actor to be human
  to stay quiet, it will fire here — that is the point of shipping this alongside scenario 1
  (`c2_beaconing`) rather than instead of it.
* **New-hire onboarding burst** — an IT admin runs a provisioning checklist (app assignments,
  a privilege grant) against one employee in a few minutes, and that employee's own browser then
  visits a couple dozen popular, org-wide-common domains it has never touched before. Every
  ingredient of account-takeover-after-privilege-escalation is present *except* the one thing
  that makes it an attack: the grants originate from an admin department member's own normal
  device and address (docs/04's rule inventory keys admin events on `ADMIN_DEPARTMENTS`
  specifically so this stays quiet), and the "new" domains are popular sites the *user* has not
  visited, not sites the *organization* has not visited — `signal.rarity` and
  `signal.newly_registered_domain` are calibrated on org-wide history, not one employee's, so
  neither should trip.
* **Scheduled pen-test window** — an authorized tester in `ADMIN_DEPARTMENTS` runs failed
  sign-on attempts against a handful of principals from their own known workstation. Shaped like
  `sigma.password_spray` on every axis it can be shaped on without becoming an actual attack: it
  deliberately sits under *two* of the three thresholds docs/04 states for that rule
  (`>= 10 distinct principals` and `<= 30m window`) rather than one, so a knob sweep that nudges
  either margin does not accidentally cross into "should have fired". It also never succeeds, so
  there is no compromised session for `sigma.first_login_new_country` or the no-prior-proxy-
  history cross-source rule to key on either.

All three sub-cases are `ctx.add(..., malicious=False)`: the events are real, scenario-tagged log
lines an eval harness can inspect, but none of them is ground truth for an attack, so
`malicious_line_numbers` comes out empty by construction (`finalize_ground_truth` only counts
`record.malicious`). That is deliberate — docs/12's false-positive rate is measured over
flagged *entity-windows* in the whole file, not against a line list, so there is nothing for this
scenario to assert about which lines fire; only that none of them should.
"""

from __future__ import annotations

import math
from datetime import timedelta
from typing import TYPE_CHECKING

from datagen.emitters.okta import ADMIN_DEPARTMENTS, OktaEmitter, app_target, user_target
from datagen.emitters.zscaler import ZScalerEmitter
from datagen.scenarios import register_scenario
from datagen.types import EntityRef, GroundTruth, Scenario, ScenarioContext, SourceType

if TYPE_CHECKING:
    from datetime import datetime

    from datagen.org import User
    from datagen.rng import SeededRandom

__all__ = ["BenignButWeirdScenario"]

# Onboarding checklist apps an IT admin assigns to a new hire, cycled in order so the notes are
# reproducible regardless of how many grants are requested.
_ONBOARDING_APPS: tuple[str, ...] = (
    "Slack",
    "Google Workspace",
    "Workday",
    "Zoom",
    "Atlassian",
    "GitHub",
)

# A file extension mix a real backup agent actually writes, so the URL is not a giveaway either.
_BACKUP_EXTENSIONS: tuple[str, ...] = ("tar.zst", "sql.gz", "img.zst")


def _local_start(
    ctx: ScenarioContext, user: User, *, start_fraction: float, local_hour: float, duration_h: float
) -> datetime:
    """Anchor a burst at a wall-clock hour in `user`'s timezone, clamped inside the window.

    Copied in shape from the other scenarios' burst anchors (see `s07`) rather than imported,
    because a scenario module owns its own file and must not reach into a sibling's internals.
    """
    anchor = ctx.window.fraction(start_fraction)
    offset = timedelta(hours=user.tz_offset_h)
    midnight = (anchor + offset).replace(hour=0, minute=0, second=0, microsecond=0)
    start = midnight + timedelta(hours=local_hour) - offset
    latest = ctx.window.end - timedelta(hours=duration_h)
    if start > latest:
        start -= timedelta(days=1)
    return ctx.window.clamp(start)


@register_scenario
class BenignButWeirdScenario(Scenario):
    key = "benign_but_weird"
    technique = None
    sources = (SourceType.ZSCALER, SourceType.OKTA)
    expected_detectors = ()
    expected_disposition = "false_positive"
    must_correlate_into_one_incident = False
    description = (
        "Three unrelated sanctioned motifs shaped like attacks — a nightly backup job, a "
        "new-hire onboarding burst, and a scheduled pen-test window. None of it is malicious; "
        "this is the docs/11 false-positive control."
    )

    def __init__(
        self,
        *,
        # regular-interval backup job (beaconing + exfil shape). Duration is not an independent
        # knob: the burst's actual span is `(backup_events - 1) * account.interval_s`, the
        # account's own already-established cadence (see module docstring) — sweep
        # `backup_events` to change how long the burst runs.
        backup_events: int = 55,
        backup_start_fraction: float = 0.28,
        backup_local_hour: float = 2.0,
        backup_mean_chunk_mb: float = 90.0,
        backup_chunk_sigma: float = 0.55,
        # new-hire onboarding (account-takeover shape)
        onboarding_domains: int = 24,
        onboarding_grants: int = 6,
        onboarding_duration_h: float = 2.0,
        onboarding_start_fraction: float = 0.5,
        onboarding_local_hour: float = 10.0,
        # scheduled pen-test window (spray shape)
        pentest_principals: int = 8,
        pentest_attempts: int = 2,
        pentest_duration_min: float = 90.0,
        pentest_start_fraction: float = 0.72,
        pentest_local_hour: float = 11.0,
    ) -> None:
        self.backup_events = backup_events
        self.backup_start_fraction = backup_start_fraction
        self.backup_local_hour = backup_local_hour
        self.backup_mean_chunk_mb = backup_mean_chunk_mb
        self.backup_chunk_sigma = backup_chunk_sigma
        self.onboarding_domains = onboarding_domains
        self.onboarding_grants = onboarding_grants
        self.onboarding_duration_h = onboarding_duration_h
        self.onboarding_start_fraction = onboarding_start_fraction
        self.onboarding_local_hour = onboarding_local_hour
        self.pentest_principals = pentest_principals
        self.pentest_attempts = pentest_attempts
        self.pentest_duration_min = pentest_duration_min
        self.pentest_start_fraction = pentest_start_fraction
        self.pentest_local_hour = pentest_local_hour

    # ------------------------------------------------------------------ inject

    def inject(self, ctx: ScenarioContext) -> GroundTruth:
        backup_principal, backup_note = self._backup_job(ctx)
        onboarding_note = self._onboarding(ctx)
        pentest_note = self._pentest(ctx)

        return self.make_ground_truth(
            ctx,
            primary_entity=EntityRef(type="user", value=backup_principal),
            notes=(
                "docs/11 false-positive control, three unrelated sanctioned motifs, none "
                f"malicious. (1) backup: {backup_note}. (2) onboarding: {onboarding_note}. "
                f"(3) pen-test: {pentest_note}."
            ),
        )

    # ------------------------------------------------------------------ (1) nightly backup job

    def _backup_job(self, ctx: ScenarioContext) -> tuple[str, str]:
        """Regular-interval, automation-UA, large-upload traffic from a catalogued svc account.

        Every column an L1 rule or the L2 beaconing score keys on is exactly what a real backup
        agent produces, on purpose: `signal.beaconing` must stay quiet only because this actor
        and this destination are already the org's own, not because the traffic looks harmless.

        Returns `(principal, note)`.
        """
        account = next(
            (u for u in ctx.org.service_accounts if "backup" in u.purpose.lower()),
            ctx.org.service_accounts[0],
        )
        r = ctx.user_rng(account)
        emitter = ZScalerEmitter()

        host, appname = self._backup_destination(ctx, account, r)
        interval = float(account.interval_s or 3600)
        # The real span is entirely determined by the account's own cadence and chunk count, not
        # an independent knob (see module docstring) -- `_local_start` must reserve room for
        # *this*, or it can anchor a burst too close to `window.end` and silently overrun it.
        span_h = ((self.backup_events - 1) * interval) / 3600.0 if self.backup_events > 1 else 0.0
        start = _local_start(
            ctx,
            account,
            start_fraction=self.backup_start_fraction,
            local_hour=self.backup_local_hour,
            duration_h=span_h,
        )
        mu = (
            math.log(max(self.backup_mean_chunk_mb, 1.0) * 1_000_000.0)
            - self.backup_chunk_sigma**2 / 2.0
        )

        ts = start
        for i in range(self.backup_events):
            chunk = int(min(r.lognormal(mu, self.backup_chunk_sigma), 2_000_000_000))
            ext = _BACKUP_EXTENSIONS[i % len(_BACKUP_EXTENSIONS)]
            emitter.inject(
                ctx,
                user=account,
                ts=ctx.window.clamp(ts),
                host=host,
                url=f"/backup/{account.username}/{r.hex_token(4)}-{i:04d}.{ext}",
                method="PUT",
                status=200,
                bytes_out=chunk,
                bytes_in=r.randint(180, 2200),
                appname=appname,
                malicious=False,
            )
            ts += timedelta(seconds=r.jitter(interval, 0.015))

        note = (
            f"{account.username} ({account.purpose}) -> {host} every {interval:.0f}s, "
            f"{self.backup_events} chunks from {start.isoformat()}, automation UA "
            f"{account.device.user_agent}"
        )
        return account.principal, note

    def _backup_destination(
        self, ctx: ScenarioContext, account: User, rng: SeededRandom
    ) -> tuple[str, str]:
        by_name = {a.name: a for a in ctx.org.saas_apps}
        for app_name in account.saas_apps:
            app = by_name.get(app_name)
            if app is not None and app.category == "storage":
                return app.domain, app.name
        storage_apps = [a for a in ctx.org.saas_apps if a.category == "storage"]
        if storage_apps:
            app = rng.choice(storage_apps)
            return app.domain, app.name
        return ctx.models.domains.sample(rng), "General Browsing"

    # ------------------------------------------------------------------ (2) new-hire onboarding

    def _onboarding(self, ctx: ScenarioContext) -> str:
        """IT provisions one employee, who then browses domains new to them but not to the org.

        The admin side stays quiet because it comes from an `ADMIN_DEPARTMENTS` member's own
        device and address — the exact discriminator docs/04 gives that rule. The browsing side
        stays quiet because `signal.rarity` and NRD are org-wide statistics: popular sites the
        organization already knows are not rare just because this one employee is new.
        """
        rng = ctx.rng.substream("benign_but_weird:onboarding")
        admin_pool = [u for u in ctx.org.users if u.department in ADMIN_DEPARTMENTS] or list(
            ctx.org.users
        )
        admin = rng.choice(admin_pool)
        new_hire = rng.choice([u for u in ctx.org.users if u != admin] or list(ctx.org.users))

        okta = OktaEmitter()
        admin_rng = ctx.user_rng(admin)
        admin_client = okta.client_for(admin, admin_rng)
        start = _local_start(
            ctx,
            admin,
            start_fraction=self.onboarding_start_fraction,
            local_hour=self.onboarding_local_hour,
            duration_h=self.onboarding_duration_h,
        )
        step = (self.onboarding_duration_h * 3600.0) / max(self.onboarding_grants, 1)

        grant_events = []
        ts = start
        for i in range(self.onboarding_grants):
            if i == self.onboarding_grants - 1:
                event_type, targets = "user.account.privilege.grant", (user_target(new_hire),)
            else:
                app = _ONBOARDING_APPS[i % len(_ONBOARDING_APPS)]
                event_type = "application.user_membership.add"
                targets = (user_target(new_hire), app_target(app))
            grant_events.append(
                okta.build_event(
                    user=admin,
                    ts=ctx.window.clamp(ts),
                    event_type=event_type,
                    rng=admin_rng,
                    client=admin_client,
                    targets=targets,
                )
            )
            ts += timedelta(seconds=admin_rng.jitter(step, 0.3))
        okta.inject(ctx, grant_events, malicious=False)

        new_hire_rng = ctx.user_rng(new_hire)
        session = okta.login_session(
            new_hire,
            start=ctx.window.clamp(start + timedelta(minutes=5)),
            rng=new_hire_rng,
            mfa=True,
            n_sso=2,
            failures=0,
        )
        okta.inject(ctx, session, malicious=False)

        proxy = ZScalerEmitter()
        candidates = [d for d in ctx.models.domains.head(400) if d not in new_hire.domain_affinity]
        picked = new_hire_rng.sample(candidates, self.onboarding_domains)
        browse_start = start + timedelta(minutes=20)
        span_s = max(self.onboarding_duration_h * 3600.0 - 1200.0, 60.0)
        offsets = sorted(new_hire_rng.uniform(0.0, span_s) for _ in picked)
        for domain, offset in zip(picked, offsets, strict=True):
            kind = ctx.models.response_sizes.sample_kind(new_hire_rng)
            proxy.inject(
                ctx,
                user=new_hire,
                ts=ctx.window.clamp(browse_start + timedelta(seconds=offset)),
                host=domain,
                url="/",
                method="GET",
                bytes_out=ctx.models.response_sizes.request_bytes(new_hire_rng, "GET"),
                bytes_in=ctx.models.response_sizes.response_bytes(new_hire_rng, kind),
                malicious=False,
            )

        return (
            f"{admin.username} ({admin.department}) provisioned {new_hire.username} with "
            f"{self.onboarding_grants} grants from {admin_client.ip}; {new_hire.username} then "
            f"visited {len(picked)} org-common domains new to them starting "
            f"{browse_start.isoformat()}"
        )

    # ------------------------------------------------------------------ (3) scheduled pen-test

    def _pentest(self, ctx: ScenarioContext) -> str:
        """Failed sign-ons against a handful of principals from a known internal address.

        Stays under two independent margins of the `sigma.password_spray` threshold
        (`< 10 distinct principals` *and* `> 30m window`) rather than one, and never succeeds, so
        there is no compromised session for the new-country or no-prior-proxy-history rules to
        key on either.
        """
        rng = ctx.rng.substream("benign_but_weird:pentest")
        okta = OktaEmitter()
        tester_pool = [u for u in ctx.org.users if u.department in ADMIN_DEPARTMENTS] or list(
            ctx.org.users
        )
        tester = rng.choice(tester_pool)
        tester_rng = ctx.user_rng(tester)
        client = okta.client_for(tester, tester_rng)

        n_principals = min(self.pentest_principals, len(ctx.org.users))
        victims = ctx.org.pick_users(rng, n_principals)
        start = _local_start(
            ctx,
            tester,
            start_fraction=self.pentest_start_fraction,
            local_hour=self.pentest_local_hour,
            duration_h=self.pentest_duration_min / 60.0,
        )

        total = max(1, self.pentest_attempts * len(victims))
        step = (self.pentest_duration_min * 60.0) / total
        events = []
        at = start
        for _ in range(self.pentest_attempts):
            for victim in victims:
                ts = ctx.window.clamp(at + timedelta(seconds=rng.uniform(0.0, step * 0.6)))
                events.append(
                    okta.build_event(
                        user=victim,
                        ts=ts,
                        event_type="user.session.start",
                        outcome="FAILURE",
                        rng=rng,
                        client=client,
                        reason="Authorized penetration test — pre-approved change CR",
                    )
                )
                at += timedelta(seconds=step)
        okta.inject(ctx, events, malicious=False)

        return (
            f"{tester.username} ({tester.department}) ran {self.pentest_attempts} attempts "
            f"against {len(victims)} principals from {client.ip} (own address) over "
            f"{self.pentest_duration_min:.0f}m starting {start.isoformat()}: under both the "
            "principal-count and time-window spray margins, no successes"
        )
