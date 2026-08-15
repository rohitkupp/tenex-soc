"""Scenario 3 — password spray, one success, then browsing from the new geography.

docs/11 scenario 3 (T1110.003 then T1078). This is the only scenario whose value lies entirely in
a join: the Okta failures and the ZScaler requests are each unremarkable on their own, and only
the shared `src_ip` turns them into one incident. Every choice below serves that join, which is
why the attacker's address is threaded explicitly through both emitters rather than left to
default to the victim's office egress.

Three shapes come straight from the docs/04 rule inventory and are what the defaults encode:

* the spray touches >= 10 distinct principals, <= 3 attempts each, one source address, inside
  30 minutes — the spray rule;
* the successful sign-on arrives from an address with no proxy history for that principal —
  cross-source rule "successful login from IP with no prior proxy history";
* that same address then appears in the proxy log fetching rare domains — cross-source rule
  "auth failure burst from an IP that also appears in proxy logs contacting a rare domain".

The knobs are deliberately not validated against those thresholds. A sweep that pushes
`attempts_per_principal` past three is asking where the rule stops firing; a scenario that raised
instead of generating would have no answer to give.
"""

from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING

from datagen.emitters.okta import OktaClient, OktaEmitter
from datagen.emitters.zscaler import ZScalerEmitter
from datagen.scenarios import register_scenario
from datagen.types import (
    SIGMA_NEW_COUNTRY,
    SIGMA_PASSWORD_SPRAY,
    SIGMA_XSRC_AUTH_AND_RARE_DOMAIN,
    SIGMA_XSRC_LOGIN_NO_PROXY_HISTORY,
    SIGNAL_RARITY,
    EntityRef,
    Scenario,
    SourceType,
)

if TYPE_CHECKING:
    from datetime import datetime

    from datagen.org import User
    from datagen.rng import SeededRandom
    from datagen.types import GroundTruth, ScenarioContext

# Failed sign-ons carry no session, so Okta stamps `externalSessionId` as the literal "unknown".
_SPRAY_EVENT = "user.session.start"

# Paths a hands-on-keyboard operator produces after taking over a session: the SaaS landing pages
# they already have SSO for, plus lookups against their own staging infrastructure.
_BROWSE_PATHS: tuple[str, ...] = (
    "/",
    "/login",
    "/dashboard",
    "/settings/profile",
    "/api/v1/me",
    "/api/v1/users?page=",
    "/search?q=",
    "/files/",
)


@register_scenario
class PasswordSprayScenario(Scenario):
    key = "password_spray"
    technique = "T1110.003"
    sources = (SourceType.OKTA, SourceType.ZSCALER)
    expected_detectors = (
        SIGMA_PASSWORD_SPRAY,
        SIGMA_XSRC_AUTH_AND_RARE_DOMAIN,
        SIGMA_XSRC_LOGIN_NO_PROXY_HISTORY,
        SIGMA_NEW_COUNTRY,
        SIGNAL_RARITY,
    )
    expected_disposition = "true_positive"
    must_correlate_into_one_incident = True
    description = (
        "One foreign address sprays a few passwords across many principals, succeeds on one, "
        "and then browses from that same address."
    )

    def __init__(
        self,
        *,
        n_sprayed_principals: int = 18,
        attempts_per_principal: int = 2,
        spray_duration_min: float = 22.0,
        start_fraction: float = 0.55,
        success_delay_min: float = 7.0,
        mfa_prompted: bool = False,
        n_sso_after_success: int = 3,
        n_browse_events: int = 45,
        n_rare_domains: int = 4,
        rare_domain_ratio: float = 0.4,
        browse_duration_h: float = 1.5,
        browse_delay_min: float = 3.0,
        hosting_source: bool = True,
    ) -> None:
        self.n_sprayed_principals = n_sprayed_principals
        self.attempts_per_principal = attempts_per_principal
        self.spray_duration_min = spray_duration_min
        self.start_fraction = start_fraction
        self.success_delay_min = success_delay_min
        self.mfa_prompted = mfa_prompted
        self.n_sso_after_success = n_sso_after_success
        self.n_browse_events = n_browse_events
        self.n_rare_domains = n_rare_domains
        self.rare_domain_ratio = rare_domain_ratio
        self.browse_duration_h = browse_duration_h
        self.browse_delay_min = browse_delay_min
        self.hosting_source = hosting_source

    def inject(self, ctx: ScenarioContext) -> GroundTruth:
        # One actor, one stream. Per-victim sub-streams would be the convention for events the
        # victims themselves generate, but every event here is produced by the same operator and
        # keying them apart would only make the attack's timing depend on who was sprayed.
        rng = ctx.rng.substream("attacker")
        okta = OktaEmitter()
        proxy = ZScalerEmitter()

        victims = ctx.org.pick_users(rng, min(self.n_sprayed_principals, len(ctx.org.users)))
        origin = ctx.models.geo.foreign_point(
            rng, exclude_country=victims[0].office.country, hosting=self.hosting_source
        )
        agent = ctx.models.user_agents.sample_desktop(rng)
        client = OktaClient(
            ip=origin.ip,
            geo=origin,
            user_agent=agent.user_agent,
            browser_family=agent.browser_family,
            os_family=agent.os_family,
            device_type=agent.device_type,
            is_proxy=self.hosting_source,
        )

        spray_start = ctx.window.fraction(self.start_fraction)
        spray_end = self._spray(ctx, okta, victims, client, rng, spray_start)

        compromised = rng.choice(victims)
        login_at = spray_end + timedelta(minutes=self.success_delay_min)
        okta.inject(
            ctx,
            okta.login_session(
                compromised,
                start=login_at,
                rng=rng,
                client=client,
                mfa=self.mfa_prompted,
                n_sso=self.n_sso_after_success,
                failures=0,
                end_session=False,
            ),
        )

        browse_start = login_at + timedelta(minutes=self.browse_delay_min)
        hosts = self._browse(ctx, proxy, compromised, client, rng, browse_start)

        return self.make_ground_truth(
            ctx,
            primary_entity=EntityRef(type="src_ip", value=origin.ip),
            technique="T1110.003",
            notes=(
                f"spray from {origin.ip} ({origin.city}, {origin.country}, AS{origin.asn}) "
                f"against {len(victims)} principals; compromised={compromised.principal} "
                f"(T1078); rare domains={','.join(hosts)}; same src_ip appears in okta and "
                "zscaler, which is the join the correlation layer must make"
            ),
        )

    # ------------------------------------------------------------------ phases

    def _spray(
        self,
        ctx: ScenarioContext,
        okta: OktaEmitter,
        victims: list[User],
        client: OktaClient,
        rng: SeededRandom,
        start: datetime,
    ) -> datetime:
        """Walk the victim list once per attempted password — how a real spray paces itself.

        Cycling passwords in the outer loop rather than victims is what keeps the per-principal
        attempt count under the lockout threshold while the aggregate stays a burst.
        """
        total = max(1, self.attempts_per_principal * len(victims))
        step = (self.spray_duration_min * 60.0) / total
        at = start
        for _ in range(self.attempts_per_principal):
            for victim in victims:
                ts = ctx.window.clamp(at + timedelta(seconds=rng.uniform(0.0, step * 0.6)))
                okta.inject(
                    ctx,
                    [
                        okta.build_event(
                            user=victim,
                            ts=ts,
                            event_type=_SPRAY_EVENT,
                            outcome="FAILURE",
                            rng=rng,
                            client=client,
                        )
                    ],
                )
                at += timedelta(seconds=step)
        return at

    def _browse(
        self,
        ctx: ScenarioContext,
        proxy: ZScalerEmitter,
        victim: User,
        client: OktaClient,
        rng: SeededRandom,
        start: datetime,
    ) -> list[str]:
        """Proxy traffic for the compromised principal from the attacker's address.

        Mixes the victim's own SaaS estate with long-tail domains drawn from the real top-sites
        list: rare-but-real is what the rarity detector is calibrated for, and a wholly invented
        hostname would be discriminable on string statistics alone.
        """
        models = ctx.models
        rare = [models.domains.sample_tail(rng) for _ in range(max(self.n_rare_domains, 1))]
        familiar = [a.domain for a in ctx.org.saas_apps if a.name in victim.saas_apps] or list(
            victim.domain_affinity[:4]
        )
        span = self.browse_duration_h * 3600.0
        offsets = sorted(rng.uniform(0.0, span) for _ in range(self.n_browse_events))

        for offset in offsets:
            host = rng.choice(rare) if rng.chance(self.rare_domain_ratio) else rng.choice(familiar)
            method = "POST" if rng.chance(0.18) else "GET"
            kind = "api" if method == "POST" else models.response_sizes.sample_kind(rng)
            path = rng.choice(_BROWSE_PATHS)
            url = f"{path}{rng.hex_token(3)}" if path.endswith(("=", "/")) and path != "/" else path
            proxy.inject(
                ctx,
                user=victim,
                ts=ctx.window.clamp(start + timedelta(seconds=offset)),
                host=host,
                src_ip=client.ip,
                user_agent=client.user_agent,
                url=url,
                method=method,
                bytes_out=models.response_sizes.request_bytes(rng, method),
                bytes_in=models.response_sizes.response_bytes(rng, kind),
            )
        return rare
