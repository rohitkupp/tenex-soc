"""Scenario 9 — multi-domain C2 failover (ATT&CK T1008, "Fallback Channels").

Ported from the legacy `datagen/generate_corpus.py` (`sc_multi_domain_c2_failover`), which had no
counterpart in this package — docs/11's eight-scenario table never grew a row for it, but the
train/validation/golden corpus generate_corpus.py built has carried it since the original
migration delivery (change 13), and dropping it on consolidation would be a silent coverage loss.

The premise: rather than one fixed callback domain (`s01_c2_beaconing`), the implant is
provisioned with a short list of sibling domains and switches to the next one every so often —
the fallback behaviour the technique name describes, and a stress test for correlation rather
than for any single L2 signal. Individually, each domain only gets a short-lived beacon burst,
which is easy to miss as an isolated 30-request blip. What should tie the bursts back into one
incident is that every sibling resolves into the *same* two-octet address block (`graph.
shared_infra`, docs/05) — this is deliberately not scored as one continuous beacon (`signal.
beaconing` needs a stable `(src_ip, domain)` pair with enough samples; each burst here is
short and the domain changes under it), it is scored as several short bursts from one source
that share destination infrastructure, which is what should pull them into a single graph
incident instead of several unrelated low-confidence ones.

`SHARED_CAMPAIGN_DOMAINS`-style cross-tenant domain reuse (the legacy generator's mechanism for
demonstrating Tier 2 overlap) is deliberately not ported here: `app/scripts/seed_tier2.py`
already seeds that overlap independently and does not import the corpus generator at all (see
its module docstring), so this scenario only has to be internally consistent, not carry that
concern too.
"""

from __future__ import annotations

import math
from datetime import timedelta
from typing import TYPE_CHECKING, Any, Final

from datagen.emitters.zscaler import ZScalerEmitter
from datagen.scenarios import register_scenario
from datagen.types import (
    GRAPH_SHARED_INFRA,
    SIGNAL_BEACONING,
    SIGNAL_RARITY,
    EntityRef,
    GroundTruth,
    Scenario,
    ScenarioContext,
    SourceType,
)

if TYPE_CHECKING:
    from datetime import datetime

    from datagen.rng import SeededRandom

__all__ = ["MultiDomainFailoverScenario"]

# Same abuse-heavy TLD pool `s01_c2_beaconing` draws from — sibling domains of one campaign are
# registered the same way its single domain would be.
_C2_TLDS: Final[tuple[str, ...]] = ("top", "xyz", "cc", "su", "info")
_DGA_STYLES: Final[dict[str, str]] = {
    "dga": "random",
    "hex": "hex",
    "consonant": "consonant",
    "numeric": "numeric",
}

_CHECKIN_PATHS: Final[tuple[str, ...]] = ("/api/v1/gate?id=", "/pixel?u=", "/updates/check?c=")

_STATUS_CODES: Final[tuple[int, ...]] = (200, 204, 404)
_STATUS_WEIGHTS: Final[tuple[float, ...]] = (0.93, 0.05, 0.02)
_POLL_OUT_BYTES: Final[tuple[int, int]] = (180, 900)
_POLL_IN_BYTES: Final[tuple[int, int]] = (140, 640)

# How long a burst lingers on one sibling before failing over to the next, and the size of each
# burst — short enough that no single domain accumulates the sample count `signal.beaconing`
# needs, which is the point (see module docstring).
_FAILOVER_GAP_MIN: Final[tuple[float, float]] = (35.0, 80.0)


@register_scenario
class MultiDomainFailoverScenario(Scenario):
    """One implant, several sibling C2 domains sharing an address block, one active at a time."""

    key = "multi_domain_c2_failover"
    technique = "T1008"
    sources = (SourceType.ZSCALER,)
    expected_detectors = (SIGNAL_BEACONING, SIGNAL_RARITY, GRAPH_SHARED_INFRA)
    description = (
        "Implant fails over across several sibling domains resolving behind one shared address "
        "block; each domain gets a short beacon burst before the next takes over."
    )

    def __init__(
        self,
        *,
        n_domains: int = 4,
        interval_s: float = 90.0,
        jitter_pct: float = 0.15,
        burst_events: int = 30,
        domain_style: str = "dga",
        blend_with_normal_traffic: bool = True,
    ) -> None:
        if not 2 <= n_domains <= 8:
            raise ValueError("n_domains must be 2..8")
        if interval_s <= 0:
            raise ValueError("interval_s must be > 0")
        if jitter_pct < 0:
            raise ValueError("jitter_pct must be >= 0")
        if burst_events < 1:
            raise ValueError("burst_events must be >= 1")
        if domain_style not in _DGA_STYLES:
            raise ValueError(f"unknown domain_style {domain_style!r}; known: {tuple(_DGA_STYLES)}")

        self.n_domains = int(n_domains)
        self.interval_s = float(interval_s)
        self.jitter_pct = float(jitter_pct)
        self.burst_events = int(burst_events)
        self.domain_style = domain_style
        self.blend_with_normal_traffic = blend_with_normal_traffic

    # ------------------------------------------------------------------ injection

    def inject(self, ctx: ScenarioContext) -> GroundTruth:
        victim = ctx.org.pick_user(ctx.rng)
        rng = ctx.user_rng(victim)
        emitter = ZScalerEmitter()

        domains = self._sibling_domains(ctx, rng)
        src_ip = victim.source_ip(rng)
        user_agent = self._user_agent(ctx, rng, victim)
        # Two-octet block shared by every sibling — the signal `graph.shared_infra` looks for.
        anchor = f"{rng.randint(20, 209)}.{rng.randint(0, 255)}"

        est_span_s = self.n_domains * (
            self.burst_events * self.interval_s + sum(_FAILOVER_GAP_MIN) / 2 * 60.0
        )
        ts = self._start(ctx, rng, est_span_s)

        total = 0
        for domain in domains:
            for _ in range(self.burst_events):
                if ts >= ctx.window.end:
                    break
                status = rng.weighted_choice(_STATUS_CODES, _STATUS_WEIGHTS)
                dst_ip = rng.ip_in(f"{anchor}.{rng.randint(0, 255)}")
                emitter.inject(
                    ctx,
                    user=victim,
                    ts=ts,
                    host=domain,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    user_agent=user_agent,
                    url=f"{rng.choice(_CHECKIN_PATHS)}{rng.hex_token(6)}",
                    status=status,
                    bytes_out=rng.randint(*_POLL_OUT_BYTES),
                    bytes_in=0 if status == 204 else rng.randint(*_POLL_IN_BYTES),
                    category=self._category(),
                )
                total += 1
                ts += timedelta(seconds=self._sleep_s(rng))
            ts += timedelta(minutes=rng.uniform(*_FAILOVER_GAP_MIN))

        return self.make_ground_truth(
            ctx,
            primary_entity=EntityRef(type="user", value=victim.principal),
            notes=(
                f"{len(domains)} sibling {self.domain_style} domains behind {anchor}.0.0/16, "
                f"{self.burst_events} events/domain from {src_ip}, {total} total callbacks"
            ),
        )

    # ------------------------------------------------------------------ knob plumbing

    def _sibling_domains(self, ctx: ScenarioContext, rng: SeededRandom) -> list[str]:
        seen: set[str] = set()
        while len(seen) < self.n_domains:
            seen.add(
                ctx.models.dga.generate(
                    rng,
                    style=_DGA_STYLES[self.domain_style],
                    tld=rng.choice(_C2_TLDS),  # type: ignore[arg-type]
                )
            )
        return sorted(seen)

    def _sleep_s(self, rng: SeededRandom) -> float:
        """Log-normal sleep, unit mean and CV `jitter_pct` — same construction as
        `s01_c2_beaconing._sleep_s`, kept local rather than imported (this scenario's `rng` stream
        is independent, and a shared helper across scenario modules is more coupling than the
        three-line function is worth)."""
        if self.jitter_pct <= 0.0:
            return self.interval_s
        sigma = math.sqrt(math.log1p(self.jitter_pct**2))
        return self.interval_s * rng.lognormal(-0.5 * sigma * sigma, sigma)

    def _user_agent(self, ctx: ScenarioContext, rng: SeededRandom, victim: Any) -> str:
        if self.blend_with_normal_traffic:
            return victim.device.user_agent
        return ctx.models.user_agents.sample_automation(rng.fresh("implant-ua")).user_agent

    def _category(self) -> str | None:
        return None  # let each domain resolve its own stable, hash-derived category

    def _start(self, ctx: ScenarioContext, rng: SeededRandom, span_s: float) -> datetime:
        slack = max(0.0, ctx.window.duration_s - span_s)
        return ctx.window.start + timedelta(seconds=rng.uniform(0.15, 0.55) * slack)
