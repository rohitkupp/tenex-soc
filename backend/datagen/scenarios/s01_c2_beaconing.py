"""Scenario 1 — C2 beaconing over the web proxy (docs/11 #1, ATT&CK T1071.001).

An implant on one workstation calls home on a fixed period. Everything the eval measures about
it lives in the inter-arrival distribution, so `jitter_pct` is defined here as *the coefficient
of variation the docs/04 L2 detector will measure*, not as the half-width of a uniform band.
Uniform jitter of width p has CV = p/sqrt(3), so the harness's 0.02 -> 0.60 sweep would top out
at CV 0.35 — regularity 0.65, still a clean detection — and the degradation curve would stay
flat exactly where it is supposed to bend. It would also produce negative sleeps past p = 1.0.
Sleeps are therefore log-normal with unit mean and CV exactly `jitter_pct`: positive by
construction, and the knob is the measurement.

The whole beacon runs from one pinned `src_ip`. L2 groups by `(src_ip, domain)` and needs eight
events in a group; a beacon that alternated between office egress and home broadband would split
into two half-length groups and under-report its own regularity.
"""

from __future__ import annotations

import math
from datetime import timedelta
from typing import TYPE_CHECKING, Any, Final

from datagen.emitters.zscaler import ZScalerEmitter
from datagen.scenarios import register_scenario
from datagen.types import (
    SIGMA_NON_BROWSER_UA,
    SIGMA_THREAT_CATEGORY,
    SIGNAL_BEACONING,
    SIGNAL_DGA,
    SIGNAL_NEWLY_REGISTERED,
    SIGNAL_RARITY,
    EntityRef,
    GroundTruth,
    Scenario,
    ScenarioContext,
    SourceType,
)

if TYPE_CHECKING:
    from collections.abc import Sequence
    from datetime import datetime

    from datagen.org import User
    from datagen.rng import SeededRandom

__all__ = ["BeaconingScenario"]

# `domain_style` values that map onto a `DGAGenerator` style. `nrd` and `tail` are the two
# non-DGA destinations the sweep needs: a registered-yesterday lookalike, and a real-but-rare
# domain from the long tail — the case where `signal.dga` correctly does not fire and beaconing
# has to carry the detection on its own.
_DGA_STYLES: Final[dict[str, str]] = {
    "dga": "random",
    "hex": "hex",
    "consonant": "consonant",
    "numeric": "numeric",
}
DOMAIN_STYLES: Final[tuple[str, ...]] = (*_DGA_STYLES, "nrd", "tail")

# Abuse-heavy TLDs, which is where DGA families actually register.
_C2_TLDS: Final[tuple[str, ...]] = ("top", "xyz", "cc", "su", "info")

_CHECKIN_PATHS: Final[tuple[str, ...]] = (
    "/api/v1/gate?id=",
    "/pixel?u=",
    "/updates/check?c=",
    "/cm/?t=",
    "/j/",
)
_UPLOAD_PATHS: Final[tuple[str, ...]] = ("/api/v1/post?id=", "/upload?s=", "/data/put?k=")

# Share of check-ins that carry a result back instead of just polling, and the share of polls
# the operator answers with a task. Both keep `bytes_out`/`bytes_in` off a constant, which would
# be a giveaway no real implant produces.
_UPLOAD_RATE: Final[float] = 0.08
_TASK_RATE: Final[float] = 0.10

_STATUS_CODES: Final[tuple[int, ...]] = (200, 204, 404)
_STATUS_WEIGHTS: Final[tuple[float, ...]] = (0.93, 0.05, 0.02)

_POLL_OUT_BYTES: Final[tuple[int, int]] = (180, 900)
_POLL_IN_BYTES: Final[tuple[int, int]] = (140, 640)
_TASK_IN_BYTES: Final[tuple[int, int]] = (2_000, 40_000)
_RESULT_OUT_BYTES: Final[tuple[int, int]] = (1_500, 60_000)
_ACK_IN_BYTES: Final[tuple[int, int]] = (140, 400)

_C2_THREAT: Final[dict[str, Any]] = {
    "threatname": "Backdoor.Generic.C2",
    "threatcategory": "Botnet",
    "riskscore": 98,
    "reason": "Advanced Threat Protection: command and control callback",
}

# Where in the corpus window the implant starts. Bounded away from both edges so the detector
# sees the full run and the baseline has clean history in front of it.
_START_FRACTION: Final[tuple[float, float]] = (0.15, 0.65)


def _dispersion(deltas: Sequence[float]) -> tuple[float, float]:
    """`(CV, MAD jitter)` of inter-arrival deltas, computed exactly as docs/04 L2 defines them.

    Reported in the ground-truth notes so a sweep row carries the realized regularity next to
    the knob that was supposed to produce it, instead of the harness having to trust the knob.
    """
    n = len(deltas)
    if n < 2:
        return (0.0, 0.0)
    mean = sum(deltas) / n
    cv = math.sqrt(sum((d - mean) ** 2 for d in deltas) / n) / mean if mean > 0 else 0.0
    ordered = sorted(deltas)
    median = ordered[n // 2] if n % 2 else (ordered[n // 2 - 1] + ordered[n // 2]) / 2.0
    if median <= 0:
        return (cv, 0.0)
    absolute = sorted(abs(d - median) for d in deltas)
    mad = absolute[n // 2] if n % 2 else (absolute[n // 2 - 1] + absolute[n // 2]) / 2.0
    return (cv, mad / median)


@register_scenario
class BeaconingScenario(Scenario):
    """Regular-interval callbacks from one host to one attacker-controlled domain."""

    key = "c2_beaconing"
    technique = "T1071.001"
    sources = (SourceType.ZSCALER,)
    expected_detectors = (SIGNAL_BEACONING, SIGNAL_DGA, SIGNAL_RARITY)
    description = "Implant polls a DGA domain on a fixed period; jitter is the difficulty knob."

    def __init__(
        self,
        *,
        interval_s: float = 60.0,
        jitter_pct: float = 0.12,
        duration_h: float = 6.0,
        n_beacons: int = 360,
        domain_style: str = "dga",
        blend_with_normal_traffic: bool = True,
    ) -> None:
        if interval_s <= 0:
            raise ValueError("interval_s must be > 0")
        if jitter_pct < 0:
            raise ValueError("jitter_pct must be >= 0")
        if duration_h <= 0:
            raise ValueError("duration_h must be > 0")
        if n_beacons < 1:
            raise ValueError("n_beacons must be >= 1")
        if domain_style not in DOMAIN_STYLES:
            raise ValueError(f"unknown domain_style {domain_style!r}; known: {DOMAIN_STYLES}")

        self.interval_s = float(interval_s)
        self.jitter_pct = float(jitter_pct)
        self.duration_h = float(duration_h)
        self.n_beacons = int(n_beacons)
        self.domain_style = domain_style
        self.blend_with_normal_traffic = blend_with_normal_traffic

    # ------------------------------------------------------------------ injection

    def inject(self, ctx: ScenarioContext) -> GroundTruth:
        victim = ctx.org.pick_user(ctx.rng)
        rng = ctx.user_rng(victim)
        emitter = ZScalerEmitter()

        domain = self._domain(ctx, rng)
        src_ip = victim.source_ip(rng)
        user_agent = self._user_agent(ctx, rng, victim)
        category = self._category()
        threat = {} if self.blend_with_normal_traffic else dict(_C2_THREAT)

        span_s = min(self.n_beacons * self.interval_s, self.duration_h * 3600.0)
        ts = self._start(ctx, rng, span_s)
        deadline = min(ts + timedelta(seconds=self.duration_h * 3600.0), ctx.window.end)

        deltas: list[float] = []
        emitted = 0
        while emitted < self.n_beacons and ts < deadline:
            is_upload = rng.chance(_UPLOAD_RATE)
            paths = _UPLOAD_PATHS if is_upload else _CHECKIN_PATHS
            status = rng.weighted_choice(_STATUS_CODES, _STATUS_WEIGHTS)
            if is_upload:
                bytes_out = rng.randint(*_RESULT_OUT_BYTES)
                bytes_in = rng.randint(*_ACK_IN_BYTES)
            else:
                bytes_out = rng.randint(*_POLL_OUT_BYTES)
                bytes_in = rng.randint(
                    *(_TASK_IN_BYTES if rng.chance(_TASK_RATE) else _POLL_IN_BYTES)
                )
            emitter.inject(
                ctx,
                user=victim,
                ts=ts,
                host=domain,
                src_ip=src_ip,
                user_agent=user_agent,
                url=f"{rng.choice(paths)}{rng.hex_token(6)}",
                method="POST" if is_upload else "GET",
                status=status,
                bytes_out=bytes_out,
                bytes_in=0 if status == 204 else bytes_in,
                category=category,
                **threat,
            )
            emitted += 1
            delta = self._sleep_s(rng)
            deltas.append(delta)
            ts += timedelta(seconds=delta)

        cv, mad_jitter = _dispersion(deltas[:-1])
        return self.make_ground_truth(
            ctx,
            primary_entity=EntityRef(type="user", value=victim.principal),
            expected_detectors=self._detectors(),
            notes=(
                f"{self.interval_s:g}s interval, {self.jitter_pct:.2f} jitter, "
                f"{self.duration_h:g}h duration, {self.domain_style} domain {domain}; "
                f"{emitted} callbacks from {src_ip}; measured cv={cv:.3f} mad_jitter="
                f"{mad_jitter:.3f}"
            ),
        )

    # ------------------------------------------------------------------ knob plumbing

    def _sleep_s(self, rng: SeededRandom) -> float:
        """One sleep, mean `interval_s` and coefficient of variation exactly `jitter_pct`.

        A log-normal with mu = -sigma^2/2 has unit mean, and CV = sqrt(exp(sigma^2) - 1), so
        inverting for sigma makes the knob and the measurement the same number.
        """
        if self.jitter_pct <= 0.0:
            return self.interval_s
        sigma = math.sqrt(math.log1p(self.jitter_pct**2))
        return self.interval_s * rng.lognormal(-0.5 * sigma * sigma, sigma)

    def _domain(self, ctx: ScenarioContext, rng: SeededRandom) -> str:
        if self.domain_style == "nrd":
            return ctx.models.newly_registered.sample(rng).domain
        if self.domain_style == "tail":
            return ctx.models.domains.sample_tail(rng)
        return ctx.models.dga.generate(
            rng,
            style=_DGA_STYLES[self.domain_style],  # type: ignore[arg-type]
            tld=rng.choice(_C2_TLDS),
        )

    def _user_agent(self, ctx: ScenarioContext, rng: SeededRandom, victim: User) -> str:
        if self.blend_with_normal_traffic:
            return victim.device.user_agent
        return ctx.models.user_agents.sample_automation(rng.fresh("implant-ua")).user_agent

    def _category(self) -> str | None:
        """`None` keeps the host's own category — only correct for a real long-tail domain."""
        if not self.blend_with_normal_traffic:
            return "c2"
        if self.domain_style == "nrd":
            return "newly_registered"
        if self.domain_style == "tail":
            return None
        return "uncategorized"

    def _start(self, ctx: ScenarioContext, rng: SeededRandom, span_s: float) -> datetime:
        slack = max(0.0, ctx.window.duration_s - span_s)
        return ctx.window.start + timedelta(seconds=rng.uniform(*_START_FRACTION) * slack)

    def _detectors(self) -> tuple[str, ...]:
        """The label has to match the configuration, not the class default.

        A long-tail destination is a real registered domain, so `signal.dga` must *not* be in
        the expected set for that variant — leaving it in would book a permanent false miss and
        quietly drag the reported per-detector recall down.
        """
        detectors: list[str] = [SIGNAL_BEACONING, SIGNAL_RARITY]
        if self.domain_style in _DGA_STYLES:
            detectors.append(SIGNAL_DGA)
        elif self.domain_style == "nrd":
            detectors.append(SIGNAL_NEWLY_REGISTERED)
        if not self.blend_with_normal_traffic:
            detectors.extend((SIGMA_THREAT_CATEGORY, SIGMA_NON_BROWSER_UA))
        return tuple(detectors)
