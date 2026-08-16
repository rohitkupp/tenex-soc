"""Scenario 10 — web shell / sensitive-path probing (ATT&CK T1505.003, "Server Software
Component: Web Shell").

Ported from the legacy `datagen/generate_corpus.py` (`sc_web_shell_probing`), which had no
counterpart in this package for the same reason `s09_multi_domain_c2_failover` did not: docs/11's
table never grew a row for it, but the train/validation/golden corpus has carried it since the
original migration delivery.

A compromised host walks a short dictionary of common web-shell and secret-file paths against one
rarely-visited destination — `/shell.php`, `/.env`, `/.git/config`, path-traversal attempts, and
similar. Nearly every request gets blocked by URL policy; the interesting signal is that a small
fraction land a `200` on the *same* host within the same short window, which is exactly what
`sigma.blocked_then_allowed` (docs/04, `app/detection/rules/blocked-then-allowed.yml`) is built to
catch — a retry that eventually gets through, grouped by `(domain, src_ip)`. The legacy
generator's expected detectors (`evidence.url_entropy`, `sigma.high_404_ratio`) do not correspond
to anything in the current `DETECTOR_KEYS` registry (`datagen/types.py`) — both were probably
renamed or dropped somewhere between the original delivery and this package's detector set — so
this port targets the two current detectors the traffic shape actually should trip:
`signal.rarity` (the destination itself is a long-tail domain nobody else in the org visits) and
`sigma.blocked_then_allowed`.
"""

from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING, Final

from datagen.emitters.zscaler import ZScalerEmitter
from datagen.scenarios import register_scenario
from datagen.types import (
    SIGMA_BLOCKED_THEN_ALLOWED,
    SIGMA_NON_BROWSER_UA,
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

__all__ = ["WebShellProbingScenario"]

# Common web-shell drop paths, framework admin panels, and secret files — a rarely-visited host
# getting hit with this exact mix is the behavioural tell, independent of any single path.
_PROBE_PATHS: Final[tuple[str, ...]] = (
    "/shell.php",
    "/cmd.jsp",
    "/uploads/x.php",
    "/wp-admin/setup-config.php",
    "/../../../../etc/passwd",
    "/admin/../../config.yml",
    "/.env",
    "/.git/config",
    "/phpmyadmin/index.php",
    "/manager/html",
    "/api/../../secrets",
)

_BLOCKED_STATUS: Final[tuple[int, ...]] = (404, 404, 403, 500)


@register_scenario
class WebShellProbingScenario(Scenario):
    """Dictionary walk of web-shell/secret-file paths against one long-tail destination."""

    key = "web_shell_probing"
    technique = "T1505.003"
    sources = (SourceType.ZSCALER,)
    expected_detectors = (SIGNAL_RARITY, SIGMA_BLOCKED_THEN_ALLOWED)
    description = (
        "Dictionary walk of web-shell and secret-file paths against a rarely-visited host; "
        "mostly blocked by URL policy with an occasional 200 close behind a block."
    )

    def __init__(
        self,
        *,
        n_probes: int = 90,
        hit_rate: float = 0.08,
        blend_with_normal_traffic: bool = True,
    ) -> None:
        if n_probes < 1:
            raise ValueError("n_probes must be >= 1")
        if not 0.0 <= hit_rate <= 1.0:
            raise ValueError("hit_rate must be in [0, 1]")

        self.n_probes = int(n_probes)
        self.hit_rate = float(hit_rate)
        self.blend_with_normal_traffic = blend_with_normal_traffic

    # ------------------------------------------------------------------ injection

    def inject(self, ctx: ScenarioContext) -> GroundTruth:
        victim = ctx.org.pick_user(ctx.rng)
        rng = ctx.user_rng(victim)
        emitter = ZScalerEmitter()

        target = ctx.models.domains.sample_tail(rng)
        src_ip = victim.source_ip(rng)
        user_agent = self._user_agent(ctx, rng, victim)

        ts = self._start(ctx, rng)
        n_hits = 0
        for _ in range(self.n_probes):
            if ts >= ctx.window.end:
                break
            path = rng.choice(_PROBE_PATHS)
            hit = rng.chance(self.hit_rate)
            if hit:
                n_hits += 1
            status = 200 if hit else rng.choice(_BLOCKED_STATUS)
            emitter.inject(
                ctx,
                user=victim,
                ts=ts,
                host=target,
                src_ip=src_ip,
                user_agent=user_agent,
                url=path,
                status=status,
                action="Allowed" if hit else "Blocked",
                reason="" if hit else "Blocked due to URL policy",
                bytes_out=rng.randint(180, 520),
                bytes_in=rng.randint(80, 4_000) if hit else rng.randint(60, 300),
                riskscore=85 if hit else None,
                category=None,  # host's own stable, hash-derived category
            )
            ts += timedelta(seconds=rng.randint(1, 9))

        return self.make_ground_truth(
            ctx,
            primary_entity=EntityRef(type="user", value=victim.principal),
            expected_detectors=self._detectors(),
            notes=(
                f"{self.n_probes} probe requests against first-seen {target}, "
                f"{n_hits} landed 200 from {src_ip}"
            ),
        )

    # ------------------------------------------------------------------ knob plumbing

    def _user_agent(self, ctx: ScenarioContext, rng: SeededRandom, victim: object) -> str:
        if self.blend_with_normal_traffic:
            return victim.device.user_agent  # type: ignore[attr-defined]
        return ctx.models.user_agents.sample_automation(rng.fresh("scanner-ua")).user_agent

    def _detectors(self) -> tuple[str, ...]:
        detectors: list[str] = [SIGNAL_RARITY, SIGMA_BLOCKED_THEN_ALLOWED]
        if not self.blend_with_normal_traffic:
            detectors.append(SIGMA_NON_BROWSER_UA)
        return tuple(detectors)

    def _start(self, ctx: ScenarioContext, rng: SeededRandom) -> datetime:
        span_s = self.n_probes * 5.0
        slack = max(0.0, ctx.window.duration_s - span_s)
        return ctx.window.start + timedelta(seconds=rng.uniform(0.15, 0.6) * slack)
