"""Scenario 7 — insider mass download (docs/11 row 7, T1530).

A trusted employee empties the corporate document repository over one evening. Nothing about
the destination is suspicious: it is the org's own sanctioned storage SaaS, a host the victim
already visits every day, reached from their own browser on their own address. Every column an
L1 rule keys on stays clean — no security category, no threat name, no direct-to-IP request, no
non-browser user agent, no upload at all.

That is deliberate. The only thing that changed is *how much*, so the scenario can only be
caught by the two detectors docs/11 assigns to it: the volumetric burst z-score (docs/04 §L2)
and the cohort comparison (`n_events_z_vs_cohort`, `bytes_in_sum`) that the peer-group model
scores. Give it a rare domain or a curl user agent and a Sigma rule would catch it for free,
and the eval would no longer measure what it claims to.

Two shaping decisions worth stating:

* **Requests come in folder batches, not on a fixed period.** A UI-driven bulk download is a
  listing call followed by a burst of file fetches, then a pause while the user picks the next
  folder. A metronomic request stream would score as a beacon on `(src_ip, domain)` and the
  scenario would be solved by the wrong detector.
* **The victim is drawn from the middle of their department by activity.** Picking the
  department's heaviest user would make peer-group deviation true before the attack starts,
  which flatters the detector rather than testing it.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import TYPE_CHECKING

from datagen.emitters.zscaler import UrlCategory, ZScalerEmitter, categorize
from datagen.scenarios import register_scenario
from datagen.types import (
    ML_PEER_GROUP,
    SIGNAL_BURST,
    EntityRef,
    EventRecord,
    GroundTruth,
    Scenario,
    ScenarioContext,
    SourceType,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

    from datagen.org import User
    from datagen.rng import SeededRandom

__all__ = ["InsiderMassDownloadScenario"]

# Seconds between file fetches inside one folder batch: a browser pulling documents back to
# back, fast enough to pile into a five-minute bucket but never machine-regular.
_FILE_GAP_S: tuple[float, float] = (0.4, 2.6)

# Batches are spread over most of the window rather than all of it, so the burst has a visible
# start and end inside the hour buckets instead of butting against the window edge.
_BATCH_SPREAD: float = 0.97

_PARTIAL_RATE: float = 0.08
_MAX_FILE_BYTES: int = 2_000_000_000
_STORAGE_CATEGORIES: tuple[str, ...] = ("storage", "cloud", "productivity")


@dataclass(frozen=True, slots=True)
class _HostProfile:
    """How the benign corpus already renders a host.

    Injected rows copy it so the category, app name and risk score of an attack line match every
    other line for the same host. A scenario that let those three drift would be separable on a
    column it never meant to manipulate.
    """

    category: UrlCategory
    appname: str
    riskscore: int


def _host_profile(stream: Sequence[EventRecord], host: str) -> _HostProfile:
    for record in stream:
        fields = record.fields
        if record.malicious or fields.get("host") != host or fields.get("action") != "Allowed":
            continue
        return _HostProfile(
            category=UrlCategory(
                name=str(fields["urlcategory"]),
                supercategory=str(fields["urlsupercategory"]),
                appclass=str(fields["appclass"]),
                risk=int(fields.get("riskscore", 0)),
            ),
            appname=str(fields.get("appname", "General Browsing")),
            riskscore=int(fields.get("riskscore", 0)),
        )
    fallback = categorize(host)
    return _HostProfile(category=fallback, appname="General Browsing", riskscore=fallback.risk)


@register_scenario
class InsiderMassDownloadScenario(Scenario):
    key = "insider_mass_download"
    technique = "T1530"
    sources = (SourceType.ZSCALER,)
    expected_detectors = (SIGNAL_BURST, ML_PEER_GROUP)
    description = "Employee bulk-downloads a document repository far beyond their cohort's rate."

    def __init__(
        self,
        *,
        n_downloads: int = 850,
        mean_file_mb: float = 4.0,
        file_sigma: float = 0.9,
        duration_h: float = 3.0,
        mean_batch: float = 14.0,
        start_fraction: float = 0.62,
        local_start_hour: float | None = 19.0,
        min_peers: int = 6,
        host_app: str | None = None,
    ) -> None:
        self.n_downloads = n_downloads
        self.mean_file_mb = mean_file_mb
        self.file_sigma = file_sigma
        self.duration_h = duration_h
        self.mean_batch = mean_batch
        self.start_fraction = start_fraction
        self.local_start_hour = local_start_hour
        self.min_peers = min_peers
        self.host_app = host_app

    # ------------------------------------------------------------------ injection

    def inject(self, ctx: ScenarioContext) -> GroundTruth:
        victim = self._pick_victim(ctx)
        rng = ctx.user_rng(victim)
        emitter = ZScalerEmitter()
        sizes = ctx.models.response_sizes

        host = self._repository(ctx, rng)
        profile = _host_profile(ctx.stream, host)
        src_ip = victim.source_ip(rng)
        referer = f"https://{host}/"
        start = self._burst_start(ctx, victim)

        batches = self._batch_sizes(rng)
        span_s = self.duration_h * 3600.0 * _BATCH_SPREAD
        offsets = sorted(rng.uniform(0.0, span_s) for _ in batches)

        # Arithmetic mean of the log-normal is pinned to `mean_file_mb`, so sweeping that knob
        # moves total volume by the factor the sweep report claims it does.
        mu = math.log(max(self.mean_file_mb, 1e-3) * 1_000_000.0) - self.file_sigma**2 / 2.0

        injected: list[EventRecord] = []
        for index, (offset, count) in enumerate(zip(offsets, batches, strict=True)):
            ts = ctx.window.clamp(start + timedelta(seconds=offset))
            injected.append(
                emitter.inject(
                    ctx,
                    user=victim,
                    ts=ts,
                    host=host,
                    src_ip=src_ip,
                    url=f"/api/2.0/folders/{rng.hex_token(5)}/items?limit=200&offset={index * 200}",
                    method="GET",
                    status=200,
                    bytes_out=sizes.request_bytes(rng, "GET"),
                    bytes_in=sizes.response_bytes(rng, "api"),
                    category=profile.category,
                    appname=profile.appname,
                    riskscore=profile.riskscore,
                    referer=referer,
                )
            )
            for _ in range(count):
                ts = ctx.window.clamp(ts + timedelta(seconds=rng.uniform(*_FILE_GAP_S)))
                injected.append(
                    emitter.inject(
                        ctx,
                        user=victim,
                        ts=ts,
                        host=host,
                        src_ip=src_ip,
                        url=f"/api/2.0/files/{rng.hex_token(6)}/content",
                        method="GET",
                        status=206 if rng.chance(_PARTIAL_RATE) else 200,
                        bytes_out=sizes.request_bytes(rng, "GET"),
                        bytes_in=int(min(rng.lognormal(mu, self.file_sigma), _MAX_FILE_BYTES)),
                        category=profile.category,
                        appname=profile.appname,
                        riskscore=profile.riskscore,
                        referer=referer,
                    )
                )

        downloaded = sum(int(r.fields["responsesize"]) for r in injected)
        cohort = ctx.org.peers(victim)
        return self.make_ground_truth(
            ctx,
            primary_entity=EntityRef(type="user", value=victim.principal),
            notes=(
                f"{victim.username} ({victim.department}, cohort {len(cohort)}) pulled "
                f"{len(injected)} objects ({downloaded / 1e9:.2f} GB) from {host} in "
                f"{self.duration_h:.1f}h from {src_ip}, starting {start.isoformat()}; "
                "sanctioned host, own browser, no L1 rule surface"
            ),
        )

    # ------------------------------------------------------------------ helpers

    def _pick_victim(self, ctx: ScenarioContext) -> User:
        """A median-activity member of a department large enough to have a peer group."""
        rng = ctx.rng.substream("victim")
        pool = [u for u in ctx.org.users if len(ctx.org.peers(u)) >= self.min_peers]
        if not pool:
            pool = list(ctx.org.users)
        ordered = sorted(pool, key=lambda u: (u.activity_weight, u.username))
        low, high = len(ordered) // 4, max(len(ordered) * 3 // 4, 1)
        return rng.choice(ordered[low:high] or ordered)

    def _repository(self, ctx: ScenarioContext, rng: SeededRandom) -> str:
        """The sanctioned repository. It is in every principal's affinity set, so it is not rare."""
        if self.host_app is not None:
            for app in ctx.org.saas_apps:
                if app.name == self.host_app:
                    return app.domain
            raise KeyError(f"unknown saas app {self.host_app!r} for scenario {self.key}")
        for category in _STORAGE_CATEGORIES:
            candidates = [a.domain for a in ctx.org.saas_apps if a.category == category]
            if candidates:
                return rng.choice(candidates)
        return ctx.models.domains.sample(rng)

    def _burst_start(self, ctx: ScenarioContext, victim: User) -> datetime:
        """Anchor the burst at a local wall-clock hour, so `off_hours_ratio` means what it says."""
        anchor = ctx.window.fraction(self.start_fraction)
        if self.local_start_hour is None:
            return ctx.window.clamp(anchor)
        offset = timedelta(hours=victim.tz_offset_h)
        midnight = (anchor + offset).replace(hour=0, minute=0, second=0, microsecond=0)
        start = midnight + timedelta(hours=self.local_start_hour) - offset
        latest = ctx.window.end - timedelta(hours=self.duration_h)
        if start > latest:
            start -= timedelta(days=1)
        return ctx.window.clamp(start)

    def _batch_sizes(self, rng: SeededRandom) -> list[int]:
        sizes: list[int] = []
        remaining = max(self.n_downloads, 1)
        while remaining > 0:
            take = min(max(1, rng.poisson(self.mean_batch)), remaining)
            sizes.append(take)
            remaining -= take
        return sizes
