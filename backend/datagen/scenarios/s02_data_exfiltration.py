"""Scenario 2 — bulk data exfiltration to a newly-registered domain (docs/11 #2, T1567.002).

Four things have to be simultaneously true for the docs/11 detector list to fire honestly, and
each one is a deliberate shape here rather than a side effect:

* **Volumetric burst** — the parts land inside a couple of hours, so a 5-minute bucket holds
  roughly eight requests and hundreds of megabytes against a benign human baseline of about one
  request and a few hundred kilobytes. Robust z-scoring (median/MAD) needs the anomaly to be
  short relative to the baseline, not merely large.
* **Out/in ratio** — every part is answered with a few hundred bytes of upload-receipt JSON.
  Browsing is the mirror image of this, which is what makes the ratio discriminative at all.
* **Newly-registered domain** — the destination carries the NSS "Newly Registered and Revived
  Domains" category regardless of `blend_with_normal_traffic`. That is a fact about the domain,
  not a choice the attacker gets to make, so it is not part of the blending knob.
* **Autoencoder** — none of `post_ratio`, `bytes_out_max`, `off_hours_ratio` or
  `n_newly_registered_domains` is individually unprecedented in the benign corpus; it is their
  co-occurrence in one entity-hour that has no support in the training manifold.

`chunk_mb` doubles as the difficulty knob for the L1 large-POST rule: it is only in the label's
expected detectors when even the smallest jittered part clears the rule's 10 MB threshold.
"""

from __future__ import annotations

import math
from datetime import timedelta
from typing import TYPE_CHECKING, Any, Final

from datagen.emitters.zscaler import ZScalerEmitter
from datagen.scenarios import register_scenario
from datagen.types import (
    ML_AUTOENCODER,
    SIGMA_LARGE_POST_NRD,
    SIGMA_NON_BROWSER_UA,
    SIGNAL_BURST,
    SIGNAL_NEWLY_REGISTERED,
    SIGNAL_OUT_IN_RATIO,
    EntityRef,
    GroundTruth,
    Scenario,
    ScenarioContext,
    SourceType,
)

if TYPE_CHECKING:
    from datetime import datetime

    from datagen.org import User
    from datagen.rng import SeededRandom

__all__ = ["DataExfiltrationScenario"]

# Decimal megabytes: the L1 rule's threshold is a round 10 MB, and matching the rule's units
# keeps `chunk_mb` a knob an analyst can reason about against the rule they wrote.
_BYTES_PER_MB: Final[int] = 1_000_000
_LARGE_POST_BYTES: Final[int] = 10_000_000

# Upload-receipt payload: an object id and an etag, nothing else. This is the denominator of
# out/in ratio and the reason it comes out in the tens of thousands.
_ACK_BYTES: Final[tuple[int, int]] = (240, 620)

_OK_CODES: Final[tuple[int, ...]] = (200, 201)
_OK_WEIGHTS: Final[tuple[float, ...]] = (0.35, 0.65)
_RETRY_CODE: Final[int] = 429
_RETRY_BACKOFF_S: Final[tuple[float, float]] = (3.0, 15.0)

# Local wall-clock hour the upload starts when `off_hours` is set. Late enough that the whole
# default two-hour run sits outside the diurnal curve's business-hours mass.
_OFF_HOURS_LOCAL: Final[float] = 22.5
_BUSINESS_LOCAL: Final[float] = 14.0

_START_FRACTION: Final[tuple[float, float]] = (0.2, 0.75)

_DLP_FIELDS: Final[dict[str, Any]] = {
    "dlpengine": "Corporate Confidential",
    "dlpdictionaries": "Source Code,PII,Financial Records",
    "riskscore": 85,
    # Encrypted-archive staging (docs/v1/zscaler-nss-web-fields.md "File Type Control", this
    # task's full-width-catalogue brief): a real exfil payload is almost always a password-
    # protected/encrypted archive precisely so DLP content inspection can't look inside it --
    # `unscannabletype` is the one field whose documented example ("Encrypted File") describes
    # exactly that. `upload_filetype` stays a plain, already-supported category ("Archive Files")
    # so `_apply_wide_fields`' `_FT_CLASS_BY_TYPE` table doesn't need an invented entry for it.
    # None of the three is a named `build_event` parameter (same as `s01_c2_beaconing`'s
    # `_C2_FILE_HASH`), so they go through the `extra={...}` catch-all, not a top-level kwarg.
    "extra": {
        "upload_filetype": "Archive Files",
        "upload_filename": "financial_records_backup.7z",
        "unscannabletype": "Encrypted File",
    },
}


def _shift_to_local_hour(ts: datetime, tz_offset_h: float, hour: float) -> datetime:
    """Next instant at or after `ts` whose local wall-clock hour is `hour`."""
    local_h = ts.hour + ts.minute / 60.0 + ts.second / 3600.0 + tz_offset_h
    return ts + timedelta(hours=(hour - local_h) % 24.0)


@register_scenario
class DataExfiltrationScenario(Scenario):
    """Sustained multi-part upload from one principal to a domain registered days ago."""

    key = "data_exfiltration"
    technique = "T1567.002"
    sources = (SourceType.ZSCALER,)
    expected_detectors = (
        SIGNAL_BURST,
        SIGNAL_OUT_IN_RATIO,
        SIGNAL_NEWLY_REGISTERED,
        ML_AUTOENCODER,
    )
    description = "Large sustained POSTs staging a corpus out to a newly-registered domain."

    def __init__(
        self,
        *,
        total_mb: float = 4800.0,
        chunk_mb: float = 24.0,
        duration_h: float = 2.0,
        size_jitter_pct: float = 0.18,
        domain_age_days: int = 6,
        off_hours: bool = True,
        automation_ua: bool = False,
        retry_rate: float = 0.04,
        blend_with_normal_traffic: bool = True,
    ) -> None:
        if total_mb <= 0 or chunk_mb <= 0:
            raise ValueError("total_mb and chunk_mb must be > 0")
        if duration_h <= 0:
            raise ValueError("duration_h must be > 0")
        if not 0.0 <= size_jitter_pct < 1.0:
            raise ValueError("size_jitter_pct must be in [0, 1)")
        if not 0 <= domain_age_days < 30:
            raise ValueError("domain_age_days must be in [0, 30) to count as newly registered")
        if not 0.0 <= retry_rate <= 1.0:
            raise ValueError("retry_rate must be in [0, 1]")

        self.total_mb = float(total_mb)
        self.chunk_mb = float(chunk_mb)
        self.duration_h = float(duration_h)
        self.size_jitter_pct = float(size_jitter_pct)
        self.domain_age_days = int(domain_age_days)
        self.off_hours = off_hours
        self.automation_ua = automation_ua
        self.retry_rate = float(retry_rate)
        self.blend_with_normal_traffic = blend_with_normal_traffic

    # ------------------------------------------------------------------ injection

    def inject(self, ctx: ScenarioContext) -> GroundTruth:
        victim = ctx.org.pick_user(ctx.rng)
        rng = ctx.user_rng(victim)
        emitter = ZScalerEmitter()

        registered = ctx.models.newly_registered.sample(rng, age_days=self.domain_age_days)
        host = registered.domain
        src_ip = victim.source_ip(rng)
        user_agent = self._user_agent(ctx, rng, victim)
        session = rng.hex_token(8)
        extra = {} if self.blend_with_normal_traffic else dict(_DLP_FIELDS)

        n_parts = max(1, math.ceil(self.total_mb / self.chunk_mb))
        gap_s = (self.duration_h * 3600.0) / n_parts
        chunk_bytes = self.chunk_mb * _BYTES_PER_MB
        start = self._start(ctx, rng, victim, self.duration_h * 3600.0)

        common: dict[str, Any] = {
            "user": victim,
            "host": host,
            "src_ip": src_ip,
            "user_agent": user_agent,
            "category": "newly_registered",
        }

        # Session setup: the landing page, then the API handshake that mints the upload id. Both
        # are ordinary-looking GET/POST traffic — they matter because a burst of huge POSTs with
        # no preceding session is a shape no real upload client produces.
        emitter.inject(
            ctx,
            ts=start,
            url="/",
            bytes_out=rng.randint(300, 900),
            bytes_in=rng.randint(8_000, 60_000),
            **common,
            **extra,
        )
        ts = start + timedelta(seconds=rng.uniform(2.0, 12.0))
        emitter.inject(
            ctx,
            ts=ts,
            url=f"/api/v2/uploads?session={session}",
            method="POST",
            status=201,
            bytes_out=rng.randint(400, 1_200),
            bytes_in=rng.randint(*_ACK_BYTES),
            **common,
            **extra,
        )

        uploaded = 0
        for part in range(1, n_parts + 1):
            ts += timedelta(seconds=rng.jitter(gap_s, 0.25))
            if ts >= ctx.window.end:
                break
            body = int(
                chunk_bytes * rng.uniform(1 - self.size_jitter_pct, 1 + self.size_jitter_pct)
            )
            url = f"/api/v2/uploads/{session}/parts?n={part}"
            if rng.chance(self.retry_rate):
                # A throttled part is re-sent whole, which is why the retry costs the full body
                # twice and nudges `error_ratio` at the same time.
                emitter.inject(
                    ctx,
                    ts=ts,
                    url=url,
                    method="POST",
                    status=_RETRY_CODE,
                    bytes_out=body,
                    bytes_in=rng.randint(180, 320),
                    **common,
                    **extra,
                )
                uploaded += body
                ts += timedelta(seconds=rng.uniform(*_RETRY_BACKOFF_S))
            emitter.inject(
                ctx,
                ts=ts,
                url=url,
                method="POST",
                status=rng.weighted_choice(_OK_CODES, _OK_WEIGHTS),
                bytes_out=body,
                bytes_in=rng.randint(*_ACK_BYTES),
                **common,
                **extra,
            )
            uploaded += body

        ts += timedelta(seconds=rng.uniform(2.0, 20.0))
        if ts < ctx.window.end:
            emitter.inject(
                ctx,
                ts=ts,
                url=f"/api/v2/uploads/{session}/complete",
                method="POST",
                status=200,
                bytes_out=rng.randint(400, 1_500),
                bytes_in=rng.randint(*_ACK_BYTES),
                **common,
                **extra,
            )

        return self.make_ground_truth(
            ctx,
            primary_entity=EntityRef(type="user", value=victim.principal),
            expected_detectors=self._detectors(),
            notes=(
                f"{uploaded / _BYTES_PER_MB:.0f} MB in {n_parts} POSTs of ~{self.chunk_mb:g} MB "
                f"over {self.duration_h:g}h to {host} (registered {registered.age_days}d ago) "
                f"from {src_ip}; {'off-hours' if self.off_hours else 'business-hours'} start "
                f"{start.isoformat()}"
            ),
        )

    # ------------------------------------------------------------------ knob plumbing

    def _user_agent(self, ctx: ScenarioContext, rng: SeededRandom, victim: User) -> str:
        if not self.automation_ua:
            return victim.device.user_agent
        return ctx.models.user_agents.sample_automation(rng.fresh("exfil-ua")).user_agent

    def _start(
        self, ctx: ScenarioContext, rng: SeededRandom, victim: User, span_s: float
    ) -> datetime:
        slack = max(0.0, ctx.window.duration_s - span_s)
        start = ctx.window.start + timedelta(seconds=rng.uniform(*_START_FRACTION) * slack)
        hour = _OFF_HOURS_LOCAL if self.off_hours else _BUSINESS_LOCAL
        aligned = _shift_to_local_hour(start, victim.tz_offset_h, hour)
        if aligned + timedelta(seconds=span_s) > ctx.window.end:
            aligned -= timedelta(days=1)
        return aligned if aligned >= ctx.window.start else start

    def _detectors(self) -> tuple[str, ...]:
        """Only claim the Sigma rules this configuration actually trips.

        The large-POST rule keys on a hard 10 MB threshold, so it is claimed only when the
        smallest possible jittered part still clears it — otherwise a low `chunk_mb` sweep point
        would book a false miss against a rule that was never supposed to fire.
        """
        detectors = list(self.expected_detectors)
        smallest = self.chunk_mb * _BYTES_PER_MB * (1.0 - self.size_jitter_pct)
        if smallest > _LARGE_POST_BYTES:
            detectors.append(SIGMA_LARGE_POST_NRD)
        if self.automation_ua:
            detectors.append(SIGMA_NON_BROWSER_UA)
        return tuple(detectors)
