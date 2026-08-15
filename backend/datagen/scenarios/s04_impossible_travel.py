"""Scenario 4 — impossible travel (docs/11 scenario 4, T1078).

Two successful sign-ons for one principal whose great-circle separation divided by the elapsed
time exceeds the 900 km/h threshold docs/04 sets. The rule recomputes that quotient itself, so
the geography has to be real: both endpoints carry the coordinates `realism.FOREIGN_LOCATIONS`
and the office catalogue actually publish, and the second login's timestamp is *derived* from
`haversine_km(anchor, hostile) / implied_speed_kmh` rather than picked. The implied speed is
therefore exactly the knob, for any pair of endpoints, which is what makes a sweep from 3000 down
to 800 km/h a clean detection curve across the threshold.

The anchor login is the real user's own session and is labelled benign, not malicious. Preferring
one already present in the benign stream is the honest construction — the attack is the second
sign-on, and claiming the victim's genuine morning login as attacker activity would inflate
recall against ground truth we know to be wrong. A synthetic anchor is injected only when the
stream carries no Okta history for the principal, and it is still labelled benign.
"""

from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING

from datagen.emitters.okta import OktaEmitter
from datagen.realism import GeoPoint, haversine_km
from datagen.scenarios import register_scenario
from datagen.types import (
    SIGMA_IMPOSSIBLE_TRAVEL,
    SIGMA_NEW_COUNTRY,
    EntityRef,
    EventRecord,
    Scenario,
    SourceType,
)

if TYPE_CHECKING:
    from datetime import datetime

    from datagen.org import User
    from datagen.rng import SeededRandom
    from datagen.types import GroundTruth, ScenarioContext

_SESSION_START = "user.session.start"

# Widest separation on the globe, rounded up. Reserving it (plus room for the hostile session to
# close) keeps the derived second login inside the corpus window whichever endpoint is drawn.
_MAX_SEPARATION_KM = 20_000.0
_SESSION_TAIL_H = 2.0


@register_scenario
class ImpossibleTravelScenario(Scenario):
    key = "impossible_travel"
    technique = "T1078"
    sources = (SourceType.OKTA,)
    expected_detectors = (SIGMA_IMPOSSIBLE_TRAVEL, SIGMA_NEW_COUNTRY)
    expected_disposition = "true_positive"
    must_correlate_into_one_incident = True
    description = (
        "A second successful sign-on from a country the principal has never used, too soon "
        "after the first to be physically possible."
    )

    def __init__(
        self,
        *,
        implied_speed_kmh: float = 1800.0,
        min_distance_km: float = 3000.0,
        n_geo_candidates: int = 12,
        start_fraction: float = 0.42,
        anchor_from_benign: bool = True,
        mfa_prompted: bool = False,
        n_sso_after: int = 3,
        hosting_source: bool = False,
    ) -> None:
        self.implied_speed_kmh = implied_speed_kmh
        self.min_distance_km = min_distance_km
        self.n_geo_candidates = n_geo_candidates
        self.start_fraction = start_fraction
        self.anchor_from_benign = anchor_from_benign
        self.mfa_prompted = mfa_prompted
        self.n_sso_after = n_sso_after
        self.hosting_source = hosting_source

    def inject(self, ctx: ScenarioContext) -> GroundTruth:
        victim = ctx.org.pick_user(ctx.rng)
        rng = ctx.user_rng(victim)
        okta = OktaEmitter()

        headroom = timedelta(hours=_MAX_SEPARATION_KM / self.implied_speed_kmh + _SESSION_TAIL_H)
        latest = ctx.window.end - headroom
        anchor_ts, anchor_geo, anchor_origin = self._anchor(ctx, okta, victim, rng, latest)

        hostile = self._hostile_point(ctx, victim, rng, anchor_geo)
        distance_km = haversine_km(anchor_geo, hostile)
        elapsed_h = distance_km / self.implied_speed_kmh
        login_at = anchor_ts + timedelta(hours=elapsed_h)

        client = okta.client_for(victim, rng, geo=hostile, is_proxy=self.hosting_source)
        okta.inject(
            ctx,
            okta.login_session(
                victim,
                start=login_at,
                rng=rng,
                client=client,
                mfa=self.mfa_prompted,
                n_sso=self.n_sso_after,
                failures=0,
                end_session=True,
            ),
        )

        return self.make_ground_truth(
            ctx,
            primary_entity=EntityRef(type="user", value=victim.principal),
            notes=(
                f"anchor {anchor_origin} sign-on from {anchor_geo.city}, {anchor_geo.country} "
                f"({anchor_geo.ip}) at {anchor_ts.isoformat()}; hostile sign-on from "
                f"{hostile.city}, {hostile.country} ({hostile.ip}, AS{hostile.asn}) "
                f"{elapsed_h:.2f}h later; {distance_km:.0f} km implies "
                f"{distance_km / elapsed_h:.0f} km/h against a 900 km/h threshold"
            ),
        )

    # ------------------------------------------------------------------ endpoints

    def _anchor(
        self,
        ctx: ScenarioContext,
        okta: OktaEmitter,
        victim: User,
        rng: SeededRandom,
        latest: datetime,
    ) -> tuple[datetime, GeoPoint, str]:
        """The legitimate sign-on the hostile one is impossible relative to.

        Returns its timestamp, the location the rule will resolve its `src_ip` to, and where it
        came from, for the notes.
        """
        target = ctx.window.fraction(self.start_fraction)
        if self.anchor_from_benign:
            existing = _nearest_benign_login(ctx, victim, target, latest)
            if existing is not None and existing.src_ip is not None:
                return existing.ts, victim.geo(existing.src_ip), "benign"

        # No Okta history for this principal in the stream: mint one, still labelled benign.
        session = okta.login_session(
            victim,
            start=min(target, latest),
            rng=rng,
            client=okta.client_for(victim, rng),
            failures=0,
            end_session=False,
        )
        ctx.add_many(session, malicious=False)
        start = next(r for r in session if r.fields["eventType"] == _SESSION_START)
        return start.ts, victim.geo(start.src_ip or victim.office_ip), "injected"

    def _hostile_point(
        self, ctx: ScenarioContext, victim: User, rng: SeededRandom, anchor: GeoPoint
    ) -> GeoPoint:
        """First drawn location at least `min_distance_km` away, else the farthest one drawn."""
        candidates = [
            ctx.models.geo.foreign_point(
                rng, exclude_country=victim.home_country, hosting=self.hosting_source
            )
            for _ in range(max(self.n_geo_candidates, 1))
        ]
        for point in candidates:
            if haversine_km(anchor, point) >= self.min_distance_km:
                return point
        return max(candidates, key=lambda p: haversine_km(anchor, p))


def _nearest_benign_login(
    ctx: ScenarioContext, victim: User, target: datetime, latest: datetime
) -> EventRecord | None:
    """Benign successful `user.session.start` for the victim closest to `target`, at or before
    `latest`. Ties keep the earliest in stream order, so the choice is stable across runs."""
    best: EventRecord | None = None
    best_gap = 0.0
    for record in ctx.stream:
        if record.malicious or record.source != SourceType.OKTA:
            continue
        if record.principal != victim.principal or record.ts > latest:
            continue
        fields = record.fields
        if fields.get("eventType") != _SESSION_START:
            continue
        if fields.get("outcome", {}).get("result") != "SUCCESS":
            continue
        gap = abs((record.ts - target).total_seconds())
        if best is None or gap < best_gap:
            best, best_gap = record, gap
    return best
