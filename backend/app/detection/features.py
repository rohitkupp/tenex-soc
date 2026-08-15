"""Canonical L3 entity-window feature definitions (docs/04 "L3 — Entity-window ML").

This module exists because `off_hours_ratio` — and the docs/04 L2 robust-z formula used to score
every L3 feature against an entity's own history — was defined **three times** in this codebase
before this module did:

1. Inside `datagen/scenarios/s08_low_and_slow_exfil.py`, as a private `_is_off_hours` — the
   per-user local-hours + per-user timezone definition, because scenario 8's whole premise
   (docs/11 row 8) depends on it being right.
2. Re-implemented independently inside `tests/test_datagen_s08_marginals.py`, to audit (1)
   without trusting the generator's own math.
3. Named but never defined in `docs/04-DETECTION.md`'s L3 feature list (`off_hours_ratio` appears
   in a bullet, with no formula) — leaving whoever implements the real feature extractor at M8
   free to invent a *third* definition from scratch.

That third definition was on a collision course with the first two: the simulated org's offices
are `US-CA`, `US-NY`, and `IE-DU` (docs/11 "Simulated org"), so the obvious naive
implementation — a fixed business-hours window in UTC — misclassifies an ordinary US-CA 9-to-5 as
"off hours" outright, which would make scenario 8's carefully-constructed invisibility (see that
module's docstring) an artifact of the generator and detector disagreeing about what the feature
even means, not evidence the autoencoder earns its slot.

This is the one place both sides import from. `datagen/scenarios/s08_low_and_slow_exfil.py` uses
`is_off_hours` and `robust_z` to *construct* a campaign that is provably invisible to these exact
formulas; `tests/test_datagen_s08_marginals.py` uses the same two functions to *audit* that claim
independently, the same way the audit that originally found scenario 8 leaking did. When M8 builds
out `app/detection/ml/features.py`'s real ~50-feature extractor, the `off_hours_ratio` computation
and every L2/L3 robust-z check should call into this module rather than re-deriving either formula
a fourth time — extend it, do not shadow it.

Scope is deliberately narrow: only the primitives the generator already depends on live here (the
two formulas, plus the entity-window feature names scenario 8's acceptance gate and its regression
test both iterate over). The full ~50-feature vector (docs/04) is M8's job, not this module's.
"""

from __future__ import annotations

import math
import statistics
from collections import Counter
from collections.abc import Sequence
from datetime import datetime
from typing import Final, Protocol

__all__ = [
    "ENTITY_WINDOW_FEATURES",
    "FEATURE_BYTES_IN",
    "FEATURE_BYTES_OUT",
    "FEATURE_N_EVENTS",
    "FEATURE_N_LARGE_UPLOADS",
    "FEATURE_OFF_HOURS_RATIO",
    "FEATURE_OUT_IN_RATIO",
    "FEATURE_POST_RATIO",
    "WorkHoursLike",
    "is_off_hours",
    "robust_z",
    "shannon_entropy",
]


# ---------------------------------------------------------------------------- work hours


class WorkHoursLike(Protocol):
    """Structural contract for a user's per-user local-hours profile.

    Matches `datagen.realism.WorkHours` today — start/end hour in the user's own office local
    time, plus the UTC offset needed to convert a UTC timestamp into that local time — without
    this module importing `datagen`. Detection code must not depend on the synthetic-data
    generator; the generator depending on detection's canonical definitions (as
    `s08_low_and_slow_exfil.py` does) is the correct direction. Any work-hours model M8
    introduces for real detection only needs to expose these three fields to use `is_off_hours`.
    """

    start_h: float
    end_h: float
    tz_offset_h: float


def is_off_hours(ts: datetime, work_hours: WorkHoursLike) -> bool:
    """True when `ts` falls outside `[start_h, end_h]` in `work_hours`'s own local time.

    Per-user local time, deliberately not a fixed UTC window: this org's offices are US-CA,
    US-NY, and IE-DU (docs/11 "Simulated org"), so a UTC-fixed business-hours window would
    misclassify an ordinary US-CA 9-to-5 as off-hours. `ts` must be timezone-aware (every
    timestamp in this codebase is UTC, per `datagen.types.TimeWindow`) — `.timestamp()` on a
    naive datetime would resolve against the host machine's local timezone and break
    reproducibility across machines.

    The boundary is inclusive on both ends (`start_h <= local_h <= end_h` counts as "on hours"),
    matching every caller's existing behavior.
    """
    local_h = (ts.timestamp() / 3600.0 + work_hours.tz_offset_h) % 24.0
    return not (work_hours.start_h <= local_h <= work_hours.end_h)


# ---------------------------------------------------------------------------- robust z-score


def robust_z(values: Sequence[float], x: float) -> float:
    """docs/04 L2's robust z-score: `0.6745 * (x - median) / MAD`, median/MAD computed over
    `values`.

    **MAD == 0 policy (explicit, not a silent epsilon).** When a population has zero spread —
    every benign observation identical — dividing by an epsilon instead of handling this
    explicitly produces a finite, often tiny, z-score for a value that is not actually close to
    the population at all, which reads as "safe" precisely when the population is degenerate.
    That is not hypothetical here: it is exactly the failure mode `docs/11` row 8's own
    acceptance gate exists to reject — a victim whose benign `off_hours_ratio` never varies
    (MAD == 0) would, under a divide-by-epsilon convention, let *any* injected value near the
    flat baseline score a near-zero deviation and silently pass a "no marginal fires" check,
    even though the check is measuring nothing (there is no spread to fire against).

    The policy instead:

    * `x == median` -> `0.0`. No deviation was measured, because there is none.
    * `x != median` -> `math.inf`. A degenerate (zero-spread) baseline makes *any* other value an
      unbounded outlier by construction, rather than a value some detector's threshold might
      still pass. This makes a zero-variance baseline loudly disqualifying to a caller checking
      `abs(z) > threshold`, instead of quietly permissive.

    Raises `statistics.StatisticsError` if `values` is empty, same as the underlying
    `statistics.median` call — callers are expected to have already established a non-empty
    baseline population before scoring anything against it.
    """
    median = statistics.median(values)
    mad = statistics.median([abs(v - median) for v in values])
    if mad == 0:
        return 0.0 if x == median else math.inf
    return 0.6745 * (x - median) / mad


# ---------------------------------------------------------------------------- Shannon entropy


def shannon_entropy(symbols: Sequence[object]) -> float:
    """Shannon entropy, in bits, of the frequency distribution of `symbols`.

    A second shared primitive, added at M8 for the same reason `is_off_hours`/`robust_z` live
    here rather than in the module that first needed them: `app/detection/signal/dga_features.py`
    already has its own character-distribution entropy (docs/04 L2 "Domain entropy / DGA"), but
    that copy is scoped to a fixed 38-symbol domain-label alphabet and lives in the L2 signal
    package, which `app/detection/ml/**` deliberately does not import (a concurrently-developed
    sibling — see `app/detection/signal/constants.py`'s own note on the same boundary). Rather
    than reintroduce a *third* entropy formula narrowly shaped for one caller, this is the
    general form — entropy of any discrete symbol sequence, characters or otherwise — that
    `app/detection/ml/features.py` uses for both `mean_domain_entropy`/`max_domain_entropy`
    (entropy over a domain label's characters) and `hour_entropy` (entropy over which sub-bucket
    of the analysis hour an entity's events land in). Empty input returns `0.0` (no distribution,
    no uncertainty) rather than raising, since a caller scoring an entity with zero events for a
    given sub-dimension is a normal, not exceptional, case.
    """
    n = len(symbols)
    if n == 0:
        return 0.0
    counts = Counter(symbols)
    entropy = 0.0
    for count in counts.values():
        p = count / n
        entropy -= p * math.log2(p)
    return entropy


# ---------------------------------------------------------------------------- feature names

# docs/04 L3 feature vector names, restricted to the ones scenario 8's acceptance gate (and its
# regression test) actually score against. `bytes_out`/`bytes_in` here are the entity-window
# *sums* docs/04 calls `bytes_out_sum`/`bytes_in_sum` — kept as the shorter form because that is
# the key every consumer of this tuple (the generator's gate, the regression test) already
# aggregates under; renaming would not add information, only a second name for the same value.
FEATURE_N_EVENTS: Final[str] = "n_events"
FEATURE_BYTES_OUT: Final[str] = "bytes_out"
FEATURE_BYTES_IN: Final[str] = "bytes_in"
FEATURE_OUT_IN_RATIO: Final[str] = "out_in_ratio"
FEATURE_POST_RATIO: Final[str] = "post_ratio"
FEATURE_OFF_HOURS_RATIO: Final[str] = "off_hours_ratio"
FEATURE_N_LARGE_UPLOADS: Final[str] = "n_large_uploads"

# Order matters only in that it is stable — both consumers build same-shaped vectors/matrices
# from this tuple, so a reordering here would silently reorder their columns identically rather
# than break anything, but keeping one fixed order avoids relying on that coincidence.
ENTITY_WINDOW_FEATURES: Final[tuple[str, ...]] = (
    FEATURE_N_EVENTS,
    FEATURE_BYTES_OUT,
    FEATURE_BYTES_IN,
    FEATURE_OUT_IN_RATIO,
    FEATURE_POST_RATIO,
    FEATURE_OFF_HOURS_RATIO,
    FEATURE_N_LARGE_UPLOADS,
)
