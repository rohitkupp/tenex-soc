"""Shared constants for the four L2 detectors (docs/04 "L2 -- Signal processing").

## `detector_key` values

These string literals must equal `datagen.types.SIGNAL_BEACONING` / `SIGNAL_DGA` /
`SIGNAL_BURST` / `SIGNAL_RARITY` byte-for-byte -- the eval harness matches a scenario's
`expected_detectors` against `signals.detector_key` by string equality. They are declared
independently here rather than imported from `datagen`, deliberately: `app/detection/**` must
not depend on the synthetic-data generator (`app/detection/features.py`'s module docstring
states this directly -- "Detection code must not depend on the synthetic-data generator"), and
`app/enrichment/loader.py` states the same boundary from the other side ("`datagen` is a
separate team's ownership"). `tests/test_signal_constants.py` asserts the two sets of literals
stay identical, so a drift is a loud test failure instead of a silent detector that never
matches ground truth.

## `entity_type` values

Match `docs/02-DATA-MODEL.md`'s `entities.type` column exactly ("user|src_ip|domain|dst_ip|
asn|session") and `datagen.types.EntityType`'s literal union -- `"user"`, not `"principal"`,
even though the column on `events` is named `principal`. Keeping the *entity* vocabulary
consistent with what `docs/05` (entity graph, not built yet) will key correlation on matters
more than matching the column name it was read from.

## Thresholds docs/04 leaves to the implementer

docs/04 gives closed-form scores for all four detectors but does not say, for three of them,
which raw-score values are worth writing a `signals` row over (as opposed to computing and
discarding). Volumetric burst is the one detector where the doc *does* give a cutoff
(`|z| > 3.5`) -- reused verbatim. The other three thresholds below are load-bearing design
choices made here, held fixed before any sweep or benchmark was run (never tuned after seeing
a result), and reported as exactly that in the M7 verification report:

* `BEACONING_SCORE_THRESHOLD` -- docs/04's beaconing score is a product of three already-
  bounded [0,1] factors (`regularity`, `min(n/50,1)`, `min(duration_h/4,1)`), so it is
  punishing by construction: a group that only just clears the `n >= 8` floor scores at most
  `8/50 = 0.16` regardless of how regular it is. 0.3 requires at least moderate regularity
  *and* moderate volume *and* moderate duration simultaneously, which is a defensible "this is
  worth a human's attention" bar without pre-tuning it to scenario 1's default knobs.
* `RARITY_MAX_ORG_EVENT_COUNT` -- `domain_rarity = 1/(1+count)` is a pure function of one
  domain's org-wide event count, so "how rare is rare enough" has to be an absolute count
  cutoff (a percentile-of-this-analysis cutoff was considered and rejected: in a Zipf-shaped
  corpus the long tail is enormous, so "below the median domain's count" would *still* flag
  almost every domain touched once, which is not a meaningfully rarer bar than no threshold at
  all). 10 reads as "ten or fewer hits, org-wide, in this file" -- rare for a few-hundred-person
  org. Documented consequence, checked in the M7 verification report rather than hidden: a
  beacon with enough check-ins to clear this count (e.g. the 360-callback default in
  `s01_c2_beaconing.py`) will *not* clear it, and `signal.rarity` will honestly not fire for
  that domain even though beaconing and DGA do. That is the formula doing exactly what it says,
  not a bug to paper over.
* `DGA_DECISION_THRESHOLD` -- 0.5, the standard decision boundary for a fitted logistic
  regression's own output probability; also serialized into the artifact
  (`training.decision_threshold`, `dga_train.py`) so a re-fit can ship a different one without
  a code change.

None of the four thresholds are recomputed per-analysis or per-tenant. Per-detector calibration
(`signals.confidence`, isotonic regression against held-out labeled data) is `docs/04`'s
"Fusion & calibration" section, milestone M10, not built yet -- see `drafts.py` for the interim
`confidence` policy this milestone uses instead.
"""

from __future__ import annotations

from typing import Final

# ---------------------------------------------------------------------------- detector_key

DETECTOR_LAYER: Final[str] = "signal"

SIGNAL_BEACONING: Final[str] = "signal.beaconing"
SIGNAL_DGA: Final[str] = "signal.dga"
SIGNAL_BURST: Final[str] = "signal.burst"
SIGNAL_RARITY: Final[str] = "signal.rarity"

# ---------------------------------------------------------------------------- entity_type

ENTITY_USER: Final[str] = "user"
ENTITY_SRC_IP: Final[str] = "src_ip"
ENTITY_DOMAIN: Final[str] = "domain"

# ---------------------------------------------------------------------------- beaconing

BEACONING_MIN_EVENTS: Final[int] = 8
BEACONING_SCORE_THRESHOLD: Final[float] = 0.3
# Autocorrelation cross-check: bucket width divides the group's own mean inter-arrival time so
# a truly periodic beacon lands close to one event per `BEACONING_ACF_BUCKET_DIVISOR` buckets;
# the bucket count is separately capped (`BEACONING_ACF_MAX_BUCKETS`) so a long-running, fast
# beacon can't blow up the O(buckets^2) `numpy.correlate(mode="full")` call.
BEACONING_ACF_BUCKET_DIVISOR: Final[int] = 10
BEACONING_ACF_MAX_BUCKETS: Final[int] = 2000
BEACONING_ACF_MIN_BUCKET_SECONDS: Final[float] = 1.0

# ---------------------------------------------------------------------------- DGA

DGA_ARTIFACT_FILENAME: Final[str] = "dga_weights.json"

# ---------------------------------------------------------------------------- volumetric burst

# docs/04 gives the bucket width ("5-minute bucket") and the flag threshold (|z| > 3.5)
# verbatim; both reused exactly.
BURST_BUCKET_SECONDS: Final[int] = 300
BURST_Z_THRESHOLD: Final[float] = 3.5
# Population for `robust_z` is an entity's own *active* (nonzero-count) buckets, not every
# 5-minute slot across the analysis window -- see `burst.py`'s module docstring for why dense
# zero-padding would make `robust_z`'s documented MAD==0 policy fire on almost every entity's
# very first event of the day. An entity needs at least this many active buckets before it has
# enough self-history to be scored against at all (mirrors beaconing's own `n >= 8` floor).
BURST_MIN_ACTIVE_BUCKETS: Final[int] = 4

# ---------------------------------------------------------------------------- rarity / first-seen

RARITY_MAX_ORG_EVENT_COUNT: Final[int] = 10

# ---------------------------------------------------------------------------- evidence

# `signals.evidence_event_ids` is a real column, not a summary count -- but an unbounded array
# is a foot-gun for a detector matching thousands of events (e.g. `signal.dga` against a
# frequently-hit domain). Evidence lists longer than this are truncated to first+last events by
# timestamp (`drafts.cap_evidence`) and the truncation is recorded in `explanation`, never silent.
EVIDENCE_CAP: Final[int] = 200
