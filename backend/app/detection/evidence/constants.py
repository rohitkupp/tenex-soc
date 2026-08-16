"""Shared constants for the six L2 detectors (docs/04 "L2 -- Signal processing"): beaconing, DGA,
volumetric burst, rarity, STL seasonal residual, and URL path analysis.

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
# Must stay byte-identical to `datagen.types.SIGNAL_STL_RESIDUAL` -- that constant already exists
# ahead of this detector (added for `datagen/scenarios/s06_seasonal_deviation.py`'s own ground
# truth), so this is the one `SIGNAL_*` literal in this module declared to *match* a pre-existing
# value rather than mint a fresh one. `tests/test_signal_constants.py` audits the two stay equal.
SIGNAL_STL_RESIDUAL: Final[str] = "signal.stl_residual"
# No pre-existing ground-truth reference for this one (docs/11 names no scenario dedicated to URL
# path analysis specifically) -- this package's own natural key for docs/04 §L2's "URL path
# analysis" detector.
SIGNAL_URL_PATH: Final[str] = "signal.url_path_entropy"

# ---------------------------------------------------------------------------- evidence extractor labels

# `EvidencePayload.extractor` values (docs/v2_migration/MIGRATION-01-evidence-first.md, change 2:
# "extractor: str  # beaconing | dga | burst | rarity | stl | url_entropy"). Deliberately a
# *separate* namespace from the `SIGNAL_*` constants above: those must stay byte-identical to
# `datagen.types.SIGNAL_*` for the eval harness's `signals.detector_key` matching (this module's
# own docstring), which has nothing to do with what the migration wants the short, LLM-facing
# `EvidencePayload.extractor` label to read as. Renaming `SIGNAL_URL_PATH` to match
# `EXTRACTOR_URL_ENTROPY` would break that byte-identical contract for no benefit -- the two
# constants intentionally spell the same detector two different ways for two different readers.
EXTRACTOR_BEACONING: Final[str] = "beaconing"
EXTRACTOR_DGA: Final[str] = "dga"
EXTRACTOR_BURST: Final[str] = "burst"
EXTRACTOR_RARITY: Final[str] = "rarity"
EXTRACTOR_STL: Final[str] = "stl"
EXTRACTOR_URL_ENTROPY: Final[str] = "url_entropy"

# ---------------------------------------------------------------------------- entity_type

ENTITY_USER: Final[str] = "user"
ENTITY_SRC_IP: Final[str] = "src_ip"
ENTITY_DOMAIN: Final[str] = "domain"

# ---------------------------------------------------------------------------- beaconing

BEACONING_MIN_EVENTS: Final[int] = 8
BEACONING_SCORE_THRESHOLD: Final[float] = 0.3
# FFT periodicity cross-check (docs/04 §L2 "Beaconing", REWRITTEN -- "frequency-domain
# cross-check, primary"), replacing the earlier bucketed-autocorrelation-at-a-single-guessed-lag
# cross-check: "autocorrelation only tests the lags it is told to test, and a beacon period that
# does not land on a bucket boundary is invisible to it, while the FFT scans every candidate
# period in one pass." `BEACONING_FFT_BUCKET_SECONDS` (1-minute buckets, docs literal) and
# `BEACONING_FFT_POWER_RATIO_K` (k=6, docs literal: "tuned on the beaconing difficulty sweep,
# docs/11") are both given verbatim, not tuned here. `BEACONING_FFT_MAX_BUCKETS` bounds the FFT
# array size for a long-duration group the same way `BEACONING_ACF_MAX_BUCKETS` bounded the old
# autocorrelation's O(buckets^2) `numpy.correlate` -- an FFT is only O(n log n), so this cap
# exists purely as a memory/latency ceiling for a pathological group, not for algorithmic safety.
BEACONING_FFT_BUCKET_SECONDS: Final[int] = 60
BEACONING_FFT_POWER_RATIO_K: Final[float] = 6.0
BEACONING_FFT_MAX_BUCKETS: Final[int] = 43_200  # 30 days at 1-minute resolution

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

# ---------------------------------------------------------------------------- STL seasonal residual

# docs/04 §L2 "Seasonal residuals (STL)": "period=24 for daily; a second pass at period=168 for
# weekly *where there is enough history*" and "~3 weeks minimum" for a full seasonal profile.
# Three tiers, not two, follow directly from that "where there is enough history" qualifier on
# the weekly pass specifically:
#
# * >= `STL_MIN_HOURS_FOR_WEEKLY_SEASONAL` -- daily + weekly MSTL (docs/04's full decomposition).
# * >= `STL_MIN_HOURS_FOR_DAILY_SEASONAL` (but short of weekly) -- daily-only MSTL. Still a real
#   seasonal decomposition, not the no-model fallback -- an entity with, say, 8 days of history
#   has no trustworthy *weekly* rhythm to fit yet, but its *daily* 9-to-5-shaped rhythm is already
#   well-supported.
# * below `STL_MIN_HOURS_FOR_DAILY_SEASONAL` -- plain robust-z over active hourly buckets, no
#   decomposition at all (module docstring's "Two scoring paths").
#
# `STL_MIN_HOURS_FOR_WEEKLY_SEASONAL` is `MSTL`'s own hard minimum for `period=168`
# (`2 * 168 == 336`, verified directly against the installed statsmodels) -- 14 days, which is
# also `datagen.corpus.DEFAULT_WINDOW_DAYS`, the single-scenario-file eval harness's own default
# window (docs/11). Docs/04's own "~3 weeks" figure is production guidance for a live deployment
# accumulating history across many uploads over time, not a number this eval harness's single
# 14-day synthetic file can ever satisfy for *any* entity -- gating on 21 days here would make
# scenario 6 (docs/11) permanently untestable through the real seasonal path on this project's own
# eval data, not a stricter detector. `STL_MIN_HOURS_FOR_DAILY_SEASONAL` is `MSTL`'s own hard
# minimum for `period=24` (`2 * 24 == 48`) plus a half-day of margin for a residual population
# that is not degenerate at the boundary.
STL_MIN_HOURS_FOR_DAILY_SEASONAL: Final[int] = 72
STL_MIN_HOURS_FOR_WEEKLY_SEASONAL: Final[int] = 336
STL_PERIOD_DAILY: Final[int] = 24
STL_PERIOD_WEEKLY: Final[int] = 168
# "Flag entities whose residual is a robust-z outlier (|z| > 3.5, same MAD formula as above)" --
# docs/04 states this is literally the same threshold as volumetric burst, so this module imports
# `BURST_Z_THRESHOLD` directly (`stl.py`) rather than defining a second constant with the same
# magic number.
# Mirrors `BURST_MIN_ACTIVE_BUCKETS` for the short-history fallback path -- an entity needs at
# least this many active (nonzero-count) hourly buckets before even the fallback robust-z is
# scored against a real distribution.
STL_MIN_ACTIVE_HOURS_FALLBACK: Final[int] = 4
# A real, measured bug this module had while being built, not a hypothetical one: a highly
# regular entity (a service account with near-perfectly periodic volume, docs/11's own "regular
# intervals... high volume" description) can have an `MSTL` residual population that is
# numerically zero for almost every hour but not *exactly* `0.0` -- LOESS-smoothed floating point
# arithmetic leaves noise on the order of `1e-13`. `robust_z`'s documented MAD==0 policy only
# triggers on an *exact* zero MAD, so a population of near-zero-but-distinct floats produces a
# tiny nonzero MAD, and any hour merely "less perfectly zero" than its neighbours (still on the
# order of `1e-14`) scores a spurious, finite `|z| > 3.5` -- caught directly against real
# `s06_seasonal_deviation.py` output as an org-wide false-positive flood (`svc-monitoring@corp.
# example` and similar highly-regular principals), not invented. Residuals are rounded to this
# many decimal places before scoring (`stl.py`) -- coarser than any genuine count-decomposition
# signal this module cares about, comfortably finer than floating-point noise's own scale, and
# large enough that it collapses a truly-degenerate population back to an exact MAD==0 so
# `robust_z`'s existing, correct policy (`0.0` or `inf`, never a fabricated finite z) applies.
STL_RESIDUAL_ROUND_DECIMALS: Final[int] = 6

# ---------------------------------------------------------------------------- URL path analysis

# docs/04 §L2 "URL path analysis": "high-entropy token pattern (base64-ish or hex-ish, length >=
# 12)" -- the minimum segment length before it is even considered as a candidate random-looking
# token; below this, short path segments (`v2`, `api`, `edit`) are too short for entropy to be a
# meaningful signal regardless of content.
URL_PATH_SEGMENT_MIN_LEN: Final[int] = 12
# "base64-ish or hex-ish" (docs/04) as a charset match alone is too permissive -- a hyphenated
# lowercase phrase like `check-in-endpoint` is entirely within the base64url charset
# (`[A-Za-z0-9_-]`), and first-order character Shannon entropy does not reliably separate the two
# either (verified empirically while building this module: a 17-25 character hyphenated English
# phrase routinely measures 3.3-3.8 bits/char, *higher* than a same-length random hex string's
# 2.9-3.5 -- natural-language text has low *conditional* entropy, given previous characters, not
# low *marginal* character-frequency entropy, so a single-character entropy statistic does not
# discriminate here). Two structural checks stand in instead, both cheap and directly justified by
# real-world token conventions rather than a statistic that measurably fails on this alphabet:
#
# * A minimum count of *distinct* characters in the segment, ruling out a degenerate repeated- or
#   low-cardinality string that would otherwise pass a pure hex/base64 charset check.
# * For the base64-ish branch specifically (`url_path.py`'s `_is_high_entropy_token`): the segment
#   must contain *both* an uppercase and a lowercase letter. Real base64 tokens are drawn
#   uniformly from a 64-symbol alphabet, so missing either case entirely in 12+ characters is
#   vanishingly unlikely (`(38/64)**12 ~ 0.0016`); REST path slugs are conventionally all-
#   lowercase, so this alone excludes essentially every legitimate kebab-case segment while still
#   catching genuine mixed-case encoded tokens. The hex-ish branch does not need this guard: hex
#   digits contain no hyphen/underscore, so a real hyphenated English phrase never matches its
#   charset to begin with.
URL_PATH_TOKEN_MIN_DISTINCT_CHARS: Final[int] = 6
# "above the 99.5th percentile of the org-wide distribution for that domain's category" -- same
# percentile M8's own interim per-model confidence convention already uses
# (`ml.iforest`/`ml.mahalanobis`/`ml.autoencoder`'s shared 99.5th-percentile calibration slice,
# `app.detection.ml.detect.SIGNAL_CONFIDENCE_THRESHOLD`), reused here as the same "top half of one
# percent is worth a human's attention" bar docs/04 gives verbatim for this detector specifically.
URL_PATH_PERCENTILE_THRESHOLD: Final[float] = 99.5
# `(entity, domain)` pairs need at least this many URLs before a percentile comparison means
# anything -- mirrors every other detector's own minimum-population floor in this module
# (`BEACONING_MIN_EVENTS`, `BURST_MIN_ACTIVE_BUCKETS`, `STL_MIN_ACTIVE_HOURS_FALLBACK`).
URL_PATH_MIN_REQUESTS: Final[int] = 5
# A domain needs at least this many distinct (entity, domain) pairs before its own 99.5th
# percentile is a meaningful cutoff rather than effectively "whichever pair happens to have the
# highest value" -- with, say, 3 pairs, the 99.5th percentile is the max by construction, which
# would flag the single most-active-looking pair on that domain regardless of whether it is
# actually unusual.
URL_PATH_MIN_PAIRS_FOR_PERCENTILE: Final[int] = 20
# `explanation.sample_paths` -- capped independently of `EVIDENCE_CAP` (evidence is event ids;
# these are literal path strings a human reads directly in the UI), and each path is truncated to
# `docs/06`'s 256-character field-truncation rule before it ever reaches a prompt.
URL_PATH_SAMPLE_COUNT: Final[int] = 5
URL_PATH_TRUNCATE_CHARS: Final[int] = 256

# ---------------------------------------------------------------------------- rarity / first-seen

RARITY_MAX_ORG_EVENT_COUNT: Final[int] = 10

# ---------------------------------------------------------------------------- evidence

# `signals.evidence_event_ids` is a real column, not a summary count -- but an unbounded array
# is a foot-gun for a detector matching thousands of events (e.g. `signal.dga` against a
# frequently-hit domain). Evidence lists longer than this are truncated to first+last events by
# timestamp (`drafts.cap_evidence`) and the truncation is recorded in `explanation`, never silent.
EVIDENCE_CAP: Final[int] = 200
