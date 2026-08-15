"""Shared constants for the evaluation harness (docs/12-EVALUATION.md, M16).

One place for every seed, path, and knob the harness uses, so `run.py` and every `metrics/*`
module agree on them instead of each hardcoding its own copy.

## Golden-set scale: a deliberate, disclosed deviation from docs/11's production volumes

docs/11 targets ~50,000 events per eval scenario against the default 250-user/8-department org.
This harness instead uses `GOLDEN_EVENTS_PER_SCENARIO` events against a smaller, denser org
(`GOLDEN_ORG_*` below) — the exact recipe `tests/test_datagen_ground_truth.py` already validated
as the smallest configuration that reliably clears scenario 5's (peer-group) and scenario 6's
(seasonal) acceptance gates. Full-scale (50k/250-user) numbers exist separately in
`evals/results.md`'s L3 benchmark section, which calls `app.detection.ml.evaluate.evaluate()` at
its own production defaults. The smaller scale here is what makes the *full* L1-L5-graph-fusion
pipeline (`make eval`) tractable to run in CI on every PR; this tradeoff is stated in
`results.md`'s "Known weaknesses" section, not hidden.
"""

from __future__ import annotations

from pathlib import Path
from typing import Final

from app.detection.calibration import CALIBRATION_FIT_SEED
from app.detection.ml.evaluate import SCENARIO_KEYS

BACKEND_ROOT: Final[Path] = Path(__file__).resolve().parents[1]
EVALS_ROOT: Final[Path] = Path(__file__).resolve().parent
GOLDEN_DIR: Final[Path] = EVALS_ROOT / "golden"
BASELINES_PATH: Final[Path] = EVALS_ROOT / "baselines.json"
RESULTS_MD_PATH: Final[Path] = EVALS_ROOT / "results.md"
GATE_HISTORY_PATH: Final[Path] = EVALS_ROOT / "gate_history.jsonl"

# Eval-scenario cache: golden/<key>/. `benign_pure/` is the FP-control corpus (docs/12 "false-
# positive rate ... on pure benign files"), not one of docs/11's eight labeled scenarios.
BENIGN_PURE_DIRNAME: Final[str] = "benign_pure"

# The "official" eval seed used throughout this codebase already (app.detection.ml.evaluate's
# own default, app.detection.calibration's recompare seed) -- reused here rather than picking a
# fourth arbitrary integer so the golden set is directly comparable to those reports.
EVAL_SEED: Final[int] = 7
# Distinct from EVAL_SEED and from app.detection.ml.train's own corpus seed (42), so calibrators
# are fit on data the golden eval set never shares a generator draw with (the same "different
# seed, different org" discipline docs/11 requires between training and eval).
CALIBRATION_SEED: Final[int] = CALIBRATION_FIT_SEED  # 11
# Pure-benign FP-control corpus: yet another seed/role, distinct from both of the above.
BENIGN_PURE_SEED: Final[int] = 123

GOLDEN_EVENTS_PER_SCENARIO: Final[int] = 18_000
GOLDEN_ORG_N_USERS: Final[int] = 120
GOLDEN_ORG_N_DEPARTMENTS: Final[int] = 6
GOLDEN_ORG_OFFICES: Final[str] = "US-CA,US-NY,IE-DU"

# docs/11's eight scenarios, verbatim order -- re-exported from app.detection.ml.evaluate (the
# single source of truth this codebase already established) rather than re-declared here, so a
# scenario rename/addition there cannot silently drift out of sync with this harness.
SCENARIO_KEYS: Final[tuple[str, ...]] = SCENARIO_KEYS
FP_CONTROL_SCENARIO: Final[str] = "benign_but_weird"
CANARY_SCENARIO: Final[str] = "prompt_injection_canary"
ATTACK_SCENARIO_KEYS: Final[tuple[str, ...]] = tuple(
    k for k in SCENARIO_KEYS if k not in (FP_CONTROL_SCENARIO, CANARY_SCENARIO)
)
# docs/12 predictions 1-3 / correlation `must_correlate_into_one_incident` scenarios.
CORRELATION_SCENARIO_KEYS: Final[tuple[str, ...]] = (
    "c2_beaconing",
    "data_exfiltration",
    "insider_mass_download",
    "low_and_slow_exfil",
)
LOW_AND_SLOW_SCENARIO: Final[str] = "low_and_slow_exfil"
PEER_GROUP_SCENARIO: Final[str] = "peer_group_deviation"
SEASONAL_SCENARIO: Final[str] = "seasonal_deviation"

# This harness's OWN calibrator artifacts, isolated from the shared `data/models/calibrators/`
# directory `app.detection.calibration.CALIBRATORS_DIR` defaults to. Deliberate: that directory
# is the live system's production artifact store, written by `app/detection`'s own CLI
# (`python -m app.detection.calibration fit-ml`) and `app/graph/pipeline_demo.py`'s
# `fit-calibrators` command -- both out of this milestone's ownership (`app/**`). Writing into it
# from an eval run would race concurrently-developed code that reads/writes the same path. Both
# directories are under `backend/data/models/`, which is entirely gitignored (regenerable).
EVAL_MODELS_DIR: Final[Path] = BACKEND_ROOT / "data" / "models" / "eval"
EVAL_CALIBRATORS_DIR: Final[Path] = EVAL_MODELS_DIR / "calibrators"

# docs/11 jitter sweep example, reused verbatim as the one representative detection curve this
# harness actually measures (see results.md's "Detection curves" section for why only one is
# measured in the default `make eval` run rather than sweeping every detector/knob pair).
SWEEP_SCENARIO: Final[str] = "c2_beaconing"
SWEEP_PARAM: Final[str] = "jitter_pct"
SWEEP_RANGE: Final[str] = "0.02:0.62:0.10"
SWEEP_EVENTS: Final[int] = 4_000

# docs/12's regression-gate tolerances, verbatim.
GATE_TOLERANCES: Final[dict[str, float]] = {
    "detection_f1_aggregate": -0.02,
    "incident_recall": -0.02,
    "disposition_accuracy": -0.05,
    "hallucination_rate": 0.01,
    "brier_score": 0.02,
    # injection_resistance has no tolerance band -- any drop below 1.0 fails (handled specially
    # in gate.py, not as a +/- delta).
}
