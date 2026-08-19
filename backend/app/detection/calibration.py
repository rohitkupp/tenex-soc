"""Per-detector isotonic calibration (docs/04 §Fusion "Per-detector calibration", docs/05).

> Each detector's raw score -> probability via isotonic regression fit on held-out labeled eval
> data. Persist the calibrator per detector. `signals.confidence` is always post-calibration.

This directly answers a measured defect (`backend/evals/results.md`, M8): the autoencoder has
the best AUC-PR of the three L3 models (ranks anomalies far better) but by far the worst
precision at its shipped operating point — it *ranks* well and *thresholds* badly, because its
"confidence" was a percentile rank against a benign calibration sample, not a probability. A
percentile rank and a calibrated probability answer different questions ("how unusual is this
compared to ordinary traffic" vs. "given this raw score, what fraction of things that scored this
way were actually attacks") and only the second one is safe to threshold at a fixed cut like 0.5.

## Design

`IsotonicCalibrator` wraps `sklearn.isotonic.IsotonicRegression` (`increasing=True`, every
detector in this system reports raw scores on a "higher = more anomalous" axis — see each
detector's own docstring; `app.detection.signal.burst`'s bidirectional `z` is the one exception,
handled by calibrating on `abs(z)` at the call site, documented below). One calibrator per
`detector_key`, persisted to `backend/data/models/calibrators/<sanitized_key>.joblib`.

`CalibratorStore` is the load/apply surface every caller (fusion, the pipeline demo) uses.
A detector_key with no fitted calibrator (never seen during fitting, or too few/degenerate
samples to fit) falls back to `clamp01(raw_score)` — documented, not hidden, the same "interim
policy, stated plainly" precedent `app.detection.signal.drafts.clamp01` already set for the
pre-M10 world this module replaces.

## Re-running the L3 benchmark with calibrated confidences

`recompare_l3` is the module's second job: `backend/evals/results.md` (M8) reports the L3 model
comparison using each model's own uncalibrated percentile-rank confidence. This function reuses
`app.detection.ml.evaluate`'s own scenario-generation and scoring helpers (read-only imports —
`app/detection/ml/**` is out of this milestone's ownership) to regenerate the *same* eval
scenarios (`eval_seed=7`, `events=50000`, `evaluate.SCENARIO_KEYS` — identical provenance to
`results.md`) and re-score every row with a calibrator fit on a **different**, held-out seed
(`CALIBRATION_FIT_SEED`), so the reported numbers are not fit-on-what-you-test circularity.
"""

from __future__ import annotations

import argparse
import json
import re
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

import joblib
import numpy as np
import numpy.typing as npt
from sklearn.isotonic import IsotonicRegression
from sklearn.metrics import average_precision_score, f1_score, precision_score, recall_score

from app.core.logging import configure_logging, get_logger

__all__ = [
    "CALIBRATORS_DIR",
    "MIN_SAMPLES_TO_FIT",
    "CalibratorStore",
    "DetectorSample",
    "IsotonicCalibrator",
    "clamp01",
    "fit_calibrator",
    "fit_calibrators",
    "recompare_l3",
]

log = get_logger(__name__)

_BACKEND_ROOT: Final[Path] = Path(__file__).resolve().parents[2]
CALIBRATORS_DIR: Final[Path] = _BACKEND_ROOT / "data" / "models" / "calibrators"

# A detector with fewer than this many held-out samples, or samples that are all one label,
# cannot support a meaningful isotonic fit (sklearn itself degrades to a constant function in
# the second case) -- `fit_calibrator` returns `None` rather than fit-and-ship a degenerate
# calibrator, and `CalibratorStore` falls back to `clamp01` for that detector, loudly logged.
MIN_SAMPLES_TO_FIT: Final[int] = 8

# `evals/results.md`'s (M8) eval seed -- reused for `recompare_l3` so the recalibrated numbers
# are directly comparable to the numbers already published there. Calibrators themselves are
# fit on a *different* seed (`CALIBRATION_FIT_SEED`, below) so this is genuinely held out. Both
# reuse `app.detection.ml.evaluate`'s own hardcoded `SCENARIO_EVENTS` (50,000/scenario) via
# `_generate_eval_scenarios` -- not independently configurable here, since the whole point is
# reusing that module's exact scenario-generation path unmodified.
_RECOMPARE_EVAL_SEED: Final[int] = 7
# Held out from `_RECOMPARE_EVAL_SEED` -- `datagen.corpus.role_seed` additionally namespaces by
# role, so this and the recompare seed cannot collide into the same simulated org even by
# accident (same guarantee `app.detection.ml.train`'s module docstring documents for its own
# three seeds).
CALIBRATION_FIT_SEED: Final[int] = 11

# Post-calibration, `signals.confidence` is a genuine probability -- the natural operating point
# is therefore the standard decision boundary (0.5), not the old percentile-rank threshold
# (0.995) that only made sense when "confidence" meant "percentile within a benign sample."
CALIBRATED_OPERATING_POINT: Final[float] = 0.5


def clamp01(x: float) -> float:
    if x != x:
        return 0.0
    return max(0.0, min(1.0, x))


# ---------------------------------------------------------------------------- fitting


@dataclass(frozen=True, slots=True)
class DetectorSample:
    """One labeled observation for calibration fitting: one detector's raw score on one
    (entity, window) or (rule-match) instance, plus whether that instance was actually part of a
    labeled attack (`label=1`) or not (`label=0`). Built by whatever harness generates labeled
    data (`recompare_l3`'s scenario loader, or a live pipeline's analyst-feedback loop in a
    future milestone) -- this module only ever consumes the pair, never produces it.
    """

    detector_key: str
    raw_score: float
    label: int


@dataclass(slots=True)
class IsotonicCalibrator:
    detector_key: str
    model: IsotonicRegression
    n_samples: int
    n_positive: int

    def calibrate(self, raw_score: float) -> float:
        predicted = self.model.predict([raw_score])[0]
        return clamp01(float(predicted))

    def calibrate_many(self, raw_scores: npt.NDArray[np.float64]) -> npt.NDArray[np.float64]:
        predicted: npt.NDArray[np.float64] = self.model.predict(raw_scores)
        return np.clip(predicted, 0.0, 1.0)


def fit_calibrator(
    detector_key: str, samples: Sequence[DetectorSample]
) -> IsotonicCalibrator | None:
    """Fit one detector's isotonic calibrator. Returns `None` (rather than a degenerate fit) when
    there are too few samples or only one label is represented -- see `MIN_SAMPLES_TO_FIT`."""
    if len(samples) < MIN_SAMPLES_TO_FIT:
        log.warning(
            "calibration.insufficient_samples",
            detector_key=detector_key,
            n_samples=len(samples),
            minimum=MIN_SAMPLES_TO_FIT,
        )
        return None
    x = np.array([s.raw_score for s in samples], dtype=np.float64)
    y = np.array([s.label for s in samples], dtype=np.float64)
    if len(np.unique(y)) < 2:
        log.warning(
            "calibration.single_class",
            detector_key=detector_key,
            n_samples=len(samples),
            label=float(y[0]),
        )
        return None
    x = np.nan_to_num(x, nan=0.0, posinf=1e12, neginf=-1e12)
    model = IsotonicRegression(y_min=0.0, y_max=1.0, out_of_bounds="clip", increasing=True)
    # Class-balanced fit: every positive carries n/(2*n_pos) weight, every negative n/(2*n_neg),
    # so the two classes contribute equally regardless of the corpus base rate.
    #
    # Unweighted isotonic learns P(malicious | score) at the *training base rate*, and on this
    # corpus that base rate is ~0.1%: the funnel detectors fire on nearly every benign event by
    # design, so their fitted curves were flat at ≈0 across the entire raw range production
    # traffic occupies (measured: sigma.non_browser_user_agent could never output above 0.0001
    # anywhere on its domain — 1 positive in 12,418 samples; signal.rarity capped at 0.0010;
    # signal.burst at 0.0017). Every UI surface reading `signals.confidence` rendered 0.00, and
    # noisy-OR fusion over ≈0 inputs made the incident queue bimodal (only detectors *without*
    # a calibrator, falling back to clamp01, could score at all — pinned at 1.0 instead).
    #
    # Balancing rescales the target to P(malicious | score, balanced prior) — a monotone
    # transform of the likelihood ratio, so ranking is untouched and isotonic's shape guarantees
    # hold, but the curve now spans (0, 1) and "twice as strong evidence" is visible instead of
    # rounding to 0.00 at two decimals. The absolute base-rate posterior was never the quantity
    # fusion or the UI wanted: docs/04 defines fused/anomaly confidence as evidence strength
    # ("how unusual"), never P(attack), and CLAUDE.md rule 5 keeps priority with the calibrated
    # fusion either way. docs/04 §Fusion records this alongside the eval re-run.
    n_pos = float(y.sum())
    n_neg = float(len(y) - n_pos)
    sample_weight = np.where(y > 0.5, len(y) / (2.0 * n_pos), len(y) / (2.0 * n_neg))
    model.fit(x, y, sample_weight=sample_weight)
    return IsotonicCalibrator(
        detector_key=detector_key,
        model=model,
        n_samples=len(samples),
        n_positive=int(y.sum()),
    )


def fit_calibrators(samples: Sequence[DetectorSample]) -> dict[str, IsotonicCalibrator]:
    """Group `samples` by `detector_key` and fit one calibrator per key. Detectors that fail
    `fit_calibrator`'s minimum-data bar are simply absent from the result (already logged)."""
    by_detector: dict[str, list[DetectorSample]] = {}
    for s in samples:
        by_detector.setdefault(s.detector_key, []).append(s)
    out: dict[str, IsotonicCalibrator] = {}
    for detector_key, group in sorted(by_detector.items()):
        fitted = fit_calibrator(detector_key, group)
        if fitted is not None:
            out[detector_key] = fitted
    return out


# ---------------------------------------------------------------------------- persistence


def _sanitize(detector_key: str) -> str:
    """`sigma.large-post-to-new-domain` -> a safe filename -- detector keys are dotted/hyphenated
    identifiers, never attacker-controlled, but sanitizing keeps this robust regardless."""
    return re.sub(r"[^A-Za-z0-9._-]", "_", detector_key)


class CalibratorStore:
    """Load/save/apply surface for a directory of persisted calibrators. Construct once per
    process (`CalibratorStore()` loads everything under `directory` eagerly) and reuse — every
    caller in this milestone (fusion demo, recompare) scores many rows against the same set of
    detectors, so loading each `.joblib` once up front is worth it over a lazy per-call load.
    """

    def __init__(self, directory: Path = CALIBRATORS_DIR) -> None:
        self.directory = directory
        self._calibrators: dict[str, IsotonicCalibrator] = {}
        if directory.exists():
            for path in sorted(directory.glob("*.joblib")):
                try:
                    calibrator: IsotonicCalibrator = joblib.load(path)
                except Exception as exc:
                    # A single unreadable/incompatible artifact (a partial write, a pickle from
                    # an incompatible sklearn/joblib version, ...) must not take down every other
                    # detector's calibrator with it -- skip it, loudly, and keep loading the
                    # rest. A caller that actually needs that specific detector's calibrator
                    # falls back to `clamp01` via `calibrate`'s own documented policy, the same
                    # as a detector that was never fitted at all.
                    log.warning(
                        "calibration.store.unreadable_artifact",
                        path=str(path),
                        error=repr(exc),
                    )
                    continue
                self._calibrators[calibrator.detector_key] = calibrator

    def __len__(self) -> int:
        return len(self._calibrators)

    def detector_keys(self) -> list[str]:
        return sorted(self._calibrators)

    def save(self, calibrator: IsotonicCalibrator) -> Path:
        self.directory.mkdir(parents=True, exist_ok=True)
        path = self.directory / f"{_sanitize(calibrator.detector_key)}.joblib"
        joblib.dump(calibrator, path)
        self._calibrators[calibrator.detector_key] = calibrator
        return path

    def save_all(self, calibrators: dict[str, IsotonicCalibrator]) -> list[Path]:
        return [self.save(c) for c in calibrators.values()]

    def has(self, detector_key: str) -> bool:
        return detector_key in self._calibrators

    def calibrate(self, detector_key: str, raw_score: float) -> float:
        """`raw_score` -> calibrated probability. Falls back to `clamp01(raw_score)`, logged
        once per (detector_key) the first time it is hit -- see module docstring."""
        calibrator = self._calibrators.get(detector_key)
        if calibrator is None:
            log.warning("calibration.fallback", detector_key=detector_key, raw_score=raw_score)
            return clamp01(raw_score)
        return calibrator.calibrate(raw_score)


# ---------------------------------------------------------------------------- L3 recompare


@dataclass(slots=True)
class _ModelRecompareRow:
    scenario: str
    model: str
    n_rows: int
    n_positive: int
    precision_uncalibrated: float
    recall_uncalibrated: float
    f1_uncalibrated: float
    precision_calibrated: float
    recall_calibrated: float
    f1_calibrated: float
    auc_pr: float  # threshold-free -- identical calibrated/uncalibrated, monotonic transform


def _model_pairs(bundle: Any) -> list[tuple[str, Any]]:
    """`[(detector_key, model), ...]` for every L3 model the *current* `MLModelBundle` exposes.

    Read dynamically off `app.detection.ml.detect`'s own exported constants/bundle fields rather
    than hardcoded here: that package (out of this milestone's ownership, concurrently developed)
    grew from three models (`ml.iforest`/`ml.mahalanobis`/`ml.autoencoder`, the M8 state
    `evals/results.md` was written against) to the full five-model docs/04 roster
    (`+ ml.ecod`, `ml.peer_group` i.e. LOF) during this milestone's own development window, then
    back down to four when migration change 19
    (`docs/v2_migration/MIGRATION-01-evidence-first.md`) removed the autoencoder. Both
    `_fit_ml_calibrators` and `recompare_l3` should score whatever the live package currently
    ships, not a snapshot frozen at the moment this file was written.
    """
    from app.detection.ml import detect as ml_detect

    # Genuinely dynamic now. This used to be four hardcoded tuples under a docstring claiming
    # it was read off the package's own constants — which meant EIF and kth-NN, added by
    # migration change 19, were silently never calibrated.
    return [(key, getattr(bundle, field)) for key, field in ml_detect.ML_MODEL_FIELDS.items()]


def _fit_ml_calibrators() -> dict[str, IsotonicCalibrator]:
    """Fit one isotonic calibrator per L3 model (see `_model_pairs`) on `CALIBRATION_FIT_SEED`
    (held out from `_RECOMPARE_EVAL_SEED`, see module docstring)."""
    # Imported lazily/locally: `app.detection.ml.evaluate` is a heavy import (torch, lightgbm's
    # sibling packages) this module's other callers (fusion, `CalibratorStore.calibrate`) should
    # never have to pay for.
    from app.detection.ml.detect import MLModelBundle
    from app.detection.ml.evaluate import SCENARIO_KEYS, _generate_eval_scenarios, _load_scenario

    bundle = MLModelBundle.load()
    fit_dir = Path("/tmp/m10_calibration_fit")  # noqa: S108 -- locally-regenerable scratch data
    scenario_dirs = _generate_eval_scenarios(fit_dir, CALIBRATION_FIT_SEED)

    samples: list[DetectorSample] = []
    for key in SCENARIO_KEYS:
        df, y, _ = _load_scenario(scenario_dirs[key])
        if df.empty:
            continue
        x_scaled = bundle.transform(df)
        for detector_key, model in _model_pairs(bundle):
            raw = model.raw_scores(x_scaled)
            samples.extend(
                DetectorSample(detector_key=detector_key, raw_score=float(r), label=int(lbl))
                for r, lbl in zip(raw, y, strict=True)
            )
    return fit_calibrators(samples)


def recompare_l3(*, out_path: Path | None = None, models_dir: Path | None = None) -> dict[str, Any]:
    """Re-run the M8 L3 comparison (every model `app.detection.ml.detect.MLModelBundle` currently
    ships -- see `_model_pairs`) with calibrated confidences instead of the interim percentile
    rank, and report whether the winner changes. See module docstring for the seed provenance
    (fit on 11, measured on 7 -- the same seed `evals/results.md` used, for a direct comparison).
    """
    from app.detection.ml.artifacts import MODELS_DIR
    from app.detection.ml.detect import MLModelBundle
    from app.detection.ml.evaluate import (
        FP_CONTROL_SCENARIO,
        SCENARIO_KEYS,
        _generate_eval_scenarios,
        _load_scenario,
    )

    t0 = time.perf_counter()
    log.info("recompare_l3.fit_calibrators.start", seed=CALIBRATION_FIT_SEED)
    calibrators = _fit_ml_calibrators()
    log.info(
        "recompare_l3.fit_calibrators.done",
        detectors=sorted(calibrators),
        n_samples={k: c.n_samples for k, c in calibrators.items()},
        n_positive={k: c.n_positive for k, c in calibrators.items()},
    )

    bundle = MLModelBundle.load(models_dir or MODELS_DIR)
    eval_dir = Path("/tmp/m10_calibration_recompare")  # noqa: S108
    scenario_dirs = _generate_eval_scenarios(eval_dir, _RECOMPARE_EVAL_SEED)
    model_pairs = _model_pairs(bundle)
    model_keys = [k for k, _ in model_pairs]

    rows: list[_ModelRecompareRow] = []
    attack_scenarios = [k for k in SCENARIO_KEYS if k != FP_CONTROL_SCENARIO]
    for key in SCENARIO_KEYS:
        df, y, _ = _load_scenario(scenario_dirs[key])
        if df.empty:
            continue
        x_scaled = bundle.transform(df)
        for detector_key, model in model_pairs:
            raw = model.raw_scores(x_scaled)
            uncal_conf = model.confidence(raw)
            calibrator = calibrators.get(detector_key)
            cal_conf = (
                calibrator.calibrate_many(raw) if calibrator is not None else np.clip(raw, 0.0, 1.0)
            )

            y_pred_uncal = (uncal_conf >= 0.995).astype(
                np.int64
            )  # docs/04 SIGNAL_CONFIDENCE_THRESHOLD
            y_pred_cal = (cal_conf >= CALIBRATED_OPERATING_POINT).astype(np.int64)
            n_positive = int(y.sum())
            auc_pr = (
                float(average_precision_score(y, raw))
                if n_positive and len(np.unique(y)) > 1
                else float("nan")
            )
            rows.append(
                _ModelRecompareRow(
                    scenario=key,
                    model=detector_key,
                    n_rows=len(y),
                    n_positive=n_positive,
                    precision_uncalibrated=float(precision_score(y, y_pred_uncal, zero_division=0)),
                    recall_uncalibrated=float(recall_score(y, y_pred_uncal, zero_division=0)),
                    f1_uncalibrated=float(f1_score(y, y_pred_uncal, zero_division=0)),
                    precision_calibrated=float(precision_score(y, y_pred_cal, zero_division=0)),
                    recall_calibrated=float(recall_score(y, y_pred_cal, zero_division=0)),
                    f1_calibrated=float(f1_score(y, y_pred_cal, zero_division=0)),
                    auc_pr=auc_pr,
                )
            )
        log.info("recompare_l3.scenario_done", scenario=key, n_rows=len(y))

    aggregate: dict[str, dict[str, float]] = {}
    for model_key in model_keys:
        model_rows = [r for r in rows if r.model == model_key and r.scenario in attack_scenarios]
        aucs = [r.auc_pr for r in model_rows if r.auc_pr == r.auc_pr]  # drop NaN
        aggregate[model_key] = {
            "mean_f1_uncalibrated": float(np.mean([r.f1_uncalibrated for r in model_rows])),
            "mean_f1_calibrated": float(np.mean([r.f1_calibrated for r in model_rows])),
            "mean_precision_uncalibrated": float(
                np.mean([r.precision_uncalibrated for r in model_rows])
            ),
            "mean_precision_calibrated": float(
                np.mean([r.precision_calibrated for r in model_rows])
            ),
            "mean_recall_uncalibrated": float(np.mean([r.recall_uncalibrated for r in model_rows])),
            "mean_recall_calibrated": float(np.mean([r.recall_calibrated for r in model_rows])),
            "mean_auc_pr": float(np.mean(aucs)) if aucs else 0.0,
        }

    winner_uncalibrated = max(
        aggregate, key=lambda m: (aggregate[m]["mean_f1_uncalibrated"], aggregate[m]["mean_auc_pr"])
    )
    winner_calibrated = max(
        aggregate, key=lambda m: (aggregate[m]["mean_f1_calibrated"], aggregate[m]["mean_auc_pr"])
    )

    result = {
        "fit_seed": CALIBRATION_FIT_SEED,
        "eval_seed": _RECOMPARE_EVAL_SEED,
        "calibrated_operating_point": CALIBRATED_OPERATING_POINT,
        "uncalibrated_operating_point": 0.995,
        "n_calibration_samples": {k: c.n_samples for k, c in calibrators.items()},
        "aggregate": aggregate,
        "winner_uncalibrated": winner_uncalibrated,
        "winner_calibrated": winner_calibrated,
        "winner_changed": winner_uncalibrated != winner_calibrated,
        "per_scenario": [
            {
                "scenario": r.scenario,
                "model": r.model,
                "n_rows": r.n_rows,
                "n_positive": r.n_positive,
                "precision_uncalibrated": r.precision_uncalibrated,
                "recall_uncalibrated": r.recall_uncalibrated,
                "f1_uncalibrated": r.f1_uncalibrated,
                "precision_calibrated": r.precision_calibrated,
                "recall_calibrated": r.recall_calibrated,
                "f1_calibrated": r.f1_calibrated,
                "auc_pr": r.auc_pr,
            }
            for r in rows
        ],
        "elapsed_seconds": time.perf_counter() - t0,
    }
    if out_path is not None:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
    log.info(
        "recompare_l3.done",
        winner_uncalibrated=winner_uncalibrated,
        winner_calibrated=winner_calibrated,
        winner_changed=result["winner_changed"],
        elapsed_s=round(float(result["elapsed_seconds"]), 2),  # type: ignore[arg-type]
    )
    return result


# ---------------------------------------------------------------------------- reliability diagram


@dataclass(frozen=True, slots=True)
class ReliabilityBin:
    bin_lo: float
    bin_hi: float
    n: int
    mean_predicted: float
    observed_precision: float


@dataclass(frozen=True, slots=True)
class ReliabilityReport:
    bins: list[ReliabilityBin]
    brier_score: float


def reliability_diagram(
    confidences: npt.NDArray[np.float64], labels: npt.NDArray[np.int64], *, n_bins: int = 10
) -> ReliabilityReport:
    """docs/12 "Calibration": 10-bin reliability diagram (predicted vs. observed precision) plus
    Brier score, over any set of `(calibrated confidence, label)` pairs -- detector-level or
    incident-level, this function does not care which."""
    edges = np.linspace(0.0, 1.0, n_bins + 1)
    bins: list[ReliabilityBin] = []
    for i in range(n_bins):
        lo, hi = edges[i], edges[i + 1]
        mask = (confidences >= lo) & (confidences < hi if i < n_bins - 1 else confidences <= hi)
        n = int(mask.sum())
        bins.append(
            ReliabilityBin(
                bin_lo=float(lo),
                bin_hi=float(hi),
                n=n,
                mean_predicted=float(confidences[mask].mean()) if n else float((lo + hi) / 2),
                observed_precision=float(labels[mask].mean()) if n else 0.0,
            )
        )
    brier = float(np.mean((confidences - labels) ** 2)) if len(confidences) else 0.0
    return ReliabilityReport(bins=bins, brier_score=brier)


# ---------------------------------------------------------------------------- CLI


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Per-detector calibration (docs/04 §Fusion, M10)")
    sub = parser.add_subparsers(dest="command", required=True)

    fit_p = sub.add_parser(
        "fit-ml", help="Fit ml.{iforest,mahalanobis,ecod,peer_group,eif,kth_nn} calibrators"
    )
    fit_p.add_argument("--log-level", default="info")

    recompare_p = sub.add_parser("recompare-l3", help="Re-run the M8 L3 comparison, calibrated")
    recompare_p.add_argument("--out", type=Path, default=None)
    recompare_p.add_argument("--log-level", default="info")

    args = parser.parse_args(argv)
    configure_logging(args.log_level)

    if args.command == "fit-ml":
        calibrators = _fit_ml_calibrators()
        store = CalibratorStore()
        paths = store.save_all(calibrators)
        log.info("fit_ml.done", saved=[str(p) for p in paths])
    elif args.command == "recompare-l3":
        result = recompare_l3(out_path=args.out)
        print(json.dumps(result["aggregate"], indent=2))  # noqa: T201 -- CLI summary output
        print(  # noqa: T201
            f"winner_uncalibrated={result['winner_uncalibrated']} "
            f"winner_calibrated={result['winner_calibrated']} "
            f"winner_changed={result['winner_changed']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
