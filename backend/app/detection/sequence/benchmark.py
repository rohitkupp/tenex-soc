"""Benchmark: Markov vs LogBERT on scenarios 5 and 6 (docs/04 §L4, docs/12, docs/13 M9).

    python -m app.detection.sequence.benchmark \\
        --scenario account_takeover_chain --scenario mfa_fatigue \\
        --eval-root /tmp/m9_eval --models-dir backend/data/models \\
        --out backend/data/models/seq_benchmark.json

## Session-level evaluation

A session is a positive iff any of its events' `line_no`s appear in a `.labels.json`'s
`malicious_line_numbers` (`label_sessions`). Both models emit a continuous `session_score`
(higher = more anomalous, for both — Markov's mean negative log-probability and LogBERT's
`anomaly_ratio + normalized hypersphere distance` are both "bigger means more surprising"); this
module sweeps every distinct score as a threshold and reports the **best-F1 operating point**
per model (`best_f1`) — the standard protocol in the log-anomaly-detection literature this
milestone's baselines are drawn from (DeepLog, LogAnomaly, and the LogBERT paper itself all
report best-F1-over-threshold rather than a single fixed cutoff), since picking one committed
cutoff is a calibration decision that belongs to `docs/04`'s fusion layer (M10's isotonic
regression), not to this benchmark.

## Pooling across seeds

`docs/11`'s per-scenario `.labels.json` typically carries only a couple of malicious sessions per
generated file (`s05_account_takeover.py`'s own docstring: the chain is deliberately short, ~10
events). `--eval-root` is expected to contain one subdirectory per generation seed
(`seed_7/scenario_account_takeover_chain.jsonl`, `seed_17/...`, ...); `discover_files` globs all
of them and every scenario's sessions across every seed are pooled into one threshold sweep, so
the reported F1 reflects more than a single attack instance without needing an implausibly large
single eval file.
"""

from __future__ import annotations

import argparse
import json
import random
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.core.logging import configure_logging, get_logger
from app.detection.sequence import logbert, markov
from app.detection.sequence.sessions import Session, build_sessions, read_okta_file
from app.detection.sequence.vocabulary import Vocabulary

log = get_logger(__name__)

_BACKEND_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_MODELS_DIR: Path = _BACKEND_ROOT / "data" / "models"
_N_EXAMPLES: int = 2

__all__ = [
    "LabeledSession",
    "ScenarioBenchmark",
    "ThresholdResult",
    "benchmark_labeled_sessions",
    "benchmark_scenario",
    "best_f1",
    "collect_labeled_sessions",
    "discover_files",
    "label_sessions",
    "load_malicious_lines",
    "main",
    "render_table",
]

_AGGREGATE_SCENARIO_KEY = "aggregate (pooled)"


# ---------------------------------------------------------------------------- labeling


@dataclass(slots=True)
class LabeledSession:
    session: Session
    malicious: bool
    source_file: str


def load_malicious_lines(labels_path: Path) -> set[int]:
    payload = json.loads(labels_path.read_text(encoding="utf-8"))
    malicious: set[int] = set()
    for scenario in payload.get("scenarios", []):
        malicious.update(int(n) for n in scenario.get("malicious_line_numbers", []))
    return malicious


def label_sessions(
    sessions: Sequence[Session], malicious_lines: set[int], *, source_file: str
) -> list[LabeledSession]:
    return [
        LabeledSession(
            session=s,
            malicious=any(ln in malicious_lines for ln in s.line_numbers),
            source_file=source_file,
        )
        for s in sessions
    ]


def discover_files(eval_root: Path, scenario_key: str) -> list[tuple[Path, Path]]:
    """Every `(log_path, labels_path)` pair under `eval_root/*/scenario_{scenario_key}.jsonl`,
    sorted for determinism."""
    pairs: list[tuple[Path, Path]] = []
    for log_path in sorted(eval_root.glob(f"*/scenario_{scenario_key}.jsonl")):
        labels_path = log_path.with_name(log_path.stem + ".labels.json")
        if labels_path.exists():
            pairs.append((log_path, labels_path))
    return pairs


# ---------------------------------------------------------------------------- threshold sweep


@dataclass(slots=True)
class ThresholdResult:
    threshold: float
    precision: float
    recall: float
    f1: float
    tp: int
    fp: int
    fn: int
    tn: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "threshold": self.threshold,
            "precision": self.precision,
            "recall": self.recall,
            "f1": self.f1,
            "tp": self.tp,
            "fp": self.fp,
            "fn": self.fn,
            "tn": self.tn,
        }


def best_f1(scores: Sequence[float], labels: Sequence[bool]) -> ThresholdResult:
    """Sweep every distinct observed score as a `>=` threshold; return the highest-F1 operating
    point. Ties broken by higher recall, then by the lower threshold — prefers catching more of a
    rare attack class over an arbitrary tie-break, and prefers a less aggressive cutoff over a
    more aggressive one that happens to land on the same F1."""
    if not scores:
        return ThresholdResult(0.0, 0.0, 0.0, 0.0, 0, 0, 0, 0)
    candidates = sorted(set(scores))
    best: ThresholdResult | None = None
    for thr in candidates:
        tp = fp = fn = tn = 0
        for score, label in zip(scores, labels, strict=True):
            pred = score >= thr
            if pred and label:
                tp += 1
            elif pred and not label:
                fp += 1
            elif not pred and label:
                fn += 1
            else:
                tn += 1
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
        candidate = ThresholdResult(thr, precision, recall, f1, tp, fp, fn, tn)
        key = (candidate.f1, candidate.recall, -candidate.threshold)
        best_key = (best.f1, best.recall, -best.threshold) if best else None
        if best is None or key > best_key:  # type: ignore[operator]
            best = candidate
    assert best is not None
    return best


# ---------------------------------------------------------------------------- scenario benchmark


@dataclass(slots=True)
class ScenarioBenchmark:
    scenario: str
    n_files: int
    n_sessions: int
    n_malicious_sessions: int
    markov_result: ThresholdResult
    logbert_result: ThresholdResult
    winner: str
    markov_examples: list[dict[str, Any]]
    logbert_examples: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario": self.scenario,
            "n_files": self.n_files,
            "n_sessions": self.n_sessions,
            "n_malicious_sessions": self.n_malicious_sessions,
            "markov": self.markov_result.to_dict(),
            "logbert": self.logbert_result.to_dict(),
            "winner": self.winner,
            "markov_examples": self.markov_examples,
            "logbert_examples": self.logbert_examples,
        }


def _top_examples(
    labeled: Sequence[LabeledSession],
    scores: Sequence[float],
    explanations: Sequence[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Up to `_N_EXAMPLES` true-positive (malicious, highest-scored) sessions' explanations --
    what the report quotes as "real surprising_transitions payload"."""
    rows = [
        (score, expl, ls)
        for score, expl, ls in zip(scores, explanations, labeled, strict=True)
        if ls.malicious
    ]
    rows.sort(key=lambda r: r[0], reverse=True)
    return [
        {"source_file": ls.source_file, "line_numbers": list(ls.session.line_numbers), **expl}
        for _score, expl, ls in rows[:_N_EXAMPLES]
    ]


def _subsample_benign(
    labeled: list[LabeledSession], *, max_benign_per_file: int | None, seed: int
) -> list[LabeledSession]:
    """Every malicious session, plus at most `max_benign_per_file` benign sessions per source
    file (a fixed-seed random subsample, not a prefix -- a prefix would just be "the earliest
    sessions in the file," a biased, non-representative slice).

    Each scenario eval file's ~50k-event background produces on the order of ten thousand benign
    sessions (`docs/11`'s eval-file volume target); pooled over several seeds (module docstring),
    scoring every single one is far more than the F1 estimate needs and turns leave-one-out
    LogBERT scoring into a multi-hour job for no statistical benefit -- a random few thousand per
    file is already two to three orders of magnitude more benign examples than malicious ones.
    `max_benign_per_file=None` disables subsampling (score everything).
    """
    if max_benign_per_file is None:
        return labeled
    rng = random.Random(seed)  # noqa: S311 -- benchmark subsampling, not security
    by_file: dict[str, list[LabeledSession]] = {}
    kept: list[LabeledSession] = []
    for ls in labeled:
        if ls.malicious:
            kept.append(ls)
        else:
            by_file.setdefault(ls.source_file, []).append(ls)
    for file_benign in by_file.values():
        if len(file_benign) <= max_benign_per_file:
            kept.extend(file_benign)
        else:
            kept.extend(rng.sample(file_benign, max_benign_per_file))
    return kept


def collect_labeled_sessions(
    scenario_key: str,
    files: Sequence[tuple[Path, Path]],
    *,
    max_benign_per_file: int | None = 1500,
    subsample_seed: int = 0,
) -> list[LabeledSession]:
    """Read, session-ize, label, and subsample every file for one scenario. Split out of
    `benchmark_scenario` so `main()` can also pool several scenarios' sessions into one
    aggregate threshold sweep without re-reading anything."""
    all_labeled: list[LabeledSession] = []
    for log_path, labels_path in files:
        events = read_okta_file(log_path)
        sessions = build_sessions(events)
        malicious_lines = load_malicious_lines(labels_path)
        # Qualified by scenario + parent directory (the per-seed subdirectory, module docstring's
        # `seed_7/scenario_...jsonl` layout), not just the basename -- every seed's file shares
        # the same basename, and `_subsample_benign`'s per-file cap needs a key that actually
        # distinguishes them or it silently caps the whole pooled set once instead of per file.
        source_file = f"{scenario_key}/{log_path.parent.name}/{log_path.name}"
        all_labeled.extend(label_sessions(sessions, malicious_lines, source_file=source_file))

    return _subsample_benign(
        all_labeled, max_benign_per_file=max_benign_per_file, seed=subsample_seed
    )


def benchmark_labeled_sessions(
    scenario_key: str,
    all_labeled: list[LabeledSession],
    n_files: int,
    markov_model: markov.MarkovModel,
    trained_logbert: logbert.TrainedLogBert,
) -> ScenarioBenchmark:
    """Score already-collected `all_labeled` sessions with both models and report the best-F1
    operating point for each -- the shared tail of both `benchmark_scenario` (one scenario) and
    the pooled cross-scenario aggregate `main()` computes when more than one `--scenario` is
    given."""
    labels = [ls.malicious for ls in all_labeled]
    sessions_only = [ls.session for ls in all_labeled]

    markov_scored = [markov_model.score_session(s) for s in sessions_only]
    markov_scores = [r.session_score for r in markov_scored]
    markov_explanations = [r.explanation for r in markov_scored]

    logbert_scored = logbert.score_sessions(trained_logbert, sessions_only)
    logbert_scores = [r.session_score for r in logbert_scored]
    logbert_explanations = [r.explanation for r in logbert_scored]

    markov_best = best_f1(markov_scores, labels)
    logbert_best = best_f1(logbert_scores, labels)
    if logbert_best.f1 > markov_best.f1:
        winner = "logbert"
    elif markov_best.f1 > logbert_best.f1:
        winner = "markov"
    else:
        winner = "tie"

    return ScenarioBenchmark(
        scenario=scenario_key,
        n_files=n_files,
        n_sessions=len(all_labeled),
        n_malicious_sessions=sum(labels),
        markov_result=markov_best,
        logbert_result=logbert_best,
        winner=winner,
        markov_examples=_top_examples(all_labeled, markov_scores, markov_explanations),
        logbert_examples=_top_examples(all_labeled, logbert_scores, logbert_explanations),
    )


def benchmark_scenario(
    scenario_key: str,
    files: Sequence[tuple[Path, Path]],
    markov_model: markov.MarkovModel,
    trained_logbert: logbert.TrainedLogBert,
    *,
    max_benign_per_file: int | None = 1500,
    subsample_seed: int = 0,
) -> ScenarioBenchmark:
    all_labeled = collect_labeled_sessions(
        scenario_key, files, max_benign_per_file=max_benign_per_file, subsample_seed=subsample_seed
    )
    return benchmark_labeled_sessions(
        scenario_key, all_labeled, len(files), markov_model, trained_logbert
    )


def render_table(results: Sequence[ScenarioBenchmark]) -> str:
    lines = [
        "| Scenario | Sessions | Malicious | Markov F1 | Markov P/R | LogBERT F1 | LogBERT P/R | Winner |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for r in results:
        lines.append(
            f"| {r.scenario} | {r.n_sessions} | {r.n_malicious_sessions} "
            f"| {r.markov_result.f1:.3f} | {r.markov_result.precision:.2f}/{r.markov_result.recall:.2f} "
            f"| {r.logbert_result.f1:.3f} | {r.logbert_result.precision:.2f}/{r.logbert_result.recall:.2f} "
            f"| {r.winner} |"
        )
    return "\n".join(lines)


# ---------------------------------------------------------------------------- CLI


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Benchmark Markov vs LogBERT (docs/04 §L4)")
    parser.add_argument("--scenario", action="append", required=True, dest="scenarios")
    parser.add_argument("--eval-root", type=Path, required=True)
    parser.add_argument("--models-dir", type=Path, default=DEFAULT_MODELS_DIR)
    parser.add_argument("--out", type=Path, default=None)
    parser.add_argument("--device", type=str, default="cpu")
    parser.add_argument(
        "--max-benign-per-file",
        type=int,
        default=1500,
        help="Random benign-session subsample cap per source file (0 disables the cap)",
    )
    parser.add_argument("--subsample-seed", type=int, default=0)
    parser.add_argument("--log-level", default="info")
    args = parser.parse_args(argv)
    max_benign_per_file = args.max_benign_per_file if args.max_benign_per_file > 0 else None

    configure_logging(args.log_level)

    vocab = Vocabulary.load(args.models_dir / "seq_vocab.json")
    markov_model = markov.MarkovModel.load(args.models_dir / "seq_markov.json")
    trained_logbert = logbert.load(
        vocab,
        model_path=args.models_dir / "seq_logbert.pt",
        meta_path=args.models_dir / "seq_logbert_meta.json",
        device=args.device,
    )

    results: list[ScenarioBenchmark] = []
    all_pooled: list[LabeledSession] = []
    total_files = 0
    for scenario_key in args.scenarios:
        files = discover_files(args.eval_root, scenario_key)
        if not files:
            log.warning(
                "sequence.benchmark.no_files", scenario=scenario_key, eval_root=str(args.eval_root)
            )
            continue
        labeled = collect_labeled_sessions(
            scenario_key,
            files,
            max_benign_per_file=max_benign_per_file,
            subsample_seed=args.subsample_seed,
        )
        result = benchmark_labeled_sessions(
            scenario_key, labeled, len(files), markov_model, trained_logbert
        )
        results.append(result)
        all_pooled.extend(labeled)
        total_files += len(files)
        log.info(
            "sequence.benchmark.scenario_done",
            scenario=scenario_key,
            n_files=result.n_files,
            n_sessions=result.n_sessions,
            n_malicious=result.n_malicious_sessions,
            markov_f1=result.markov_result.f1,
            logbert_f1=result.logbert_result.f1,
            winner=result.winner,
        )

    # A single pooled cross-scenario sweep, not just the per-scenario rows -- docs/04's "must beat
    # the Markov baseline on eval F1 to ship as primary" is a verdict about the layer overall, and
    # a model can win one scenario's own F1 while losing badly enough on the other that picking
    # per-scenario winners would hide the real aggregate answer (see the M9 report).
    if len(results) > 1:
        aggregate = benchmark_labeled_sessions(
            _AGGREGATE_SCENARIO_KEY, all_pooled, total_files, markov_model, trained_logbert
        )
        results.append(aggregate)
        log.info(
            "sequence.benchmark.aggregate_done",
            n_sessions=aggregate.n_sessions,
            n_malicious=aggregate.n_malicious_sessions,
            markov_f1=aggregate.markov_result.f1,
            logbert_f1=aggregate.logbert_result.f1,
            winner=aggregate.winner,
        )

    table = render_table(results)
    print(table)  # noqa: T201 -- the benchmark table is this script's deliverable stdout output

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(
            json.dumps({"results": [r.to_dict() for r in results], "table_md": table}, indent=2),
            encoding="utf-8",
        )
        log.info("sequence.benchmark.written", path=str(args.out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
