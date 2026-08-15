"""Fit both L4 sequence models on the benign identity corpus (docs/04 §L4).

    python -m datagen benign --events 400000 --seed 42 --out /tmp/m9_corpus
    python -m app.detection.sequence.train \\
        --corpus /tmp/m9_corpus/benign_okta.jsonl --seed 42 --out backend/data/models

Mirrors `app.detection.signal.dga_train`'s shape: a `fit()` importable from a test or another
script, plus a thin CLI `main()` that resolves paths and calls it. Not wired into the top-level
`make train` target -- that Makefile entry is outside this milestone's ownership
(`backend/app/detection/sequence/**` per the M9 brief) -- so it is run directly, per the command
above.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path

from app.core.logging import configure_logging, get_logger
from app.detection.sequence import logbert, markov
from app.detection.sequence.sessions import (
    SessionStats,
    build_sessions,
    read_okta_file,
    session_stats,
)
from app.detection.sequence.vocabulary import Vocabulary, build_vocabulary

log = get_logger(__name__)

_BACKEND_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_MODELS_DIR: Path = _BACKEND_ROOT / "data" / "models"

__all__ = ["DEFAULT_MODELS_DIR", "FitResult", "fit", "main", "write_artifacts"]


@dataclass(slots=True)
class FitResult:
    vocab: Vocabulary
    markov_model: markov.MarkovModel
    logbert_trained: logbert.TrainedLogBert
    stats: SessionStats


def fit(
    corpus_path: Path,
    *,
    seed: int = 42,
    epochs: int = 8,
    batch_size: int = 64,
    lr: float = 1e-3,
    device: str = "cpu",
) -> FitResult:
    """Read `corpus_path` (an Okta `.jsonl` file — the benign corpus), build sessions, fit the
    vocabulary from what those sessions actually contain, then fit both models on them."""
    log.info("sequence.train.read.start", corpus=str(corpus_path))
    events = read_okta_file(corpus_path)
    sessions = build_sessions(events)
    stats = session_stats(sessions)
    log.info(
        "sequence.train.sessions",
        n_sessions=stats.n_sessions,
        n_principals=stats.n_principals,
        n_truncated=stats.n_truncated,
        n_events=stats.n_events,
        mean_len=round(stats.mean_len, 2),
        max_len_observed=stats.max_len_observed,
    )

    vocab = build_vocabulary(key for s in sessions for key in s.token_keys)
    log.info("sequence.train.vocab", vocab_size=len(vocab))

    markov_model = markov.fit(sessions, vocab)
    log.info("sequence.train.markov.fit_done")

    trained_logbert = logbert.train(
        sessions, vocab, epochs=epochs, batch_size=batch_size, lr=lr, seed=seed, device=device
    )
    log.info(
        "sequence.train.logbert.fit_done",
        epoch_losses=trained_logbert.training["epoch_losses"],
        training_dist_scale=trained_logbert.training_dist_scale,
    )

    return FitResult(
        vocab=vocab, markov_model=markov_model, logbert_trained=trained_logbert, stats=stats
    )


def write_artifacts(result: FitResult, out_dir: Path = DEFAULT_MODELS_DIR) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    vocab_path = out_dir / "seq_vocab.json"
    markov_path = out_dir / "seq_markov.json"
    logbert_model_path = out_dir / "seq_logbert.pt"
    logbert_meta_path = out_dir / "seq_logbert_meta.json"

    result.vocab.save(vocab_path)
    result.markov_model.save(markov_path)
    logbert.save(
        result.logbert_trained,
        model_path=logbert_model_path,
        meta_path=logbert_meta_path,
        vocab_path=vocab_path,
    )
    log.info("sequence.train.artifacts_written", out_dir=str(out_dir))
    return {
        "vocab": vocab_path,
        "markov": markov_path,
        "logbert_model": logbert_model_path,
        "logbert_meta": logbert_meta_path,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Fit both L4 sequence models (docs/04 §L4)")
    parser.add_argument("--corpus", type=Path, required=True, help="Path to benign_okta.jsonl")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--epochs", type=int, default=8)
    parser.add_argument("--batch-size", type=int, default=64)
    parser.add_argument("--lr", type=float, default=1e-3)
    parser.add_argument("--device", type=str, default="cpu")
    parser.add_argument("--out", type=Path, default=DEFAULT_MODELS_DIR)
    parser.add_argument("--log-level", default="info")
    args = parser.parse_args(argv)

    configure_logging(args.log_level)
    result = fit(
        args.corpus,
        seed=args.seed,
        epochs=args.epochs,
        batch_size=args.batch_size,
        lr=args.lr,
        device=args.device,
    )
    write_artifacts(result, args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
