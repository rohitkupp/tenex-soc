"""Golden-set generation and loading (docs/12 "Harness structure": `golden/` — frozen scenario
files + labels, version-controlled).

`ensure_golden_set()` generates the eight docs/11 scenario files plus a pure-benign FP-control
corpus into `evals/golden/<key>/` **once**, via the real `datagen` CLI (the same subprocess-call
pattern `app.detection.ml.evaluate` and `app.graph.pipeline_demo` already use — this module does
not import `datagen` directly, matching that established boundary). Once written, these files are
committed to git and treated as frozen: re-running `make eval` never regenerates them, so every
run scores the exact same bytes and the report's numbers are reproducible run over run.

`--regenerate` forces a fresh draw (documented as a deliberate, occasional action — e.g. after a
`datagen` scenario change — not something a normal `make eval` run does).

See `evals/config.py`'s module docstring for why this harness uses a smaller org/event count than
docs/11's ~50k/250-user production target: this exact recipe (120 users / 6 departments / 18,000
events) is the one `tests/test_datagen_ground_truth.py` already validated as reliably clearing
scenario 4/5/6's acceptance gates at `EVAL_SEED`.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from app.core.logging import get_logger
from evals.config import (
    BENIGN_PURE_DIRNAME,
    BENIGN_PURE_SEED,
    GOLDEN_DIR,
    GOLDEN_EVENTS_PER_SCENARIO,
    GOLDEN_ORG_N_DEPARTMENTS,
    GOLDEN_ORG_N_USERS,
    GOLDEN_ORG_OFFICES,
    SCENARIO_KEYS,
)

log = get_logger(__name__)

_BACKEND_ROOT = Path(__file__).resolve().parents[1]


def _run_datagen(args: list[str]) -> None:
    cmd = [sys.executable, "-m", "datagen", "--log-level", "warning", *args]
    log.info("golden.datagen_invoke", cmd=cmd)
    subprocess.run(cmd, check=True, cwd=_BACKEND_ROOT)  # noqa: S603


def _is_populated(directory: Path) -> bool:
    return directory.exists() and any(directory.glob("*.log"))


def _org_args() -> list[str]:
    return [
        "--n-users",
        str(GOLDEN_ORG_N_USERS),
        "--n-departments",
        str(GOLDEN_ORG_N_DEPARTMENTS),
        "--offices",
        GOLDEN_ORG_OFFICES,
    ]


def scenario_dir(key: str) -> Path:
    return GOLDEN_DIR / key


def scenario_log_and_labels(key: str) -> tuple[Path, Path]:
    d = scenario_dir(key)
    logs = sorted(d.glob("*.log"))
    labels = sorted(d.glob("*.labels.json"))
    if not logs or not labels:
        raise FileNotFoundError(
            f"golden scenario {key!r} not generated at {d} — run ensure_golden_set()"
        )
    return logs[0], labels[0]


def benign_pure_log() -> Path:
    d = GOLDEN_DIR / BENIGN_PURE_DIRNAME
    logs = sorted(d.glob("*.log"))
    if not logs:
        raise FileNotFoundError(f"golden benign_pure corpus not generated at {d}")
    return logs[0]


def generate_scenario(key: str, seed: int, out_dir: Path, events: int) -> None:
    """Write one scenario's log+labels into `out_dir` (skips if already populated) — the same
    generation recipe `ensure_golden_set` uses per scenario, exposed standalone so other callers
    (calibration fitting, which deliberately uses a *different* seed on scratch, non-committed
    output) can reuse it without duplicating the org-spec/subprocess wiring."""
    if not _is_populated(out_dir):
        _run_datagen(
            [
                "scenario",
                "--name",
                key,
                "--seed",
                str(seed),
                "--out",
                str(out_dir),
                "--events",
                str(events),
                *_org_args(),
            ]
        )


def ensure_golden_set(
    *, seed: int, events: int = GOLDEN_EVENTS_PER_SCENARIO, regenerate: bool = False
) -> dict[str, Path]:
    """Write the eight scenario dirs + `benign_pure/` under `evals/golden/` if not already
    present (or unconditionally, if `regenerate=True`). Returns `{key: directory}` for the eight
    scenario keys (`benign_pure` is available separately via `benign_pure_log()`)."""
    written: dict[str, Path] = {}
    for key in SCENARIO_KEYS:
        out_dir = scenario_dir(key)
        if regenerate or not _is_populated(out_dir):
            _run_datagen(
                [
                    "scenario",
                    "--name",
                    key,
                    "--seed",
                    str(seed),
                    "--out",
                    str(out_dir),
                    "--events",
                    str(events),
                    *_org_args(),
                ]
            )
        written[key] = out_dir

    benign_dir = GOLDEN_DIR / BENIGN_PURE_DIRNAME
    if regenerate or not _is_populated(benign_dir):
        _run_datagen(
            [
                "benign",
                "--seed",
                str(BENIGN_PURE_SEED),
                "--out",
                str(benign_dir),
                "--events",
                str(events),
                *_org_args(),
            ]
        )
    return written
