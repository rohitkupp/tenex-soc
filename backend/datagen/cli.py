"""`python -m datagen` — argparse entry point (docs/11 "CLI").

    python -m datagen benign   --events 2000000 --seed 42 --out data/corpus/
    python -m datagen scenario --name c2_beaconing --seed 7 --out data/eval/
    python -m datagen sweep    --scenario c2_beaconing --param jitter_pct --range 0.02:0.6:0.05
    python -m datagen demo     --out data/demo/
    python -m datagen all

`all` is what `make gen-data` calls. It runs `benign`, every registered scenario into `data/eval/`,
and `demo` — each through its own `role_seed` namespace (`datagen.corpus.role_seed`), so a single
`--seed` on `all` cannot accidentally give the benign corpus and the eval scenarios the same
underlying org even though only one integer was typed.
"""

from __future__ import annotations

import argparse
import time
from ast import literal_eval
from pathlib import Path
from typing import Any

from app.core.logging import configure_logging, get_logger

from . import corpus
from .sweep import run_sweep
from .types import TimeWindow

log = get_logger(__name__)

_DEFAULT_BENIGN_EVENTS = 2_000_000
_DEFAULT_SCENARIO_EVENTS = 50_000
_DEFAULT_DEMO_EVENTS = 150_000


# ---------------------------------------------------------------------------- shared argument groups


def _add_seed_out(parser: argparse.ArgumentParser, *, default_out: str, default_seed: int) -> None:
    parser.add_argument(
        "--seed", type=int, default=default_seed, help="Root seed (default: %(default)s)"
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=Path(default_out),
        help="Output directory (default: %(default)s)",
    )


def _add_org_args(parser: argparse.ArgumentParser) -> None:
    group = parser.add_argument_group("org")
    group.add_argument("--n-users", type=int, default=250)
    group.add_argument("--n-departments", type=int, default=8)
    group.add_argument(
        "--offices", type=str, default="US-CA,US-NY,IE-DU", help="Comma-separated office codes"
    )
    group.add_argument("--n-service-accounts", type=int, default=12)


def _org_spec_from_args(args: argparse.Namespace) -> corpus.OrgSpec:
    return corpus.OrgSpec(
        n_users=args.n_users,
        n_departments=args.n_departments,
        offices=tuple(o.strip() for o in args.offices.split(",") if o.strip()),
        n_service_accounts=args.n_service_accounts,
    )


def _add_knob_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--knob",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="Override one scenario knob (repeatable), e.g. --knob interval_s=30",
    )


def _parse_knobs(pairs: list[str]) -> dict[str, Any]:
    knobs: dict[str, Any] = {}
    for pair in pairs:
        if "=" not in pair:
            raise ValueError(f"--knob must be KEY=VALUE, got {pair!r}")
        key, raw = pair.split("=", 1)
        key = key.strip()
        try:
            value = literal_eval(raw)
        except (ValueError, SyntaxError):
            value = raw  # a bare string knob, e.g. --knob domain_style=nrd
        knobs[key] = value
    return knobs


# ---------------------------------------------------------------------------- commands


def _cmd_benign(args: argparse.Namespace) -> int:
    org_spec = _org_spec_from_args(args)
    org = corpus.build_org(args.seed, corpus.ROLE_BENIGN, org_spec)
    window = TimeWindow.of_days(args.window_days)
    root = corpus.SeededRandom(corpus.role_seed(args.seed, corpus.ROLE_BENIGN))

    log.info(
        "benign.start",
        seed=args.seed,
        org_fingerprint=org.fingerprint(),
        proxy_events=args.events,
        out=str(args.out),
    )
    t0 = time.perf_counter()
    counts = corpus.write_benign_corpus(
        org,
        root,
        window,
        args.out,
        proxy_events=args.events,
        chunk_size=args.chunk_size,
    )
    elapsed = time.perf_counter() - t0
    log.info("benign.done", elapsed_s=round(elapsed, 2), counts=counts)
    return 0


def _cmd_scenario(args: argparse.Namespace) -> int:
    org_spec = _org_spec_from_args(args)
    knobs = _parse_knobs(args.knob)
    t0 = time.perf_counter()
    written = corpus.run_scenario(
        args.name,
        args.seed,
        args.out,
        index=args.index,
        total_events=args.events,
        window_days=args.window_days,
        knobs=knobs,
        org_spec=org_spec,
    )
    elapsed = time.perf_counter() - t0
    log.info(
        "scenario.done",
        name=args.name,
        elapsed_s=round(elapsed, 2),
        files=[str(p) for p in written],
    )
    return 0


def _cmd_sweep(args: argparse.Namespace) -> int:
    base_knobs = _parse_knobs(args.knob)
    t0 = time.perf_counter()
    manifest = run_sweep(
        args.scenario,
        args.param,
        args.range,
        args.seed,
        args.out,
        total_events=args.events,
        window_days=args.window_days,
        base_knobs=base_knobs,
    )
    elapsed = time.perf_counter() - t0
    log.info("sweep.done", elapsed_s=round(elapsed, 2), manifest=str(manifest))
    return 0


def _cmd_demo(args: argparse.Namespace) -> int:
    org_spec = _org_spec_from_args(args)
    t0 = time.perf_counter()
    written = corpus.run_demo(
        args.seed,
        args.out,
        total_events=args.events,
        window_days=args.window_days,
        org_spec=org_spec,
    )
    elapsed = time.perf_counter() - t0
    log.info("demo.done", elapsed_s=round(elapsed, 2), files=[str(p) for p in written])
    if elapsed > 120:
        log.warning("demo.slow", elapsed_s=round(elapsed, 2), budget_s=120)
    return 0


def _cmd_split(args: argparse.Namespace) -> int:
    from .labeled_corpus import (
        DEFAULT_SPLITS,
        build_baseline,
        build_labeled_corpus,
        build_split_org,
    )

    t0 = time.perf_counter()
    manifest = build_labeled_corpus(
        args.out, total_files=args.files, events_per_file=args.events_per_file
    )
    log.info(
        "split.corpus.done",
        elapsed_s=round(time.perf_counter() - t0, 2),
        total_files=len(manifest["files"]),
        scenario_counts=manifest["scenario_counts"],
    )

    if not args.skip_baseline:
        # The baseline is the live tenant's own six-month history — the train/northwind split by
        # construction (docs/11), not a fourth org.
        train = DEFAULT_SPLITS[0]
        t1 = time.perf_counter()
        stats = build_baseline(build_split_org(train), args.out / "baseline", train.seed)
        log.info("split.baseline.done", elapsed_s=round(time.perf_counter() - t1, 2), **stats)

    log.info("split.done", elapsed_s=round(time.perf_counter() - t0, 2))
    return 0


def _cmd_all(args: argparse.Namespace) -> int:
    from .scenarios import scenario_keys

    org_spec = _org_spec_from_args(args)
    t0 = time.perf_counter()

    corpus_dir = args.out / "corpus"
    eval_dir = args.out / "eval"
    demo_dir = args.out / "demo"

    log.info("all.start", seed=args.seed, out=str(args.out))

    benign_org = corpus.build_org(args.seed, corpus.ROLE_BENIGN, org_spec)
    eval_org = corpus.build_org(args.seed, corpus.ROLE_EVAL, org_spec)
    demo_org_probe = corpus.build_org(args.seed, corpus.ROLE_DEMO, org_spec)
    # `role_seed` makes this an invariant, not a hope — assert it so a future change to the
    # derivation (or a hash collision astronomically unlikely enough to be a bug elsewhere) fails
    # loudly instead of silently sharing a corpus between train and test.
    fingerprints = {benign_org.fingerprint(), eval_org.fingerprint(), demo_org_probe.fingerprint()}
    assert len(fingerprints) == 3, "benign/eval/demo orgs must be pairwise distinct"

    root = corpus.SeededRandom(corpus.role_seed(args.seed, corpus.ROLE_BENIGN))
    window = TimeWindow.of_days(args.window_days)
    counts = corpus.write_benign_corpus(
        benign_org,
        root,
        window,
        corpus_dir,
        proxy_events=args.benign_events,
    )
    log.info("all.benign.done", counts=counts)

    for key in scenario_keys():
        written = corpus.run_scenario(
            key, args.seed, eval_dir, total_events=_DEFAULT_SCENARIO_EVENTS, org=eval_org
        )
        log.info("all.scenario.done", name=key, files=[str(p) for p in written])

    demo_written = corpus.run_demo(
        args.seed, demo_dir, total_events=_DEFAULT_DEMO_EVENTS, org_spec=org_spec
    )
    log.info("all.demo.done", files=[str(p) for p in demo_written])

    elapsed = time.perf_counter() - t0
    log.info("all.done", elapsed_s=round(elapsed, 2))
    return 0


# ---------------------------------------------------------------------------- argparse wiring


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m datagen", description="Synthetic SOC log generator (docs/11)"
    )
    parser.add_argument(
        "--log-level", default="info", choices=["debug", "info", "warning", "error"]
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_benign = sub.add_parser("benign", help="Write the large unlabeled benign corpus")
    _add_seed_out(p_benign, default_out="data/corpus", default_seed=42)
    _add_org_args(p_benign)
    p_benign.add_argument(
        "--events", type=int, default=_DEFAULT_BENIGN_EVENTS, help="Target proxy event count"
    )
    p_benign.add_argument("--window-days", type=int, default=corpus.DEFAULT_WINDOW_DAYS)
    p_benign.add_argument(
        "--chunk-size", type=int, default=200_000, help="External-sort run size (peak memory)"
    )
    p_benign.set_defaults(func=_cmd_benign)

    p_scenario = sub.add_parser("scenario", help="Write one labeled eval scenario file")
    p_scenario.add_argument("--name", required=True, help="Scenario key, e.g. c2_beaconing")
    _add_seed_out(p_scenario, default_out="data/eval", default_seed=7)
    _add_org_args(p_scenario)
    _add_knob_args(p_scenario)
    p_scenario.add_argument("--index", type=int, default=1)
    p_scenario.add_argument("--events", type=int, default=_DEFAULT_SCENARIO_EVENTS)
    p_scenario.add_argument("--window-days", type=int, default=corpus.DEFAULT_WINDOW_DAYS)
    p_scenario.set_defaults(func=_cmd_scenario)

    p_sweep = sub.add_parser("sweep", help="Write a detection-curve manifest across a knob range")
    p_sweep.add_argument("--scenario", required=True, dest="scenario", help="Scenario key")
    p_sweep.add_argument("--param", required=True, help="Knob name to vary")
    p_sweep.add_argument("--range", required=True, help="start:stop:step, e.g. 0.02:0.6:0.05")
    _add_seed_out(p_sweep, default_out="data/eval/sweeps", default_seed=7)
    _add_knob_args(p_sweep)
    p_sweep.add_argument("--events", type=int, default=20_000, help="Events per sweep point")
    p_sweep.add_argument("--window-days", type=int, default=corpus.DEFAULT_WINDOW_DAYS)
    p_sweep.set_defaults(func=_cmd_sweep)

    p_demo = sub.add_parser(
        "demo", help="Write the mixed demo file (three scenarios + scenario 10)"
    )
    _add_seed_out(p_demo, default_out="data/demo", default_seed=99)
    _add_org_args(p_demo)
    p_demo.add_argument("--events", type=int, default=_DEFAULT_DEMO_EVENTS)
    p_demo.add_argument("--window-days", type=int, default=corpus.DEFAULT_WINDOW_DAYS)
    p_demo.set_defaults(func=_cmd_demo)

    p_all = sub.add_parser("all", help="benign + every eval scenario + demo, in one run")
    p_all.add_argument("--seed", type=int, default=42)
    p_all.add_argument("--out", type=Path, default=Path("data"))
    _add_org_args(p_all)
    p_all.add_argument("--benign-events", type=int, default=_DEFAULT_BENIGN_EVENTS)
    p_all.add_argument("--window-days", type=int, default=corpus.DEFAULT_WINDOW_DAYS)
    p_all.set_defaults(func=_cmd_all)

    p_split = sub.add_parser(
        "split",
        help=(
            "Write the labeled train/validation/golden corpus + manifest.json "
            "(docs/v2_migration change 13; `make gen-data`'s target)"
        ),
    )
    p_split.add_argument("--out", type=Path, default=Path("data"))
    p_split.add_argument(
        "--files",
        type=int,
        default=1000,
        help="Total files across train/val/golden, 70/20/10 split (default: %(default)s)",
    )
    p_split.add_argument(
        "--events-per-file",
        type=int,
        default=6_000,
        help="Benign background events per file, before scenario injection (default: %(default)s)",
    )
    p_split.add_argument(
        "--skip-baseline", action="store_true", help="Skip the 6-month data/baseline/ rollup"
    )
    p_split.set_defaults(func=_cmd_split)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    configure_logging(args.log_level)
    return int(args.func(args))
