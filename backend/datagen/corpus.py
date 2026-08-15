"""Corpus construction: the simulated `Org`, benign backdrops, and labeled file writing.

Two file-size regimes live in this module and are handled by genuinely different code paths.

**The benign corpus (`write_benign_corpus`) is ~2.2M events and must not be held in memory at
once.** Emitters already stream per-principal (never buffering the whole corpus themselves), but
`datagen.types.merge_streams` sorts by materializing every record — correct and necessary for the
eval/demo files below, wrong here. Instead this module spills bounded chunks of records to sorted
run files on disk and performs a bounded-memory `heapq.merge` over them (classic external
merge-sort), so peak memory is `chunk_size` records, not the whole corpus. The benign corpus is
also unlabeled by design (docs/11's Outputs table lists no `.labels.json` for it) — it exists to
train models on *clean* traffic, so there is nothing here for `finalize_ground_truth` to fill.

**Eval scenario and demo files (`run_scenario`, `run_demo`) are tens to ~150k events** — small
enough that the canonical in-memory flow (`merge_streams` + `assign_line_numbers` +
`finalize_ground_truth`) is both correct and fast, and it is what stamps the ground-truth line
numbers the eval harness depends on, so it is used verbatim rather than reinvented.

**Seed/org independence is enforced here, not left to caller discipline** (docs/11: "benign
corpus and eval scenarios MUST use different seeds and different orgs" — "enforce in code, don't
merely document"). Every entry point below routes the caller's `--seed` through `role_seed`,
keyed by a role string (`"benign"` / `"eval"` / `"demo"`). Blake2b makes two roles collide on the
same derived integer astronomically unlikely, so a caller who passes the identical `--seed` value
to `benign` and `scenario` still gets two `Org` instances with different `fingerprint()`s — the
sharing this guards against is structurally impossible, not just discouraged.

**Multi-source scenarios split into one file pair per source.** `LabelSet.log_file` is a single
string naming one physical file (docs/11's ground-truth schema). ZScaler is the only registered
source today (Okta and CloudTrail were removed, along with the cross-source rules that read both
identity and proxy logs), so this reduces to exactly the docs/11 example
(`scenario_c2_beaconing.log` + `scenario_c2_beaconing.labels.json`) for every scenario. The
splitting machinery (`write_labeled_files` grouping by source and suffixing multi-source output
`_{source}`) is left in place rather than collapsed to a single-file writer: a source touches
vendor-specific formats that cannot share one file (tab-delimited NSS vs. a JSON-Lines identity
export, were one registered again), and this is the one place that split has to happen regardless
of how many sources are registered.
"""

from __future__ import annotations

import heapq
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import TYPE_CHECKING, Any, TextIO

from app.core.logging import get_logger

from .emitters.zscaler import ZScalerEmitter
from .org import Org
from .realism import DEFAULT_OFFICE_CODES
from .rng import SeededRandom, derive_seed
from .types import (
    BenignContext,
    EventRecord,
    GroundTruth,
    LabelSet,
    LogEmitter,
    ScenarioContext,
    SourceType,
    TimeWindow,
    assign_line_numbers,
    finalize_ground_truth,
    merge_streams,
)

if TYPE_CHECKING:
    from .types import Scenario

__all__ = [
    "DEFAULT_WINDOW_DAYS",
    "ROLE_BENIGN",
    "ROLE_DEMO",
    "ROLE_EVAL",
    "OrgSpec",
    "SourceVolumes",
    "build_org",
    "make_emitter",
    "role_seed",
    "run_demo",
    "run_scenario",
    "split_by_source",
    "split_volume",
    "write_benign_corpus",
    "write_labeled_files",
]

log = get_logger(__name__)

DEFAULT_WINDOW_DAYS = 14

# Role strings namespace the seed derivation (see module docstring). Anything that builds an
# `Org` or a root `SeededRandom` for generation must go through `role_seed`, never use a raw CLI
# seed directly, or the independence guarantee silently stops holding for that one caller.
ROLE_BENIGN = "benign"
ROLE_EVAL = "eval"
ROLE_DEMO = "demo"

_DEFAULT_CHUNK = 200_000

# ZScaler is the only registered source (Okta and CloudTrail were removed), so the full budget
# goes to it. Kept as a weight table rather than collapsed to a constant: `split_volume` below
# renormalizes over whichever sources are actually present in a given call, which is what lets a
# second source rejoin later as one more entry here rather than a rewrite of the splitting logic.
_SOURCE_WEIGHTS: dict[SourceType, float] = {
    SourceType.ZSCALER: 1.0,
}


def role_seed(cli_seed: int, role: str) -> int:
    """The actual seed used for a role, never the raw CLI value.

    Two different roles can never resolve to a caller-controlled collision: the role string is
    baked into the blake2b input, so `role_seed(42, "benign") == role_seed(42, "eval")` would
    require a hash collision, not a coincidence of CLI arguments.
    """
    return derive_seed(cli_seed, "datagen", "org", role)


# ---------------------------------------------------------------------------- org construction


@dataclass(frozen=True, slots=True)
class OrgSpec:
    """The org-shaping knobs exposed on the CLI, everything else left at `Org` defaults."""

    n_users: int = 250
    n_departments: int = 8
    offices: tuple[str, ...] = DEFAULT_OFFICE_CODES
    n_service_accounts: int = 12


def build_org(cli_seed: int, role: str, spec: OrgSpec | None = None) -> Org:
    spec = spec or OrgSpec()
    return Org(
        n_users=spec.n_users,
        n_departments=spec.n_departments,
        offices=spec.offices,
        n_service_accounts=spec.n_service_accounts,
        seed=role_seed(cli_seed, role),
    )


def make_emitter(source: SourceType) -> LogEmitter:
    """A freshly constructed, default-configured emitter for `source`."""
    if source is SourceType.ZSCALER:
        return ZScalerEmitter()
    raise ValueError(f"no emitter for {source!r}")  # pragma: no cover — exhaustive over the enum


# ---------------------------------------------------------------------------- volume splitting


@dataclass(frozen=True, slots=True)
class SourceVolumes:
    zscaler: int = 0

    def get(self, source: SourceType) -> int:
        return getattr(self, source.value)


def split_volume(total: int, sources: Sequence[SourceType]) -> SourceVolumes:
    """Divide `total` across `sources` using the corpus-wide `_SOURCE_WEIGHTS` ratio.

    Restricted to whichever sources are actually present and renormalized. With ZScaler the only
    registered source this always resolves to the full budget on it, but the renormalization is
    what would let a proxy-only scenario keep doing that without losing a share to a source it
    never emits, if a second source were registered again.
    """
    present = [s for s in sources if s in _SOURCE_WEIGHTS]
    if not present or total <= 0:
        return SourceVolumes()
    weight_sum = sum(_SOURCE_WEIGHTS[s] for s in present)
    values = {s: round(total * _SOURCE_WEIGHTS[s] / weight_sum) for s in present}
    return SourceVolumes(**{s.value: v for s, v in values.items()})


def split_by_source(records: Sequence[EventRecord]) -> dict[SourceType, list[EventRecord]]:
    grouped: dict[SourceType, list[EventRecord]] = {}
    for record in records:
        grouped.setdefault(record.source, []).append(record)
    return grouped


# ---------------------------------------------------------------------------- benign corpus (streamed)


def write_benign_corpus(
    org: Org,
    root: SeededRandom,
    window: TimeWindow,
    out_dir: Path,
    *,
    proxy_events: int,
    chunk_size: int = _DEFAULT_CHUNK,
) -> dict[str, int]:
    """Write the large unlabeled benign corpus. Bounded memory regardless of total volume.

    `root` should be a fresh `SeededRandom(role_seed(cli_seed, ROLE_BENIGN))` — the `"benign"`
    sub-stream key below matches the canonical `root.substream("benign").substream("zscaler")`
    shape documented for the driver. ZScaler is the only source in `plan` today (Okta and
    CloudTrail were removed); `plan` stays a tuple of `(source, events, filename)` triples rather
    than collapsing to a single call so a source added back is one more entry, not a rewrite.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    benign_root = root.substream("benign")
    plan: tuple[tuple[SourceType, int, str], ...] = (
        (SourceType.ZSCALER, proxy_events, "benign_zscaler.log"),
    )
    counts: dict[str, int] = {}
    for source, n_events, filename in plan:
        if n_events <= 0:
            continue
        emitter = make_emitter(source)
        rng = benign_root.substream(source.value)
        ctx = BenignContext(org=org, rng=rng, window=window, n_events=n_events)
        log.info("benign.source.start", source=source.value, target_events=n_events, file=filename)
        n_written = _write_sorted_stream(
            emitter.generate_benign(ctx), emitter, out_dir / filename, chunk_size=chunk_size
        )
        counts[filename] = n_written
        log.info("benign.source.done", source=source.value, lines=n_written, file=filename)
    return counts


def _write_sorted_stream(
    records: Iterator[EventRecord], emitter: LogEmitter, out_path: Path, *, chunk_size: int
) -> int:
    """External merge-sort: spill `chunk_size`-record sorted runs, then `heapq.merge` them."""
    with TemporaryDirectory(prefix="datagen-sort-") as tmp:
        tmp_dir = Path(tmp)
        run_paths: list[Path] = []
        chunk: list[EventRecord] = []
        for record in records:
            chunk.append(record)
            if len(chunk) >= chunk_size:
                run_paths.append(_spill_run(chunk, emitter, tmp_dir, len(run_paths)))
                chunk = []
        if chunk:
            run_paths.append(_spill_run(chunk, emitter, tmp_dir, len(run_paths)))

        with out_path.open("w", encoding="utf-8") as out:
            header = emitter.header()
            if header is not None:
                out.write(header)
                out.write("\n")
            if not run_paths:
                return 0
            return _merge_runs(run_paths, out)


def _spill_run(chunk: list[EventRecord], emitter: LogEmitter, tmp_dir: Path, index: int) -> Path:
    """Sort one chunk by the canonical `sort_key` and write it as a run file.

    Each line is `ts_iso\\tsource\\tprincipal\\tlocal_seq\\tPAYLOAD` — the first four tab-separated
    fields are the merge key (none of them can themselves contain a tab), the rest of the line
    (tabs and all — ZScaler's own serialization is tab-delimited) is the payload written verbatim.
    """
    chunk.sort(key=lambda r: r.sort_key)
    path = tmp_dir / f"run-{index:06d}.tsv"
    with path.open("w", encoding="utf-8") as fh:
        for local_seq, record in enumerate(chunk):
            payload = emitter.serialize(record)
            fh.write(
                f"{record.ts.isoformat()}\t{record.source}\t{record.principal}\t{local_seq}\t{payload}\n"
            )
    return path


def _merge_runs(run_paths: Sequence[Path], out: TextIO) -> int:
    def _iter_run(path: Path) -> Iterator[tuple[str, str, str, int, str]]:
        with path.open("r", encoding="utf-8") as fh:
            for line in fh:
                ts, source, principal, seq, payload = line.rstrip("\n").split("\t", 4)
                yield (ts, source, principal, int(seq), payload)

    count = 0
    merged = heapq.merge(
        *(_iter_run(p) for p in run_paths), key=lambda item: (item[0], item[1], item[2], item[3])
    )
    for _ts, _source, _principal, _seq, payload in merged:
        out.write(payload)
        out.write("\n")
        count += 1
    return count


# ---------------------------------------------------------------------------- eval/demo (in-memory)


def generate_scenario_background(
    org: Org,
    root: SeededRandom,
    window: TimeWindow,
    sources: Sequence[SourceType],
    total_events: int,
) -> list[EventRecord]:
    """In-memory benign backdrop for one eval/demo file — small enough to just build a list.

    `root` should already be scoped with the `"benign"` sub-stream key (see `run_scenario`),
    matching the corpus-writer's stream naming so the two code paths are recognizably the same
    model even though one streams to disk and the other stays in memory.
    """
    volumes = split_volume(total_events, sources)
    stream: list[EventRecord] = []
    for source in sources:
        n_events = volumes.get(source)
        if n_events <= 0:
            continue
        emitter = make_emitter(source)
        rng = root.substream(source.value)
        ctx = BenignContext(org=org, rng=rng, window=window, n_events=n_events)
        stream.extend(emitter.generate_benign(ctx))
    return stream


def write_labeled_files(
    *,
    stream: list[EventRecord],
    ground_truths: Sequence[GroundTruth],
    org: Org,
    seed: int,
    window: TimeWindow,
    out_dir: Path,
    base_name: str,
) -> list[Path]:
    """Split `stream` by source, sort/label each subset, and write a log + `.labels.json` pair.

    A `GroundTruth` is included in a source's `.labels.json` iff at least one record tagged with
    its `scenario_id` landed in that source's subset (checked before `finalize_ground_truth`
    narrows `malicious_line_numbers` to that file's own line numbers) — this is what lets
    `benign_but_weird`, whose events are all `malicious=False` by construction, still show up in
    both its files' ground truth instead of silently vanishing because the malicious-count filter
    would otherwise be empty everywhere.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    by_source = split_by_source(stream)
    present_sources = sorted(by_source, key=lambda s: s.value)
    written: list[Path] = []

    for source in present_sources:
        emitter = make_emitter(source)
        suffix = emitter.file_suffix.lstrip(".")
        filename = (
            f"{base_name}.{suffix}"
            if len(present_sources) == 1
            else f"{base_name}_{source.value}.{suffix}"
        )

        merged = merge_streams(by_source[source])
        header = emitter.header()
        assign_line_numbers(merged, start=2 if header is not None else 1)

        scenario_gts: list[GroundTruth] = []
        for gt in ground_truths:
            if not any(r.scenario_id == gt.scenario_id for r in merged):
                continue
            gt_copy = gt.model_copy(deep=True)
            finalize_ground_truth(gt_copy, merged)
            scenario_gts.append(gt_copy)
        if not scenario_gts:
            continue

        log_path = out_dir / filename
        with log_path.open("w", encoding="utf-8") as fh:
            if header is not None:
                fh.write(header)
                fh.write("\n")
            for record in merged:
                fh.write(emitter.serialize(record))
                fh.write("\n")

        physical_lines = len(merged) + (1 if header is not None else 0)
        labels = LabelSet(
            log_file=filename,
            seed=seed,
            org_fingerprint=org.fingerprint(),
            total_lines=physical_lines,
            window_start=window.start,
            window_end=window.end,
            scenarios=scenario_gts,
        )
        labels_path = (
            out_dir
            / f"{base_name}{'' if len(present_sources) == 1 else f'_{source.value}'}.labels.json"
        )
        labels_path.write_text(labels.to_json(), encoding="utf-8")

        written.extend((log_path, labels_path))
        log.info(
            "labels.written",
            file=filename,
            lines=physical_lines,
            scenarios=[g.scenario_id for g in scenario_gts],
            malicious=sum(len(g.malicious_line_numbers) for g in scenario_gts),
        )

    return written


def run_scenario(
    scenario_key: str,
    cli_seed: int,
    out_dir: Path,
    *,
    index: int = 1,
    total_events: int = 50_000,
    window_days: int = DEFAULT_WINDOW_DAYS,
    knobs: dict[str, Any] | None = None,
    org_spec: OrgSpec | None = None,
    org: Org | None = None,
    base_name: str | None = None,
    rng_key: str | None = None,
) -> list[Path]:
    """Generate one labeled eval scenario file (or one file per source it touches).

    `org` lets a caller (namely `run_demo`) reuse one org across several scenarios instead of
    building a new one per call — the demo file is one org's worth of activity, not several.
    `rng_key` lets `sweep` pin the injection randomness identical across every point in a knob
    sweep (see `datagen.sweep`): everything about the run is held fixed except the swept knob,
    which is what makes the resulting curve isolate that knob's effect rather than measuring
    knob-plus-resampled-noise.
    """
    from .scenarios import get_scenario  # local: importing the package triggers discovery

    scenario_cls = get_scenario(scenario_key)
    scenario: Scenario = scenario_cls(**(knobs or {}))

    resolved_org = org if org is not None else build_org(cli_seed, ROLE_EVAL, org_spec)
    window = TimeWindow.of_days(window_days)
    root = SeededRandom(role_seed(cli_seed, ROLE_EVAL))

    background = generate_scenario_background(
        resolved_org, root.substream("benign"), window, scenario.sources, total_events
    )

    scenario_id = scenario.instance_id(index)
    scenario_rng = root.substream(rng_key or f"scenario:{scenario_key}:{index}")
    ctx = ScenarioContext(
        org=resolved_org,
        rng=scenario_rng,
        window=window,
        stream=background,
        scenario_id=scenario_id,
    )
    gt = scenario.inject(ctx)
    log.info(
        "scenario.injected",
        scenario=scenario_id,
        technique=scenario.technique,
        sources=[s.value for s in scenario.sources],
        events=len(ctx.injected),
    )

    return write_labeled_files(
        stream=ctx.stream,
        ground_truths=[gt],
        org=resolved_org,
        seed=cli_seed,
        window=window,
        out_dir=out_dir,
        base_name=base_name or f"scenario_{scenario_key}",
    )


# Default demo cast: one L1/L2 signal-layer attack (beaconing), one L2 volumetric/ratio attack
# (data exfiltration), one attack only the L3 autoencoder can see (low-and-slow exfil, no single
# feature out of range), and the mandatory false-positive control — a spread across detection
# layers rather than four scenarios that would all exercise the same detector.
DEFAULT_DEMO_SCENARIOS: tuple[tuple[str, dict[str, Any]], ...] = (
    ("c2_beaconing", {}),
    ("data_exfiltration", {}),
    ("low_and_slow_exfil", {}),
    ("benign_but_weird", {}),
)


def run_demo(
    cli_seed: int,
    out_dir: Path,
    *,
    total_events: int = 150_000,
    window_days: int = DEFAULT_WINDOW_DAYS,
    scenarios: Sequence[tuple[str, dict[str, Any]]] = DEFAULT_DEMO_SCENARIOS,
    org_spec: OrgSpec | None = None,
    base_name: str = "demo_mixed",
) -> list[Path]:
    """One org, one shared benign backdrop, several scenarios injected into it in sequence."""
    from .scenarios import get_scenario

    if not scenarios:
        raise ValueError("demo needs at least one scenario")

    org = build_org(cli_seed, ROLE_DEMO, org_spec)
    window = TimeWindow.of_days(window_days)
    root = SeededRandom(role_seed(cli_seed, ROLE_DEMO))

    instances: list[Scenario] = [get_scenario(key)(**kw) for key, kw in scenarios]

    # Fixed, scenario-cast-independent split: always the full `_SOURCE_WEIGHTS` set, never the
    # union of whichever scenarios happen to be in this particular cast. `split_volume` renormalizes
    # over whatever `sources` it is given, so a scenario touching a different source joining or
    # leaving the demo mix must not change ZScaler's (or any other source's) benign event *count*
    # -- and therefore must not consume a different number of RNG draws generating it. A source
    # nobody's scenario touches simply produces benign-only output that `write_labeled_files`
    # already omits from the output (no `GroundTruth` references it), so generating it
    # unconditionally is harmless, just fixed.
    stream = generate_scenario_background(
        org, root.substream("benign"), window, tuple(_SOURCE_WEIGHTS), total_events
    )

    # Key each scenario's RNG stream and instance number by *how many times this key has appeared
    # so far*, not by its position in the overall list -- adding, removing, or reordering an
    # unrelated entry elsewhere in `scenarios` must not change another scenario's victim, timing,
    # or injected content (rng.py's "derive by string key, never by draw order" invariant).
    ground_truths: list[GroundTruth] = []
    key_counts: dict[str, int] = {}
    for (key, _kw), inst in zip(scenarios, instances, strict=True):
        key_counts[key] = key_counts.get(key, 0) + 1
        idx = key_counts[key]
        scenario_id = inst.instance_id(idx)
        scenario_rng = root.substream(f"scenario:{key}:{idx}")
        ctx = ScenarioContext(
            org=org, rng=scenario_rng, window=window, stream=stream, scenario_id=scenario_id
        )
        gt = inst.inject(ctx)
        ground_truths.append(gt)
        log.info(
            "demo.scenario.injected",
            scenario=scenario_id,
            technique=inst.technique,
            events=len(ctx.injected),
        )

    return write_labeled_files(
        stream=stream,
        ground_truths=ground_truths,
        org=org,
        seed=cli_seed,
        window=window,
        out_dir=out_dir,
        base_name=base_name,
    )
