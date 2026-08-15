"""Detection-curve artifact generator for `python -m datagen sweep` (docs/11 "Parameterization").

Scope stops at generating material for a curve, not scoring one: this module writes one full
labeled scenario file per parameter value across a range, plus a manifest joining each value to
its ground-truth artifacts. Actually measuring detector recall against them is the eval harness's
job (`app/detection`, docs/12), which lives outside `datagen` and does not exist yet at this
milestone. "A curve is far more informative than a point estimate" (docs/11) applies to what we
can control here too: the manifest is a JSON array over parameter values, never a single result.

**Every point in the sweep shares one randomness stream, intentionally.** The only thing that
should change between two points is the swept knob. If each point instead reseeded independently,
a curve that dipped at knob value 0.3 could not be attributed to the knob — it might just be an
unlucky victim or an unlucky domain draw at that one point. `run_scenario`'s `rng_key` /
`base_name` parameters exist for exactly this: passing the same `rng_key` at every point pins the
victim, the background traffic, and every other random choice identical run to run, while the
knob under test is the one thing that legitimately varies `Scenario.__init__`'s draws downstream.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.core.logging import get_logger

from .corpus import run_scenario
from .types import LabelSet

__all__ = ["SweepPoint", "parse_range", "run_sweep"]

log = get_logger(__name__)

# Sweeping is many points times a full generation each; default well below a single eval
# scenario's ~50k target (docs/11) so a dozen-point range still finishes quickly. Overridable.
DEFAULT_SWEEP_EVENTS = 20_000


def parse_range(spec: str) -> list[float]:
    """`"0.02:0.6:0.05"` -> `[0.02, 0.07, ..., 0.6]`, inclusive of the endpoint."""
    parts = spec.split(":")
    if len(parts) != 3:
        raise ValueError(f"range must be start:stop:step, got {spec!r}")
    try:
        start, stop, step = (float(p) for p in parts)
    except ValueError as exc:
        raise ValueError(f"range must be start:stop:step of numbers, got {spec!r}") from exc
    if step <= 0:
        raise ValueError("range step must be > 0")
    if stop < start:
        raise ValueError("range stop must be >= start")

    values: list[float] = []
    n = 0
    v = start
    while v <= stop + step * 1e-9:
        values.append(round(v, 10))
        n += 1
        v = start + n * step
    # The arithmetic progression from `start` only lands exactly on `stop` when `(stop - start)`
    # is an integer multiple of `step` — e.g. "0.02:0.6:0.05" never does. "inclusive of the
    # endpoint" (this docstring) means the literal `stop` value, so append it when the grid
    # stopped short rather than silently truncating the documented range.
    if not values or not math.isclose(values[-1], stop, abs_tol=max(step * 1e-6, 1e-9)):
        values.append(round(stop, 10))
    return values


def _slug(param: str, value: float) -> str:
    """Filesystem-safe token for one sweep point, e.g. `jitter_pct_0p12`."""
    text = f"{value:g}".replace(".", "p").replace("-", "m")
    return f"{param}_{text}"


@dataclass(frozen=True, slots=True)
class SweepPoint:
    value: float
    scenario_id: str
    log_files: tuple[str, ...]
    label_files: tuple[str, ...]
    malicious_line_counts: tuple[int, ...]
    notes: tuple[str, ...]


def run_sweep(
    scenario_key: str,
    param: str,
    range_spec: str,
    cli_seed: int,
    out_dir: Path,
    *,
    total_events: int = DEFAULT_SWEEP_EVENTS,
    window_days: int = 14,
    base_knobs: dict[str, Any] | None = None,
) -> Path:
    """Generate one labeled file per value of `param` in `range_spec`; return the manifest path."""
    from .scenarios import get_scenario  # local: importing the package triggers discovery

    scenario_cls = get_scenario(scenario_key)
    base_knobs = dict(base_knobs or {})
    probe = scenario_cls(**base_knobs)
    known = probe.knobs()
    if param not in known:
        raise ValueError(f"{scenario_key!r} has no knob {param!r}; known: {sorted(known)}")

    values = parse_range(range_spec)
    out_dir.mkdir(parents=True, exist_ok=True)
    rng_key = f"scenario:{scenario_key}:sweep:{param}"

    points: list[SweepPoint] = []
    for i, value in enumerate(values, start=1):
        # Preserve the knob's own type (int knobs like `n_beacons` must stay int) while letting
        # the swept axis itself be float-valued for fractional steps like `jitter_pct`.
        knobs = {**base_knobs, param: _coerce_like(known[param], value)}
        slug = _slug(param, value)
        base_name = f"scenario_{scenario_key}_{slug}"

        written = run_scenario(
            scenario_key,
            cli_seed,
            out_dir,
            index=i,
            total_events=total_events,
            window_days=window_days,
            knobs=knobs,
            base_name=base_name,
            rng_key=rng_key,
        )
        log_files = tuple(sorted(str(p) for p in written if not p.name.endswith(".labels.json")))
        label_files = tuple(sorted(str(p) for p in written if p.name.endswith(".labels.json")))

        malicious_counts: list[int] = []
        notes: list[str] = []
        for label_path in label_files:
            label_set = LabelSet.from_json(Path(label_path).read_text(encoding="utf-8"))
            for gt in label_set.scenarios:
                malicious_counts.append(len(gt.malicious_line_numbers))
                notes.append(gt.notes)

        points.append(
            SweepPoint(
                value=value,
                scenario_id=f"{scenario_key}_{i:03d}",
                log_files=log_files,
                label_files=label_files,
                malicious_line_counts=tuple(malicious_counts),
                notes=tuple(notes),
            )
        )
        log.info(
            "sweep.point",
            scenario=scenario_key,
            param=param,
            value=value,
            index=i,
            of=len(values),
            malicious_lines=sum(malicious_counts),
        )

    manifest = {
        "scenario": scenario_key,
        "param": param,
        "range": range_spec,
        "seed": cli_seed,
        "total_events_per_point": total_events,
        "base_knobs": base_knobs,
        "points": [
            {
                "value": p.value,
                "scenario_id": p.scenario_id,
                "log_files": list(p.log_files),
                "label_files": list(p.label_files),
                "malicious_line_counts": list(p.malicious_line_counts),
                "notes": list(p.notes),
            }
            for p in points
        ],
    }
    manifest_path = out_dir / f"sweep_{scenario_key}_{param}.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, default=str), encoding="utf-8")
    log.info("sweep.done", manifest=str(manifest_path), points=len(points))
    return manifest_path


def _coerce_like(reference: Any, value: float) -> Any:
    """Cast a swept float back to the knob's own type — `n_beacons` must stay an `int`."""
    if isinstance(reference, bool):
        return bool(value)
    if isinstance(reference, int):
        return round(value)
    return value
