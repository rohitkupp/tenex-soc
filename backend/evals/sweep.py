"""One representative detection curve (docs/12 "Detection curves from the difficulty sweeps",
docs/11's own jitter-sweep example): `signal.beaconing` recall vs. `c2_beaconing`'s `jitter_pct`
knob, swept via `python -m datagen sweep` (the generator docs/11 specifies; that module's own
docstring is explicit its job stops at generating material for a curve — "actually measuring
detector recall against them is the eval harness's job").

Runs entirely offline, no DB: `detect_beaconing` (`app.detection.evidence.beaconing`) is a pure
function of `Sequence[EventRow]`, and `EventRow.id` is deliberately set to each line's
`raw_line_no` rather than a real `events.id` — the same substitution
`app.detection.ml.events.MLEvent.line_no` already makes for the L3 harness, safe here for the
identical reason (nothing in `detect_beaconing` or `evidence_event_ids` ever dereferences it
against a real `events` table).

Only `signal.beaconing` / `c2_beaconing` / `jitter_pct` is swept by default — `evals/config.py`'s
`SWEEP_*` constants — as the one representative curve `make eval` measures on every run; other
detector/knob combinations are reproducible on demand with
`python -m datagen sweep --scenario <key> --param <knob> --range a:b:c` but are not all swept here
for time (each point is a full scenario generation + detector run).
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path
from typing import Any

from app.core.logging import get_logger
from app.detection.evidence.beaconing import detect_beaconing
from app.detection.evidence.events_dao import EventRow
from app.parsers.base import ParseFailure
from app.parsers.registry import iter_events, make_parser
from evals.config import SWEEP_EVENTS, SWEEP_PARAM, SWEEP_RANGE, SWEEP_SCENARIO

log = get_logger(__name__)

_BACKEND_ROOT = Path(__file__).resolve().parents[1]


def _load_event_rows(log_path: Path, source_type: str = "zscaler") -> list[EventRow]:
    parser = make_parser(source_type)
    rows: list[EventRow] = []
    with log_path.open("r", encoding="utf-8") as fh:
        for result in iter_events(source_type, fh, parser=parser):
            if isinstance(result, ParseFailure):
                continue
            hot = result.hot_columns()
            rows.append(
                EventRow(
                    id=hot["raw_line_no"],
                    ts=hot["ts"],
                    src_ip=hot["src_ip"],
                    domain=hot["domain"],
                    principal=hot["principal"],
                    url_path=hot["url_path"],
                )
            )
    return rows


def run_beaconing_jitter_sweep() -> dict[str, Any]:
    import subprocess

    with tempfile.TemporaryDirectory(prefix="tenex-eval-sweep-") as tmp:
        out_dir = Path(tmp)
        cmd = [
            sys.executable,
            "-m",
            "datagen",
            "--log-level",
            "warning",
            "sweep",
            "--scenario",
            SWEEP_SCENARIO,
            "--param",
            SWEEP_PARAM,
            "--range",
            SWEEP_RANGE,
            "--events",
            str(SWEEP_EVENTS),
            "--out",
            str(out_dir),
        ]
        subprocess.run(cmd, check=True, cwd=_BACKEND_ROOT)  # noqa: S603
        manifest_path = out_dir / f"sweep_{SWEEP_SCENARIO}_{SWEEP_PARAM}.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

        points: list[dict[str, Any]] = []
        for point in manifest["points"]:
            log_files = [Path(p) for p in point["log_files"]]
            label_files = [Path(p) for p in point["label_files"]]
            if not log_files or not label_files:
                continue
            malicious: set[int] = set()
            for label_path in label_files:
                payload = json.loads(label_path.read_text(encoding="utf-8"))
                for s in payload["scenarios"]:
                    malicious.update(s["malicious_line_numbers"])
            rows = _load_event_rows(log_files[0])
            drafts = detect_beaconing(rows)
            covered: set[int] = set()
            for d in drafts:
                covered |= set(d.evidence_event_ids) & malicious
            recall = (len(covered) / len(malicious)) if malicious else None
            points.append(
                {
                    "value": point["value"],
                    "recall": recall,
                    "n_malicious": len(malicious),
                    "n_covered": len(covered),
                    "n_drafts": len(drafts),
                }
            )
            log.info(
                "sweep.point_scored",
                value=point["value"],
                recall=recall,
                n_malicious=len(malicious),
            )

    return {
        "scenario": SWEEP_SCENARIO,
        "param": SWEEP_PARAM,
        "detector_key": "signal.beaconing",
        "points": points,
    }
