"""`python -m app.workers.detector` — consumes `q.detect` (docs/01's `detector` service). Real
detection — Sigma (L1), the six evidence extractors (L2), the ML model bundle (L3), calibrated —
see `app.pipeline.stages.detect`."""

from __future__ import annotations

from app.pipeline.stages import detect
from app.workers._entrypoint import run_worker


def main() -> None:
    run_worker("detect", detect.handle)


if __name__ == "__main__":
    main()
