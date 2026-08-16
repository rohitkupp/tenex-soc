"""`python -m app.workers.correlator` — consumes `q.correlate` (docs/01's `correlator` service).
Real graph correlation — entity graph, Louvain communities, incident formation, fusion,
titling, timeline, recurrence — see `app.pipeline.stages.correlate`."""

from __future__ import annotations

from app.pipeline.stages import correlate
from app.workers._entrypoint import run_worker


def main() -> None:
    run_worker("correlate", correlate.handle)


if __name__ == "__main__":
    main()
