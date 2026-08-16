"""`python -m app.workers.agent` — consumes `q.triage` (docs/01's `agent` service — named `agent`
in the services table, but it consumes the `triage` queue). Real Claude agent — Path B
(`triage_top_incidents_for_analysis`) and Path A (`narrate_analysis`) — see
`app.pipeline.stages.triage`. Always uses a real `LiveCaller`; `ANTHROPIC_API_KEY` must be
configured for this worker to make progress."""

from __future__ import annotations

from app.pipeline.stages import triage
from app.workers._entrypoint import run_worker


def main() -> None:
    run_worker("triage", triage.handle)


if __name__ == "__main__":
    main()
