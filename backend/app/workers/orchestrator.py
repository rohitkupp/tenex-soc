"""`python -m app.workers.orchestrator` — consumes `q.orchestrator` (docs/01's
`orchestrator` service). See `app.pipeline.stages.orchestrator` for the `ingest` stage
contract this implements."""

from __future__ import annotations

from app.pipeline.stages import orchestrator
from app.workers._entrypoint import run_worker


def main() -> None:
    run_worker("orchestrator", orchestrator.handle)


if __name__ == "__main__":
    main()
