"""`python -m app.workers.agent` — consumes `q.triage` (docs/01's `agent` service —
named `agent` in the services table, but it consumes the `triage` queue). **Skeleton
at M4** — pass-through only, the real Claude agent lands at M11. See
`app.pipeline.stages.skeleton` for exactly what "skeleton" means here."""

from __future__ import annotations

from app.pipeline.stages.skeleton import make_skeleton_handler
from app.workers._entrypoint import run_worker


def main() -> None:
    run_worker("triage", make_skeleton_handler("triage"))


if __name__ == "__main__":
    main()
