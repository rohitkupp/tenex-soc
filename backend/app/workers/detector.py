"""`python -m app.workers.detector` — consumes `q.detect` (docs/01's `detector`
service). **Skeleton at M4** — pass-through only, real detectors land M6-M9. See
`app.pipeline.stages.skeleton` for exactly what "skeleton" means here."""

from __future__ import annotations

from app.pipeline.stages.skeleton import make_skeleton_handler
from app.workers._entrypoint import run_worker


def main() -> None:
    run_worker("detect", make_skeleton_handler("detect"))


if __name__ == "__main__":
    main()
