"""`python -m app.workers.correlator` — consumes `q.correlate` (docs/01's `correlator`
service). **Skeleton at M4** — pass-through only, real graph correlation lands at M10.
See `app.pipeline.stages.skeleton` for exactly what "skeleton" means here."""

from __future__ import annotations

from app.pipeline.stages.skeleton import make_skeleton_handler
from app.workers._entrypoint import run_worker


def main() -> None:
    run_worker("correlate", make_skeleton_handler("correlate"))


if __name__ == "__main__":
    main()
