"""`python -m app.workers.enricher` — consumes `q.enrich` (docs/01's `enricher`
service). **Skeleton at M4** — pass-through only, real enrichment lands at M5. See
`app.pipeline.stages.skeleton` for exactly what "skeleton" means here."""

from __future__ import annotations

from app.pipeline.stages.skeleton import make_skeleton_handler
from app.workers._entrypoint import run_worker


def main() -> None:
    run_worker("enrich", make_skeleton_handler("enrich"))


if __name__ == "__main__":
    main()
