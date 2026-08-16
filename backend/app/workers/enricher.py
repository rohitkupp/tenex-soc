"""`python -m app.workers.enricher` — consumes `q.enrich` (docs/01's `enricher` service). Real
enrichment (M5) — see `app.pipeline.stages.enrich` for what this stage actually does."""

from __future__ import annotations

from app.pipeline.stages import enrich
from app.workers._entrypoint import run_worker


def main() -> None:
    run_worker("enrich", enrich.handle)


if __name__ == "__main__":
    main()
