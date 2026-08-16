"""`python -m app.workers.tier2_sync` — consumes `q.tier2` (docs/01's `tier2-sync` service,
terminal — "Produces" is "—"). Real signature sync (M14) — see `app.pipeline.stages.tier2`. This
is the stage that flips `analyses.status` to `complete`."""

from __future__ import annotations

from app.pipeline.stages import tier2
from app.workers._entrypoint import run_worker


def main() -> None:
    run_worker("tier2", tier2.handle)


if __name__ == "__main__":
    main()
