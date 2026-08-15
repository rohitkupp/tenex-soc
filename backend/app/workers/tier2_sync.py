"""`python -m app.workers.tier2_sync` — consumes `q.tier2` (docs/01's `tier2-sync`
service, terminal — "Produces" is "—"). **Skeleton at M4** — pass-through only, real
signature sync lands at M14. Its one real M4 job: this is the stage that flips
`analyses.status` to `complete` (`app.pipeline.stages.skeleton`'s `next_queue is None`
branch)."""

from __future__ import annotations

from app.pipeline.stages.skeleton import make_skeleton_handler
from app.workers._entrypoint import run_worker


def main() -> None:
    run_worker("tier2", make_skeleton_handler("tier2"))


if __name__ == "__main__":
    main()
