"""`python -m app.workers.responder` — consumes `q.respond` (docs/01's `responder`
service). **Skeleton at M4** — pass-through only, the real response graph and
enforcement plane land at M12. See `app.pipeline.stages.skeleton` for exactly what
"skeleton" means here."""

from __future__ import annotations

from app.pipeline.stages.skeleton import make_skeleton_handler
from app.workers._entrypoint import run_worker


def main() -> None:
    run_worker("respond", make_skeleton_handler("respond"))


if __name__ == "__main__":
    main()
