"""`python -m app.workers.anonymizer` — consumes `q.anonymize` (docs/01's `anonymizer`
service). **Skeleton at M4** — pass-through only, real redaction/pseudonymization
lands at M5. See `app.pipeline.stages.skeleton` for exactly what "skeleton" means here."""

from __future__ import annotations

from app.pipeline.stages.skeleton import make_skeleton_handler
from app.workers._entrypoint import run_worker


def main() -> None:
    run_worker("anonymize", make_skeleton_handler("anonymize"))


if __name__ == "__main__":
    main()
