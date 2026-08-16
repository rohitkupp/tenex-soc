"""`python -m app.workers.anonymizer` — consumes `q.anonymize` (docs/01's `anonymizer` service).
Real privacy audit pass — see `app.pipeline.stages.anonymize` for what this stage actually does
and why it does not rewrite `events` rows in place."""

from __future__ import annotations

from app.pipeline.stages import anonymize
from app.workers._entrypoint import run_worker


def main() -> None:
    run_worker("anonymize", anonymize.handle)


if __name__ == "__main__":
    main()
