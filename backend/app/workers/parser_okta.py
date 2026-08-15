"""`python -m app.workers.parser_okta` — consumes `q.parse.okta` (docs/01's
`parser-okta` service). See `app.workers.parser_zscaler` for why this is a thin
wrapper around the shared `app.pipeline.stages.parse` handler."""

from __future__ import annotations

from app.pipeline.stages import parse
from app.workers._entrypoint import run_worker


def main() -> None:
    run_worker("parse.okta", parse.handle)


if __name__ == "__main__":
    main()
