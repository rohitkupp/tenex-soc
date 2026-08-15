"""`python -m app.workers.parser_zscaler` — consumes `q.parse.zscaler` (docs/01's
`parser-zscaler` service). Real parsing logic lives in `app.pipeline.stages.parse`,
shared verbatim by all three parser workers — they differ only in which queue they
bind to, since `source_type` travels on the `StageMessage` itself."""

from __future__ import annotations

from app.pipeline.stages import parse
from app.workers._entrypoint import run_worker


def main() -> None:
    run_worker("parse.zscaler", parse.handle)


if __name__ == "__main__":
    main()
