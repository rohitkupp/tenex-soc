"""`python -m app.workers.parser_zscaler` — consumes `q.parse.zscaler` (docs/01's
`parser-zscaler` service). Real parsing logic lives in `app.pipeline.stages.parse`,
shared verbatim by every parser worker — a worker differs from its siblings only in
which queue it binds to, since `source_type` travels on the `StageMessage` itself. The
only parser worker today (Okta's and CloudTrail's sibling modules were removed along
with those sources); a second source back is one more `app/workers/parser_<source>.py`
this thin, not a rewrite of this one."""

from __future__ import annotations

from app.pipeline.stages import parse
from app.workers._entrypoint import run_worker


def main() -> None:
    run_worker("parse.zscaler", parse.handle)


if __name__ == "__main__":
    main()
