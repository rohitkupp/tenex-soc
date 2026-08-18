"""The frontend's funnel stage list must match `STAGE_SEQUENCE`, in order.

`frontend/components/pipeline/FunnelProgress.tsx` hand-maintains a copy of the pipeline's stage
order. That is the exact failure this codebase keeps repeating — a second list, in another
language, that nobody remembers to update — and it had already rotted twice over: `anonymize` was
still sitting between `enrich` and `detect` after it moved to the tenant boundary, and `tier2` was
missing outright, so `currentIndex` was -1 for the entire final stage and the funnel never lit it.

Neither showed up as a test failure or a type error, because nothing connected the two lists. This
does: it reads the `.tsx` and compares. A reader might reasonably object that a Python test
parsing a TypeScript file is unusual, and it is — but the alternative is trusting that two
independent lists stay in sync, which is precisely what did not happen. `test_contract_openapi_
schema.py` guards the other frontend/backend contract for the same reason.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from app.pipeline.contracts import STAGE_SEQUENCE

_FUNNEL = Path(__file__).resolve().parents[2] / "frontend/components/pipeline/FunnelProgress.tsx"
_STAGE_KEY_RE = re.compile(r'\{\s*key:\s*"([a-z0-9_]+)"\s*,\s*label:')


def _frontend_stage_keys() -> list[str]:
    source = _FUNNEL.read_text(encoding="utf-8")
    start = source.index("const STAGES = [")
    end = source.index("] as const;", start)
    return _STAGE_KEY_RE.findall(source[start:end])


@pytest.mark.skipif(not _FUNNEL.exists(), reason="frontend not checked out beside backend")
def test_funnel_stage_order_matches_the_pipeline_contract() -> None:
    assert _frontend_stage_keys() == list(STAGE_SEQUENCE), (
        "FunnelProgress.tsx's STAGES and app.pipeline.contracts.STAGE_SEQUENCE have drifted. "
        "The funnel renders stages in its own order and matches the live `analyses.stage` "
        "against it, so a mismatch shows the wrong pipeline and silently fails to highlight any "
        "stage whose key it does not know."
    )
