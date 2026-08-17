"""The 13-technique proxy-observable MITRE allowlist, loaded standalone for `app.graph.tags`.

`app/agent/mitre.py` already loads and validates `backend/data/kb/mitre/allowlist.yml` (docs/07,
MIGRATION-01 change 4) — but that module lives under `app/agent/`, and the cost constraint on
this task is absolute: *nothing under `app/agent/` may execute*, so that no code path in the
correlate stage can accidentally grow a dependency edge toward the package that makes live LLM
calls. `app.graph` and `app.pipeline` already never import `app.agent` (only
`app.pipeline.stages.triage` does, and that is the one stage this task must not touch) — this
module keeps that boundary intact rather than being the first crack in it.

So this is a second, deliberately smaller loader of the *same* file: just `{id: name}` from
`allowlist.yml`, with the same two structural checks `app.agent.mitre._load_allowlist` makes (no
duplicate ids, exactly `ALLOWLISTED_TECHNIQUE_COUNT` entries) and none of the heavier
per-technique-document corpus validation that module also does — this loader has no use for
`data/kb/mitre/techniques/*.yml` at all, since incident tagging only ever needs to answer "is this
id allowlisted", never "what does the RAG corpus say about it".

Two loaders reading one file is the honest tradeoff here, not a bug: the alternative (importing
`app.agent.mitre`) would make `app.graph` depend on `app.agent`, which is backwards (`app.agent`
already depends on `app.graph`, e.g. `app.agent.context`) and exactly the coupling this task's
cost constraint rules out.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Final

import yaml

from app.core.logging import get_logger

__all__ = [
    "ALLOWLISTED_TECHNIQUE_COUNT",
    "MitreAllowlistError",
    "is_allowlisted_technique",
    "load_allowlisted_technique_ids",
]

log = get_logger(__name__)

_ALLOWLIST_PATH: Final[Path] = (
    Path(__file__).resolve().parents[2] / "data" / "kb" / "mitre" / "allowlist.yml"
)

# Same constant, same value, as `app.agent.mitre.ALLOWLISTED_TECHNIQUE_COUNT` — MIGRATION-01
# change 4's "exactly this starting set". Not imported from that module for the reason in this
# file's docstring; kept in sync by `tests/test_graph_mitre_allowlist.py` asserting both loaders
# see the same file and agree on the id set.
ALLOWLISTED_TECHNIQUE_COUNT: Final[int] = 13


class MitreAllowlistError(Exception):
    """`allowlist.yml` is malformed or has drifted from its own documented shape -- a packaging
    bug, fails loudly at load time rather than silently tagging nothing."""


@lru_cache(maxsize=1)
def load_allowlisted_technique_ids(path: Path = _ALLOWLIST_PATH) -> frozenset[str]:
    """`{technique_id, ...}` from `allowlist.yml` -- validated to be exactly
    `ALLOWLISTED_TECHNIQUE_COUNT` entries with no duplicates, same gate
    `app.agent.mitre._load_allowlist` applies. Cached: the file does not change at runtime."""
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise MitreAllowlistError(f"could not read {path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise MitreAllowlistError(f"{path} is not valid YAML: {exc}") from exc

    if not isinstance(raw, dict) or not isinstance(raw.get("techniques"), list):
        raise MitreAllowlistError(f"{path} must contain a top-level 'techniques' list")

    ids: set[str] = set()
    for entry in raw["techniques"]:
        if not isinstance(entry, dict) or "id" not in entry:
            raise MitreAllowlistError(f"{path} has a malformed entry: {entry!r}")
        tid = str(entry["id"]).strip()
        if tid in ids:
            raise MitreAllowlistError(f"{path} lists duplicate technique id {tid!r}")
        ids.add(tid)

    if len(ids) != ALLOWLISTED_TECHNIQUE_COUNT:
        raise MitreAllowlistError(
            f"{path} must list exactly {ALLOWLISTED_TECHNIQUE_COUNT} techniques; found {len(ids)}"
        )
    return frozenset(ids)


def is_allowlisted_technique(technique_id: str) -> bool:
    return technique_id in load_allowlisted_technique_ids()
