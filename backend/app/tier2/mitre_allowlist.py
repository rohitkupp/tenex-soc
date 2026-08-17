"""A third, standalone loader of `data/kb/mitre/allowlist.yml` — same file, same
`{id, name}` shape, deliberately not imported from `app.agent.mitre` (the RAG corpus loader)
or `app.graph.mitre_allowlist` (the id-only loader `app.graph.tags` uses).

`app.graph.mitre_allowlist`'s own docstring explains why a second loader exists at all: the
cost constraint on this task is absolute (*nothing under `app/agent/` may execute*), so no
package outside `app.agent` may import it, on pain of growing a dependency edge toward the
package that makes live LLM calls. `app.tier2` is under exactly the same constraint — Tier 2
is cross-tenant analytics, not agent output — and `app.graph.mitre_allowlist` only exposes
ids, not the `{id: name}` mapping `app.tier2.technique_prevalence` needs to label a chart. The
alternative, `app.tier2` importing `app.graph`, would be a new cross-package dependency this
module has no other reason to take on. A third small loader of the same file is the same
"honest tradeoff" `app.graph.mitre_allowlist` already documents, not a new pattern.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Final

import yaml

from app.core.logging import get_logger

__all__ = ["ALLOWLISTED_TECHNIQUE_COUNT", "Tier2MitreAllowlistError", "load_allowlisted_techniques"]

log = get_logger(__name__)

_ALLOWLIST_PATH: Final[Path] = (
    Path(__file__).resolve().parents[2] / "data" / "kb" / "mitre" / "allowlist.yml"
)

# Same value as app.agent.mitre.ALLOWLISTED_TECHNIQUE_COUNT / app.graph.mitre_allowlist.
# ALLOWLISTED_TECHNIQUE_COUNT -- MIGRATION-01 change 4's "exactly this starting set". Kept in
# sync by tests/test_tier2_mitre_allowlist.py asserting all three loaders agree.
ALLOWLISTED_TECHNIQUE_COUNT: Final[int] = 13


class Tier2MitreAllowlistError(Exception):
    """`allowlist.yml` is malformed or has drifted from its documented shape."""


@lru_cache(maxsize=1)
def load_allowlisted_techniques(path: Path = _ALLOWLIST_PATH) -> dict[str, str]:
    """`{technique_id: technique_name}`, in file order, for exactly the 13 allowlisted
    techniques -- validated the same way `app.graph.mitre_allowlist.load_allowlisted_technique_ids`
    is (no duplicate ids, exactly `ALLOWLISTED_TECHNIQUE_COUNT` entries). Cached: the file does
    not change at runtime."""
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise Tier2MitreAllowlistError(f"could not read {path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise Tier2MitreAllowlistError(f"{path} is not valid YAML: {exc}") from exc

    if not isinstance(raw, dict) or not isinstance(raw.get("techniques"), list):
        raise Tier2MitreAllowlistError(f"{path} must contain a top-level 'techniques' list")

    techniques: dict[str, str] = {}
    for entry in raw["techniques"]:
        if not isinstance(entry, dict) or "id" not in entry or "name" not in entry:
            raise Tier2MitreAllowlistError(f"{path} has a malformed entry: {entry!r}")
        tid = str(entry["id"]).strip()
        if tid in techniques:
            raise Tier2MitreAllowlistError(f"{path} lists duplicate technique id {tid!r}")
        techniques[tid] = str(entry["name"]).strip()

    if len(techniques) != ALLOWLISTED_TECHNIQUE_COUNT:
        raise Tier2MitreAllowlistError(
            f"{path} must list exactly {ALLOWLISTED_TECHNIQUE_COUNT} techniques; "
            f"found {len(techniques)}"
        )
    return techniques
