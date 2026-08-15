"""Loads and validates `app/response/actions.yml` — docs/08's response action catalog.

Every action the agent can recommend (docs/07: `recommended_actions[].action` "must be an
action ID from the response action graph... Free-text actions are rejected") must resolve to
exactly one node here. This module is the source of truth for what a valid action ID is; nothing
downstream (`planner.py`, `preconditions.py`, `state.py`, `effects.py`) hardcodes the id list —
they all key off `ActionCatalog`.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, field_validator, model_validator

_CATALOG_PATH = Path(__file__).parent / "actions.yml"

BlastRadius = Literal["user", "host", "org"]


class CatalogError(Exception):
    """The catalog file itself is malformed — a config bug, not a runtime condition. Fails
    loudly at load time rather than surfacing as a confusing error on the first plan derived
    from it."""


class ActionDef(BaseModel):
    """One node of the response action graph."""

    model_config = ConfigDict(frozen=True)

    id: str
    name: str
    target_type: str
    preconditions: tuple[str, ...]
    effects: tuple[str, ...]
    blast_radius: BlastRadius
    reversible: bool
    rollback: str | None
    depends_on: tuple[str, ...]
    mitre_mitigation: str

    @field_validator("id", "target_type", "mitre_mitigation")
    @classmethod
    def _not_blank(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("must not be blank")
        return v

    @model_validator(mode="after")
    def _rollback_matches_reversibility(self) -> ActionDef:
        # Not a hard invariant in principle (a real system can be reversible with a rollback
        # not yet wired up), but every action this build ships is one or the other cleanly —
        # catch a copy-paste mistake in actions.yml (e.g. `reversible: false` with a `rollback`
        # id still attached) rather than silently rendering an inconsistent catalog entry.
        if not self.reversible and self.rollback is not None:
            raise ValueError(
                f"action {self.id!r} is not reversible but declares rollback={self.rollback!r}"
            )
        if self.reversible and self.rollback is None:
            raise ValueError(f"action {self.id!r} is reversible but declares no rollback")
        return self


class ActionCatalog(BaseModel):
    """The full set of actions, keyed by id, with graph-shape invariants checked once at load
    time (`depends_on` referencing a real id, no duplicate ids, no self-loop) — the acyclicity
    of the *whole catalog* is checked here too, even though `planner.py` also detects cycles in
    the smaller per-plan induced subgraph, because a cycle anywhere in `actions.yml` is a config
    bug (docs/08: "Cycles are a config bug — fail loudly") that should fail at import/load time,
    not wait for some future plan to happen to touch it.
    """

    model_config = ConfigDict(frozen=True)

    actions: dict[str, ActionDef]

    def __getitem__(self, action_id: str) -> ActionDef:
        return self.actions[action_id]

    def __contains__(self, action_id: object) -> bool:
        return action_id in self.actions

    def get(self, action_id: str) -> ActionDef | None:
        return self.actions.get(action_id)


def _validate_graph_shape(actions: dict[str, ActionDef]) -> None:
    for action in actions.values():
        if action.id in action.depends_on:
            raise CatalogError(f"action {action.id!r} depends on itself")
        for dep in action.depends_on:
            if dep not in actions:
                raise CatalogError(f"action {action.id!r} depends_on unknown action {dep!r}")

    # Whole-catalog cycle check via plain DFS — deliberately not networkx here (that's used in
    # planner.py for the per-plan induced subgraph); this one runs once, at load time, over a
    # handful of nodes, and a hand-rolled DFS keeps this module's only dependency on the YAML
    # parser.
    white, gray, black = 0, 1, 2
    color: dict[str, int] = dict.fromkeys(actions, white)

    def visit(node_id: str, path: list[str]) -> None:
        color[node_id] = gray
        for dep in actions[node_id].depends_on:
            if color[dep] == gray:
                cycle = [*path, node_id, dep]
                raise CatalogError(f"actions.yml has a dependency cycle: {' -> '.join(cycle)}")
            if color[dep] == white:
                visit(dep, [*path, node_id])
        color[node_id] = black

    for action_id in actions:
        if color[action_id] == white:
            visit(action_id, [])


def load_catalog(
    path: Path | None = None, *, raw: list[dict[str, Any]] | None = None
) -> ActionCatalog:
    """Parse and validate the catalog. `raw` lets tests build a catalog from an in-memory list
    of node dicts (e.g. to construct a deliberately cyclic catalog and prove it fails loudly)
    without writing a throwaway YAML file to disk."""
    if raw is None:
        target = path or _CATALOG_PATH
        try:
            text = target.read_text()
        except OSError as exc:
            raise CatalogError(f"could not read action catalog at {target}: {exc}") from exc
        try:
            loaded = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise CatalogError(f"{target} is not valid YAML: {exc}") from exc
        if not isinstance(loaded, list):
            raise CatalogError(f"{target} must be a YAML list of action nodes")
        raw = loaded

    actions: dict[str, ActionDef] = {}
    for node in raw:
        try:
            action = ActionDef.model_validate(node)
        except Exception as exc:
            raise CatalogError(f"invalid action node {node!r}: {exc}") from exc
        if action.id in actions:
            raise CatalogError(f"duplicate action id in catalog: {action.id!r}")
        actions[action.id] = action

    _validate_graph_shape(actions)
    return ActionCatalog(actions=actions)


@lru_cache
def get_catalog() -> ActionCatalog:
    """The real, on-disk `actions.yml`, loaded and validated once per process."""
    return load_catalog()
