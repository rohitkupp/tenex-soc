"""Plan derivation — docs/08-RESPONSE-AND-LEARNING.md "Plan derivation".

1. Map the agent's `recommended_actions` to catalog action IDs (reject anything unmapped).
2. Build the induced subgraph over those actions plus their transitive `depends_on`.
3. Topological sort -> ordered plan. Cycles are a config bug; fail loudly.
4. Annotate each step with resolved preconditions, blast radius, and rollback availability.

"Graph reasoning, not LLM ordering. The order is derivable from the dependency structure, so
derive it" — this module never calls an LLM and never asks one to order anything. The only
non-deterministic input is the *set* of requested actions (which comes from the triage agent);
everything from there is a pure function of that set and `actions.yml`, which is why the same
`recommended_actions` always produces the same ordered plan (CLAUDE.md's determinism rule).

**Per-target closure.** A dependency edge in `actions.yml` (e.g. `force_credential_reset` depends
on `revoke_okta_sessions`) is about *one user's* Okta identity — if the agent recommends
`force_credential_reset` for `alice` without separately recommending `revoke_okta_sessions` for
`alice`, the missing prerequisite step is still inserted automatically (targeting `alice`, not
some other principal). Dependency closure is therefore computed per `(action_id, target)` pair,
not per bare `action_id`.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict

from app.response.catalog import ActionCatalog, BlastRadius, get_catalog

ActionKey = tuple[str, str]  # (action_id, target)


class UnknownActionError(Exception):
    """`recommended_actions[].action` did not match any id in the response action catalog.
    docs/07: "Free-text actions are rejected" — this is that rejection, raised instead of
    silently dropping or best-effort-matching the action."""

    def __init__(self, action: str) -> None:
        self.action = action
        super().__init__(f"unknown response action: {action!r} is not in the action catalog")


class InvalidRecommendationError(Exception):
    """A `recommended_actions` entry is missing a required field (`action`, `target`) or is not
    a mapping at all — malformed agent output, not a catalog mismatch."""


class PlanCycleError(Exception):
    """The induced subgraph for this plan contains a dependency cycle. docs/08: "Cycles are a
    config bug; fail loudly" — this halts plan derivation with the offending cycle spelled out,
    rather than silently dropping an edge to force an ordering (which is exactly the "silently
    break them" docs/08 forbids)."""

    def __init__(self, cycle: list[ActionKey]) -> None:
        self.cycle = cycle
        described = " -> ".join(f"{action_id}({target})" for action_id, target in cycle)
        super().__init__(f"dependency cycle in response plan: {described}")


class PlanStep(BaseModel):
    """One ordered, fully-annotated step of a derived plan. `model_dump(mode="json")` is the
    shape persisted into `response_plans.actions` (docs/02: "ordered [{action_id, target,
    preconditions, rollback}]" — this is that shape, with the extra fields docs/08 §4 requires
    ("blast radius, and rollback availability") folded in rather than tracked separately).
    """

    model_config = ConfigDict(frozen=True)

    step: int
    action_id: str
    name: str
    target: str
    target_type: str
    preconditions: tuple[str, ...]
    blast_radius: BlastRadius
    reversible: bool
    rollback: str | None
    rollback_available: bool
    depends_on: tuple[str, ...]
    mitre_mitigation: str
    rationale: str | None = None
    implied: bool
    """True if this step was pulled in by dependency closure rather than directly recommended
    by the agent — surfaced in the UI so an analyst can see which steps the agent asked for
    versus which the action graph added to make those steps valid."""


def _normalize_recommendation(entry: Any) -> tuple[str, str, str | None]:
    if not isinstance(entry, dict):
        raise InvalidRecommendationError(
            f"recommended_actions entry must be an object, got {type(entry).__name__}: {entry!r}"
        )
    action = entry.get("action")
    target = entry.get("target")
    if not isinstance(action, str) or not action.strip():
        raise InvalidRecommendationError(f"recommended_actions entry missing 'action': {entry!r}")
    if not isinstance(target, str) or not target.strip():
        raise InvalidRecommendationError(f"recommended_actions entry missing 'target': {entry!r}")
    rationale = entry.get("rationale")
    return action, target, (rationale if isinstance(rationale, str) else None)


def derive_plan(
    recommended_actions: list[dict[str, Any]], *, catalog: ActionCatalog | None = None
) -> list[PlanStep]:
    """Turn the agent's `recommended_actions` into an ordered, annotated `PlanStep` list.

    Raises `UnknownActionError` for any action id not in the catalog, `InvalidRecommendationError`
    for malformed input, and `PlanCycleError` if the induced subgraph is cyclic (only reachable
    with an injected, deliberately-broken `catalog` — the real `actions.yml` is validated
    acyclic at load time by `app.response.catalog`, so this is defense at the layer docs/08
    names, not dead code).
    """
    catalog = catalog or get_catalog()

    requested: list[tuple[str, str, str | None]] = []
    for entry in recommended_actions:
        action_id, target, rationale = _normalize_recommendation(entry)
        if action_id not in catalog:
            raise UnknownActionError(action_id)
        requested.append((action_id, target, rationale))

    # ---- build the induced subgraph, closed over depends_on, per (action_id, target) ----
    directly_requested: set[ActionKey] = set()
    rationale_by_key: dict[ActionKey, str | None] = {}
    discovery_order: list[ActionKey] = []  # insertion order drives the deterministic tie-break

    def add_node(action_id: str, target: str, rationale: str | None) -> None:
        key = (action_id, target)
        if key not in rationale_by_key:
            rationale_by_key[key] = rationale
            discovery_order.append(key)
            for dep in catalog[action_id].depends_on:
                add_node(dep, target, None)
        elif rationale and not rationale_by_key[key]:
            rationale_by_key[key] = rationale

    for action_id, target, rationale in requested:
        directly_requested.add((action_id, target))
        add_node(action_id, target, rationale)

    edges: dict[ActionKey, set[ActionKey]] = {key: set() for key in discovery_order}
    for action_id, target in discovery_order:
        for dep in catalog[action_id].depends_on:
            edges[(dep, target)].add((action_id, target))

    ordered_keys = _topological_sort(discovery_order, edges)

    steps: list[PlanStep] = []
    for i, (action_id, target) in enumerate(ordered_keys, start=1):
        definition = catalog[action_id]
        steps.append(
            PlanStep(
                step=i,
                action_id=action_id,
                name=definition.name,
                target=target,
                target_type=definition.target_type,
                preconditions=definition.preconditions,
                blast_radius=definition.blast_radius,
                reversible=definition.reversible,
                rollback=definition.rollback,
                rollback_available=definition.rollback is not None,
                depends_on=definition.depends_on,
                mitre_mitigation=definition.mitre_mitigation,
                rationale=rationale_by_key.get((action_id, target)),
                implied=(action_id, target) not in directly_requested,
            )
        )
    return steps


def _topological_sort(
    nodes: list[ActionKey], edges: dict[ActionKey, set[ActionKey]]
) -> list[ActionKey]:
    """Kahn's algorithm, ties broken by `nodes`' order (== discovery/insertion order) so the
    result is deterministic given deterministic input — never networkx's own iteration order,
    which this build does not want to depend on for reproducibility."""
    in_degree: dict[ActionKey, int] = dict.fromkeys(nodes, 0)
    for _src, dsts in edges.items():
        for dst in dsts:
            in_degree[dst] += 1

    order_index = {node: i for i, node in enumerate(nodes)}
    ready = sorted((n for n in nodes if in_degree[n] == 0), key=lambda n: order_index[n])
    result: list[ActionKey] = []

    while ready:
        node = ready.pop(0)
        result.append(node)
        newly_ready = []
        for dst in edges[node]:
            in_degree[dst] -= 1
            if in_degree[dst] == 0:
                newly_ready.append(dst)
        ready.extend(newly_ready)
        ready.sort(key=lambda n: order_index[n])

    if len(result) != len(nodes):
        remaining = [n for n in nodes if n not in result]
        cycle = _find_cycle(remaining, edges)
        raise PlanCycleError(cycle)

    return result


def _find_cycle(
    remaining: list[ActionKey], edges: dict[ActionKey, set[ActionKey]]
) -> list[ActionKey]:
    """DFS over the nodes Kahn's algorithm never reached (every node still in a cycle, or
    depending on one) to produce a concrete cycle for the error message."""
    remaining_set = set(remaining)
    visiting: list[ActionKey] = []
    on_stack: set[ActionKey] = set()

    def dfs(node: ActionKey) -> list[ActionKey] | None:
        visiting.append(node)
        on_stack.add(node)
        for dst in edges[node]:
            if dst not in remaining_set:
                continue
            if dst in on_stack:
                start = visiting.index(dst)
                return [*visiting[start:], dst]
            found = dfs(dst)
            if found is not None:
                return found
        visiting.pop()
        on_stack.discard(node)
        return None

    for start_node in remaining:
        found = dfs(start_node)
        if found is not None:
            return found
    # Every node in `remaining` has unsatisfied in-degree by construction, so a cycle must
    # exist; this is unreachable but keeps the function total instead of returning None.
    raise AssertionError("Kahn's algorithm reported a cycle but none was found")
