"""Response action graph and simulated enforcement plane — docs/08-RESPONSE-AND-LEARNING.md,
Part 1.

  catalog.py       `actions.yml` loader/validator — the response action graph's nodes.
  planner.py       Maps an agent's recommended_actions to catalog ids, derives the ordered plan
                    (topological sort over the induced dependency subgraph — graph reasoning,
                    never LLM ordering).
  state.py          `enforcement_state` read/write/seed primitives, and the action -> resource
                    binding every other module in this package goes through.
  preconditions.py  Real checks against `enforcement_state`, shared by the executor (the real
                    gate) and the API's plan preview (so the preview never drifts from the gate).
  effects.py        Pure `(action, target, before) -> after` state transformations.
  executor.py       Runs an approved plan for real: read -> check -> apply -> journal -> halt on
                    the first failing precondition. Also owns rollback (reverse-replay the
                    journal).
  verification.py   The optional, narrow Claude safety pass over an already-ordered plan.
  outcome.py        Post-execution containment verification and the autonomous containment rate.

What's simulated: the resources in `enforcement_state` (there is no real Okta tenant or proxy
behind them). What's real: the graph reasoning, precondition checking, ordering, execution
semantics, and rollback that operate on those resources — none of it is mocked or faked for the
sake of a demo.
"""

from __future__ import annotations
