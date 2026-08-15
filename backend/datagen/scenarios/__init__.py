"""Scenario registry with deterministic auto-discovery.

A scenario author adds exactly one module to this package and decorates their class. Nothing in
this file changes — an import list that ten agents edit concurrently is a merge conflict
generator, and one forgotten line is a scenario that silently never runs.

Discovery order is `sorted(module names)`, not filesystem order. Filesystem order differs
between machines and would make `SCENARIOS` iteration order machine-dependent; anything that
iterates the registry to build a corpus would then produce a different file on a different host.

    from datagen.scenarios import register_scenario
    from datagen.types import Scenario

    @register_scenario
    class BeaconingScenario(Scenario):
        key = "c2_beaconing"
        ...
"""

from __future__ import annotations

import importlib
import pkgutil
from typing import TypeVar

from ..types import Scenario

__all__ = [
    "SCENARIOS",
    "get_scenario",
    "load_scenarios",
    "register_scenario",
    "scenario_keys",
]

# Live dict: `from datagen.scenarios import SCENARIOS` stays correct after discovery because the
# object is mutated in place, never rebound.
SCENARIOS: dict[str, type[Scenario]] = {}

_T = TypeVar("_T", bound=type[Scenario])
_discovered = False


def register_scenario(cls: _T) -> _T:
    """Register a `Scenario` subclass under its `key`. Returns the class, so use as a decorator."""
    key = getattr(cls, "key", None)
    if not key or not isinstance(key, str):
        raise TypeError(f"{cls.__name__} must define a non-empty class attribute `key`")
    if not issubclass(cls, Scenario):
        raise TypeError(f"{cls.__name__} must subclass datagen.types.Scenario")

    existing = SCENARIOS.get(key)
    if existing is not None and existing is not cls:
        raise ValueError(
            f"scenario key {key!r} is already registered by {existing.__module__}."
            f"{existing.__name__}; keys must be unique across the package"
        )
    SCENARIOS[key] = cls
    return cls


def load_scenarios(*, force: bool = False) -> dict[str, type[Scenario]]:
    """Import every sibling module in sorted order, populating `SCENARIOS`. Idempotent."""
    global _discovered
    if _discovered and not force:
        return SCENARIOS

    names = sorted(
        info.name for info in pkgutil.iter_modules(__path__) if not info.name.startswith("_")
    )
    for name in names:
        importlib.import_module(f"{__name__}.{name}")

    _discovered = True
    return SCENARIOS


def get_scenario(key: str) -> type[Scenario]:
    load_scenarios()
    try:
        return SCENARIOS[key]
    except KeyError:
        raise KeyError(f"unknown scenario {key!r}; known: {scenario_keys()}") from None


def scenario_keys() -> tuple[str, ...]:
    """Registered keys, sorted. Iterate this rather than `SCENARIOS` when order matters."""
    load_scenarios()
    return tuple(sorted(SCENARIOS))


# Eager: importing the package is the documented way to get a populated registry. A scenario
# module that fails to import raises here rather than disappearing from the eval set.
load_scenarios()
