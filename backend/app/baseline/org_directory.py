"""`user -> department` resolution for the single seeded live tenant.

docs/v2_migration change 23 collapses the system to one live tenant (`northwind`,
`app.models.tenant.LIVE_TENANT_NAME`), seeded from `datagen.generate_corpus`'s train-split org.
That org is the *only* source this system has for "which department is this user in" — docs/02
defines no identity/HR directory table, and change 1's schema (`app.baseline`) adds exactly the
three tables the migration lists, none of them a directory.

`datagen.generate_corpus.Org.build` is a pure function of `(name, n_users, n_service, seed)` —
`random.Random(seed)` makes it fully reproducible. Reconstructing the same org here, with the
exact parameters `datagen.generate_corpus.main()` uses for the baseline's org, reproduces the
same `user -> department` assignment as whatever produced `data/baseline/`, with no extra file
to ship and no drift risk between "what `app.baseline.loader` rolled contacts up by" and "what a
live `app.baseline.resolve.contact_counts` call resolves department as" — both call
`department_for_user` below.

**This is deliberately scoped to the one demo org, not a general identity directory.** A real
multi-tenant deployment would replace this module with a lookup against a real HR/identity feed,
keyed by tenant — out of scope for change 1, and not needed while docs/v2_migration change 23
keeps the whole system on one seeded tenant.

Importing `datagen.generate_corpus.Org` here (rather than `datagen`'s own top-level `Org`,
`datagen/org.py` — the *other* generator, predating the migration's delivered single-file
replacement) is deliberate: `datagen/__init__.py` re-exports its own, differently-shaped `Org`
(`Org(seed=42)`, no `.department` per user in the same way), so the import below is
module-qualified on purpose to avoid picking up the wrong one.
"""

from __future__ import annotations

import random
from functools import lru_cache

from datagen.generate_corpus import Org

# Exactly datagen/generate_corpus.py::main()'s northwind (train-split) org -- the org
# build_baseline() is always called with, regardless of --files. Changing --files changes how
# many corpus *files* that org narrates, not the org itself.
_BASELINE_ORG_NAME = "northwind"
_BASELINE_ORG_USERS = 250
_BASELINE_ORG_SERVICE_ACCOUNTS = 12
_BASELINE_ORG_SEED = 42

__all__ = ["department_for_user"]


@lru_cache(maxsize=1)
def _department_directory() -> dict[str, str]:
    # Reproducing the generator's own deterministic org, not a security-sensitive random value.
    rng = random.Random(_BASELINE_ORG_SEED)  # noqa: S311
    org = Org.build(_BASELINE_ORG_NAME, _BASELINE_ORG_USERS, _BASELINE_ORG_SERVICE_ACCOUNTS, rng)
    return {user.email: user.department for user in org.users}


def department_for_user(user_email: str) -> str | None:
    """`None` when `user_email` isn't in the seeded org — callers must treat that as
    "department unknown", not fall back to guessing (e.g. `app.baseline.resolve.contact_counts`
    returns a `department` scope with `scope_value=None` in that case, distinct from a resolved
    department with zero contacts)."""
    return _department_directory().get(user_email)
