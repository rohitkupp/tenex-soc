"""`user -> department` resolution for the single seeded live tenant.

docs/v2_migration change 23 collapses the system to one live tenant (`northwind`,
`app.models.tenant.LIVE_TENANT_NAME`), seeded from `datagen`'s train-split org
(`datagen.labeled_corpus.DEFAULT_SPLITS[0]`). That org is the *only* source this system has for
"which department is this user in" — docs/02 defines no identity/HR directory table, and change
1's schema (`app.baseline`) adds exactly the three tables the migration lists, none of them a
directory.

`datagen.labeled_corpus.build_split_org` is a pure function of a `SplitSpec` — `SeededRandom`
(blake2b-derived, not stdlib `random`) makes it fully reproducible. Reconstructing the same org
here, with the exact `SplitSpec` `python -m datagen split` uses for the baseline's org
(`build_labeled_corpus`'s `--skip-baseline`-guarded step, same module), reproduces the same
`user -> department` assignment as whatever produced `data/baseline/`, with no extra file to
ship and no drift risk between "what `app.baseline.loader` rolled contacts up by" and "what a
live `app.baseline.resolve.contact_counts` call resolves department as" — both call
`department_for_user` below.

**This is deliberately scoped to the one demo org, not a general identity directory.** A real
multi-tenant deployment would replace this module with a lookup against a real HR/identity feed,
keyed by tenant — out of scope for change 1, and not needed while docs/v2_migration change 23
keeps the whole system on one seeded tenant.

**History:** this used to reconstruct the org via `datagen.generate_corpus.Org.build`, the
generator delivered for migration change 13. That generator wrote a `datetime` format the shipped
parser could not read and was deleted rather than patched (see
`datagen/labeled_corpus.py`'s module docstring) — `data/baseline/` is now produced by
`build_baseline` in that same module, on the real `datagen.org.Org`, so this directory was
repointed to match rather than left resolving departments against an org nothing else builds
anymore.
"""

from __future__ import annotations

from functools import lru_cache

from datagen.labeled_corpus import DEFAULT_SPLITS, build_split_org

__all__ = ["department_for_user"]


@lru_cache(maxsize=1)
def _department_directory() -> dict[str, str]:
    # DEFAULT_SPLITS[0] is the train/northwind split -- the org build_baseline() is always
    # called with, regardless of --files. Changing --files changes how many corpus *files* that
    # org narrates, not the org itself. `.principals`, not `.users`: service accounts get a
    # baseline_contacts row too (app.baseline.loader's user-scope rollup does not distinguish),
    # so they need a department to roll up into just as much as human users do.
    org = build_split_org(DEFAULT_SPLITS[0])
    return {user.email: user.department for user in org.principals}


def department_for_user(user_email: str) -> str | None:
    """`None` when `user_email` isn't in the seeded org — callers must treat that as
    "department unknown", not fall back to guessing (e.g. `app.baseline.resolve.contact_counts`
    returns a `department` scope with `scope_value=None` in that case, distinct from a resolved
    department with zero contacts)."""
    return _department_directory().get(user_email)
