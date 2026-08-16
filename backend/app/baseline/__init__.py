"""The historical baseline store — docs/v2_migration/MIGRATION-01-evidence-first.md, change 1.

"The single biggest change": percentiles, rarity, and deviations resolve against a persistent
6-month per-tenant history instead of the uploaded file. Three tables back this
(`app.models.baseline_window.BaselineWindow`, `app.models.baseline_profile.BaselineProfile`,
`app.models.baseline_contact.BaselineContact`), added in the alembic revision that follows
`bcc348df665e` (change 20's response-graph removal).

| Module | Job |
|---|---|
| `app.baseline.loader` | Idempotent ETL: `data/baseline/*` (`datagen.labeled_corpus.build_baseline`'s output) -> the three tables. CLI entry point for `make seed`. |
| `app.baseline.org_directory` | The one place `user -> department` is resolved, for both the loader's contact rollup and `resolve.contact_counts`. See its docstring for why this is scoped to the single seeded live tenant, not a general identity directory. |
| `app.baseline.resolve` | Read-side query helpers every later evidence extractor calls: `percentile_for` and `contact_counts`. Cold start (`n_windows < 20`) is a first-class field of the return type, not a caller's problem. |
"""

from __future__ import annotations
