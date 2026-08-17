"""Entity graph and incident correlation (docs/05, docs/04 §L5).

Public surface, re-exported for callers that want the whole pipeline without reaching into each
submodule:

- `app.graph.builder` — `networkx.MultiGraph` construction (docs/05 "Graph construction").
- `app.graph.ingest` — load a plain log file into Postgres `events` for a fresh analysis.
- `app.graph.incidents` — seed marking, 1-hop expansion, Louvain, merge (docs/05 "Incident
  formation").
- `app.graph.features` — L5 graph anomaly features + infrastructure clustering (docs/04 §L5).
- `app.graph.titling` — deterministic incident titles (docs/05 "Incident titling").
- `app.graph.timeline` — deterministic incident timelines (docs/05 "Timeline").
- `app.graph.pipeline_demo` — the end-to-end CLI that ties all of the above together against a
  real generated scenario and a real Postgres database, for M10's verification bar.
"""

from __future__ import annotations
