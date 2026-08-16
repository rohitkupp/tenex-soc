"""Agentic triage layer — docs/07-AGENT.md, superseded by
docs/v2_migration/MIGRATION-01-evidence-first.md changes 5, 6, 7, 14, 15: the four-stage
evidence-first pipeline (Analyst -> Judge -> deterministic verifier -> Presenter, "Path B") plus
the single-call analysis-level Narrator ("Path A"), replacing the old three-role
Investigator -> Devil's Advocate -> Reporter flow entirely.

Public entry points: `app.agent.orchestrator.triage_incident` /
`app.agent.orchestrator.triage_top_incidents_for_analysis` (Path B, per incident) and
`app.agent.orchestrator.narrate_analysis` (Path A, once per upload). Everything else in this
package (`tools`, `mitre`, `retrieval`, `prompts`, `client`, `verifier`, `schemas`, `context`) is
an implementation detail the orchestrator composes — import from those modules directly when
writing tests against one piece in isolation, but `app.api.incidents` and any future pipeline
integration should only need `app.agent.orchestrator`. `DEMO_MODE` and the old no-key demo-verdict
fallback (`app.agent.demo`) were removed entirely by change 12 — every upload makes real calls.
"""

from __future__ import annotations
