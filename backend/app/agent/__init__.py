"""Agentic triage layer — docs/07-AGENT.md.

Public entry point: `app.agent.orchestrator.triage_incident` /
`app.agent.orchestrator.triage_top_incidents_for_analysis`. Everything else in this package
(`tools`, `mitre`, `prompts`, `client`, `verifier`, `schemas`, `demo`, `context`) is an
implementation detail the orchestrator composes — import from those modules directly when
writing tests against one piece in isolation, but `app.api.incidents` and any future pipeline
integration should only need `app.agent.orchestrator`.
"""

from __future__ import annotations
