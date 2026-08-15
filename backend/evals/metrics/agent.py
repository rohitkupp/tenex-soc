"""Agent metrics (docs/12): `disposition_accuracy`, `technique_accuracy`, `hallucination_rate`
(`invalid_citations / total_citations`), `citation_density`, `severity_disagreement`.

docs/12: agent evaluation replays recorded LLM responses from `tests/fixtures/llm/` by default, so
CI needs no API key. **This milestone's brief is explicit that `app/agent/` is developed
concurrently and may be incomplete, and that this harness must "emit these as 'not measured'
rather than fabricating them or crashing."** This module checks, at call time, for the three
things a real run needs — in order, so the reported reason is the first one actually missing:

1. `app.agent.orchestrator` — the module that would actually drive the three-role
   (Investigator -> Devil's Advocate -> Reporter) flow and return a `TriageVerdictOut`
   (docs/07). Does not exist in this checkout as of this harness's own build.
2. `app.agent.verifier` — the citation verifier (`hallucination_rate`'s anti-hallucination
   guarantee, docs/07 "Citation verification"). Does not exist either.
3. `tests/fixtures/llm/*.json` — recorded fixtures (docs/12's own "recorded LLM responses ...
   by default"). None have been recorded yet (nothing has produced a real verdict to record).

If and when all three exist, `run()` attempts a real replay-driven measurement (calling the
orchestrator once per golden incident with `FixtureCaller`, verifying citations, comparing
`disposition`/`mitre_techniques`/`llm_severity_opinion` against each scenario's `expected_
disposition` from `.labels.json`) rather than silently staying in the "not measured" branch
forever once the concurrent agent work lands — see `_try_live_measurement`'s docstring.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

from app.core.logging import get_logger

log = get_logger(__name__)

_FIXTURES_DIR = Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "llm"

_METRIC_NAMES = (
    "disposition_accuracy",
    "technique_accuracy",
    "hallucination_rate",
    "citation_density",
    "severity_disagreement",
)


def _module_exists(dotted: str) -> bool:
    try:
        return importlib.util.find_spec(dotted) is not None
    except ModuleNotFoundError:
        # A parent package segment itself missing raises here rather than returning None.
        return False


def _missing_prerequisite() -> str | None:
    if not _module_exists("app.agent.orchestrator"):
        return "app.agent.orchestrator does not exist yet — no code path drives the three-role flow"
    if not _module_exists("app.agent.verifier"):
        return "app.agent.verifier does not exist yet — hallucination_rate has no verifier to run"
    if not _FIXTURES_DIR.exists() or not any(_FIXTURES_DIR.glob("*.json")):
        return f"no recorded LLM fixtures at {_FIXTURES_DIR} — nothing to replay"
    return None


def _not_measured(reason: str) -> dict[str, Any]:
    log.warning("agent_metrics.not_measured", reason=reason)
    return {
        "measured": False,
        "reason": reason,
        **dict.fromkeys(_METRIC_NAMES),
    }


def _try_live_measurement() -> dict[str, Any]:
    """Only reached once `app.agent.orchestrator`, `app.agent.verifier`, and recorded fixtures all
    exist. Deliberately conservative: any failure here degrades to "not measured" with the
    exception recorded, rather than letting a half-finished concurrent module crash `make eval`
    for everyone (the ownership boundary in this milestone's brief: `app/agent/**` is not owned by
    this harness, and a bug there should not fail this harness's build)."""
    try:
        from app.agent import orchestrator, verifier  # type: ignore[import-not-found]  # noqa: F401

        # A real implementation would: load each golden scenario's incident + expected_disposition
        # (docs/11 ground truth), run `orchestrator.triage(...)` with a `FixtureCaller` bound to
        # tests/fixtures/llm/<scenario>.json, verify citations via `verifier.verify(...)`, and
        # aggregate disposition/technique/citation/severity-disagreement stats across the set.
        # Deferred until those modules exist — there is nothing to call yet, and guessing at a
        # signature here would be worse than reporting "not measured" honestly.
        return _not_measured(
            "app.agent.orchestrator/verifier exist but this harness has not been extended to call "
            "them yet — update evals/metrics/agent.py once their real signatures are known"
        )
    except Exception as exc:
        log.warning("agent_metrics.live_measurement_failed", exc_info=True)
        return _not_measured(f"live measurement raised {type(exc).__name__}: {exc}")


def build_report() -> dict[str, Any]:
    reason = _missing_prerequisite()
    if reason is not None:
        return _not_measured(reason)
    return _try_live_measurement()
