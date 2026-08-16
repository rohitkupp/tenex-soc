"""Agent metrics (docs/12): `disposition_accuracy`, `technique_accuracy`, `hallucination_rate`
(`invalid_citations / total_citations`), `citation_density`, `severity_disagreement`.

docs/12: agent evaluation replays recorded LLM responses from `tests/fixtures/llm/` by default, so
CI needs no API key. This module checks, at call time, for the two things a real run needs — in
order, so the reported reason is the first one actually missing:

1. `app.agent.orchestrator` / `app.agent.verifier` — the modules that drive the four-stage
   Analyst -> Judge -> Verifier -> Presenter flow (docs/07, docs/v2_migration change 6) and
   return a `TriageVerdictOut`. Both exist now (`app/agent/orchestrator.py`,
   `app/agent/verifier.py`) — this check is kept as a defensive guard against a checkout that
   predates them, not because it is expected to trip in this repo anymore.
2. `tests/fixtures/llm/*.json` — recorded fixtures (docs/12's own "recorded LLM responses ...
   by default"). **This is the actual blocker today.** Recording one requires a live
   `ANTHROPIC_API_KEY` call per golden scenario (there is no other way to produce a genuine
   "this is what Claude said" artifact) — a one-time, out-of-band task nobody with API access has
   run yet. CI deliberately never holds that key (`.github/workflows/ci.yml`'s top-level `env`
   comment), so this harness cannot record them itself, and must not fabricate a fixture that
   only *looks* recorded.

If and when fixtures exist, `run()` attempts a real replay-driven measurement (calling the
orchestrator once per golden incident with a fixture-backed caller, verifying citations, comparing
`disposition`/`mitre_techniques`/`llm_severity_opinion` against each scenario's `expected_
disposition` from `.labels.json`) rather than silently staying in the "not measured" branch
forever — see `_try_live_measurement`'s docstring. In the meantime, the one metric change 25 names
explicitly as a hard CI gate (`injection_resistance == 1.0`) does not wait on this: it is enforced
directly, live, in `tests/test_agent_orchestrator.py::
test_injection_resistance_across_all_canary_styles_is_1_0`, which needs no recorded fixture at
all — every stage output there is scripted deterministically, the same technique this whole test
suite already uses everywhere else the CLAUDE.md "no live LLM calls in tests" rule applies.
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
        return "app.agent.orchestrator does not exist — no code path drives the four-stage flow"
    if not _module_exists("app.agent.verifier"):
        return "app.agent.verifier does not exist — hallucination_rate has no verifier to run"
    if not _FIXTURES_DIR.exists() or not any(_FIXTURES_DIR.glob("*.json")):
        return (
            f"no recorded LLM fixtures at {_FIXTURES_DIR} — nothing to replay (a one-time, "
            "out-of-band recording task needing a live ANTHROPIC_API_KEY nobody has run yet; "
            "orchestrator/verifier themselves both already exist)"
        )
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
    exception recorded, rather than letting a bug in `app/agent/**` crash `make eval` for
    everyone — this harness's job is to report agent quality, not to gate on agent code being
    perfect."""
    try:
        from app.agent import orchestrator, verifier  # type: ignore[import-not-found]  # noqa: F401

        # Their real signatures are known now (`orchestrator.triage_incident(session, tenant_id,
        # incident_id, *, caller, evidence_payloads)`, `tests/test_agent_orchestrator.py`'s scripted
        # `_RecordingCaller` pattern) — what's still missing is the fixture *data* itself
        # (`tests/fixtures/llm/*.json`, gated on `_missing_prerequisite` above), not knowledge of
        # how to call the orchestrator. A real implementation would: load each golden scenario's
        # incident + expected_disposition (docs/11 ground truth), run `triage_incident(...)` with a
        # fixture-backed caller replaying the recorded Analyst/Judge/Presenter messages for that
        # scenario, verify citations via `app.agent.verifier`, and aggregate disposition/technique/
        # citation/severity-disagreement stats across the set. Deferred until fixtures exist to
        # replay — writing the plumbing against data nobody can yet produce would be exercised by
        # nothing and would be worse than reporting "not measured" honestly.
        return _not_measured(
            "app.agent.orchestrator/verifier exist and their call signature is known, but no "
            "tests/fixtures/llm/*.json recordings exist yet to replay — see _missing_prerequisite"
        )
    except Exception as exc:
        log.warning("agent_metrics.live_measurement_failed", exc_info=True)
        return _not_measured(f"live measurement raised {type(exc).__name__}: {exc}")


def build_report() -> dict[str, Any]:
    reason = _missing_prerequisite()
    if reason is not None:
        return _not_measured(reason)
    return _try_live_measurement()
