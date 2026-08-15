"""The Sigma rule evaluator (docs/04 §L1).

`app/detection/rules/*.yml` are Sigma-format rule files; nothing in this package hardcodes a
rule's own logic — see each submodule's docstring for its slice of the pipeline:

* `grammar` — tokenizes/parses the `condition` mini-language into an AST.
* `rule` — the rule YAML schema (`SigmaRule`) and its loader.
* `fields` — Sigma field name -> SQL expression over `events`/`events.ocsf`/`events.enrichment`.
* `compiler` — compiles a rule's `detection` blocks + condition AST into SQL executed against
  Postgres, returning `Match`es.
* `runner` — loads every rule (and suppression) under `app/detection/rules/`, evaluates each
  against one analysis, and turns surviving matches into `signals` rows (docs/02).
"""

from __future__ import annotations

from app.detection.sigma.compiler import Match, UnsupportedConditionError, evaluate_rule
from app.detection.sigma.rule import RuleLoadError, SigmaRule, load_rule_file
from app.detection.sigma.runner import (
    RULES_DIR,
    SUPPRESSIONS_DIR,
    SignalDraft,
    SuppressionRule,
    load_rules,
    load_suppressions,
    run_rules,
    signal_drafts_to_rows,
    write_signals,
)

__all__ = [
    "RULES_DIR",
    "SUPPRESSIONS_DIR",
    "Match",
    "RuleLoadError",
    "SigmaRule",
    "SignalDraft",
    "SuppressionRule",
    "UnsupportedConditionError",
    "evaluate_rule",
    "load_rule_file",
    "load_rules",
    "load_suppressions",
    "run_rules",
    "signal_drafts_to_rows",
    "write_signals",
]
