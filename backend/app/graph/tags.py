"""Deterministic incident tags — a machine-computed pipeline output, not an LLM one.

## Why this exists

Before this module, `mitre_techniques` on an incident existed only as a side effect of LLM
triage (`triage_verdicts.mitre_techniques`), and `MAX_TRIAGE_INCIDENTS` triages only the top few
incidents per analysis by `fused_score` — everything else showed no techniques at all, not
because nothing fired, but because nothing *expensive* looked at it. `Signal.mitre_technique` is
already set deterministically at detect time (`app.detection.sigma.runner._draft_from_match`,
`rule.primary_mitre_technique`, derived from each rule YAML's own `tags:`) — L2/L3/L5 detectors
currently never set it (verified: no assignment site outside `app.detection.sigma`), so an
incident's *own* technique tags are exactly the L1 rule techniques among its member signals,
today. This module aggregates that already-computed field (plus `detector_layer`/`detector_key`,
already on every signal regardless of layer) into a per-incident tag list at correlate time — zero
additional LLM cost, computed once, alongside the title (`app.graph.titling`) and the deterministic
summary (`app.graph.summary`).

## A real finding, not a hypothetical: five of eleven L1 rules tag a technique outside the allowlist

`data/kb/mitre/allowlist.yml` is MIGRATION-01 change 4's 13-technique, proxy-observable subset —
"loading anything outside the allowlist is rejected" (CLAUDE.md). But the Sigma rules under
`app/detection/rules/*.yml` predate that narrowing and were never updated to match it. Their
`primary_mitre_technique` (first `attack.tXXXX` tag, `app.detection.sigma.rule.SigmaRule`) is:

| rule | primary_mitre_technique | in the 13-technique allowlist? |
|---|---|---|
| `anonymizer-proxy-avoidance-category` | `T1090.003` | no (only the parent `T1090` is listed) |
| `blocked-then-allowed` | `T1090` | yes |
| `credentials-in-url` | `T1552.001` | no |
| `direct-to-ip-request` | `T1071.001` | yes |
| `dlp-engine-triggered` | `T1048.003` | no |
| `executable-archive-download-new-domain` | `T1105` | yes |
| `high-risk-score-allowed` | `T1071` | no (only the `.001` sub-technique is listed) |
| `large-post-to-new-domain` | `T1567` | yes |
| `malicious-url-category` | `T1071` | no |
| `non-browser-user-agent` | `T1105` | yes |
| `threat-name-present` | `T1071` | no |

**This is a bug in the rule corpus, reported here rather than silently worked around**: five of
the eleven L1 rules (`anonymizer-proxy-avoidance-category`, `credentials-in-url`,
`dlp-engine-triggered`, `high-risk-score-allowed`, `malicious-url-category`,
`threat-name-present` — six, not five, once `T1071` is counted for all three of its rules) tag a
technique the migration's own allowlist does not recognize as proxy-observable. `app.graph.titling`
is unaffected (it never claimed allowlist-conformance — its own docstring: "not a technique-ID
generator... never invents an ID", used only to render a title from whatever id a signal already
carries). This module's `tags` field is different: CLAUDE.md's instruction for it is explicit —
"If a signal carries a technique outside the allowlist, that is a bug to report, not to pass
through." So `compute_incident_tags` below drops (and logs) any `mitre_technique` not in
`app.graph.mitre_allowlist`'s 13 ids, rather than tagging an incident with a technique the system's
own RAG corpus would refuse to load. The fix belongs in the rule YAML `tags:` (re-pointing
`T1090.003`→`T1090`, `T1552.001`→ nothing proxy-observable maps credential-harvesting-via-URL
cleanly, `T1048.003`→`T1041`/`T1029`, `T1071`→`T1071.001`), which is a detection-content change
outside this task's scope (CLAUDE.md: rule changes need a re-run of `make eval`, not a silent
edit here) — recorded for a follow-up, not fixed by working around it in this module.

## Tag shape

One flat, namespaced `TEXT[]`, sorted and deduplicated — a single "tags" concept (like GitHub
labels: `technique:T1090`, `layer:rule`) rather than four separate array columns, so the frontend
renders one list and the schema stays a single field. Four kinds:

* `technique:<id>` — one per distinct *allowlisted* `mitre_technique` among the incident's signals.
* `layer:<detector_layer>` — one per distinct `detector_layer` (`rule|signal|ml|graph`).
* `detector:<detector_key>` — one per distinct `detector_key` (already namespaced itself, e.g.
  `sigma.blocked_then_allowed`, `signal.beaconing` — this file just adds one more prefix segment
  so it sorts and filters as a tag alongside the other three kinds).
* Derived, unprefixed: `multi-layer` when the incident's signals span more than one
  `detector_layer` — docs/05's own fusion rationale ("corroboration across independent detection
  methods... is stronger evidence than any single high-scoring signal") made visible as a label,
  not just folded into the score.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Final

from app.core.logging import get_logger
from app.graph.incidents import SignalRef
from app.graph.mitre_allowlist import is_allowlisted_technique

__all__ = [
    "TAG_DETECTOR_PREFIX",
    "TAG_LAYER_PREFIX",
    "TAG_MULTI_LAYER",
    "TAG_TECHNIQUE_PREFIX",
    "compute_incident_tags",
]

log = get_logger(__name__)

TAG_TECHNIQUE_PREFIX: Final[str] = "technique:"
TAG_LAYER_PREFIX: Final[str] = "layer:"
TAG_DETECTOR_PREFIX: Final[str] = "detector:"
TAG_MULTI_LAYER: Final[str] = "multi-layer"


def compute_incident_tags(signals: Sequence[SignalRef]) -> list[str]:
    """Deterministic, sorted, deduplicated. `signals` is `IncidentCandidate.signals` at correlate
    time — the same list `score_incident`/`title_for_incident` already consume, so this never
    needs its own DB round trip. Never raises on an out-of-allowlist technique — see module
    docstring; that case is dropped and logged (`tags.technique_outside_allowlist`), once per
    distinct offending id per call, not once per signal."""
    tags: set[str] = set()
    dropped: set[str] = set()

    for s in signals:
        tags.add(f"{TAG_LAYER_PREFIX}{s.detector_layer}")
        tags.add(f"{TAG_DETECTOR_PREFIX}{s.detector_key}")
        if s.mitre_technique is None:
            continue
        if is_allowlisted_technique(s.mitre_technique):
            tags.add(f"{TAG_TECHNIQUE_PREFIX}{s.mitre_technique}")
        else:
            dropped.add(s.mitre_technique)

    if dropped:
        log.warning(
            "tags.technique_outside_allowlist",
            techniques=sorted(dropped),
            detail=(
                "signal carried a mitre_technique not in the 13-technique proxy-observable "
                "allowlist (data/kb/mitre/allowlist.yml) -- dropped from incident tags rather "
                "than passed through; see app.graph.tags module docstring"
            ),
        )

    if len({s.detector_layer for s in signals}) > 1:
        tags.add(TAG_MULTI_LAYER)

    return sorted(tags)
