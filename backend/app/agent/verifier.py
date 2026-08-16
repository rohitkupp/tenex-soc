"""The deterministic verifier -- docs/v2_migration/MIGRATION-01-evidence-first.md change 7 ("Dual
citations + numeric verification") and change 15 ("Verifier runs before the judge, and again
after"). This is stage 3 of the four-stage pipeline (change 6):

    Analyst -> Judge -> Deterministic verifier -> Presenter

**This is what actually prevents hallucination.** Change 6 says so explicitly: the Judge (an LLM
call) is "a second opinion... LLM judges have known self-preference and correlated-error
problems." Every check in this module is code, not a model call, and every check is run twice per
change 15's ordering refinement:

    Analyst output
       -> verifier pass 1  (existence + numeric match + retrieval match)   <- cheap, no LLM
           claims failing here are dropped before the judge sees them
       -> Judge LLM        (rubric, PASS | REVISE | REJECT)
       -> verifier pass 2  (full, including scope + confidence integrity)  <- catches new numbers
                                                                               introduced by REVISE
       -> Presenter LLM

Pass 1 operates on `HypothesisEvaluation.evidence_for`/`evidence_against` claims (change 5's own
claim/citation contract) and *drops* failing claims -- `app.agent.orchestrator` builds the Judge's
prompt from the sanitized output this pass returns, so a claim that fails here is never spent
Judge tokens on. Pass 2 operates on `Finding`s (the Judge's own unit of grading, including any
`revised_finding`) and *surfaces* failures rather than dropping them (`invalid_citations`,
`citation_valid`) -- the same "never silently drop a bad citation" philosophy the pre-migration
citation verifier used, now applied to the finding that actually reaches the Presenter.

## The five checks (change 7, verbatim numbering)

1. **Existence** -- every cited `EVIDENCE-n`/`BASELINE-n` exists in this incident's evidence
   package; every cited `LOG-n` exists in this analysis; every cited `MITRE-Txxx.xxx` exists in
   the allowlisted corpus.
2. **Numeric match** -- every number in a claim's text appears, or is a straightforward unit
   conversion of a number that appears, in the object(s) the claim cited. Exact for bare counts,
   +/-1% for byte/duration values that were rounded for display. See `extract_numbers`/
   `_numeric_match` below -- this is the hardest and most valuable check (change 7's own words),
   implemented properly rather than as a token-overlap heuristic.
3. **Retrieval match** -- every cited technique was actually retrieved for this incident (the
   automatic evidence-driven step, or a `search_mitre` tool call this run) -- see
   `AgentContext.retrieved_technique_ids`. `NO_KNOWN_MAPPING` is exempt: it is never "retrieved",
   it is the built-in escape hatch.
4. **Scope** -- a cited `LOG-n` line's entities intersect the incident's entity scope and its
   timestamp falls within the incident's window +/-1h. Pass 2 only (change 15).
5. **Confidence integrity** -- `verify_anomaly_confidence`, unchanged from the pre-migration
   design (arrived early as change 3's own hard-rejection check, reused here as change 7's fifth
   check). A hard rejection of the whole verdict, not a per-claim flag -- see that function's own
   docstring for why.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Final

from pydantic import ValidationError
from sqlalchemy import select

from app.agent.context import CITATION_TEMPORAL_SLACK, AgentContext
from app.agent.mitre import technique_exists
from app.agent.schemas import (
    NO_KNOWN_MAPPING,
    AnalystOutput,
    Claim,
    DomainSemanticOutput,
    Finding,
    HypothesisEvaluation,
    NarratorOutput,
    SchemaValidationError,
    TriageVerdictOut,
)
from app.models.base import tenant_scope
from app.models.event import Event

__all__ = [
    "ANOMALY_CONFIDENCE_TOLERANCE",
    "AnomalyConfidenceCheck",
    "AnomalyConfidenceIntegrityError",
    "Citation",
    "ClaimCheck",
    "ExtractedNumber",
    "FindingCheck",
    "HallucinationStats",
    "Pass1Result",
    "Pass2Result",
    "check_finding",
    "claims_for_finding",
    "classify_citation",
    "extract_numbers",
    "hallucination_stats",
    "numeric_leaves",
    "parse_verdict_payload",
    "verify_anomaly_confidence",
    "verify_citations",
    "verify_domain_semantic_output",
    "verify_narrator_output",
    "verify_pass1",
    "verify_pass2",
]

# ---------------------------------------------------------------------------- citation namespaces

# docs/v2_migration change 7's two citation namespaces, six concrete forms.
_EVIDENCE_OR_BASELINE_RE: Final[re.Pattern[str]] = re.compile(r"^(EVIDENCE|BASELINE)-(\d+)$")
_LOG_RE: Final[re.Pattern[str]] = re.compile(r"^LOG-(\d+)$")
_MITRE_RE: Final[re.Pattern[str]] = re.compile(r"^MITRE-(T\d{4}(?:\.\d{3})?)$")
_ZSCALER_KB_RE: Final[re.Pattern[str]] = re.compile(r"^ZSCALER-KB-(.+)$")

CITATION_EVIDENCE: Final[str] = "evidence"  # EVIDENCE-n / BASELINE-n
CITATION_LOG: Final[str] = "log"  # LOG-n
CITATION_MITRE: Final[str] = "mitre"  # MITRE-Txxx.xxx
CITATION_ZSCALER_KB: Final[str] = "zscaler_kb"  # ZSCALER-KB-*
CITATION_UNKNOWN: Final[str] = "unknown"


def classify_citation(cid: str) -> tuple[str, str]:
    """`(namespace, key)` for one citation string. `key` is the bare id inside the namespace --
    `EVIDENCE-14` -> `("evidence", "EVIDENCE-14")` (evidence/baseline share a namespace because
    both resolve against `AgentContext` id maps the same way), `LOG-1291` -> `("log", "1291")`,
    `MITRE-T1567.002` -> `("mitre", "T1567.002")`, `ZSCALER-KB-threat-cat` ->
    `("zscaler_kb", "threat-cat")`. Anything else is `("unknown", cid)` -- never crashes on a
    malformed citation, just fails its existence check downstream."""
    if _EVIDENCE_OR_BASELINE_RE.match(cid):
        return CITATION_EVIDENCE, cid
    m = _LOG_RE.match(cid)
    if m:
        return CITATION_LOG, m.group(1)
    m = _MITRE_RE.match(cid)
    if m:
        return CITATION_MITRE, m.group(1)
    m = _ZSCALER_KB_RE.match(cid)
    if m:
        return CITATION_ZSCALER_KB, m.group(1)
    return CITATION_UNKNOWN, cid


# ---------------------------------------------------------------------------- numeric extraction

# Stripped out *before* number extraction so a technique id or a citation token embedded in prose
# ("...consistent with T1567.002, see [EVIDENCE-14]...") never gets misread as measurement
# numbers ("1567", "002", "14"). ISO-ish timestamps and bare clock times are stripped too --
# narratives constantly reference "2026-02-23T16:19Z" or "16:19-18:16", neither of which is a
# measurement a citation's numeric pool could ever be expected to contain.
_NOISE_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    re.compile(r"\bT\d{4}(?:\.\d{3})?\b"),  # MITRE technique ids
    re.compile(r"\b(?:EVIDENCE|BASELINE|LOG)-\d+\b"),
    re.compile(r"\bMITRE-T\d{4}(?:\.\d{3})?\b"),
    re.compile(r"\bZSCALER-KB-[\w-]+\b"),
    re.compile(r"\b\d{4}-\d{2}-\d{2}T[\d:.]+Z?\b"),  # ISO-8601 timestamps
    re.compile(r"\b\d{1,2}:\d{2}(?::\d{2})?\b"),  # bare clock times / durations (16:19, 02:03:04)
)

_UNIT_TO_BYTES: Final[dict[str, float]] = {
    "b": 1.0,
    "byte": 1.0,
    "bytes": 1.0,
    "kb": 1e3,
    "mb": 1e6,
    "gb": 1e9,
    "tb": 1e12,
}
# The same magnitude also expressed as a binary (KiB/MiB/...) unit -- prose says "GB" for either
# convention interchangeably, so both are offered as candidate canonical forms (`_UNIT_TO_BYTES`'s
# decimal-power alternative, kept separate rather than picked once) and either matching the cited
# object's own leaf value is accepted.
_UNIT_TO_BYTES_BINARY: Final[dict[str, float]] = {
    "kb": 1024.0,
    "mb": 1024.0**2,
    "gb": 1024.0**3,
    "tb": 1024.0**4,
}
_UNIT_TO_SECONDS: Final[dict[str, float]] = {
    "ms": 1e-3,
    "millisecond": 1e-3,
    "milliseconds": 1e-3,
    "s": 1.0,
    "sec": 1.0,
    "secs": 1.0,
    "second": 1.0,
    "seconds": 1.0,
    "min": 60.0,
    "mins": 60.0,
    "minute": 60.0,
    "minutes": 60.0,
    "h": 3600.0,
    "hr": 3600.0,
    "hrs": 3600.0,
    "hour": 3600.0,
    "hours": 3600.0,
}
_PERCENT_UNITS: Final[frozenset[str]] = frozenset({"%", "percent", "percentile"})

_NUMBER_RE: Final[re.Pattern[str]] = re.compile(
    r"(?P<num>[-+]?\d{1,3}(?:,\d{3})+(?:\.\d+)?|\d+\.\d+|\d+)"
    r"\s*(?P<unit>%|percent(?:ile)?|kb|mb|gb|tb|bytes?|b|ms|milliseconds?|"
    r"seconds?|secs?|s|minutes?|mins?|min|hours?|hrs?|hr|h)?",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class ExtractedNumber:
    raw: str
    value: float
    unit: str | None
    is_count: bool  # bare integer, no unit, no decimal point -> exact match required
    # Every plausible canonical (base-unit) reading of `value unit` -- e.g. "2.4 GB" yields both
    # the decimal (2.4e9) and binary (2.4 * 1024**3) byte readings. A bare number's only
    # candidate is itself.
    candidates: tuple[float, ...]

    @property
    def tolerance(self) -> float:
        return 0.0 if self.is_count else 0.01


def _strip_citation_noise(text: str) -> str:
    out = text
    for pattern in _NOISE_PATTERNS:
        out = pattern.sub(" ", out)
    return out


def extract_numbers(text: str) -> list[ExtractedNumber]:
    """Every measurement-shaped number in `text`, with unit-aware candidate canonical forms.
    Citation tokens and technique ids are stripped first (`_strip_citation_noise`) so they can
    never be misread as numbers. Change 7 check 2's tolerance rule -- "exact for counts, +/-1%
    for byte/duration values rounded for display" -- is captured per-number in `is_count`/
    `tolerance`, not decided globally for the whole claim."""
    cleaned = _strip_citation_noise(text)
    out: list[ExtractedNumber] = []
    for m in _NUMBER_RE.finditer(cleaned):
        raw_num = m.group("num")
        unit = (m.group("unit") or "").lower() or None
        try:
            value = float(raw_num.replace(",", ""))
        except ValueError:  # pragma: no cover - regex only matches numeric text
            continue
        is_count = unit is None and "." not in raw_num
        candidates: tuple[float, ...]
        if unit is None or unit in _PERCENT_UNITS:
            candidates = (value,)
        elif unit in _UNIT_TO_BYTES:
            forms = {value * _UNIT_TO_BYTES[unit]}
            if unit in _UNIT_TO_BYTES_BINARY:
                forms.add(value * _UNIT_TO_BYTES_BINARY[unit])
            candidates = tuple(forms)
        elif unit in _UNIT_TO_SECONDS:
            candidates = (value * _UNIT_TO_SECONDS[unit],)
        else:  # pragma: no cover - regex's own unit alternation only matches known units
            candidates = (value,)
        out.append(
            ExtractedNumber(
                raw=m.group(0).strip(),
                value=value,
                unit=unit,
                is_count=is_count,
                candidates=candidates,
            )
        )
    return out


_NUMERIC_LEAF_SKIP_KEYS: Final[frozenset[str]] = frozenset(
    {"id", "evidence_id", "log_id", "baseline_id", "raw_line_no"}
)


def numeric_leaves(obj: Any, *, _skip: frozenset[str] = _NUMERIC_LEAF_SKIP_KEYS) -> list[float]:
    """Every numeric leaf value inside `obj` (a dict/list/scalar tree -- an `EvidencePayload`'s
    `measurements`/`historical`, a `get_entity_baseline` result, or a serialized event), excluding
    pure identifier fields (`_skip`) that are never a "measurement" a claim would legitimately
    cite as a quantity. Booleans are excluded (`isinstance(x, bool)` before the `int` check --
    `bool` is a subclass of `int` in Python)."""
    pool: list[float] = []

    def walk(value: Any, key: str | None) -> None:
        if key is not None and key in _skip:
            return
        if isinstance(value, bool):
            return
        if isinstance(value, int | float):
            pool.append(float(value))
        elif isinstance(value, dict):
            for k, v in value.items():
                walk(v, k)
        elif isinstance(value, list | tuple):
            for v in value:
                walk(v, None)

    walk(obj, None)
    return pool


def _numeric_match(extracted: ExtractedNumber, pool: list[float]) -> bool:
    if not pool:
        return False
    tol = extracted.tolerance
    for candidate in extracted.candidates:
        for leaf in pool:
            if tol == 0.0:
                if candidate == leaf:
                    return True
            else:
                denom = max(abs(leaf), 1e-9)
                if abs(candidate - leaf) / denom <= tol:
                    return True
    return False


# ---------------------------------------------------------------------------- citation resolution


@dataclass(frozen=True, slots=True)
class Citation:
    """One resolved citation id -- `exists` is change 7 check 1; `numeric_pool` feeds check 2;
    `is_technique`/`technique_id` feed check 3; `event` (LOG-n only) feeds check 4."""

    id: str
    namespace: str
    exists: bool
    numeric_pool: tuple[float, ...] = ()
    technique_id: str | None = None
    event: Event | None = None


def _resolve_citations(
    ctx: AgentContext, ids: set[str], events_by_line_no: dict[int, Event]
) -> dict[str, Citation]:
    resolved: dict[str, Citation] = {}
    evidence_by_id = {p.evidence_id: p for p in ctx.evidence_payloads}
    baseline_by_id = ctx.baseline_citations
    for cid in ids:
        namespace, key = classify_citation(cid)
        if namespace == CITATION_EVIDENCE:
            if key in evidence_by_id:
                p = evidence_by_id[key]
                pool = numeric_leaves(p.measurements) + numeric_leaves(p.historical)
                resolved[cid] = Citation(
                    id=cid, namespace=namespace, exists=True, numeric_pool=tuple(pool)
                )
            elif key in baseline_by_id:
                pool = numeric_leaves(baseline_by_id[key])
                resolved[cid] = Citation(
                    id=cid, namespace=namespace, exists=True, numeric_pool=tuple(pool)
                )
            else:
                resolved[cid] = Citation(id=cid, namespace=namespace, exists=False)
        elif namespace == CITATION_LOG:
            try:
                line_no = int(key)
            except ValueError:  # pragma: no cover - regex only matches digits
                resolved[cid] = Citation(id=cid, namespace=namespace, exists=False)
                continue
            event = events_by_line_no.get(line_no)
            if event is None:
                resolved[cid] = Citation(id=cid, namespace=namespace, exists=False)
            else:
                pool = [
                    float(v)
                    for v in (event.bytes_in, event.bytes_out, event.status_code)
                    if v is not None
                ]
                resolved[cid] = Citation(
                    id=cid, namespace=namespace, exists=True, numeric_pool=tuple(pool), event=event
                )
        elif namespace == CITATION_MITRE:
            resolved[cid] = Citation(
                id=cid, namespace=namespace, exists=technique_exists(key), technique_id=key
            )
        elif namespace == CITATION_ZSCALER_KB:
            # No bounded, per-document citable-id registry exists yet for the Zscaler semantics
            # KB (`data/kb/zscaler/*.yml` is organized by category/appclass, not by a citable doc
            # id) -- the namespace is recognized and existence trivially passes rather than either
            # fabricating an id registry or silently rejecting every citation in it. Reported as a
            # known limitation, not hidden.
            resolved[cid] = Citation(id=cid, namespace=namespace, exists=True)
        else:
            resolved[cid] = Citation(id=cid, namespace=namespace, exists=False)
    return resolved


def _fetch_events_by_line_no(ctx: AgentContext, line_nos: set[int]) -> dict[int, Event]:
    if not line_nos:
        return {}
    with tenant_scope(ctx.session, ctx.tenant_id):
        rows = (
            ctx.session.execute(
                select(Event)
                .where(Event.analysis_id == ctx.analysis_id)
                .where(Event.raw_line_no.in_(line_nos))
            )
            .scalars()
            .all()
        )
    by_line_no: dict[int, Event] = {}
    for e in rows:
        by_line_no.setdefault(e.raw_line_no, e)  # first row wins; see module docstring on ties
    return by_line_no


def _all_citation_ids(objects: Any) -> set[str]:
    """Collects every `evidence_ids`/`anomaly_ids`/`supporting_evidence_ids`/
    `contradicting_evidence_ids` string across whatever claim/finding objects are passed --
    duck-typed on attribute name so one helper serves `Claim`, `Finding`, and plain iterables of
    either."""
    ids: set[str] = set()
    for obj in objects:
        for attr in (
            "evidence_ids",
            "anomaly_ids",
            "supporting_evidence_ids",
            "contradicting_evidence_ids",
        ):
            ids.update(getattr(obj, attr, ()) or ())
    return ids


# ---------------------------------------------------------------------------- claim-level check


@dataclass(frozen=True, slots=True)
class ClaimCheck:
    claim: Claim
    existence_ok: bool
    numeric_ok: bool
    retrieval_ok: bool
    scope_ok: bool | None  # None when scope was not checked (pass 1)
    missing_ids: tuple[str, ...] = ()
    mismatched_numbers: tuple[str, ...] = ()
    unretrieved_techniques: tuple[str, ...] = ()
    out_of_scope_ids: tuple[str, ...] = ()

    @property
    def valid_pass1(self) -> bool:
        return self.existence_ok and self.numeric_ok and self.retrieval_ok

    @property
    def valid(self) -> bool:
        return self.valid_pass1 and (self.scope_ok is not False)

    def as_dict(self) -> dict[str, Any]:
        return {
            "claim": self.claim.text,
            "evidence_ids": list(self.claim.evidence_ids),
            "existence_ok": self.existence_ok,
            "numeric_ok": self.numeric_ok,
            "retrieval_ok": self.retrieval_ok,
            "scope_ok": self.scope_ok,
            "missing_ids": list(self.missing_ids),
            "mismatched_numbers": list(self.mismatched_numbers),
            "unretrieved_techniques": list(self.unretrieved_techniques),
            "out_of_scope_ids": list(self.out_of_scope_ids),
        }


def _in_scope(ctx: AgentContext, event: Event) -> bool:
    lo = ctx.window_start - CITATION_TEMPORAL_SLACK
    hi = ctx.window_end + CITATION_TEMPORAL_SLACK
    pairs = ctx.event_entity_pairs(
        principal=event.principal, src_ip=event.src_ip, dst_ip=event.dst_ip, domain=event.domain
    )
    return bool(pairs & ctx.entity_scope) and lo <= event.ts <= hi


def _check_claim(
    ctx: AgentContext, claim: Claim, resolved: dict[str, Citation], *, check_scope: bool
) -> ClaimCheck:
    missing: list[str] = []
    unretrieved: list[str] = []
    out_of_scope: list[str] = []
    pool: list[float] = []
    scope_relevant = False
    scope_ok = True

    for cid in claim.evidence_ids:
        c = resolved.get(cid)
        if c is None or not c.exists:
            missing.append(cid)
            continue
        pool.extend(c.numeric_pool)
        if (
            c.namespace == CITATION_MITRE
            and c.technique_id is not None
            and c.technique_id != NO_KNOWN_MAPPING
            and c.technique_id not in ctx.retrieved_technique_ids
        ):
            unretrieved.append(cid)
        if check_scope and c.namespace == CITATION_LOG and c.event is not None:
            scope_relevant = True
            if not _in_scope(ctx, c.event):
                out_of_scope.append(cid)
                scope_ok = False

    numbers = extract_numbers(claim.text)
    mismatched = [n.raw for n in numbers if not _numeric_match(n, pool)]

    # scope_ok is None when scope was not checked at all (pass 1); True when it was checked and
    # either there was nothing LOG-n-shaped to check (vacuously fine) or every LOG-n citation was
    # in scope; False when at least one LOG-n citation was out of scope.
    if not check_scope:
        resolved_scope_ok: bool | None = None
    else:
        resolved_scope_ok = scope_ok if scope_relevant else True

    return ClaimCheck(
        claim=claim,
        existence_ok=not missing,
        numeric_ok=not mismatched,
        retrieval_ok=not unretrieved,
        scope_ok=resolved_scope_ok,
        missing_ids=tuple(missing),
        mismatched_numbers=tuple(mismatched),
        unretrieved_techniques=tuple(unretrieved),
        out_of_scope_ids=tuple(out_of_scope),
    )


# ---------------------------------------------------------------------------- finding-level check


@dataclass(frozen=True, slots=True)
class FindingCheck:
    finding_id: str
    claim_checks: tuple[ClaimCheck, ...]
    technique_retrieval_ok: bool  # attack_technique_id itself was retrieved (or NO_KNOWN_MAPPING)

    @property
    def valid(self) -> bool:
        return self.technique_retrieval_ok and all(c.valid for c in self.claim_checks)


def claims_for_finding(finding: Finding) -> list[Claim]:
    """The finding's own text fields, reframed as citable claims for verification -- change 6's
    Analyst fields (`observation`, `hypothesis`, `confidence_reason`) are prose, not a list of
    `{claim, evidence_ids}` entries the way `HypothesisEvaluation.evidence_for` is, so this
    function is what lets the same claim-checking machinery cover them too."""
    tech_citation = (
        (f"MITRE-{finding.attack_technique_id}",)
        if finding.attack_technique_id != NO_KNOWN_MAPPING
        else ()
    )
    return [
        Claim(text=finding.observation, evidence_ids=tuple(finding.anomaly_ids)),
        Claim(
            text=finding.hypothesis,
            evidence_ids=tuple(finding.supporting_evidence_ids) + tech_citation,
        ),
        Claim(
            text=finding.confidence_reason,
            evidence_ids=tuple(finding.supporting_evidence_ids),
        ),
    ]


def check_finding(
    ctx: AgentContext, finding: Finding, resolved: dict[str, Citation], *, check_scope: bool
) -> FindingCheck:
    claim_checks = tuple(
        _check_claim(ctx, c, resolved, check_scope=check_scope) for c in claims_for_finding(finding)
    )
    technique_ok = finding.attack_technique_id == NO_KNOWN_MAPPING or (
        finding.attack_technique_id in ctx.retrieved_technique_ids
    )
    return FindingCheck(
        finding_id=finding.finding_id,
        claim_checks=claim_checks,
        technique_retrieval_ok=technique_ok,
    )


# ---------------------------------------------------------------------------- pass 1 (pre-judge)


@dataclass(frozen=True, slots=True)
class Pass1Result:
    """`sanitized_output` is what `app.agent.orchestrator` builds the Judge's prompt from --
    every `HypothesisEvaluation.evidence_for`/`evidence_against` claim that failed existence,
    numeric match, or retrieval match (change 15: "existence + numeric match + retrieval match --
    cheap, no LLM") has been removed. `dropped_claim_checks` is kept for reporting/eval, never
    shown to the Judge. `finding_flags` surfaces (not drops -- a `Finding`'s prose fields cannot be
    partially removed) each finding's own text-field issues so the Judge's rubric grading (items
    1-3) has them to weigh."""

    sanitized_output: AnalystOutput
    dropped_claim_checks: tuple[ClaimCheck, ...]
    finding_flags: dict[str, tuple[str, ...]]


def _sanitize_hypothesis_evaluation(
    ctx: AgentContext, h: HypothesisEvaluation, resolved: dict[str, Citation]
) -> tuple[HypothesisEvaluation, list[ClaimCheck]]:
    dropped: list[ClaimCheck] = []

    def keep(claims: tuple[Claim, ...]) -> tuple[Claim, ...]:
        survivors: list[Claim] = []
        for c in claims:
            check = _check_claim(ctx, c, resolved, check_scope=False)
            if check.valid_pass1:
                survivors.append(c)
            else:
                dropped.append(check)
        return tuple(survivors)

    sanitized = h.model_copy(
        update={
            "evidence_for": keep(h.evidence_for),
            "evidence_against": keep(h.evidence_against),
        }
    )
    return sanitized, dropped


def _finding_flag_notes(check: FindingCheck) -> tuple[str, ...]:
    notes: list[str] = []
    if not check.technique_retrieval_ok:
        notes.append("attack_technique_id was not among the techniques retrieved for this incident")
    for field_name, cc in zip(
        ("observation", "hypothesis", "confidence_reason"), check.claim_checks, strict=True
    ):
        if not cc.existence_ok:
            notes.append(f"{field_name}: cites nonexistent id(s) {list(cc.missing_ids)}")
        if not cc.numeric_ok:
            notes.append(
                f"{field_name}: number(s) {list(cc.mismatched_numbers)} do not match cited evidence"
            )
        if not cc.retrieval_ok:
            notes.append(f"{field_name}: cites unretrieved technique(s)")
    return tuple(notes)


def verify_pass1(ctx: AgentContext, analyst_output: AnalystOutput) -> Pass1Result:
    """change 15's first pass, run immediately on the Analyst's raw output, before the Judge is
    ever called."""
    all_ids = _all_citation_ids(
        [
            c
            for h in analyst_output.hypothesis_evaluations
            for c in (*h.evidence_for, *h.evidence_against)
        ]
    ) | _all_citation_ids([c for f in analyst_output.findings for c in claims_for_finding(f)])
    events_by_line_no = _fetch_events_by_line_no(
        ctx, {int(m.group(1)) for cid in all_ids if (m := _LOG_RE.match(cid))}
    )
    resolved = _resolve_citations(ctx, all_ids, events_by_line_no)

    sanitized_evals: list[HypothesisEvaluation] = []
    dropped: list[ClaimCheck] = []
    for h in analyst_output.hypothesis_evaluations:
        s, d = _sanitize_hypothesis_evaluation(ctx, h, resolved)
        sanitized_evals.append(s)
        dropped.extend(d)

    finding_flags: dict[str, tuple[str, ...]] = {}
    for f in analyst_output.findings:
        check = check_finding(ctx, f, resolved, check_scope=False)
        notes = _finding_flag_notes(check)
        if notes:
            finding_flags[f.finding_id] = notes

    sanitized_output = analyst_output.model_copy(
        update={"hypothesis_evaluations": tuple(sanitized_evals)}
    )
    return Pass1Result(
        sanitized_output=sanitized_output,
        dropped_claim_checks=tuple(dropped),
        finding_flags=finding_flags,
    )


# ---------------------------------------------------------------------------- pass 2 (post-judge)


@dataclass(frozen=True, slots=True)
class Pass2Result:
    """change 15's second pass, run on whatever the Judge actually leaves behind (PASS'd findings
    unchanged, REVISE'd findings replaced by `revised_finding`, REJECT'd findings absent).
    `citation_valid`/`invalid_citations` are exactly the two fields the pre-migration citation
    verifier persisted onto `triage_verdicts` -- surfaced, never suppressed."""

    finding_checks: tuple[FindingCheck, ...]
    citation_valid: bool
    invalid_citations: tuple[dict[str, Any], ...]


def verify_pass2(ctx: AgentContext, findings: list[Finding]) -> Pass2Result:
    all_ids = _all_citation_ids([c for f in findings for c in claims_for_finding(f)])
    events_by_line_no = _fetch_events_by_line_no(
        ctx, {int(m.group(1)) for cid in all_ids if (m := _LOG_RE.match(cid))}
    )
    resolved = _resolve_citations(ctx, all_ids, events_by_line_no)

    checks = tuple(check_finding(ctx, f, resolved, check_scope=True) for f in findings)
    invalid: list[dict[str, Any]] = []
    for check in checks:
        if not check.technique_retrieval_ok:
            invalid.append(
                {
                    "finding_id": check.finding_id,
                    "issue": "attack_technique_id not in retrieved candidate set",
                }
            )
        for cc in check.claim_checks:
            if not cc.valid:
                entry = cc.as_dict()
                entry["finding_id"] = check.finding_id
                invalid.append(entry)

    return Pass2Result(
        finding_checks=checks, citation_valid=not invalid, invalid_citations=tuple(invalid)
    )


def hallucination_stats(pass2: Pass2Result) -> HallucinationStats:
    total = sum(len(c.claim_checks) for c in pass2.finding_checks)
    rejected = sum(1 for c in pass2.finding_checks for cc in c.claim_checks if not cc.valid)
    return HallucinationStats(total_citations=total, invalid_citations=rejected)


@dataclass(frozen=True, slots=True)
class HallucinationStats:
    total_citations: int
    invalid_citations: int

    @property
    def hallucination_rate(self) -> float:
        if self.total_citations == 0:
            return 0.0
        return self.invalid_citations / self.total_citations


# ---------------------------------------------------------------------------- confidence integrity
#
# docs/v2_migration change 3 ("two confidences, never mixed"), arriving early as change 7's own
# check 5. This check is **different in kind** from every check above: citation failures are
# surfaced, not suppressed (a bad citation gets flagged and the claim still renders, with a
# warning marker); `anomaly_confidence` gets no such leniency. It is not something any LLM stage
# has a basis to recompute (none of them see raw detector scores, only this one already-calibrated
# number), so a difference from the value passed in is never "weak evidence" the way a shaky
# citation can be -- it is either an exact copy or CLAUDE.md rule 5 was violated.
# `app.agent.orchestrator` treats a failure here as a hard rejection of the whole verdict (the run
# falls back to `needs_review`, reason recorded), not a flag on an otherwise-trusted verdict.

ANOMALY_CONFIDENCE_TOLERANCE: Final[float] = 1e-6


class AnomalyConfidenceIntegrityError(Exception):
    """Raised by `app.agent.orchestrator` when `verify_anomaly_confidence` fails."""


@dataclass(frozen=True, slots=True)
class AnomalyConfidenceCheck:
    expected: float
    actual: float
    ok: bool
    reason: str | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "expected": self.expected,
            "actual": self.actual,
            "ok": self.ok,
            "reason": self.reason,
        }


def verify_anomaly_confidence(
    ctx: AgentContext, verdict: TriageVerdictOut
) -> AnomalyConfidenceCheck:
    expected = ctx.anomaly_confidence
    actual = verdict.anomaly_confidence
    ok = abs(expected - actual) <= ANOMALY_CONFIDENCE_TOLERANCE
    reason = (
        None
        if ok
        else (
            f"anomaly_confidence integrity check failed: incident {ctx.incident_id} carries "
            f"{expected!r}, the Presenter's present_verdict returned {actual!r} instead. "
            "anomaly_confidence is upstream-computed (app.detection.fusion."
            "anomaly_confidence_from_fused_score) and no LLM stage has a basis to change it -- "
            "CLAUDE.md rule 5, docs/v2_migration change 3."
        )
    )
    return AnomalyConfidenceCheck(expected=expected, actual=actual, ok=ok, reason=reason)


# ---------------------------------------------------------------------------- final narrative check
#
# `verify_citations` re-runs the same claim-checking machinery over the Presenter's own final
# narrative -- this is what populates `TriageVerdictOut.citation_valid`/`invalid_citations` for
# persistence and UI rendering. Change 6 tells the Presenter not to introduce anything unverified,
# but the Presenter is still an LLM call assembling prose; checking what it actually produced,
# the same way every earlier stage's output was checked, is the same "never silently drop a bad
# citation" discipline applied to the narrative an analyst actually reads.


def verify_citations(
    ctx: AgentContext, verdict: TriageVerdictOut
) -> tuple[bool, list[dict[str, Any]], list[ClaimCheck]]:
    claims = [Claim(text=step.claim, evidence_ids=step.evidence_ids) for step in verdict.narrative]
    all_ids = _all_citation_ids(claims)
    events_by_line_no = _fetch_events_by_line_no(
        ctx, {int(m.group(1)) for cid in all_ids if (m := _LOG_RE.match(cid))}
    )
    resolved = _resolve_citations(ctx, all_ids, events_by_line_no)
    checks = [_check_claim(ctx, c, resolved, check_scope=True) for c in claims]
    invalid = [c.as_dict() for c in checks if not c.valid]
    return not invalid, invalid, checks


# ---------------------------------------------------------------------------- Path A verification
#
# change 14: "Verifier still runs [for Path A] -- descriptive prose hallucinating a byte count is
# still a hallucination." No `AgentContext` here -- Path A is analysis-wide, not incident-scoped,
# and every input (`overview`, `incidents`, `timeline_phases`) is already a fully-computed,
# self-contained dict handed in by the caller (`app.agent.orchestrator.narrate_analysis`), not
# something this function looks up itself. Phase *selection* is deterministic and happens upstream
# (docs/05) -- this only checks that the Narrator wrote about phases it was actually given, and
# that every number and log citation it wrote traces back to that same input.


def verify_narrator_output(
    *,
    overview: dict[str, Any],
    incidents: list[dict[str, Any]],
    timeline_phases: list[dict[str, Any]],
    output: NarratorOutput,
) -> tuple[bool, list[dict[str, Any]]]:
    invalid: list[dict[str, Any]] = []

    exec_pool = numeric_leaves(overview) + numeric_leaves(incidents)
    for n in extract_numbers(output.executive_summary):
        if not _numeric_match(n, exec_pool):
            invalid.append({"section": "executive_summary", "mismatched_number": n.raw})

    phases_by_index = {p.get("phase_index"): p for p in timeline_phases}
    for phase_narrative in output.phase_narratives:
        phase = phases_by_index.get(phase_narrative.phase_index)
        if phase is None:
            invalid.append(
                {
                    "section": f"phase_{phase_narrative.phase_index}",
                    "issue": "phase_index was not among the timeline_phases supplied to the Narrator",
                }
            )
            continue

        allowed_log_ids = {
            *(phase.get("log_ids") or []),
            *(phase.get("evidence_ids") or []),
        }
        out_of_scope = [cid for cid in phase_narrative.cited_log_ids if cid not in allowed_log_ids]
        if out_of_scope:
            invalid.append(
                {
                    "section": f"phase_{phase_narrative.phase_index}",
                    "issue": "cited id(s) outside this phase's own scope",
                    "ids": out_of_scope,
                }
            )

        phase_pool = numeric_leaves(phase)
        for n in extract_numbers(phase_narrative.narrative):
            if not _numeric_match(n, phase_pool):
                invalid.append(
                    {"section": f"phase_{phase_narrative.phase_index}", "mismatched_number": n.raw}
                )

    return not invalid, invalid


# ---------------------------------------------------------------------------- change 8 verification
#
# `verify_domain_semantic_output` mirrors `verify_narrator_output`'s shape exactly, and for the
# same reason: `candidates` is the exact, already-computed list `app.api.analyses` built and
# handed to the single LLM turn (`app.agent.orchestrator.assess_domain_semantics`), so both
# "does this citation exist" and "does this number match" resolve against data already in hand,
# not a fresh DB lookup -- no `AgentContext` is needed here any more than Path A's verifier needs
# one. Reuses change 7's own numeric-match machinery (`extract_numbers`/`numeric_leaves`/
# `_numeric_match`) rather than a second implementation: a semantic judgement's hallucination risk
# (a fabricated contact count, an invented connection count) is the same shape of risk change 7
# already solves for the four-stage pipeline.


def verify_domain_semantic_output(
    *, candidates: list[dict[str, Any]], output: DomainSemanticOutput
) -> tuple[bool, list[dict[str, Any]]]:
    """Every flagged `DomainAssessment` is checked against the candidate it claims to be about:

    1. **Existence / scope** -- the assessed `domain` must be one of the candidates actually
       supplied, and every id in `evidence_ids` must be one of that specific candidate's own
       `evidence_id` / `log_ids` -- never an id shown for a *different* candidate domain. This is
       change 7 check 1 (existence) and check 4 (scope), applied to this pass's own, narrower
       citation surface.
    2. **Numeric match** -- change 7 check 2: every number written in `assessment`/`rationale`
       must appear, or be a straightforward restatement of, a number already present somewhere in
       that candidate's own evidence dict (`numeric_leaves(candidate)`).

    Unflagged assessments (`flagged is False`) are not checked beyond the domain-existence check
    -- an unflagged domain never reaches `app.schemas.overview.DomainSemanticFinding` at all
    (`app.agent.orchestrator.assess_domain_semantics` only keeps `flagged=True` entries), so
    there is nothing downstream a bad citation on an unflagged entry could ever mislead.
    """
    invalid: list[dict[str, Any]] = []
    by_domain = {c["domain"]: c for c in candidates}

    for a in output.assessments:
        candidate = by_domain.get(a.domain)
        if candidate is None:
            invalid.append(
                {"domain": a.domain, "issue": "domain was not among the candidates supplied"}
            )
            continue
        if not a.flagged:
            continue

        allowed_ids = {candidate.get("evidence_id"), *(candidate.get("log_ids") or ())}
        allowed_ids.discard(None)
        out_of_scope = [cid for cid in a.evidence_ids if cid not in allowed_ids]
        if out_of_scope:
            invalid.append(
                {
                    "domain": a.domain,
                    "issue": "cited id(s) outside this candidate's own scope",
                    "ids": out_of_scope,
                }
            )

        pool = numeric_leaves(candidate)
        mismatched = [
            n.raw
            for n in (*extract_numbers(a.assessment), *extract_numbers(a.rationale))
            if not _numeric_match(n, pool)
        ]
        if mismatched:
            invalid.append({"domain": a.domain, "mismatched_numbers": mismatched})

    return not invalid, invalid


def parse_verdict_payload(raw: dict[str, Any]) -> TriageVerdictOut:
    """Parse a raw `present_verdict` tool-call payload into a validated `TriageVerdictOut`, or
    raise `SchemaValidationError` with every field error collected."""
    try:
        return TriageVerdictOut.model_validate(raw)
    except ValidationError as exc:
        raise SchemaValidationError(str(exc)) from exc
