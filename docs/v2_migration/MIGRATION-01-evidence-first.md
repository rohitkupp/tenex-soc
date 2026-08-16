# MIGRATION 01 — Evidence-first architecture

**Read this alongside the existing docs. Where this document and an existing doc disagree, this
document wins.** Apply every change, then update the affected doc in place so the doc set stays
authoritative. Do not treat this as a separate spec to maintain.

## Why this exists

The architecture shifts from *"layers that detect"* to *"layers that measure, and an LLM that
judges."* One sentence governs every change below:

> **Machines calculate facts. The LLM interprets meaning.**

Test for placement: *could I write a deterministic function that produces a more precise answer
than asking an LLM?* If yes, compute it before the LLM and pass the number in.

## Change index

| # | Change | Docs affected |
|---|---|---|
| 1 | Historical baseline store (6-month per-tenant history) | 02, 04, 11, 13 |
| 2 | L2 reframed as deterministic evidence extractors | 04, 02, 07 |
| 3 | Two separate confidences: anomaly vs. threat | 02, 04, 07, 10 |
| 4 | RAG restructured: proxy-observable filter + detection-strategy docs + Zscaler KB | 07 |
| 5 | Hypothesis *evaluation* replaces free generation | 07 |
| 6 | Four-stage LLM pipeline: Analyst → Judge → Verifier → Presenter | 07 |
| 7 | Dual citation types + numeric-claim verification | 07, 02 |
| 8 | LLM semantic domain analysis, labelled separately from ML findings | 04, 07, 10 |
| 9 | Deterministic log overview, always produced | 09, 10 |
| 10 | Three-level output + notable users / destinations | 09, 10 |
| 11 | Highlighted lines come from attribution, not the LLM | 04, 07 |
| 12 | **DEMO_MODE removed entirely** | 01, 07, 13 |
| 13 | 1000-file synthetic corpus | 11, 12, 13 |
| 14 | Two LLM paths separated: analysis narrative vs. incident investigation | 07, 09, 10 |
| 15 | Verifier runs before the judge, and again after REVISE | 07 |
| 16 | Evidence sections — per incident and per analysis | 09, 10 |
| 17 | Explicitly preserved components (absent from source diagrams) | — |
| 18 | **Sequence modelling removed**; navigation chain extractor instead | 04, 03 |
| 19 | **Autoencoder and LightGBM removed** | 04, 02, 12 |
| 20 | **Response action graph and enforcement plane removed** | 08, 02, 09, 10 |
| 21 | Continuous learning — 15 mechanisms | 08, 02, 10 |
| 22 | Feedback UI | 10, 09 |
| 23 | Shared workspace, single live tenant, Tier 2 preserved | 02, 06, 09, 10 |
| 24 | GCP deployment topology | 01 |
| 25 | Comprehensive test plan | 12 |
| 26 | Post-build validation run | 13 |
| 27 | **Remove Upload, Models, and Ops routes** — content relocated | 09, 10, 13 |

## Decisions carried forward — do not reverse

- **No sequence model.** The proxy-only rationale in `docs/04` stands. If a diagram in source
  material shows a transformer or sequence pillar, ignore it.
- **Evidence extractors can still nominate candidates.** See change 2.
- **Severity and ranking are never set by an LLM.** Unchanged.
- **Evidence extractors can nominate candidates**, not only enrich them.

---

# 1. Historical baseline store

**The single biggest change.** Percentiles, rarity, and deviations are currently computed against
the uploaded file. They must instead be computed against a persistent per-tenant history.

This is what makes statements like *"Alice has contacted github.com 7,921 times and this domain
zero times"* possible, and it removes the largest methodological weakness in the old design.

### Schema (add to `docs/02`)

```sql
CREATE TABLE baseline_windows (
  id BIGSERIAL PRIMARY KEY,
  tenant_id UUID NOT NULL,
  entity_type TEXT NOT NULL,          -- user|src_ip|department|org
  entity_value TEXT NOT NULL,
  window_start TIMESTAMPTZ NOT NULL,
  features JSONB NOT NULL,            -- same ~50-feature vector as L3
  UNIQUE (tenant_id, entity_type, entity_value, window_start)
);
CREATE INDEX ON baseline_windows (tenant_id, entity_type, entity_value);

CREATE TABLE baseline_profiles (
  tenant_id UUID NOT NULL,
  entity_type TEXT NOT NULL,
  entity_value TEXT NOT NULL,
  metric TEXT NOT NULL,               -- bytes_out, n_events, n_unique_domains, ...
  p50 DOUBLE PRECISION, p95 DOUBLE PRECISION, p99 DOUBLE PRECISION,
  mean DOUBLE PRECISION, mad DOUBLE PRECISION,
  n_windows INT NOT NULL,
  PRIMARY KEY (tenant_id, entity_type, entity_value, metric)
);

CREATE TABLE baseline_contacts (
  tenant_id UUID NOT NULL,
  scope TEXT NOT NULL,                -- user|department|org
  scope_value TEXT NOT NULL,
  domain TEXT NOT NULL,
  contact_count BIGINT NOT NULL,
  first_seen TIMESTAMPTZ NOT NULL,
  last_seen TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (tenant_id, scope, scope_value, domain)
);
CREATE INDEX ON baseline_contacts (tenant_id, domain);
```

### Behaviour

- `make seed` loads a pre-generated 6-month baseline per demo tenant from `data/baseline/`.
- Every percentile in the system resolves against `baseline_profiles`, never against the
  uploaded file.
- Rarity resolves against `baseline_contacts` at three scopes — user, department, org — and all
  three go into the evidence payload. "Zero for Alice, one for Finance, four org-wide" is far
  more informative than a single rarity number.
- L3 models train on `baseline_windows`, not on a separate synthetic corpus concept. The
  baseline *is* the training corpus.
- **Cold start:** an entity with `n_windows < 20` gets `baseline_status: "insufficient_history"`
  in its evidence payload, and the LLM is instructed to weight its deviations accordingly. Do
  not silently emit a percentile computed from four windows.

---

# 2. L2 → deterministic evidence extractors

Rename `detection/signal/` → `detection/evidence/`. This is not cosmetic — the output contract
changes.

### Old contract
A detector emitted a `signals` row with a calibrated score.

### New contract
An extractor emits an `EvidencePayload`: the **raw measurements plus historical context**, which
travels to the LLM intact.

```python
class EvidencePayload(BaseModel):
    evidence_id: str                  # "EVIDENCE-14" — stable, citable
    extractor: str                    # beaconing | dga | burst | rarity | stl | url_entropy
    entity: dict
    window: tuple[datetime, datetime]
    measurements: dict[str, float]    # the actual numbers
    historical: dict[str, float]      # percentiles vs. baseline
    contributing_line_numbers: list[int]
    nominates_candidate: bool
    nomination_score: float | None    # calibrated, only if nominates_candidate
```

Example for beaconing — this is what the LLM receives, verbatim:

```json
{ "evidence_id": "EVIDENCE-14", "extractor": "beaconing",
  "measurements": {"requests": 63, "median_interval_s": 60.1, "interval_cv": 0.018,
                   "mad_s": 1.0, "dominant_period_s": 60, "spectral_strength": 0.94},
  "historical": {"beaconing_percentile": 99.7},
  "contributing_line_numbers": [1291, 1294, 1301] }
```

### Extractors may still nominate

**This is where we diverge from the source material.** An extractor that finds something no
entity-window model would surface must be able to raise a candidate on its own. Sixty requests
over six hours produces an entirely unremarkable feature vector — the beacon would be lost.

Rule: an extractor sets `nominates_candidate = true` when its historical percentile exceeds
99.5 **and** no existing candidate already covers its entity-window. Nominated candidates enter
the same correlation and triage path as model-detected ones.

### What each extractor computes

| Extractor | Measurements | Historical context |
|---|---|---|
| beaconing | requests, median interval, CV, MAD, FFT dominant period, spectral strength | beaconing percentile vs. baseline |
| dga | classifier probability, entropy, bigram log-likelihood, digit ratio, consonant run | — (probability is already the answer) |
| burst | requests/min, bytes/min, unique domains/min | ratio vs. user / dept / org baseline, percentile |
| rarity | contact counts at user, dept, org scope | first-seen flags per scope, percentile |
| stl | observed, seasonal expectation, trend, residual | residual z, percentile |
| url_entropy | Shannon entropy, path depth, encoded-param flags, **the literal path string** | entropy percentile |

The literal path string matters — the LLM does the semantic half (`/password-reset/verify-account`
is low-entropy but interesting; `/a8q7zw9f23v82` is high-entropy and probably a session ID).

---

# 3. Two confidences, never mixed

A behaviour can be extremely anomalous and not remotely malicious. Collapsing these into one
number is the mistake this change prevents.

| | Source | Means | Range |
|---|---|---|---|
| `anomaly_confidence` | ML + evidence layer, isotonic-calibrated | how unusual vs. history | 0–100 |
| `threat_confidence` | hypothesis evaluation | how well evidence supports *this specific* security interpretation | low / moderate / high |

The LLM **may not modify** `anomaly_confidence`. Pass it in the prompt with an explicit
instruction to reproduce it unchanged; the verifier rejects any output where it differs.

UI must render both, and must never phrase `anomaly_confidence` as a probability of malice:

```
Anomaly confidence: 96/100
Threat assessment:  Possible C2 — moderate confidence
```

Schema: replace `triage_verdicts.confidence` with `threat_confidence TEXT` +
`threat_confidence_reason TEXT`. Add `anomaly_confidence REAL` to `incidents`.

---

# 4. RAG restructure

### Filter ATT&CK to proxy-observable techniques

Do **not** load all of ATT&CK. A web proxy cannot observe registry modification, LSASS dumping,
or process injection, and retrieving those techniques invites hypotheses the telemetry can never
support.

Starting allowlist in `data/kb/mitre/allowlist.yml`:

`T1071.001` Web Protocols · `T1102` Web Service · `T1567` Exfiltration Over Web Service ·
`T1567.002` Exfiltration to Cloud Storage · `T1567.004` Exfiltration Over Webhook ·
`T1041` Exfiltration Over C2 Channel · `T1029` Scheduled Transfer ·
`T1568.002` Domain Generation Algorithms · `T1105` Ingress Tool Transfer ·
`T1090` Proxy · `T1505.003` Web Shell · `T1595` Active Scanning · `T1204` User Execution

Source via MITRE's STIX/TAXII distribution rather than scraping. Cache locally in `data/kb/`;
no network calls at runtime.

### Technique documents carry detection knowledge, not just descriptions

Each document must contain:

```yaml
technique: T1029
name: Scheduled Transfer
description: ...
observable_with_zscaler_proxy: YES        # YES | PARTIAL | NO
required_fields: [user, domain, bytes_out, timestamp]
useful_additional_evidence: [file_info, dlp_findings, endpoint_telemetry]
zscaler_observables:
  - periodic outbound requests to a stable destination
  - outbound volume
  - destination rarity
supporting_detectors: [beaconing, stl, rarity, burst]
evidence_required:
  - recurrent timing
  - data movement
  - stable destination
evidence_that_weakens:
  - known software updater
  - expected SaaS synchronisation
  - historically common for this user
attack_detection_guidance: ...
source: MITRE ATT&CK
```

`observable_with_zscaler_proxy` and `useful_additional_evidence` are load-bearing — the judge
uses them to reject claims requiring telemetry we don't have.

### Second corpus: Zscaler semantics

`data/kb/zscaler/` — log field meanings, threat categories, URL categories, action values, risk
fields. Lets the LLM interpret `threatcategory` correctly.

**Keep Zscaler's own verdicts as a distinct evidence source.** A Zscaler threat-field hit is
*Zscaler said so*, not *our model detected it*. Never merge them.

### Retrieval is evidence-driven

Build the query from the evidence payload, not from the raw logs. Large unusual upload +
cloud-storage destination + rare-for-user retrieves T1567, T1567.002, T1041 — a small,
evidence-relevant candidate set rather than free association across all of security.

---

# 5. Hypothesis evaluation, not free generation

The LLM no longer answers *"what attack happened?"* It answers *"is each retrieved hypothesis
supported by the supplied evidence?"*

Required output per candidate:

```json
{ "technique_id": "T1567.002",
  "evidence_for": [{"claim": "...", "evidence_ids": ["EVIDENCE-14", "BASELINE-3"]}],
  "evidence_against": [{"claim": "...", "evidence_ids": ["EVIDENCE-9"]}],
  "missing_evidence": ["file content", "endpoint process telemetry"],
  "assessment": "supported | plausible | unsupported | not_observable",
  "threat_confidence": "low | moderate | high" }
```

### `NO_KNOWN_MAPPING` is mandatory in every candidate set

Without it, RAG creates a new failure mode: retrieve five techniques, the model assumes one must
be right, false attribution follows. Prompt text, verbatim:

> Do not select a technique solely because it is the closest retrieved result. If the evidence
> does not sufficiently support any retrieved technique, return NO_KNOWN_MAPPING and describe the
> behaviour as an unexplained anomaly. That is a correct answer, not a failure.

The assignment asks for anomaly explanations and confidence scores. It does not ask for every
anomaly to receive a named technique.

---

# 6. Four-stage LLM pipeline

Replaces Investigator → Devil's Advocate → Reporter. The devil's-advocate function survives as
the mandatory `evidence_against` field and in the judge rubric.

```
Analyst  →  Judge  →  Deterministic verifier  →  Presenter
(structured) (rubric)   (code, not a model)      (prose)
```

**Stage 1 — Analyst.** Evidence package + retrieved KB + rubric in. Structured findings out.
No prose. Fields: `finding_id`, `anomaly_ids`, `observation`, `hypothesis`,
`supporting_evidence_ids`, `contradicting_evidence_ids`, `missing_evidence`,
`attack_technique_id`, `attack_source_id`, `threat_confidence`, `confidence_reason`,
`benign_alternatives`.

**Stage 2 — Judge.** Separate call, receives finding + evidence + KB. Returns
`PASS | REVISE | REJECT` per finding against this rubric:

1. Is every factual claim supported by supplied evidence?
2. Do all numerical claims appear exactly in the evidence?
3. Does each cited log line actually support the statement?
4. Does the cited ATT&CK document support the mapping?
5. Is observation clearly separated from inference?
6. Are benign alternatives considered?
7. Is required evidence missing?
8. Does confidence match evidence strength?
9. Is the technique observable from Zscaler proxy telemetry?
10. Has maliciousness been claimed where only anomaly is established?

Prefer REJECT over REVISE when evidence is insufficient.

**Stage 3 — Deterministic verifier.** Code. See change 7. This is what actually prevents
hallucination; the judge is a second opinion, and LLM judges have known self-preference and
correlated-error problems. Do not present the judge as the safeguard.

**Stage 4 — Presenter.** Verified findings in, human-readable prose out. Presentation only —
it may not introduce a fact, a number, or a technique that did not survive verification.

---

# 7. Dual citations + numeric verification

Two citation namespaces:

| Kind | Form | Points to |
|---|---|---|
| Evidence | `[EVIDENCE-14]` `[BASELINE-3]` `[LOG-1291]` | measurements, baselines, raw lines |
| Knowledge | `[MITRE-T1567.002]` `[ZSCALER-KB-threat-cat]` | retrieved KB documents |

Verifier checks, all in code:

1. **Existence** — every cited `LOG-n` exists in this analysis; every `EVIDENCE-n` / `BASELINE-n`
   exists in the payload.
2. **Numeric match** — every number in the narrative appears in the cited evidence object.
   `"transferred 2.4 GB [EVIDENCE-14]"` where EVIDENCE-14 says 1.8 GB → reject the statement.
   Tolerance: exact for counts, ±1% for byte/duration values that were rounded for display.
3. **Retrieval match** — every cited technique was actually in the retrieved candidate set.
   A technique the model recalled from training and never retrieved is a hallucination even if
   the mapping happens to be reasonable.
4. **Scope** — cited log lines belong to the incident's entities and time window ±1h.
5. **Confidence integrity** — `anomaly_confidence` in the output equals the value passed in.

Failures are surfaced, not suppressed. Record in `invalid_citations`, mark the claim in the UI.

Track `hallucination_rate = rejected_claims / total_claims` and gate it in CI.

---

# 8. LLM semantic domain analysis

The DGA classifier handles lexical randomness. It cannot catch `microsoft-security-login-support.com`
— linguistically that looks perfectly human. The LLM can.

Add a semantic pass over destinations flagged rare or first-seen, assessing brand impersonation,
typosquatting intent, and contextual relevance (`github-update-security.com` immediately after a
GitHub credential event).

**This does not replace the DGA classifier.** Research showing LLMs competitive at DGA detection
concerns *fine-tuned* models, not a general-purpose prompt asking whether a domain looks fishy.
Keep the classifier as primary lexical evidence; the LLM adds the semantic half.

**Findings from this pass are labelled differently in the UI:**

| Source | Label |
|---|---|
| ML / statistical pipeline | `ML anomaly — high confidence` |
| LLM semantic assessment | `Analyst insight — requires validation` |

Never let a semantic judgement inherit the statistical backing of EIF or a calibrated classifier.

---

# 9. Deterministic log overview, always

Produced on every upload regardless of whether anything is flagged. Computed in SQL; the LLM only
chooses what to highlight.

```json
{ "period": ["2026-08-14T09:00Z", "2026-08-14T17:00Z"],
  "events": 83241, "users": 127, "src_ips": 139, "unique_domains": 4921,
  "allowed": 78201, "blocked": 5040,
  "bytes_out": 41034969088, "bytes_in": 227263938560,
  "parse_failure_rate": 0.0021 }
```

Do not ask a model to count 83,241 rows.

Also computed deterministically: **notable users** (anomalous windows, volume vs. baseline,
first-seen domain count, top anomaly score) and **notable destinations** (first-observed flag,
distinct users, DGA score, connection count, periodicity). The LLM writes a short executive
summary over these — an analyst should understand the file in ten seconds.

---

# 10. Three output levels

| Level | Content | Route |
|---|---|---|
| 1 — What happened | Overview stats + executive summary + count of anomalies | `/analyses/[id]` |
| 2 — Timeline | Chronological narrative with evidence-linked phases | `/analyses/[id]` |
| 3 — Investigation | Per anomaly: flagged what, why, confidence, lines, contributing models, hypotheses, benign alternatives, next steps | `/analyses/[id]/incidents/[iid]` |

Add sections to `/analyses/[id]`: Summary · Timeline · Anomalies · Notable users ·
Notable destinations · Traffic statistics.

---

# 11. Highlighted lines come from attribution

The analysis layer decides which lines are anomalous; the LLM explains why they matter. It does
not choose rows to colour red.

Trace path: model flags an entity-window → feature attribution identifies the top contributing
features → each contributing evidence extractor supplies its `contributing_line_numbers` → union
becomes `highlight_lines` on the incident.

The LLM receives `highlight_lines` as input and must explain them. It may not add to the list.

---

# 12. Remove DEMO_MODE

Delete `DEMO_MODE` from config, all branches on it, and `data/demo/` precomputed results. Every
upload runs the full pipeline and makes real API calls for every account. Remove the demo-mode
references from `docs/01`, `docs/07`, and `docs/13`.

Consequences to handle properly rather than paper over:
- Pipeline latency is now visible to every user — the SSE progress funnel must be genuinely
  informative, not decorative.
- Cost is real per upload. Keep `MAX_TRIAGE_INCIDENTS` enforced and surface spend per analysis.
- Tests still use recorded LLM fixtures. CI must never need an API key. This change affects the
  product, not the test suite.

---

# 13. 1000-file synthetic corpus

`make gen-data` produces **1000 labelled ZScaler log files** plus the 6-month baseline.

| Artifact | Contents |
|---|---|
| `data/baseline/` | 6 months, 250 users, 8 departments — loads into `baseline_*` tables |
| `data/corpus/` | 1000 `.log` files + 1000 `.labels.json` |
| `data/eval/golden/` | 100 held-out files, frozen, version-controlled, used by the CI gate |

Split: 700 train / 200 validation / 100 golden test. **Different seeds and different simulated
orgs across splits** — sharing a seed between train and test is how you fake good numbers.

Distribution across scenario types, with difficulty parameters swept within each type so the eval
reports detection *curves* rather than point estimates. Roughly 25% benign / benign-but-weird as
the false-positive control.

See `datagen/generate_corpus.py` — the generator is written and delivered; wire it into
`make gen-data` and run at full scale locally.

---

# 14. Two LLM paths, explicitly separated

Source diagram 1 shows a single LLM emitting summary, timeline, and anomalies in parallel.
Diagram 3 shows a four-stage per-incident pipeline. **These are two different paths** and both
exist. Do not run one where the other belongs.

### Path A — analysis-level narrative (once per upload)

```
deterministic overview stats + incident list + analysis timeline entries
    → Narrator LLM (one call)
    → Deterministic verifier
    → executive summary + timeline phase narratives
```

- Timeline entry *selection* is deterministic (`docs/05`). The LLM writes prose for each
  selected phase and the executive summary. It does not choose entries or order them.
- **No judge stage.** A judge pass over descriptive narrative is not worth the call.
- **Verifier still runs.** Every number in the summary must appear in the overview stats;
  every phase narrative must cite the line numbers of its own timeline entry. Descriptive
  prose hallucinating a byte count is still a hallucination.

### Path B — per-incident investigation (once per triaged incident)

```
evidence package + retrieved KB
    → Analyst LLM → verifier (cheap pass) → Judge LLM → verifier (full pass) → Presenter LLM
```

Full four-stage treatment per change 6, with the ordering refinement below.

### Cost accounting
`1 narrator call + (4 × triaged incidents)`. With `MAX_TRIAGE_INCIDENTS=15` that is ≤ 61 calls
per upload. Surface the count and spend on the analysis page.

---

# 15. Verifier runs before the judge, and again after

**Refinement to the source diagrams**, which both place the judge first.

The deterministic verifier is free; the judge costs a model call. Running the cheap check first
means the judge never spends tokens on a claim whose arithmetic already fails, and every claim it
does see is numerically sound.

```
Analyst output
   → verifier pass 1   (existence + numeric match + retrieval match)   ← cheap, no LLM
       claims failing here are dropped before the judge sees them
   → Judge LLM         (evidentiary rubric, PASS | REVISE | REJECT)
   → verifier pass 2   (full, including scope + confidence integrity)  ← catches new numbers
                                                                          introduced by REVISE
   → Presenter LLM
```

Pass 2 is not optional. A REVISE can introduce a number that was not in the original output, and
that number has never been checked.

---

# 16. Evidence sections

Two views, both required.

### Per incident — primary
New section in incident detail, between Timeline and Signals. Every `EvidencePayload` that
contributed to this incident, rendered by `ExplanationRenderer`:

- Measurements table (raw numbers as produced by the extractor)
- Historical context (percentile vs. baseline, with `n_windows` so thin baselines are visible)
- Contributing line numbers, click-to-expand into the raw log rows
- Per-evidence relevance toggle — *was this useful?* — feeding learning mechanism 13
- Evidence ID displayed (`EVIDENCE-14`) so citations in the narrative are traceable by eye

The narrative cites `[EVIDENCE-14]`; clicking the citation scrolls to that card here.

### Per analysis — secondary
`/analyses/[id]/evidence`. Every payload produced for the analysis, filterable by extractor,
entity, and percentile, **including evidence that never formed an incident**. That residue is
exactly what an analyst wants when they suspect the pipeline missed something.

---

# 17. Preserved — absent from source diagrams, NOT removed

The source diagrams terminate at the SOC dashboard. **Absence from a diagram is not an
instruction to delete.** These remain exactly as specified:

| Component | Doc |
|---|---|
| Entity graph + Louvain correlation | `docs/05` |
| Recurrence detection via embeddings | `docs/05` |
| Deterministic incident titling | `docs/05` |
| Both timelines + indicator extraction | `docs/05` |
| Continuous learning | superseded by change 21 below |
| Regression gate on retrain | `docs/08`, `docs/12` |
| Tier 1 / Tier 2 | superseded by change 23 below |

---

# 18. Sequence modelling — removed

**Decision made. Do not build any sequence model.** Delete `detection/sequence/` if present,
drop `drain3` sequence usage, keep Drain3 only for URL path templating.

Per-user filtering was considered and rejected. It removes inter-user concurrency but leaves two
larger sources of disorder: browser parallelism (one page load fires 20–80 subresource requests
in nondeterministic order) and multi-tab concurrency (background Slack polling interleaved with
active browsing). The deeper issue is that an identity session is *serialised by protocol* —
`auth_via_mfa` cannot be concurrent with `session.start` — whereas HTTP has no such constraint.
There is no grammar to learn. And no scenario in the corpus has an ordering signal that other
detectors miss.

**Build this instead — navigation chain extractor.** Reconstruct referer chains per user to
recover the structural evidence the sequence idea was reaching for:

| Feature | Why it matters |
|---|---|
| `referer_less_deep_path` | arrived at a deep path with no referer |
| `navigation_depth` | clicks from an entry point |
| `entry_domain` | how the user reached this destination |
| `cross_domain_redirect_chain` | typosquat → legitimate site handoff |
| `download_without_navigation` | file fetched with no preceding page load |

Deterministic, cheap, feeds the L3 feature vector and the LLM's context about *how* a user got
somewhere. This is the part of the sequence idea that pays for itself.

---

# 19. Model roster — autoencoder and LightGBM removed

Both had their jobs absorbed by other changes in this migration.

**Autoencoder — cut.** Two justifications, both now gone. Per-feature reconstruction attribution
answered *"why was this flagged"*; change 2 gave that job to evidence extractors, which produce
measurements and historical percentiles deterministically. Joint-distribution anomalies where no
single feature is in a tail are what EIF's oblique splits address — and `docs/04` already set the
rule *"if EIF matches the autoencoder, the autoencoder is cut."* The migration answered that
before the benchmark ran.

**LightGBM — cut.** Its job was multiclass technique attribution. Change 5 replaced that with LLM
hypothesis evaluation over RAG-retrieved candidates, which produces evidence-for, evidence-against,
missing-evidence, and `NO_KNOWN_MAPPING`. A softmax over classes produces none of that. Keeping
both leaves two components assigning techniques with no defined precedence.

### Post-migration roster

| Component | Type | Role |
|---|---|---|
| EIF | fitted trees | global entity anomaly, oblique splits |
| kth-NN | instance-based | global distance, handles multimodality |
| LOF | instance-based | peer-relative / local density |
| DGA logistic regression | fitted | lexical DGA probability, inside the extractor |
| Isotonic calibrators | fitted, one per detector | raw score → calibrated confidence |

Benchmarked but **not shipped**: Isolation Forest, ECOD, Mahalanobis. Retained as baselines so EIF
must still prove oblique splitting earns its cost, and so the hypothesis-outcome table in
`docs/12` still has contenders.

Write a short README section on this. *"The migration let me delete two models because
better-suited components absorbed their jobs"* is a more mature claim than a longer roster.

---

# 20. Response action graph and enforcement plane — removed

Delete entirely: `response/` package, `response_plans`, `enforcement_state`,
`enforcement_journal`, all plan/approve/rollback endpoints, the response plan UI section, the
responder worker and `q.respond`, and `docs/08` Part 1.

Consequences to handle:
- Pipeline shortens: `agent` publishes directly to `q.tier2`.
- The four-stage LLM output's `recommended_actions` becomes **investigation guidance** — free-text
  next steps for a human analyst, not action IDs from a catalog. Diagram 3 calls this
  "Investigation guidance"; match that wording in the UI.
- Autonomous containment rate is gone as a metric. The learning loop below becomes the closing
  loop of the system, which is why change 21 is substantial.

---

# 21. Continuous learning

Now the system's closing loop. Fifteen mechanisms, none requiring fine-tuning.

### Feedback taxonomy

| Tier | Captured | Effort |
|---|---|---|
| Incident | Confirm / Override / Dismiss + reason category | one click |
| Finding | per-claim accuracy, technique correctness, missed benign alternative | optional, hover-revealed |
| Evidence | was this extractor relevant; did you need raw logs | opt-in toggle |

### ML consumers

| # | Mechanism | Target | Refit | Applies |
|---|---|---|---|---|
| 1 | Isotonic recalibration | calibrators | trivial | auto |
| 2 | Fusion weight tuning — `w_d = clamp(precision_d / prior, 0.25, 1.5)` | fusion | none | auto |
| 3 | Entity threshold adaptation — raise for one service account, not globally | per-entity overrides | none | auto |
| 4 | **Reference set curation** | kNN, LOF | **none** | auto |
| 5 | **Contamination exclusion** | kNN, LOF, EIF | none / next refit | auto |
| 6 | Baseline expansion — confirmed-benign windows append with `analyst_confirmed` | `baseline_windows` → EIF | yes | gated |
| 7 | Cohort re-derivation — recluster peer groups | LOF | yes | gated |
| 8 | DGA classifier retraining — corrected domain labels | logistic regression | yes | gated |

**4 and 5 exist only because the autoencoder is gone, and they are the interesting ones.**
kNN and LOF are instance-based — they score against stored reference points, not learned weights.
Adding a confirmed-benign window to the reference set makes similar future windows score as normal
**immediately, with no training loop, in constant time.**

Mechanism 5 is the converse and the one people miss: a confirmed *malicious* window left in the
reference set gives the next similar attack a close neighbour, so it scores as normal. Confirmed
true positives must be actively **excluded** from reference and training pools. Classic
instance-based failure mode — implement it explicitly and test for it.

Consequence worth exploiting: the learning loop is now **demonstrable inside a single session**.
One dismissal visibly changes the next score. Show that live in the recording.

### LLM consumers

| # | Mechanism | How it learns |
|---|---|---|
| 9 | **Verdict retrieval** | embed confirmed incidents; retrieve top-3 similar *with analyst verdicts* into the Analyst prompt. Dynamic, immediate, no training. |
| 10 | **Curated exemplar bank** | stable set of analyst-corrected findings pinned into the prompt, covering the most frequent error modes. Distinct from 9 — that is dynamic retrieval, this is deliberate curriculum. |
| 11 | **Judge rubric evolution** | an analyst rejecting a finding the judge PASSED is a judge miss. Cluster misses, propose new rubric items. *"14 rejections ignored known service accounts"* → propose rubric item 11. |
| 12 | **RAG document enrichment** | repeated mis-mapping means a technique's `evidence_that_weakens` is thin. Dismissal reasons become proposed KB additions. **The knowledge base itself learns.** |
| 13 | **Retrieval prior tuning** | track which retrieved techniques the Analyst supports vs. ignores. Retrieved 40 times and never supported for an evidence pattern → down-weight for that pattern. |
| 14 | **Verifier rule induction** | an analyst catching a factual error the verifier missed is a verifier gap. When a pattern emerges (model conflates `bytes_in`/`bytes_out`) add a deterministic check. |
| 15 | **Evidence profile widening** | track how often analysts expand past the bundle to raw logs, per extractor. High rate means that profile's context window is too narrow. |

11, 12, and 14 belong in the recording. A system whose *judge rubric*, *knowledge base*, and
*verifier rules* improve from analyst disagreement is a different claim from logging thumbs-up.

### Auto-apply vs. propose-for-review

The line is principled and defensible:

- **Auto-applies** — anything changing how *confident* the system is: 1, 2, 3, 4, 5, 9, 13.
  Monotone, reversible, gated by the regression harness.
- **Requires human approval** — anything changing what the system *detects or believes*:
  6, 7, 8, 10, 11, 12, 14, 15. Suppression rules, rubric additions, KB edits.
  Auto-suppression is how you miss a breach.

Every gated change passes the golden-set gate. A candidate regressing precision, recall,
hallucination rate, or injection resistance is rejected; the incumbent stays live. Keep the
rejection history — evidence the gate bites is worth more than a clean record.

### Demonstrating it works — replay the corpus as the analyst

You have 1000 files with ground truth. **Replay 200 incidents feeding the ground-truth disposition
back as the analyst verdict**, and plot metrics over the sequence:

Brier score falling · per-detector precision rising · judge miss rate falling · human–AI alignment
climbing · kNN/LOF reference set growing.

That converts "we have a learning loop" into a measured improvement curve with real ground truth.
State plainly in the README that the analyst is simulated from labels.

New table:

```sql
CREATE TABLE learning_events (
  id BIGSERIAL PRIMARY KEY,
  mechanism INT NOT NULL,              -- 1..15
  trigger_feedback_id UUID,
  applied BOOL NOT NULL,               -- false = proposed, awaiting approval
  before_state JSONB, after_state JSONB,
  metric_delta JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

`/learning` renders this as **"what your feedback changed"** — recent adaptations with before/after
metrics, so the loop is visible rather than asserted.

---

# 22. Feedback UI

Currently missing entirely. Incident detail gains:

- **Primary bar, always visible:** `Confirm` · `Override` · `Dismiss` — one click each
- **Override** → corrected disposition; corrected technique (dropdown limited to retrieved
  candidates plus `NO_KNOWN_MAPPING`); free text
- **Dismiss** → reason category (sanctioned automation / known business process / expected for
  this entity / insufficient evidence / other); free text; `mark entity baseline` checkbox
- **Per-claim thumbs** on narrative claims, hover-revealed
- **Evidence relevance toggle** in the per-incident Evidence section
- **Confirmation toast naming the effect**: *"Added to benign reference set — similar activity will
  score lower."* The analyst should see that feedback did something.

---

# 23. Shared workspace, single live tenant

**Every login lands in the same workspace and sees identical data.** Authentication still exists
(the brief requires it) but does not partition data.

- One live tenant, `northwind`, seeded from the corpus baseline.
- All uploads, incidents, feedback, and learning state are shared. A reviewer's feedback is
  visible to the next reviewer — good for the demo.
- Remove per-user scoping from queries. **Keep `tenant_id` on every table and in the query layer** —
  it costs nothing and Tier 2 needs it.

### Tier 2 still works

Tier 2 aggregates the live tenant plus **two seeded peer tenants** (`contoso`, `fabrikam`) —
the val and golden corpus orgs, loaded at seed time as `tier2_signatures`.

For cross-tenant indicator overlap to be demonstrable, the same indicators must genuinely appear
in more than one tenant. The generator has been updated with a shared campaign-domain pool so a
subset of C2 and exfiltration scenarios across all three orgs draw from the same domains. Verify
at seed time that overlap is non-zero before shipping.

---

# 24. GCP deployment

All services on GCP, coordinated by orchestrator and RabbitMQ.

| Component | GCP service | Notes |
|---|---|---|
| `web` (Next.js) | Cloud Run | public |
| `api` (FastAPI) | Cloud Run | public, CORS to web origin |
| `orchestrator`, `parser` ×N, `enricher`, `anonymizer`, `detector`, `correlator`, `agent`, `tier2-sync`, `learner` | Cloud Run | **`min-instances=1`, CPU always allocated** |
| RabbitMQ | **CloudAMQP** | no managed RabbitMQ on GCP; CloudAMQP has GCP regions |
| Postgres + pgvector | Cloud SQL for PostgreSQL 16 | enable `vector` extension |
| Object storage | Cloud Storage | replaces MinIO |
| Redis (SSE relay) | Memorystore | small tier |
| Images | Artifact Registry | |
| Secrets | Secret Manager | never in env files |
| CI/CD | Cloud Build | build → push → deploy per service |

**The Cloud Run trap:** by default Cloud Run allocates CPU only during request processing, so a
background queue consumer is throttled to near-zero between requests and messages sit unconsumed.
Every worker needs `--no-cpu-throttling` and `--min-instances=1`. Getting this wrong produces a
pipeline that silently stalls — and it will look like a queue bug, not a config bug.

Alternative if worker cost is a concern: GKE Autopilot for workers, Cloud Run for `web`/`api`.
More correct for long-running consumers, more setup. Cloud Run is the recommended default here.

`docker-compose.yml` must still bring the whole stack up locally with MinIO and local RabbitMQ,
so development never requires GCP.

---

# 25. Test plan

| Layer | Scope | Gate |
|---|---|---|
| **Unit** | parser vs. golden vendor fixtures (8 valid, 5 malformed); every extractor positive + negative; calibrator monotonicity; verifier numeric/existence/retrieval checks; Sigma rule fixtures | 100% of rules and extractors have both fixtures |
| **Contract** | OpenAPI schema matches generated TS types; `StageMessage` round-trip | schema drift fails CI |
| **Integration** | each stage precondition→postcondition; queue retry backoff; DLQ on poison message; chunk completion counter; SSE ordering | kill a worker mid-run → clean dead-letter + retry |
| **Model** | benchmark table; hypothesis-outcome table; distance methods full-space vs. PCA | predictions recorded *before* run |
| **LLM** | recorded fixtures, zero live calls in CI; citation existence; **numeric-claim mismatch must be rejected**; retrieval-match; `NO_KNOWN_MAPPING` reachable; injection canaries | injection resistance = 1.0, else build fails |
| **Judge** | seeded bad findings (fabricated number, unretrieved technique, malice from anomaly alone, missing benign alternative) | each must REJECT |
| **E2E** | upload → overview → timeline → incident → evidence → feedback → learning event | Playwright, headless, in CI |
| **Load** | chunk-parallel throughput at `PARSER_REPLICAS` 1 / 2 / 4 / 8 | measurable speedup, no lost chunks |
| **Security** | unauthenticated route access; NL→SQL rejects mutation, out-of-scope tables, stacked statements; upload type/size/MIME; secrets absent from logs and prompts | any bypass fails the build |
| **Learning** | each of the 15 mechanisms has a test asserting its specific state change; **contamination exclusion has a dedicated test** — confirmed TP must not enter the reference set | all 15 |
| **Tier 2** | cross-tenant overlap non-zero; no identifiable value crosses the boundary | both assertions |

---

# 26. Post-build validation run

**Required after implementation.** The system must be exercised with real data before it is
considered done. Produce every artifact below and commit them.

1. **Seed.** Load the 6-month baseline; seed `contoso` and `fabrikam` Tier 2 signatures. Verify
   `baseline_profiles` is populated and cross-tenant overlap is non-zero.
2. **Ingest 50 corpus files** through the full live pipeline — real LLM calls, no fixtures, mixed
   scenarios including benign controls. Record wall-clock and cost per analysis.
3. **Verify data exists everywhere.** Every dashboard section non-empty: overview, timeline,
   anomalies, evidence, notable users, notable destinations, traffic statistics, Tier 2, learning.
   A section that renders empty in the recording is a bug.
4. **Detection accuracy.** Score against ground truth. Publish per-scenario precision/recall, the
   layer-decomposition table, and the hypothesis-outcome table.
5. **Hallucination audit.** Across all findings: citation validity, numeric-claim rejection count,
   retrieval-match failures, `NO_KNOWN_MAPPING` frequency. Manually read 10 narratives end to end.
6. **Learning replay.** Feed ground-truth dispositions back for 200 incidents. **Produce the
   improvement curve** — Brier, per-detector precision, judge miss rate, alignment. This is the
   headline chart.
7. **Contamination check.** Confirm a true positive, re-run a similar file, assert the score did
   **not** drop.
8. **Tier 2 check.** Confirm a campaign domain appears across ≥2 tenants and that no raw
   identifiable value crossed the boundary.
9. **Injection check.** Run all canary files. Disposition must match the control pair exactly.
10. **Failure injection.** Kill a worker mid-analysis; kill RabbitMQ; submit a malformed file.
    All three recover or dead-letter cleanly with a UI-visible error.

Commit outputs to `evals/validation-run/`: metrics JSON, the learning curve, the benchmark tables,
and the ten read narratives.

---

# 27. Remove Upload, Models, and Ops routes

Three routes deleted. Two of them carried content that must **move, not vanish**.

### `/upload` — deleted, upload moves inline

Upload becomes a drop zone in the header of `/`, alongside the analysis list. On submit, route
straight to `/analyses/[id]`.

**The funnel survives and gets better placement.** `/analyses/[id]` gains a running state: while
`analyses.status` is `queued` or `running`, the page renders the live SSE stage funnel with
counters incrementing (events → signals → incidents → needs attention). When the pipeline
completes, the same page becomes the overview. No separate page, no navigation, and the funnel is
now on the page the analyst actually stays on.

Format sniffing and the 5-line parse preview move into the drop zone as an inline confirmation
step before the upload commits.

`POST /api/uploads` is unchanged.

### `/models` — deleted, content merges into `/learning`

This content is a differentiator and must not be reduced to a README table. `/learning` becomes
the single page about model quality, with the static benchmarks sitting directly above the
improvement curve:

1. **Model performance** — benchmark comparison table (EIF / kth-NN / LOF against the
   iForest, ECOD, and Mahalanobis baselines), full-space vs. PCA for the distance methods
2. **Hypothesis outcomes** — the table from `docs/12`, with predictions recorded before the run
3. **Calibration** — reliability diagram, Brier score
4. **Model versions** — history with the eval scores that gated each promotion
5. **Learning events** — the feed from change 21
6. **What your feedback changed** — recent adaptations with before/after metrics

This is a stronger page than two separate ones: *here is how good the models are, and here is
them getting better.* Keep the `/api/models/*` endpoints as they are — only the route is removed.

### `/ops` — deleted, failures surface on the analysis

Queue depth monitoring belongs in Cloud Monitoring, not in the product. But failures still need a
UI surface, because validation run item 10 requires a UI-visible error on worker death, broker
loss, and malformed input.

Replace with **per-analysis error state**:

- A stage that exhausts retries sets `analyses.status = 'failed'`, `analyses.stage` to the failing
  stage, and `analyses.error` to a human-readable message
- `/analyses/[id]` renders the failure at the point in the funnel where it occurred, so the
  analyst sees *which* stage died rather than a generic error
- The analysis list shows a failed badge
- `POST /api/analyses/{id}/retry` republishes from the failed stage using the dead-lettered
  payload

Delete `/api/ops/queues`, `/api/ops/dead-letters`, `/api/ops/dead-letters/{id}/retry`.
**Keep `/api/health`** — Cloud Run needs it. **Keep the `dead_letters` table** — it is the retry
source and the debugging record; only the console is removed.

### Resulting route list

| Route | Purpose |
|---|---|
| `/login` | credentials |
| `/` | analysis list + upload drop zone + aggregate funnel |
| `/analyses/[id]` | live funnel while running, overview when complete |
| `/analyses/[id]/incidents` | incident queue |
| `/analyses/[id]/incidents/[iid]` | case file — includes per-incident Evidence section |
| `/analyses/[id]/evidence` | analysis-wide evidence browser |
| `/analyses/[id]/events` | raw event explorer |
| `/learning` | model performance + learning loop |
| `/tier2` | cross-tenant analytics + NL→SQL |

Nine routes, down from twelve. Update the M15 acceptance criteria in `docs/13` accordingly.

---

# Application order

1. Change 12 (remove DEMO_MODE), 18 (remove sequence), 19 (remove autoencoder + LightGBM),
   20 (remove response graph) — deletions first, they shrink everything downstream
2. Change 23 (shared workspace) — touches every query
3. Change 1 (baseline store)
4. Change 13 (corpus, regenerated with shared campaign domains)
5. Change 2 (evidence extractors) + navigation chain extractor from change 18
6. Change 3 (two confidences)
7. Changes 4, 5, 6, 7, 14, 15 — RAG, hypothesis evaluation, both LLM paths, verifier ordering
8. Changes 8, 9, 10, 11, 16, 27 — semantic pass, overview, output levels, highlighting,
   evidence views, and the reduced route list. Do change 27 **before** building any UI so the
   deleted pages are never written.
9. Changes 21, 22 — learning loop and feedback UI
10. Change 24 — GCP deployment
11. Change 25 — test plan
12. Change 26 — validation run
13. Update every affected doc in place

Change 17 is a standing instruction, not a work item.
