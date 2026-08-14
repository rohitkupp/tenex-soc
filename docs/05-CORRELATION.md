# 05 — Entity Graph & Incident Correlation

Turns hundreds of signals into a dozen readable incidents. This stage is what makes the output
usable by a human, and it is where cross-source correlation becomes visible.

## Graph construction

`networkx.MultiGraph`, built per analysis in `graph/builder.py`.

**Nodes** (`entities` table)
| Type | Value | Source |
|---|---|---|
| `user` | pseudonymized principal | all |
| `src_ip` | client IP | all |
| `domain` | registrable domain | proxy |
| `dst_ip` | server IP | proxy |
| `asn` | AS number | enrichment |
| `country` | ISO code | enrichment |
| `session` | session id | identity |

**Edges** (`entity_edges`) — derived from co-occurrence within a single event:
`user —accessed→ domain`, `user —from→ src_ip`, `src_ip —resolves_to→ asn`,
`domain —hosted_at→ dst_ip`, `user —authenticated_from→ country`, `user —owns→ session`.

Edge `weight` = event count, log-scaled. Prune singleton edges below a configurable threshold to
keep the graph tractable; record what was pruned.

## Incident formation

1. Mark every entity carrying at least one signal as a **seed**.
2. Expand each seed to its 1-hop neighborhood.
3. Induce a subgraph over the union of seeds and their neighborhoods.
4. Run **Louvain community detection** on the induced subgraph.
5. Each community containing ≥ 1 seed becomes one incident.
6. Merge communities sharing ≥ 50% of their seed entities.

Rationale to record in the README: alerting per signal produces alert fatigue; alerting per
community produces stories. A single incident that contains an Okta impossible-travel signal and
a ZScaler beaconing signal on the same principal is one investigation, not two alerts.

## Incident scoring

```
base       = fusion over member signals (docs/04 §Fusion)
graph_bonus = 1 + 0.15*log1p(n_distinct_detector_layers)
                + 0.20*(1 if multi_source else 0)
                + 0.10*min(community_signal_density, 1)
fused_score = min(base * graph_bonus, 0.99)
```

The bonus encodes a real belief: corroboration across independent detection methods and
independent log sources is stronger evidence than any single high-scoring signal.

## Incident titling

Deterministic template, not LLM-generated — titles must be stable across runs for the eval
harness to match on them:

```
"{top_technique_name} — {primary_entity_type} {primary_entity_value_short}"
e.g. "Command and Control — user u_8f3a91"
```

The LLM writes the `summary` and `narrative`; it does not write the title.

## Recurrence detection

Replaces the heavyweight signature/dedup service. Cheap and directly attacks alert fatigue.

1. Build a canonical text representation of the incident: sorted technique IDs, detector keys,
   entity types, and enrichment tags. **Not** the raw entity values — we want structural
   similarity, not identity.
2. Embed it. Store in `incidents.embedding`.
3. Cosine search against prior incidents for the same tenant via the HNSW index.
4. If similarity ≥ 0.92, set `recurrence_of` and `recurrence_similarity`.
5. Recurrences skip agent triage entirely and inherit the parent's verdict — a direct LLM cost
   saving, and worth showing in the funnel counters.

Surface in the UI as "Recurrence of #14, seen 3 times this week" rather than a fresh alert.

## Timeline

Per incident, the timeline is built **deterministically** from member events, ordered by `ts`.
The agent only annotates each phase with an ATT&CK tactic. Never let the model order events —
ordering is a fact, and getting it from the database is both accurate and free.

Output shape:
```json
[{ "ts": "...", "tactic": "Initial Access", "event_ids": [123, 124],
   "summary": "Authentication from previously unseen ASN" }]
```
