# 02 — Data Model

Postgres 16 + pgvector. All tables carry `tenant_id`; every query filters on it.
Alembic migration per change, no exceptions.

## Core

```sql
CREATE TABLE tenants (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  pseudonym_salt BYTEA NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES tenants(id),
  email CITEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,          -- argon2id
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE uploads (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES tenants(id),
  user_id UUID NOT NULL REFERENCES users(id),
  filename TEXT NOT NULL,
  size_bytes BIGINT NOT NULL,
  sha256 TEXT NOT NULL,
  storage_ref TEXT NOT NULL,
  detected_sources TEXT[] NOT NULL DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE analyses (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES tenants(id),
  upload_id UUID NOT NULL REFERENCES uploads(id),
  status TEXT NOT NULL DEFAULT 'queued',   -- queued|running|complete|failed
  stage TEXT,
  progress REAL NOT NULL DEFAULT 0,
  pending_parsers INT NOT NULL DEFAULT 0,
  counters JSONB NOT NULL DEFAULT '{}',    -- events/signals/incidents/needs_attention
  parse_failure_rate REAL,
  llm_cost_usd NUMERIC(10,4) DEFAULT 0,
  error TEXT,
  started_at TIMESTAMPTZ,
  finished_at TIMESTAMPTZ
);
```

## Events

Hot columns are indexed; full OCSF fidelity lives in `ocsf`. Bulk-load with `COPY`, never
row-by-row inserts.

```sql
CREATE TABLE events (
  id BIGSERIAL PRIMARY KEY,
  analysis_id UUID NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
  tenant_id UUID NOT NULL,
  ts TIMESTAMPTZ NOT NULL,
  source_type TEXT NOT NULL,
  raw_line_no INT NOT NULL,
  ocsf_class_uid INT NOT NULL,
  -- hot columns
  principal TEXT,          -- pseudonymized user
  src_ip INET,
  dst_ip INET,
  domain TEXT,
  url_path TEXT,
  action TEXT,
  http_method TEXT,
  status_code INT,
  bytes_in BIGINT,
  bytes_out BIGINT,
  user_agent TEXT,
  event_key TEXT,          -- discretized token, Drain3-templated on url_path (see docs/03)
  -- device/asset hot columns — asset-tag task, docs/v1/zscaler-nss-web-fields.md
  hostname TEXT,           -- Client Connector device hostname (not the URL host — that's `domain`)
  device_name TEXT,        -- opaque device identifier
  device_owner TEXT,       -- the asset's assigned user (may diverge from `principal`)
  os_type TEXT,            -- normalized: windows|macos|ios|android|linux|chromeos|other
  os_version TEXT,         -- raw, verbatim device OS version string
  bypassed_traffic BOOLEAN,-- traffic that bypassed the Client Connector
  flow_type TEXT,          -- Direct|Loopback|VPN|VPN Tunnel|ZIA|ZPA
  -- Phase 2 detection-field hot column — encoding-variant + detection-field task,
  -- docs/v1/zscaler-nss-web-fields.md. The one field of twenty new ones promoted to a hot,
  -- indexed column; the other nineteen (certificate posture, file hashes, domain fronting, geo
  -- risk, upload metadata, threat severity) ride in `ocsf` JSONB only.
  ja4_hash TEXT,            -- JA4 client TLS fingerprint (pseudonymize via the shared indicator
                             -- salt at the LLM/Tier 2 boundary, docs/06 — not the per-tenant one)
  ocsf JSONB NOT NULL,
  enrichment JSONB NOT NULL DEFAULT '{}'
);

CREATE INDEX ON events (analysis_id, ts);
CREATE INDEX ON events (analysis_id, principal, ts);
CREATE INDEX ON events (analysis_id, domain);
CREATE INDEX ON events (analysis_id, src_ip);
CREATE INDEX ON events USING GIN (ocsf jsonb_path_ops);
CREATE INDEX ON events (analysis_id, ja4_hash);
```

## Detection

```sql
CREATE TABLE signals (
  id BIGSERIAL PRIMARY KEY,
  analysis_id UUID NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
  tenant_id UUID NOT NULL,
  detector_key TEXT NOT NULL,      -- e.g. sigma.large_post_new_domain, ml.autoencoder
  detector_layer TEXT NOT NULL,    -- rule|signal|ml|graph
  raw_score REAL NOT NULL,
  confidence REAL NOT NULL,        -- calibrated 0..1
  entity_type TEXT NOT NULL,
  entity_value TEXT NOT NULL,
  window_start TIMESTAMPTZ,
  window_end TIMESTAMPTZ,
  mitre_technique TEXT,
  evidence_event_ids BIGINT[] NOT NULL,
  explanation JSONB NOT NULL,      -- per-detector; see docs/04
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX ON signals (analysis_id, confidence DESC);
```

`explanation` is a structured payload, not prose. Autoencoder writes per-feature reconstruction
error; tree models write SHAP values; beaconing writes interval statistics. The UI renders it.

## Graph & incidents

```sql
CREATE TABLE entities (
  id BIGSERIAL PRIMARY KEY,
  analysis_id UUID NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
  type TEXT NOT NULL,              -- user|src_ip|domain|dst_ip|asn|country
  value TEXT NOT NULL,
  first_seen TIMESTAMPTZ,
  last_seen TIMESTAMPTZ,
  event_count INT NOT NULL DEFAULT 0,
  risk_score REAL NOT NULL DEFAULT 0,
  attrs JSONB NOT NULL DEFAULT '{}',
  UNIQUE (analysis_id, type, value)
);

CREATE TABLE entity_edges (
  id BIGSERIAL PRIMARY KEY,
  analysis_id UUID NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
  src_entity_id BIGINT NOT NULL REFERENCES entities(id),
  dst_entity_id BIGINT NOT NULL REFERENCES entities(id),
  relation TEXT NOT NULL,
  weight REAL NOT NULL DEFAULT 1,
  event_count INT NOT NULL DEFAULT 0
);

CREATE TABLE incidents (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  analysis_id UUID NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
  tenant_id UUID NOT NULL,
  title TEXT NOT NULL,
  severity TEXT NOT NULL,          -- set by fusion, NOT by the LLM
  fused_score REAL NOT NULL,
  entity_ids BIGINT[] NOT NULL,
  signal_ids BIGINT[] NOT NULL,
  status TEXT NOT NULL DEFAULT 'open',
  recurrence_of UUID REFERENCES incidents(id),
  recurrence_similarity REAL,
  embedding VECTOR(1024),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX ON incidents USING hnsw (embedding vector_cosine_ops);
```

## Triage & response

```sql
CREATE TABLE triage_verdicts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  incident_id UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  disposition TEXT NOT NULL,
  confidence REAL NOT NULL,
  llm_severity_opinion TEXT,       -- recorded for disagreement metric, not used for ranking
  mitre_techniques JSONB NOT NULL,
  summary TEXT NOT NULL,
  narrative JSONB NOT NULL,        -- [{step, claim, evidence_event_ids}]
  contradicting_evidence TEXT,
  recommended_actions JSONB NOT NULL,
  tool_trace JSONB NOT NULL,
  citation_valid BOOL NOT NULL,
  invalid_citations JSONB NOT NULL DEFAULT '[]',
  model TEXT NOT NULL,
  tokens_in INT, tokens_out INT,
  cost_usd NUMERIC(10,6),
  latency_ms INT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- REMOVED by docs/v2_migration change 20 (response action graph + enforcement plane):
--   response_plans, enforcement_state, enforcement_journal.
-- The agent stage now publishes directly to q.tier2, and the LLM's `recommended_actions`
-- became free-text investigation guidance for a human analyst rather than action IDs from a
-- catalog. Autonomous containment rate is gone as a metric; the learning loop is now the
-- system's closing loop. Migration: bcc348df665e.

CREATE TABLE analyst_feedback (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  verdict_id UUID NOT NULL REFERENCES triage_verdicts(id),
  user_id UUID NOT NULL REFERENCES users(id),
  agrees BOOL NOT NULL,
  corrected_disposition TEXT,
  corrected_technique TEXT,
  dismissal_reason TEXT,           -- feeds suppression rule generation
  mark_benign_baseline BOOL NOT NULL DEFAULT false,
  note TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE detector_stats (
  detector_key TEXT PRIMARY KEY,
  tenant_id UUID NOT NULL,
  true_positives INT NOT NULL DEFAULT 0,
  false_positives INT NOT NULL DEFAULT 0,
  fusion_weight REAL NOT NULL DEFAULT 1.0,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE model_versions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  model_key TEXT NOT NULL,         -- autoencoder|iforest|mahalanobis|ecod|lof|lightgbm
  version INT NOT NULL,
  artifact_ref TEXT NOT NULL,
  trained_at TIMESTAMPTZ NOT NULL,
  eval_scores JSONB NOT NULL,
  promoted BOOL NOT NULL DEFAULT false,
  UNIQUE (model_key, version)
);
```

## Ops & Tier 2

```sql
CREATE TABLE dead_letters (
  id BIGSERIAL PRIMARY KEY,
  analysis_id UUID,
  stage TEXT NOT NULL,
  payload JSONB NOT NULL,
  error TEXT NOT NULL,
  attempts INT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  retried_at TIMESTAMPTZ
);

CREATE TABLE tier2_signatures (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_hash TEXT NOT NULL,       -- HMAC, not tenant_id
  incident_type TEXT NOT NULL,
  mitre_techniques TEXT[] NOT NULL,
  source_types TEXT[] NOT NULL,
  confidence REAL NOT NULL,
  indicator_hashes TEXT[] NOT NULL,  -- HMAC'd domains/IPs for cross-tenant overlap
  observed_at TIMESTAMPTZ NOT NULL,
  embedding VECTOR(1024)
);
```

`indicator_hashes` is what enables "this C2 domain appeared in 3 other tenants" without any
tenant seeing another's raw data. Same salt across tenants for indicators only — document
this tradeoff in the README.

## Eval

```sql
CREATE TABLE eval_runs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  git_sha TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  metrics JSONB NOT NULL,
  passed BOOL NOT NULL
);
```


## Baseline store — `docs/v2_migration` change 1

The single biggest change in the v2 migration. Percentiles, rarity, and deviations previously
resolved against the uploaded file, which meant "unusual" was only ever "unusual relative to the
last few hours we happened to be given". They now resolve against persistent per-tenant history,
which is what makes a statement like *"Alice has contacted github.com 7,921 times and this domain
zero times"* possible at all.

```sql
CREATE TABLE baseline_windows (
  id BIGSERIAL PRIMARY KEY,
  tenant_id UUID NOT NULL,
  entity_type TEXT NOT NULL,          -- user|src_ip|department|org
  entity_value TEXT NOT NULL,
  window_start TIMESTAMPTZ NOT NULL,
  features JSONB NOT NULL,
  UNIQUE (tenant_id, entity_type, entity_value, window_start)
);
CREATE INDEX ON baseline_windows (tenant_id, entity_type, entity_value);

CREATE TABLE baseline_profiles (
  tenant_id UUID NOT NULL, entity_type TEXT NOT NULL, entity_value TEXT NOT NULL,
  metric TEXT NOT NULL,
  p50 DOUBLE PRECISION, p95 DOUBLE PRECISION, p99 DOUBLE PRECISION,
  mean DOUBLE PRECISION, mad DOUBLE PRECISION,
  n_windows INT NOT NULL,
  PRIMARY KEY (tenant_id, entity_type, entity_value, metric)
);

CREATE TABLE baseline_contacts (
  tenant_id UUID NOT NULL, scope TEXT NOT NULL, scope_value TEXT NOT NULL,
  domain TEXT NOT NULL, contact_count BIGINT NOT NULL,
  first_seen TIMESTAMPTZ NOT NULL, last_seen TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (tenant_id, scope, scope_value, domain)
);
CREATE INDEX ON baseline_contacts (tenant_id, domain);
```

Migration `744b82efc029`. Loaded by `app/baseline/loader.py` (idempotent via `ON CONFLICT DO
UPDATE`, not a pre-check), read through `app/baseline/resolve.py`.

### The feature vector actually stored — a three-way mismatch, recorded not smoothed over

The migration's own SQL comment says `features` holds "the same ~50-feature vector as L3".
`docs/v1/04-DETECTION.md` specifies roughly **40** named features across seven families. The
delivered generator's `build_baseline()` emits exactly **nine**:

`n_events` · `n_unique_domains` · `bytes_out` · `bytes_in` · `post_ratio` · `blocked_ratio` ·
`off_hours_ratio` · `automation_ua_ratio` · `direct_ip_ratio`

Those cover five of the seven families. **Session and most of Device are absent, and none of the
entity-relative variants** (`_z_vs_own_history`, `_z_vs_cohort`) exist in the baseline — which is
notable, because those were the features whose introduction falsified pre-registered prediction 2
(see `AI_APPROACH.md`).

The loader stores the nine that exist and fabricates nothing. Change 1 also says "L3 models train
on `baseline_windows`" — so L3's input vector is bounded by what the baseline carries, and any
detector that silently loses an input must be treated as a real regression rather than absorbed.
Closing this gap means extending the generator, not the loader.

### Cold start is a first-class return value

An entity with `n_windows < 20` returns `baseline_status: "insufficient_history"` and **no
percentile** — never a number computed from four windows. That is part of the resolver's return
type rather than a caller's responsibility, so it cannot be forgotten at a call site.

### Contact scope rollup

The generator emits contacts at **user scope only**; the table and change 1 require user,
department, and org. The loader derives the two higher scopes deterministically. Department comes
from `app/baseline/org_directory.py`, which reconstructs the seeded org
(`Org.build("northwind", 250, 12, random.Random(42))` — exactly what `build_baseline()` uses), and
both the loader's rollup and the resolver's department lookup call that one function so they
cannot drift apart. It is scoped to the single seeded live tenant (change 23), not a general
identity directory.

`baseline_contacts.json` carries no per-contact timestamps, so `first_seen`/`last_seen` are set to
the min/max `window_start` actually loaded in that run — a true statement about the period rather
than an invented date.

### Percentiles from summary statistics

`baseline_profiles` stores five summary numbers, not raw samples, so `percentile_for` reuses
docs/04's robust-z (`0.6745 * (x - median) / MAD`) against the precomputed median and MAD and maps
through the standard normal CDF. It diverges from `app.detection.features.robust_z` in one
deliberate respect: it returns a **signed** infinity when `MAD == 0`, because a percentile needs a
direction where a deviation magnitude does not.


## Two confidences — `docs/v2_migration` change 3

A behaviour can be extremely anomalous and not remotely malicious. Collapsing those into one
number is the mistake this change exists to prevent, so the schema now carries both separately
and they are never mixed.

```sql
ALTER TABLE incidents        ADD COLUMN anomaly_confidence REAL;          -- 0–100
ALTER TABLE triage_verdicts  DROP COLUMN confidence;
ALTER TABLE triage_verdicts  ADD COLUMN threat_confidence TEXT;           -- low|moderate|high
ALTER TABLE triage_verdicts  ADD COLUMN threat_confidence_reason TEXT;
```

Migration `81f36664938b`.

| | Source | Means | Range |
|---|---|---|---|
| `anomaly_confidence` | ML + evidence layer, isotonic-calibrated | how unusual vs. history | 0–100 |
| `threat_confidence` | hypothesis evaluation | how well evidence supports *this specific* interpretation | low / moderate / high |

### The LLM may not modify `anomaly_confidence`, and that is enforced in code

It is passed into the prompt with an explicit instruction to reproduce it unchanged, and
`app/agent/verifier.py::verify_anomaly_confidence` compares the returned value against
`AgentContext.anomaly_confidence` deterministically. A mismatch raises and the whole verdict falls
to `needs_review` with the reason recorded — a **hard rejection**, not the soft per-claim flag
citation failures get, because a model that silently rewrote a calibrated statistical score has
produced output whose provenance can no longer be trusted at all.

The comparison tolerance is `1e-6`, sized purely to absorb Postgres `REAL` round-trip noise. It is
not there to be lenient.

`anomaly_confidence` has exactly one derivation point,
`app/detection/fusion.py::anomaly_confidence_from_fused_score()`, called by every path that
persists an incident, so the score and the confidence cannot drift apart. Nothing in the agent
path writes it — `triage_verdicts` does not even have the column.

### Backfill

`incidents.anomaly_confidence` ← `fused_score * 100`, exact rather than approximate since it is the
same number rescaled. `triage_verdicts.threat_confidence` ← bucketed from the old float
(≥0.75 high, ≥0.4 moderate, else low), with `threat_confidence_reason` stating plainly that it is a
migration artifact rather than a genuine hypothesis-evaluation judgement — a reader should not
mistake a mechanical bucketing for reasoning. `downgrade()` reverses both from bucket midpoints;
lossy by construction in both directions, but it always round-trips to a valid, fully populated
schema rather than leaving NULLs.


## Device/asset hot columns & the asset tag bank — this task

Migration `f4c8a1d9e2b6`, seven new `events` columns (`hostname`, `device_name`, `device_owner`,
`os_type`, `os_version`, `bypassed_traffic`, `flow_type`, listed in the `events` table above) —
the "critical gap" this task closes: Zscaler Client Connector device fields
(`docs/v1/zscaler-nss-web-fields.md`) had no column to land in, so the parser had nothing to map
them to and `incidents.tags` had no device data to aggregate. No new `incidents` column: that
table's `tags TEXT[]` (migration `356bd7cbdfe9`) already exists as a flat, namespaced list —
`app.graph.asset_tags.compute_asset_tags` adds a second family of namespaces
(`device:`/`os:`/`os_version:`/`dept:`/`location:`/`app:`/`risk:`/`flow:`, plus derived
`bypassed-client-connector`/`shared-device`) onto the *same* column, unioned with
`app.graph.tags.compute_incident_tags`'s technique/layer/detector tags at correlate time
(`app.pipeline.stages.correlate`), not a second array.

No index on any of the seven — consistent with `user_agent`/`http_method`/`action` (already
unindexed hot columns on this table): asset-tag computation reads them through a targeted
`id IN (...)` query over one incident's own evidence events, never a full-table scan.

`hostname`/`device_name`/`device_owner` are identifiers (docs/06's do list: "usernames... IPs,
hostnames... device IDs") and are pseudonymized at the LLM/Tier 2 boundary exactly like
`principal`/`src_ip` — see docs/06's own addendum on this. `os_type`/`os_version`/
`bypassed_traffic`/`flow_type` are categorical/behavioral metadata, not identifiers, and stay
plaintext at every boundary, the same status `user_agent`/`http_method` already have.


## Phase 2 detection fields — encoding-variant + detection-field task

Migration `c2a71f5e9d34`, one new `events` column (`ja4_hash`, listed in the `events` table
above) plus its own dedicated index — the only one of twenty new Phase 2 detection fields
(`docs/v1/zscaler-nss-web-fields.md` "SSL/TLS", "Server Connection", "Sandbox", "File Type
Control", "Network", "Threat Protection") promoted to a hot column. The rest (certificate
posture, file hashes, domain fronting, geo risk, upload metadata, threat severity) ride in `ocsf`
JSONB only, unindexed — the same treatment `urlcategory`/`appname`/`threatname` already get; see
`app.models.event.Event`'s own comment for why `ja4_str` specifically earns the column (a better
cross-tenant Tier 2 indicator than a domain, per this task's own design note — an indexed
`(analysis_id, ja4_hash)` lookup is the "same fingerprint, different domain" query that value
depends on being cheap).

`ja4_hash` is an identifier (a client TLS fingerprint) but does **not** follow `hostname`/
`device_name`'s per-tenant pseudonymization route above — it routes through
`app.privacy.pseudonymize.indicator_hash`'s *shared*, cross-tenant salt instead, at whichever
boundary eventually serializes it to an LLM prompt or a Tier 2 signature (not wired up by this
task — see docs/06's own Phase 2 addendum for the full reasoning). `sha256`/`bamd5` (also
identifiers, also indicator-hash-routed by the same reasoning) are not hot columns at all —
`ocsf.file` JSONB only — so no column-level privacy decision applies to them here.

No backfill for `ja4_hash`: rows written before this revision were parsed by a version of
`app.parsers.zscaler` that never read `%s{ja4_str}`, so every existing row gets `NULL`, the
honest state for a historical row (same policy the device columns above already established).
