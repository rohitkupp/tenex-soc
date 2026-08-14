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
  event_key TEXT,          -- discretized token for sequence models
  ocsf JSONB NOT NULL,
  enrichment JSONB NOT NULL DEFAULT '{}'
);

CREATE INDEX ON events (analysis_id, ts);
CREATE INDEX ON events (analysis_id, principal, ts);
CREATE INDEX ON events (analysis_id, domain);
CREATE INDEX ON events (analysis_id, src_ip);
CREATE INDEX ON events USING GIN (ocsf jsonb_path_ops);
```

## Detection

```sql
CREATE TABLE signals (
  id BIGSERIAL PRIMARY KEY,
  analysis_id UUID NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
  tenant_id UUID NOT NULL,
  detector_key TEXT NOT NULL,      -- e.g. sigma.okta_mfa_fatigue, ml.autoencoder
  detector_layer TEXT NOT NULL,    -- rule|signal|ml|sequence|graph
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
  type TEXT NOT NULL,              -- user|src_ip|domain|dst_ip|asn|session
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

CREATE TABLE response_plans (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  incident_id UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  actions JSONB NOT NULL,          -- ordered [{action_id, target, preconditions, rollback}]
  verification JSONB NOT NULL,     -- LLM safety pass result
  status TEXT NOT NULL DEFAULT 'pending_approval',
  approved_by UUID REFERENCES users(id),
  approved_at TIMESTAMPTZ,
  execution_log JSONB NOT NULL DEFAULT '[]',
  outcome TEXT,                    -- contained|partially_contained|failed
  outcome_detail JSONB
);
```

## Enforcement plane (simulated, stateful)

```sql
CREATE TABLE enforcement_state (
  id BIGSERIAL PRIMARY KEY,
  tenant_id UUID NOT NULL,
  resource_type TEXT NOT NULL,     -- proxy_policy|okta_session|okta_factor|host|api_key
  resource_id TEXT NOT NULL,
  state JSONB NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, resource_type, resource_id)
);

CREATE TABLE enforcement_journal (
  id BIGSERIAL PRIMARY KEY,
  plan_id UUID NOT NULL REFERENCES response_plans(id),
  action_id TEXT NOT NULL,
  before_state JSONB,
  after_state JSONB,
  succeeded BOOL NOT NULL,
  precondition_failure TEXT,
  executed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

The journal is what makes rollback real — reverse-iterate and restore `before_state`.

## Learning

```sql
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
  model_key TEXT NOT NULL,         -- autoencoder|iforest|lightgbm|logbert|markov
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
