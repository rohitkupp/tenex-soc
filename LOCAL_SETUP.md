# Running this locally

A step-by-step guide to getting the Tenex SOC Analyst pipeline running on your own machine,
written to be followed literally from a fresh `git clone`.

Everything runs in Docker. You do not need Python, Node, Postgres or anything else installed.

> If you just want the commands, jump to [The short version](#the-short-version). The rest of
> this document explains what each step does and what to do when something goes wrong.

---

## 1. What you need before you start

| | |
|---|---|
| **Docker Desktop** | Running, with at least **8 GB** of memory allocated (Settings → Resources). The stack is 16 containers. |
| **Disk space** | Keep **~20 GB** free. Measured actual use: ~9 GB of images, ~2 GB of database volumes, and ~600 MB of generated baseline and model artifacts inside the repo. |
| **An Anthropic API key** | Required for the AI triage layer, **with credit on the account**. Get one at [console.anthropic.com](https://console.anthropic.com/) → API Keys → Create Key. This must be an **API key**, not a Claude.ai Pro/Max subscription — those are separate products and a subscription grants no API access. |
| **Claude Sonnet 5** | Leave `ANTHROPIC_MODEL=claude-sonnet-5` as shipped. It is the model this project was built and measured against, and the cheaper of the two ids the app accepts. |
| **Time** | About **5 minutes of setup**, then about **12 minutes** for the recommended demo analysis (measured end to end). Both are unattended. |

### About the API key

The application makes **real Anthropic API calls**. There is no offline or canned-response mode —
`DEMO_MODE` was deliberately removed so that latency and cost are visible rather than hidden
behind precomputed verdicts.

- **Use Claude Sonnet 5.** `.env.example` ships `ANTHROPIC_MODEL=claude-sonnet-5` and you should
  leave it there. Only two model ids are accepted at all — `claude-sonnet-5` ($3/$15 per Mtok)
  and `claude-opus-5` ($5/$25) — and anything else raises rather than guessing at cost. Opus
  roughly doubles the per-incident spend for no benefit here.
- **Cost, measured rather than estimated:** triage averages **~$1.40 and ~3 minutes per
  incident**, so a run costs whatever the uploaded log's incident count comes to, capped by
  `MAX_TRIAGE_INCIDENTS` (shipped at 10). The recommended demo log is
  `backend/data/demo5_tiny/scenario_c2_beaconing.log` — **that directory holds the five logs this
  guide uses, and they are the only files you need to upload.** It is 100 lines and produces only a
  handful of incidents: **measured at $3.09 and 12 minutes**, producing 5 incidents. The other four
  are the same order of size (73–181 lines), so budget a similar few dollars for each.
- **Make sure the account has credit.** If it runs dry mid-run, the triage stage takes a
  non-retryable HTTP 400 and the entire analysis is marked `failed`. Verdicts already paid for
  are kept and stay browsable in the UI, but the run does not resume on its own.
- **You can evaluate most of the system without a key.** Ingest, parsing, all three detection
  layers, correlation and the whole UI work fine — you simply get incidents with no LLM
  narrative, disposition or ATT&CK mapping. See [Running without an API key](#running-without-an-api-key).
- **The test suite never needs a key.** It replays recorded fixtures.

---

## 2. The short version

```bash
git clone https://github.com/rohitkupp/tenex-soc.git
cd tenex-soc

cp .env.example .env
#  → open .env and set ANTHROPIC_API_KEY=sk-ant-...

make up                 # build + start all 16 containers   (~2-10 min, see note)
make migrate            # create the database schema        (~5 s)
make gen-data FILES=10  # generate the historical baseline  (~10 s)
make seed               # demo user, Tier 2 peers, baseline (~20 s)
make train              # fit the detection models          (~2 min)
```

Then open **http://localhost:3000**, log in with:

```
demo@tenex.local
tenex-demo-password
```

then click **Click to browse** on the Analyses page and pick
**`backend/data/demo5_tiny/scenario_c2_beaconing.log`**. That directory —
[`backend/data/demo5_tiny/`](backend/data/demo5_tiny/) — holds the five logs this guide uses; it
is the set to demo with.

Measured on a 15-CPU / 8 GB Docker Desktop: **~2 minutes for `make up`** once Docker has the
base images, and about **2.5 minutes for the other four targets combined**. Budget closer to 10
minutes for `make up` on a machine that still has to pull `python:3.12-slim`, `node:22-alpine`,
`pgvector/pgvector:pg16`, `rabbitmq`, `minio` and `redis`.

**The order of those five `make` targets matters.** `make seed` reads files that `make gen-data`
produces, and uploads cannot be analyzed until `make train` has written the model artifacts.
Section 3 explains why.

---

## 3. Step by step

### Step 1 — Clone and configure

```bash
git clone https://github.com/rohitkupp/tenex-soc.git
cd tenex-soc
cp .env.example .env
```

Now open `.env` and set one value:

```ini
ANTHROPIC_API_KEY=sk-ant-api03-...
```

Everything else in the file already has a working local default, and
[`.env.example`](.env.example) documents each one inline — what it does, when you would change
it, and what breaks if it is wrong. Nothing else needs editing.

Two things worth knowing:

- **`.env` is gitignored.** Your key stays on your machine.
- **The placeholder secrets are intentional.** `JWT_SECRET=dev-only-insecure-change-me` and
  friends are recognisable sentinels. They are accepted only while `ENVIRONMENT=local`; booting
  with `ENVIRONMENT=production` while any of them is unchanged raises at startup rather than
  running an app whose JWTs anyone could forge
  ([`backend/app/core/config.py`](backend/app/core/config.py)).

There is also an optional [`frontend/.env.example`](frontend/.env.example), which you only need
if you want to run the Next.js dev server on your host instead of in Docker. The normal path
never touches it — compose supplies those values from the root `.env`.

### Step 2 — Start the stack

```bash
make up
```

This builds the backend and frontend images and starts 16 containers: Postgres (plus a second,
physically separate Postgres for the cross-tenant Tier 2 store), RabbitMQ, MinIO, Redis, the
FastAPI API, the Next.js web app, and nine pipeline workers — one per queue.

**First run measured ~2 minutes** on a machine that already had the base images, and it installs
the Python scientific stack and builds the Next.js production bundle in that time. Budget closer
to 10 minutes if Docker still has to pull `python:3.12-slim`, `node:22-alpine`,
`pgvector/pgvector:pg16`, `rabbitmq`, `minio` and `redis`. Subsequent runs are seconds.

Wait for the API to answer before continuing:

```bash
curl -s http://localhost:8000/api/health
```

You want `{"status":"ok", ...}`. If it refuses the connection, the API container is still
booting — give it another 20 seconds. Check progress with `make ps` or `make logs`.

### Step 3 — Create the schema

```bash
make migrate
```

Runs `alembic upgrade head` inside the API container. This also provisions the SELECT-only
`tier2_readonly` Postgres role used by the Tier 2 layer.

### Step 4 — Generate the historical baseline

```bash
make gen-data FILES=10
```

**Do not skip this, and do not run it after `make seed`.**

Anomaly detection here is relative to what is *normal* for each user, department and
organisation, so the system needs six months of historical rollups to compare an upload against.
Those live in `backend/data/baseline/`, which is **not committed** — it is generated data, and
committing it would put a regenerated corpus a few pushes away from GitHub's file size limit.

`make seed` loads that directory into the `baseline_*` tables and raises `FileNotFoundError` if
it is missing, so this step has to come first.

`FILES=10` is the important part — it takes about 10 seconds. The default is `FILES=1000`, which writes roughly 2.5 GB of
labeled training corpus — that corpus is used for benchmarking, not for running the app, so
there is no reason to generate it just to demo the product. The six-month baseline is a fixed
size regardless of `FILES`, so `FILES=10` gets you everything the application actually needs in
a fraction of the time.

> Do **not** substitute `make gen-data-quick` here. It passes `--skip-baseline`, which is
> precisely the part you need.

### Step 5 — Seed the database

```bash
make seed
```

Four things, in order:

1. The live tenant and the demo user (`demo@tenex.local` / `tenex-demo-password`)
2. Tier 2 peer signatures, so cross-tenant indicator overlap has peers to overlap with
3. The six-month baseline generated in Step 4 (~188,000 windows, ~1,000 profiles, ~16,600
   contact rows), covering the corpus org
4. A second six-month baseline covering the **demo logs' own principals** (~66 users, ~50 source
   IPs, 415 profiles)

Step 4 and step 3 above build the baseline for the *corpus* org (`northwind.example`), but the
logs this guide has you upload — the five in `backend/data/demo5_tiny/` — belong to a different
org on `corp.example`. Without step 4 none of their principals would have a single
baseline row, and every percentile annotation in the UI would read `insufficient history (n=0)`.
Step 4 derives that history from the benign remainder of the demo logs themselves, so the
evidence layer has something real to compare against. Both baselines coexist.

To use a different login, set `SEED_USER_EMAIL` and `SEED_USER_PASSWORD` in `.env` **before**
running this. Changing them afterwards and re-running adds a second user rather than updating
the first.

### Step 6 — Train the detection models

```bash
make train
```

**This is a real prerequisite, not an optimisation.** The L3 model artifacts total ~350 MB and
are not committed — `ecod.joblib` alone is 143 MB, over GitHub's hard 100 MB per-file limit, and
it is that large because ECOD is instance-based: the artifact *is* the training set.

The detect stage loads all seven artifacts *before* it writes anything, and fails the analysis
permanently if any is missing, with a message naming this command. That is deliberate — a run
that quietly skipped L3 and reported zero ML signals would look like a successful analysis.

Training generates its own clean benign corpus (400k events into `/tmp/m8_corpus`), so it does
**not** depend on Step 4. It is seeded and deterministic: same input, same models, every time.
Expect about **2 minutes**, and ~330 MB of artifacts in `backend/data/models/`.

### Step 7 — Log in and upload a log from `backend/data/demo5_tiny/`

Open **http://localhost:3000** and sign in:

```
email:    demo@tenex.local
password: tenex-demo-password
```

**Click the "Click to browse" control** — top right of the Analyses page — and select this file
in the picker that opens. Use the button; dragging a file onto the dashed area does not start an
upload.

```
backend/data/demo5_tiny/scenario_c2_beaconing.log
```

100 lines, 6 users, 3 days. 55 of those lines are a C2 beacon — `nbertrando@corp.example` calling
`bfuxjndgrpcpsfbeqb.xyz` at regular intervals, a textbook DGA domain. It is the fastest way to
see the whole pipeline work end to end, and it is cheap: 5 incidents, about $3.

Four more single-scenario logs sit beside it in
[`backend/data/demo5_tiny/`](backend/data/demo5_tiny/), all the same shape. **These five are the
files to upload** — every filename in the table below is relative to that directory:

| File — all in `backend/data/demo5_tiny/` | Lines | Malicious | Campaign |
|---|--:|--:|---|
| **`scenario_c2_beaconing.log`** | 101 | 55 | **Start here.** C2 beaconing (T1071.001) |
| `scenario_multi_domain_c2_failover.log` | 181 | 120 | C2 with failover across four domains (T1008) |
| `scenario_data_exfiltration.log` | 73 | 27 | Exfiltration to cloud storage (T1567.002) |
| `scenario_web_shell_probing.log` | 151 | 90 | Web shell probing (T1505.003) |
| `scenario_prompt_injection_canary.log` | 85 | 24 | Log content that tries to hijack the LLM prompt |

**When one run is not enough, work down that table** — each file exercises a different path
through the system, and each is small enough to stay a few-dollar run:

- **`scenario_multi_domain_c2_failover.log`** — the correlation showcase. Four sibling DGA domains
  behind one `99.156.0.0/16`, 30 callbacks each from a single host. The question it asks is whether
  the entity graph pulls all four into **one** incident on shared infrastructure, or reports four
  unrelated ones; its labels assert the former.
- **`scenario_data_exfiltration.log`** — ~950 MB in 23 POSTs of ~40 MB, off-hours, to
  `drivehub.buzz`, registered six days earlier. Several kinds of evidence stack on one entity:
  volume burst, an inverted out/in byte ratio, and a newly-registered destination.
- **`scenario_web_shell_probing.log`** — 90 probe requests against a host the org has never
  contacted, of which 6 return 200. The interesting part is the blocked-then-allowed pattern, which
  is a Sigma rule rather than a model.
- **`scenario_prompt_injection_canary.log`** — the adversarial one. Its 24 malicious requests carry
  payloads engineered to hijack the triage agent — instruction override, delimiter escape, turn
  forgery, tool coercion, authority spoofing, system-prompt leak — hidden in the `useragent`, `url`
  and `referer` fields, the longest running 568 characters against a 256-character truncation limit.
  Log content is treated as untrusted data end to end, so the verdict should come back unmoved.

Every one of these is a real-format ZScaler NSS log carrying all 181 documented fields — the same
shape `app/parsers/zscaler.py` sniffs in production, not a trimmed demo format. Each ships with a
`.labels.json` beside it holding ground truth: `malicious_line_numbers`, the ATT&CK `technique`,
the `primary_entity` it victimises, the `expected_detectors` that should fire, and the
`expected_disposition` the agent should reach. That is what makes these more than a smoke test —
you can check what the system found against what was actually there, which is the same comparison
`evals/` runs.

### Step 8 — Watch it run

The analysis page streams progress as the upload moves through the pipeline: parse → enrich →
detect → correlate → triage → anonymize.

Everything up to triage finishes in **well under a minute**. Triage is the long pole — it is
making live LLM calls, roughly **3 minutes per incident** — but on the recommended demo log there
are only a handful of incidents to triage, so the whole run takes around 10 to 15 minutes.

`MAX_TRIAGE_INCIDENTS` (shipped at 10) is a **cap, not a target**: the run triages whichever is
smaller, that number or the incidents the upload actually produced. The recommended demo log
yields **100 events → 115 signals → 5 incidents**, so the cap never binds and the run costs
about $3.

You do not have to wait for triage to finish before exploring. Events, signals, evidence and the
entity graph are all populated and browsable as soon as detect and correlate are done.

Check the result against ground truth: `backend/data/demo5_tiny/scenario_c2_beaconing.labels.json`
marks **55 of the 101 lines** as the T1071.001 beacon, names `nbertrando@corp.example` as the
victim, and lists the detectors that should fire (`signal.beaconing`, `signal.rarity`,
`signal.dga`).

Read the demo as a demo. These five files run between 28% and 66% malicious lines — a deliberately
generous ratio, chosen so a 100-line file can show the whole funnel. Real proxy traffic is far
quieter, and [`backend/evals/results.md`](backend/evals/results.md) scores the system at realistic
ratios where recall drops sharply. Read the benchmark numbers as the honest ones, not the demo.

---

## 4. Where everything lives

| Service | URL | Credentials |
|---|---|---|
| **Web UI** | http://localhost:3000 | `demo@tenex.local` / `tenex-demo-password` |
| API health | http://localhost:8000/api/health | — |
| API docs (OpenAPI) | http://localhost:8000/api/docs | — |
| RabbitMQ management | http://localhost:15672 | `tenex` / `tenex` |
| MinIO console | http://localhost:9001 | `tenexminio` / `tenexminio123` |
| Postgres | `localhost:5432` | `tenex` / `tenex`, db `tenex` |
| Tier 2 Postgres | `localhost:5433` | `tenex` / `tenex`, db `tenex_tier2` |

Useful commands (`make help` lists them all):

```bash
make ps          # container status
make logs        # tail everything
make down        # stop, keeping data
make clean       # stop AND delete all volumes (full reset)
make test        # backend + frontend test suites (no API key needed)
make eval        # the benchmark harness
```

---

## 5. Troubleshooting

**`make migrate` fails with "no such service" or a connection error**
The API container has not finished starting. Wait for `curl -s http://localhost:8000/api/health`
to return JSON, then retry.

**Port already allocated on 3000, 8000, 5432, 5433, 5672, 15672, 9000, 9001 or 6379**
Something else is using that port — often a previous run of this stack, or a local Postgres.
Run `make down` first, or stop the other service.

**`make seed` fails with `FileNotFoundError` mentioning `data/baseline`**
Step 4 was skipped or was run as `make gen-data-quick`. Run `make gen-data FILES=10`, then
`make seed` again.

**Every percentile in the UI reads `insufficient history (n=0)`**
`make seed` did not get as far as `app.scripts.seed_demo_baselines`, so the demo logs' own
principals have no baseline rows. Re-run `make seed`; it is idempotent.

**An analysis fails with "L3 model artifacts missing or stale"**
`make train` has not been run, or was interrupted. Run it again — it is idempotent.

**Triage produces no narrative, or an incident shows an agent error**
`ANTHROPIC_API_KEY` is unset, invalid, or out of credit. Confirm with
`curl -s http://localhost:8000/api/health` — the `llm_enabled` field tells you whether the API
sees a key at all. After editing `.env`, restart so containers pick it up: `make down && make up`.

**Dragging a file onto the upload area does nothing**
Drag-and-drop is not wired up. Click the **Click to browse** control instead and choose the file
from the picker.

**The upload succeeds but nothing progresses**
Check the workers: `make ps` should show every container `Up`. `make logs` will show the failing
stage. Dead-lettered messages are recorded in the `dead_letters` table rather than lost.

**`make seed` fails with `ModuleNotFoundError: No module named 'app.learning'`**
Your checkout predates the fix. Commit `ed9b024` deleted the learning loop but left
`app/scripts/seed_feedback.py` behind still importing it, and `make seed` still called that
script. The `seed` target no longer does. Pull the latest `Makefile`, or just run the three
steps yourself:
`make migrate` then
`docker compose exec -T api python -m app.scripts.seed`,
`... app.scripts.seed_tier2`, `... app.baseline.loader`.

**The analysis is marked `failed` with "credit balance is too low"**
The Anthropic account ran out of credit partway through triage. This fails the whole analysis —
the stage treats an HTTP 400 as non-retryable, correctly, since retrying cannot conjure credit.
Incidents triaged before that point keep their verdicts and are still browsable; the rest stay
untriaged. Top up, lower `MAX_TRIAGE_INCIDENTS`, and upload again.

**Triage seems stuck / is taking far longer than the rest of the pipeline**
That is expected, not a hang — it is ~3 minutes of live LLM calls per incident. Watch it work
with `docker compose logs -f agent`. Lower `MAX_TRIAGE_INCIDENTS` in `.env` and restart to
shorten it.

**Docker runs out of memory / containers get killed**
Raise Docker Desktop's memory allocation to at least 8 GB (Settings → Resources).

**Starting completely over**

```bash
make clean       # deletes containers AND all volumes
make up && make migrate && make gen-data FILES=10 && make seed && make train
```

Then use **Click to browse** to upload `backend/data/demo5_tiny/scenario_c2_beaconing.log` again.

---

## 6. Optional

### Running without an API key

Leave `ANTHROPIC_API_KEY` blank. Everything up to and including correlation runs normally —
upload, parse, all detection layers, the entity graph, incident formation, scoring, and every UI
route. Only agentic triage fails, so incidents carry no LLM narrative, disposition or technique
mapping. `GET /api/health` reports `llm_enabled: false` so the mode is visible from outside.

### Email verification

Not needed, and off by default. With `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY` blank,
`POST /api/auth/signup` marks new accounts verified immediately and logs a warning saying so —
which is what lets a fresh `make up` work with no Supabase project. Supabase Auth is used for
exactly one thing when configured: proving someone controls an email address. It is never the
identity provider; this app keeps its own users, argon2id hashes, JWTs and tenant binding either
way.

### Frontend hot reload

To iterate on the UI with the backend still in Docker:

```bash
cd frontend
cp .env.example .env.local
npm install
npm run dev
```

`frontend/.env.example` explains the two variables and why `API_ORIGIN` differs between host and
container.

### Regenerating the full benchmark corpus

`make gen-data` with no `FILES` override writes the full 1000-file labeled corpus (~2.5 GB) used
by `make eval`. You only need this to reproduce the numbers in
[`backend/evals/results.md`](backend/evals/results.md) — not to run the application.

---

## 7. What to read next

- [`README.md`](README.md) — what the system is and how it is built
- [`AI_APPROACH.md`](AI_APPROACH.md) — the models, what each was benchmarked against, and the
  three results that came back differently than predicted
- [`backend/evals/results.md`](backend/evals/results.md) — every benchmark number
- [`docs/`](docs/) — the design docs, written before the code
