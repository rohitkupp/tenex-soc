# Deployment

Two deploy targets live in this repo side by side — this file documents both and is
explicit about which section is which. Nothing below deletes or replaces the other path.

1. **The VM path** (`deploy/gcp/{provision.sh,ship.sh,compose.prod.yml,Caddyfile}`) — one
   GCE VM running the real `docker-compose.yml` topology behind Caddy. This is what is
   actually live today (see the URLs below) and may stay the live demo regardless of
   whether the path below is ever run.
2. **The Cloud Run path** (`deploy/gcp/cloudrun/`) — docs/v2_migration change 24's fully
   managed topology: every service on Cloud Run, Postgres on Cloud SQL, RabbitMQ on
   CloudAMQP, object storage on GCS, Redis on Memorystore. See "GCP Cloud Run topology"
   near the end of this file. Authored, not deployed — nobody has run it against a real
   project yet.

Live (VM path): frontend https://tenex-soc.vercel.app · API https://34-150-170-252.sslip.io

Two hosts, one reason: **Vercel cannot run this backend.** The pipeline is a long-running,
queue-driven, multi-stage process over files up to 200 MB. Serverless functions cap request bodies
near 4.5 MB, have no persistent filesystem, and time out long before a multi-minute analysis
finishes. So the frontend goes to Vercel, everything else to one VM, and **uploads go browser →
API directly**, never through Vercel. That single decision removes the body-size problem rather
than working around it.

| Component | Host | Why |
|---|---|---|
| `web` (Next.js) | Vercel | Edge-cached, and it is the bonus the brief asks for |
| `api` + all workers | One GCE `e2-standard-2` in `us-east4-b` | Runs the real `docker-compose.yml` topology — same queues, same stage contracts as local, not a reduced variant |
| Postgres + pgvector | Supabase (free tier) | pgvector 0.8.2, IPv4-reachable |
| RabbitMQ, Redis, MinIO | On the VM | Same images as local |
| TLS | Caddy → Let's Encrypt via `sslip.io` | A real certificate without buying a domain |

**Total cost: $0.** GCP's $300 / 90-day trial covers the VM; Supabase and Vercel are free tiers.

**Not Render.** Its free tier spins down after 15 minutes and cold-starts in ~50 seconds. The
reviewer opens the link once; a minute of blank page is the whole first impression.

**Why one VM and not managed everything.** The interesting property of this system is its queue
topology — quorum queues, `x-delivery-limit`, per-stage delay queues that survive `kill -9`. Split
across managed services, most of that becomes someone else's implementation. On one VM the
deployed thing is the thing in `docker-compose.yml`.

## `sslip.io`

`34-150-170-252.sslip.io` resolves to `34.150.170.252` — the service reflects any IP embedded in
the hostname. That gives Caddy a real DNS name to complete an ACME HTTP-01 challenge against, so
the API gets a genuine Let's Encrypt certificate with no domain purchase and no self-signed
warning. It matters beyond aesthetics: the auth cookie is `SameSite=None`, which browsers only
accept on `Secure` (HTTPS) connections.

## First-time provisioning

```bash
deploy/gcp/provision.sh <gcp-project-id> [zone]
```

Creates the firewall rules and the VM, installs Docker via the startup script, and prints the
`sslip.io` address. Then, once, out of band:

1. Copy the production env file to `~/tenex/.env` on the VM. It is **never** in git and never
   shipped by a deploy — see below.
2. Set `NEXT_PUBLIC_API_URL` in the Vercel project to the `sslip.io` address, and `CORS_ORIGINS`
   in the VM's `.env` to the Vercel domain. They reference each other, so both must be set before
   login works: a cookie will not cross origins otherwise.

## Secrets

Never in a compose file, never in git. `app/core/config.py` refuses to boot outside `local` while
any secret is still at its development default, so a misconfigured deploy fails loudly at startup
instead of silently running with a forgeable JWT secret.

```bash
python3 -c 'import secrets; print(secrets.token_urlsafe(48))'   # JWT_SECRET
python3 -c 'import secrets; print(secrets.token_urlsafe(32))'   # PSEUDONYM_SALT, TIER2_*
```

`.gitignore` covers `.env` **and** `.env.*` with an `!.env.example` exception. The narrower `.env`
pattern alone does not match `.env.prod`, which is how a production secrets file nearly got
staged once.

## Deploying

```bash
deploy/gcp/ship.sh          # API + workers
cd frontend && npx vercel --prod --yes
```

`ship.sh` refuses to run on a dirty tree, and packs with `git archive HEAD` — **tracked files
only**, so `backend/.env` and `deploy/gcp/.env.prod` physically cannot reach the server by
accident. It then rebuilds, restarts, runs `alembic upgrade head`, and curls `/api/health`.

## Order of operations

1. `deploy/gcp/provision.sh <project>` — VM, firewall, Docker
2. Put `.env` on the VM (see Secrets)
3. `deploy/gcp/ship.sh` — confirm `/api/health` reports every dependency `ok` and `pgvector: true`
4. `npx vercel --prod` from `frontend/`
5. Set `CORS_ORIGINS` to the real Vercel domain and re-run `ship.sh`

## Things that bit, recorded so they do not bite twice

- **`CORS_ORIGINS` crash-looped the API on the first deploy.** pydantic-settings JSON-decodes
  complex-typed env fields *before* validators run, so a comma-delimited string dies inside
  `json.loads`. `Annotated[list[str], NoDecode]` in `app/core/config.py` is the fix and is
  load-bearing. The bug survived four milestones because the API container had never been started
  locally with production-shaped env vars — there are regression tests now that use real ones.
- **Fly Managed Postgres is $38/month.** Provisioned and destroyed within minutes. Supabase's free
  tier was the right call, and `docs/01` had specified exactly that before the detour.
- **The default `torch` wheel bundles ~2.5 GB of CUDA libraries.** Multiplied across the service
  images, that exhausted the VM's disk mid-build. `backend/Dockerfile` installs the CPU-only wheel;
  nothing here runs on a GPU.

---

## GCP Cloud Run topology

docs/v2_migration/MIGRATION-01-evidence-first.md, change 24. A fully managed alternative to
the VM path above — same application, same images, different hosts for everything.
`docker-compose.yml` is unaffected: local dev still runs the whole stack with MinIO and
local RabbitMQ, no GCP dependency, no change from this section.

| Component | GCP service | Notes |
|---|---|---|
| `web` (Next.js) | Cloud Run | public |
| `api` (FastAPI) | Cloud Run | public, CORS to `web`'s origin |
| `orchestrator`, `parser-zscaler`, `enricher`, `anonymizer`, `detector`, `correlator`, `agent`, `tier2-sync`, `dead-letter-sink` | Cloud Run | `--no-cpu-throttling`, `--min-instances=1` — see "The trap" below |
| `learner` | — | **not deployed.** Listed in the migration table but change 21 (the worker itself) hasn't shipped. `cloudrun/deploy.sh` enumerates it in a commented-out block rather than omitting it silently. |
| RabbitMQ | CloudAMQP | no managed RabbitMQ on GCP; provisioned out of band, see `cloudrun/provision.sh` |
| Postgres + pgvector | Cloud SQL for PostgreSQL 16 | private IP only; `vector`/`citext` extensions created by `alembic upgrade head` itself, no separate enable step |
| Object storage | Cloud Storage (S3-compatible XML API) | replaces MinIO — see "GCS and `app/storage/`" below |
| Redis (SSE relay) | Memorystore, basic tier | private IP only, same VPC connector as everything else |
| Images | Artifact Registry | one Docker repo, two images (`backend`, `frontend`) |
| Secrets | Secret Manager | every secret below; never in an env file |
| CI/CD | Cloud Build | `cloudrun/cloudbuild.yaml`: build → push → deploy, triggered on push to `main` |

### Files

```
deploy/gcp/cloudrun/
├── provision.sh    # one-time: VPC, Cloud SQL, Memorystore, Artifact Registry, GCS, IAM
├── secrets.sh      # populate Secret Manager (never embeds a value in the script itself)
├── deploy.sh       # build-image-agnostic: deploys every Cloud Run service from an
│                   # already-pushed image tag. Called by a human or by cloudbuild.yaml.
└── cloudbuild.yaml # Cloud Build pipeline: build, push, then calls deploy.sh
```

Run order: `provision.sh` → `secrets.sh` → `deploy.sh` (or push to `main` once the Cloud
Build trigger from `provision.sh`'s printed command exists). None of these have been run
against a real project — they are configuration, authored to be reviewed and then run by
a human, same as `deploy/gcp/provision.sh` always has been.

**Cost, stated because the VM path above is genuinely $0 and this one is not.**
Memorystore has no free tier (~$35/mo at the smallest size), Cloud SQL and nine
always-on `--min-instances=1 --no-cpu-throttling` workers are billed by the hour
regardless of load, and CloudAMQP needs its own account. Budget for it before running
`provision.sh` against a billing-enabled project.

### The trap

Cloud Run allocates CPU only while a request is being handled. A queue consumer has no
requests — it sits between deliveries — so without `--no-cpu-throttling` and
`--min-instances=1` it gets throttled to near-zero the instant it goes idle, and messages
pile up on the queue unconsumed. It reads as a stalled pipeline — a queue bug — when it
is actually a Cloud Run config bug, and that's the failure mode this has to be hard to
reintroduce, not just documented against:

- `cloudrun/deploy.sh`'s `deploy_worker` function hardcodes both flags in the function
  body, not as caller-supplied arguments a future worker could be added without.
- Every worker deploy is followed by `assert_worker_flags`, which reads the *deployed*
  revision back from Cloud Run and `exit 1`s the whole script if either flag did not
  actually stick — an executable check, not just a comment someone could skim past.
- `api`/`web` deliberately do **not** get `--no-cpu-throttling` (see the comment in
  `deploy_api`) — they're request-driven, default throttling is the cheaper *correct*
  choice for them, and keeping that distinction explicit in code is what stops someone
  "fixing" a perceived inconsistency by applying the flag everywhere.

`parser-zscaler` is the table's "parser ×N": Cloud Run cannot autoscale a service that
receives no HTTP traffic, so N concurrent consumers means `--min-instances=N
--max-instances=N`, fixed, set via `PARSER_REPLICAS` (default 2) — not a min/max range
the way `api`/`web` get, since there's no request volume for the autoscaler to react to.

### GCS and `app/storage/`

No code change needed. `backend/app/storage/client.py` builds a plain `boto3` S3 client
pointed at `settings.s3_endpoint`; `streaming_upload.py` and `pipeline/stages/parse.py`
only ever call `head_bucket`, `create_bucket`, `put_object`, the four-call multipart
sequence (`create_multipart_upload`/`upload_part`/`complete_multipart_upload`/
`abort_multipart_upload`), and `get_object`. All of those are part of GCS's XML API
("Cloud Storage interoperability"), which is what `S3_ENDPOINT=https://storage.googleapis.com`
plus an HMAC access key/secret (`gcloud storage hmac create`, see `cloudrun/provision.sh`)
gets you — a drop-in swap for MinIO's own S3 API from this codebase's point of view. The
5 MiB multipart-part-size minimum `streaming_upload.py` already respects (`_PART_SIZE = 8
MiB`) is the same S3 rule GCS's XML API enforces, so that constraint travels unchanged too.

Two non-blocking observations, not code changes:

- `ensure_bucket()`'s lazy `create_bucket` fallback maps onto GCS's own bucket-creation
  semantics (location, uniform access, project billing), not tested against GCS and not
  needed if the bucket is pre-created — which `cloudrun/provision.sh` does, so
  `head_bucket` always succeeds and `create_bucket` is never reached in this topology.
- `client.py` hardcodes `region_name="us-east-1"` for the SigV4 signature scope. GCS's
  XML API does not validate the region string against real AWS regions, so this works
  as-is; it's only worth revisiting if `app/storage/` ever needs to *know* it's talking
  to GCS for some other reason.

### Cloud SQL

Private IP only, same VPC connector every Cloud Run service uses (Memorystore has no
public-IP option at all, so the connector is required regardless — Cloud SQL rides the
same one rather than the separate `--add-cloudsql-instances` Unix-socket mechanism, one
connectivity story instead of two). `vector` and `citext` need no explicit enable step on
Cloud SQL the way some extensions do on AlloyDB — both are on Cloud SQL's extension
allow-list, and `backend/alembic/versions/b67faee96cf5_core_tables.py` already runs
`CREATE EXTENSION IF NOT EXISTS vector` / `citext` as part of `alembic upgrade head`.
`/api/health` (`backend/app/core/db.py:ping`) asserting `pgvector: true` is what actually
proves this end to end, same as it does on the VM path today.

### CloudAMQP

No managed RabbitMQ on GCP, so this is the one component `cloudrun/provision.sh` cannot
create with `gcloud` — it prints the manual steps (create an instance in a GCP region,
confirm RabbitMQ ≥ 3.8 for the quorum queues this system relies on, copy the `amqps://`
URL into `cloudrun/secrets.sh` as `RABBITMQ_URL`). No code change: `aio_pika.connect_robust`
(`backend/app/queue/topology.py`) already accepts whatever scheme the URL uses, `amqps://`
included, the same call that takes the plain `amqp://` URL today.

### Secret Manager

Every secret from `deploy/gcp/.env.prod` plus two more `compose.prod.yml` requires that
`.env.prod` is currently missing (`TIER2_INDICATOR_SALT`, `TIER2_READONLY_DB_PASSWORD`) —
`cloudrun/secrets.sh`'s list is the canonical one, matching `backend/app/core/config.py`'s
`Settings` fields, not the possibly-stale `.env.prod` file:

`JWT_SECRET`, `PSEUDONYM_SALT`, `TIER2_INDICATOR_SALT`, `TIER2_READONLY_DB_PASSWORD`,
`ANTHROPIC_API_KEY`, `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`, `DATABASE_URL`,
`RABBITMQ_URL`, `S3_ACCESS_KEY`, `S3_SECRET_KEY`.

`SUPABASE_URL`/`SUPABASE_SERVICE_ROLE_KEY` stay in the picture even though Cloud SQL now
owns Postgres — they're unrelated to that; Supabase Auth is only used here as the email
transport for signup verification (`app/core/verification`). Every value is written
straight into Secret Manager from stdin (generated with `openssl rand` or pasted with
hidden input) — never held in a shell variable that could be logged or echoed, and never
written to a file.

### CI/CD

`cloudrun/cloudbuild.yaml` builds both images, pushes them to Artifact Registry, then
calls `cloudrun/deploy.sh` — the same script a human runs by hand, so a CI deploy and a
manual deploy can never define the worker contract differently. Wire it up with the
`gcloud builds triggers create github` command `cloudrun/provision.sh` prints once the
GitHub repo is connected in the Cloud Build console (a one-time, interactive, OAuth step
that cannot be scripted). No GitHub Actions workflow was added for this — Cloud Build's
native GitHub trigger is the CI/CD mechanism the migration doc calls for, and it needs
no separate workflow file or federated credentials to set up.
