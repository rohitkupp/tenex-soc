# Deployment

Two hosts, one reason: Vercel cannot run this backend.

The pipeline is a long-running, queue-driven, multi-stage process over files up to 200 MB.
Serverless functions cap request bodies near 4.5 MB, have no persistent filesystem, and time out
long before a multi-minute analysis finishes. So the frontend goes to Vercel, everything else to
Fly, and **uploads go browser → Fly directly**, never through Vercel. That single decision
removes the body-size problem rather than working around it.

| Component | Host | Why |
|---|---|---|
| `web` (Next.js) | Vercel | Edge-cached, and it is the bonus the brief asks for |
| `api` (FastAPI) | Fly | Long-lived container, large request bodies, SSE |
| workers | Fly, one app with per-stage process groups | Topology of docs/01 without paying for 12 separate apps |
| Postgres + pgvector | Supabase (free tier) | pgvector 0.8.2, IPv4-reachable. Fly's managed Postgres is $38/mo — untenable for a demo database holding very little |
| Object store | Fly Tigris | S3-compatible; replaces MinIO in production |
| Redis (SSE pub/sub) | Fly (Upstash) | Only used to relay progress events |
| RabbitMQ | Fly app | No managed option; small instance with a volume |

**Not Render.** Its free tier spins down after 15 minutes and cold-starts in ~50 seconds. The
reviewer opens the link once; a minute of blank page is the whole first impression.

## First-time provisioning

```bash
export PATH="/Applications/Docker.app/Contents/Resources/bin:$PATH"   # if docker is not on PATH

# Postgres lives on Supabase — see backend/.env for SUPABASE_DATABASE_URL.
# Use the SESSION pooler (port 5432): the direct endpoint is IPv6-only and the
# transaction pooler (6543) lacks prepared statements, which breaks Alembic.
# S3-compatible object storage; prints AWS_* credentials — capture them
flyctl storage create --org personal --name tenex-soc-uploads

# Redis for SSE fan-out
flyctl redis create --org personal --name tenex-soc-redis --region iad

# The API itself
cd backend
flyctl launch --config ../deploy/fly/api.toml --copy-config --no-deploy --org personal
```

## Secrets

Never in `fly.toml`, never in git. `app/core/config.py` refuses to boot outside `local` while any
secret is still at its development default, so a misconfigured deploy fails loudly at startup
instead of silently running with a forgeable JWT secret.

```bash
flyctl secrets set --app tenex-soc-api \
  JWT_SECRET="$(python3 -c 'import secrets;print(secrets.token_urlsafe(48))')" \
  PSEUDONYM_SALT="$(python3 -c 'import secrets;print(secrets.token_urlsafe(32))')" \
  ANTHROPIC_API_KEY="..." \
  DATABASE_URL="..." \
  REDIS_URL="..." \
  S3_ENDPOINT="https://fly.storage.tigris.dev" \
  S3_ACCESS_KEY="..." \
  S3_SECRET_KEY="..." \
  CORS_ORIGINS="https://<the-vercel-domain>"
```

## Deploying

```bash
cd backend && flyctl deploy --config ../deploy/fly/api.toml   # API
cd frontend && vercel --prod                                  # web
```

Set `NEXT_PUBLIC_API_URL` in the Vercel project to the Fly hostname, and `CORS_ORIGINS` on Fly to
the Vercel domain. They reference each other, so both must be set before login will work — a
cookie will not cross origins otherwise.

## Order of operations

1. Provision Postgres, Tigris, Redis
2. Set secrets
3. Deploy the API, confirm `/api/health` reports every dependency `ok` and `pgvector: true`
4. `alembic upgrade head` via `flyctl ssh console`
5. Deploy the frontend, set `NEXT_PUBLIC_API_URL`
6. Set `CORS_ORIGINS` on Fly to the real Vercel domain and redeploy the API
