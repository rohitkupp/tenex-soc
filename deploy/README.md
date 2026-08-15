# Deployment

Live: frontend https://tenex-soc.vercel.app · API https://34-150-170-252.sslip.io

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
