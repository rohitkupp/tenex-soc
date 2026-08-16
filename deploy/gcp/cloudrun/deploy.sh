#!/usr/bin/env bash
# Deploy every Cloud Run service in the docs/v2_migration change 24 topology.
#
# Why a script instead of ~12 near-identical Cloud Run YAML manifests: every service here
# is the *same* backend image (only `web` differs), differing only in which module its
# `command:` runs and how many replicas it needs — exactly the shape
# docker-compose.yml/compose.prod.yml already express with a single YAML anchor. A script
# lets that stay true here too: one `deploy_worker` function is the only place the worker
# contract is defined, instead of the same six flags copy-pasted across a dozen YAML
# files where one of them silently drifting is how the trap below gets reintroduced. It
# also lets the trap be *checked*, not just declared — see `assert_worker_flags` — which a
# static manifest cannot do on its own. This mirrors deploy/gcp/provision.sh and ship.sh,
# which are scripts for the same reason.
#
# Run order: cloudrun/provision.sh, then cloudrun/secrets.sh, then this file. Called
# directly by a human, or by cloudrun/cloudbuild.yaml on every push to main — same script
# either way, so a manual deploy and a CI deploy can never produce different config.
#
# Nothing here is run by the assistant that authored it. Read it, then run it yourself.
#
# Usage: PROJECT=<id> deploy/gcp/cloudrun/deploy.sh [region] [image-tag]
set -euo pipefail

PROJECT="${PROJECT:?set PROJECT=<gcp-project-id>}"
REGION="${1:-us-east4}"
IMAGE_TAG="${2:-$(git rev-parse --short HEAD)}"

ARTIFACT_REPO="tenex"
VPC_CONNECTOR="tenex-connector"
RUNTIME_SA="tenex-cloudrun@${PROJECT}.iam.gserviceaccount.com"

REGISTRY="${REGION}-docker.pkg.dev/${PROJECT}/${ARTIFACT_REPO}"
BACKEND_IMAGE="${REGISTRY}/backend:${IMAGE_TAG}"
FRONTEND_IMAGE="${REGISTRY}/frontend:${IMAGE_TAG}"

log() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }

gcloud config set project "${PROJECT}" --quiet

# --- Shared config for `api` and every worker ---------------------------------------
# Same variable names as deploy/gcp/compose.prod.yml's `x-worker-env` anchor and
# backend/app/core/config.py's `Settings` fields — this is the same image, the same env
# contract, a different host. S3_ENDPOINT points at GCS's XML/S3-interoperability API
# rather than MinIO; nothing else in this list changes shape from the VM path.
#
# Comma is `gcloud`'s own delimiter inside --set-env-vars/--set-secrets, so any value
# that might itself contain a comma (CORS_ORIGINS with more than one origin) must use
# gcloud's `^:^` custom-delimiter escape instead of the default. Only CORS_ORIGINS is at
# risk of that here; see deploy_api below.
COMMON_ENV_VARS="ENVIRONMENT=production,ANTHROPIC_MODEL=claude-opus-5,MAX_TRIAGE_INCIDENTS=15,AGENT_MAX_TOOL_CALLS=8,AGENT_TIMEOUT_SECONDS=120,LOG_LEVEL=info,JWT_TTL_MINUTES=60,S3_ENDPOINT=https://storage.googleapis.com,S3_BUCKET=${PROJECT}-tenex-uploads,REDIS_URL=$(gcloud redis instances describe tenex-redis --region="${REGION}" --format='value(host)' | sed 's#^#redis://#; s#$#:6379/0#')"

COMMON_SECRETS="JWT_SECRET=jwt-secret:latest,PSEUDONYM_SALT=pseudonym-salt:latest,TIER2_INDICATOR_SALT=tier2-indicator-salt:latest,TIER2_READONLY_DB_PASSWORD=tier2-readonly-db-password:latest,ANTHROPIC_API_KEY=anthropic-api-key:latest,SUPABASE_URL=supabase-url:latest,SUPABASE_SERVICE_ROLE_KEY=supabase-service-role-key:latest,DATABASE_URL=database-url:latest,RABBITMQ_URL=rabbitmq-url:latest,S3_ACCESS_KEY=s3-access-key:latest,S3_SECRET_KEY=s3-secret-key:latest"

# =====================================================================================
# THE TRAP (docs/v2_migration change 24): Cloud Run allocates CPU only while a request
# is in flight. A queue consumer has no requests — it sits between deliveries — so
# without the two flags below it gets throttled to near-zero the moment it goes idle,
# messages pile up unconsumed, and it *looks exactly like a queue bug* (a stalled
# pipeline, a stuck analysis) when it is actually a Cloud Run config bug. Both flags are
# hardcoded inside this function, not accepted as caller-supplied arguments, specifically
# so a future worker added by copy-pasting a call to this function cannot omit them by
# accident. See assert_worker_flags below for the second, executable half of this
# guardrail: it re-reads the deployed revision and fails the script if either flag is
# not actually set on it.
# =====================================================================================
deploy_worker() {
  local name="$1" module="$2" min_instances="${3:-1}" max_instances="${4:-1}"

  log "Deploying worker: ${name} (python -m app.workers.${module}, replicas ${min_instances}-${max_instances})"

  # `python -m http.server` on $PORT satisfies Cloud Run's platform contract (a Cloud Run
  # *service* must have something listening on its port to pass the startup probe) — it
  # is not part of this worker's job, which is entirely the RabbitMQ consume loop `exec`'d
  # right after. This is a deploy-time shim, added here rather than in
  # backend/app/workers/_entrypoint.py (out of this change's scope — that package belongs
  # to the agent working on backend/app/) because it only exists to satisfy Cloud Run, not
  # anything the worker itself needs; local docker-compose never runs this line.
  local shim="python -m http.server \${PORT:-8080} >/dev/null 2>&1 & exec python -m app.workers.${module}"

  gcloud run deploy "${name}" \
    --image="${BACKEND_IMAGE}" \
    --region="${REGION}" \
    --service-account="${RUNTIME_SA}" \
    --vpc-connector="${VPC_CONNECTOR}" \
    --vpc-egress=private-ranges-only \
    --no-cpu-throttling \
    --min-instances="${min_instances}" \
    --max-instances="${max_instances}" \
    --no-allow-unauthenticated \
    --ingress=internal \
    --port=8080 \
    --cpu=1 --memory=1Gi \
    --command=/bin/sh \
    --args="-c,${shim}" \
    --set-env-vars="${COMMON_ENV_VARS}" \
    --set-secrets="${COMMON_SECRETS}" \
    --quiet

  assert_worker_flags "${name}"
}

# Executable half of the guardrail above: read back the revision `deploy_worker` just
# created and fail loudly if either flag did not stick (a bad `gcloud` version, a
# denied org policy, a future edit to this function that drops one of them). This is the
# check the migration doc asks for "expressed as a check in the deploy script" — a
# comment can be skimmed past, `set -euo pipefail` exiting non-zero cannot.
assert_worker_flags() {
  local name="$1"
  local throttling min_scale
  throttling="$(gcloud run services describe "${name}" --region="${REGION}" \
    --format='value(spec.template.metadata.annotations."run.googleapis.com/cpu-throttling")')"
  min_scale="$(gcloud run services describe "${name}" --region="${REGION}" \
    --format='value(spec.template.metadata.annotations."autoscaling.knative.dev/minScale")')"

  # The annotation must be the literal string "false" — --no-cpu-throttling is what
  # writes that. An *absent* annotation (empty string here) means Cloud Run's default,
  # which is throttled, so "not true" is not a strong enough check; only "false" passes.
  if [[ "${throttling}" != "false" ]]; then
    echo "FATAL: ${name} deployed without cpu-throttling disabled (saw '${throttling:-<unset>}') — it will stall as soon as it goes idle. Aborting." >&2
    exit 1
  fi
  if [[ -z "${min_scale}" || "${min_scale}" -lt 1 ]]; then
    echo "FATAL: ${name} deployed with min-instances < 1 — it will scale to zero and stop consuming its queue. Aborting." >&2
    exit 1
  fi
}

deploy_api() {
  log "Deploying api"
  # api is request-driven, not a queue consumer — the trap above does not apply to it.
  # Default CPU allocation (billed only while handling a request) is the correct,
  # cheaper choice here; --min-instances=1 is only to avoid a cold start on the first
  # request after idle, which is a UX nicety, not the correctness issue workers have.
  #
  # --command/--args below override backend/Dockerfile's bare CMD to add
  # --proxy-headers --forwarded-allow-ips='*', the same addition
  # deploy/gcp/compose.prod.yml's api command makes over docker-compose.yml's dev one —
  # Cloud Run's front end is a proxy in front of the container exactly like Caddy is on
  # the VM path, and without this flag the app sees every request as if it came from
  # Cloud Run's internal IP instead of the real client.
  gcloud run deploy api \
    --image="${BACKEND_IMAGE}" \
    --region="${REGION}" \
    --service-account="${RUNTIME_SA}" \
    --vpc-connector="${VPC_CONNECTOR}" \
    --vpc-egress=private-ranges-only \
    --min-instances=1 --max-instances=10 \
    --allow-unauthenticated \
    --port=8000 \
    --cpu=2 --memory=2Gi \
    --timeout=900 \
    --command=uvicorn \
    --args="app.main:app,--host,0.0.0.0,--port,8000,--proxy-headers,--forwarded-allow-ips=*" \
    --set-env-vars="${COMMON_ENV_VARS},CORS_ORIGINS=http://placeholder.invalid" \
    --set-secrets="${COMMON_SECRETS}" \
    --quiet
}

deploy_web() {
  local api_origin="$1"
  log "Deploying web (API_ORIGIN=${api_origin})"
  # NEXT_PUBLIC_API_URL is deliberately NOT set. frontend/lib/api/client.ts defaults it
  # to "" (same-origin) whenever NODE_ENV=production, which is exactly what this
  # topology wants: the browser calls web's own origin, and frontend/next.config.ts's
  # `/api/:path*` rewrite — driven by the server-only API_ORIGIN below — proxies it to
  # `api` without ever exposing api's URL to client code or needing a build-time value
  # baked into the image. That rewrite also means large uploads inherit Cloud Run's
  # 32 MB request-body ceiling the same way they inherit Vercel's on the VM path today
  # (see frontend/next.config.ts's rewrite comment) — pre-existing frontend behavior,
  # not something this Cloud Run config changes.
  gcloud run deploy web \
    --image="${FRONTEND_IMAGE}" \
    --region="${REGION}" \
    --min-instances=1 --max-instances=10 \
    --allow-unauthenticated \
    --port=8080 \
    --cpu=1 --memory=512Mi \
    --set-env-vars="API_ORIGIN=${api_origin}" \
    --quiet
}

service_url() {
  gcloud run services describe "$1" --region="${REGION}" --format='value(status.url)'
}

# =====================================================================================
# Deploy order: api and web first (each needs the other's URL — same chicken-and-egg
# deploy/README.md already documents for Vercel+the VM), then every worker.
# =====================================================================================

deploy_api
API_URL="$(service_url api)"

deploy_web "${API_URL}"
WEB_URL="$(service_url web)"

log "Re-deploying api with CORS_ORIGINS=${WEB_URL}"
gcloud run services update api --region="${REGION}" \
  --update-env-vars="CORS_ORIGINS=${WEB_URL}" --quiet

# --- Workers --------------------------------------------------------------------------
# Same nine names as deploy/gcp/compose.prod.yml, minus dead-letter-sink's absence from
# the change-24 table (it predates that table — see docker-compose.yml's comment on it —
# and needs the identical always-on treatment, so it is included here too) plus `learner`,
# which the table lists but which does not exist yet.
#
# `parser-zscaler` is the table's "parser x N": Cloud Run cannot autoscale a service that
# receives no HTTP traffic (its autoscaler has nothing to react to), so getting N
# concurrent consumers means min=max=N, fixed, not a range — unlike api/web above there is
# no burst headroom to leave on the table. PARSER_REPLICAS defaults to 2; override via env.
PARSER_REPLICAS="${PARSER_REPLICAS:-2}"

deploy_worker orchestrator   orchestrator
deploy_worker parser-zscaler parser_zscaler "${PARSER_REPLICAS}" "${PARSER_REPLICAS}"
deploy_worker enricher       enricher
deploy_worker anonymizer     anonymizer
deploy_worker detector       detector
deploy_worker correlator     correlator
deploy_worker agent          agent
deploy_worker tier2-sync     tier2_sync
deploy_worker dead-letter-sink dead_letter_sink

# --- learner: NOT YET IMPLEMENTED --------------------------------------------------
# docs/v2_migration change 21 (continuous learning) specifies this worker; it has not
# been built (no backend/app/workers/learner.py exists as of this deploy). It is in the
# change-24 table, so it stays enumerated here rather than silently vanishing from the
# topology — but calling deploy_worker for it today would deploy a container that
# ImportErrors on start and crash-loops. Uncomment once app/workers/learner.py ships:
#
# deploy_worker learner learner
echo
echo "learner: NOT DEPLOYED — backend/app/workers/learner.py does not exist yet (change 21)."

log "Done."
echo "  web: ${WEB_URL}"
echo "  api: ${API_URL}"
