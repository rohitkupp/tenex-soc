#!/usr/bin/env bash
# One-time GCP infrastructure for the Cloud Run topology (docs/v2_migration change 24).
#
# This is a SIBLING deployment path to deploy/gcp/{provision.sh,ship.sh,compose.prod.yml},
# not a replacement. That other path is one GCE VM running docker-compose behind Caddy —
# it stays the live demo unless/until someone decides otherwise. Everything under
# deploy/gcp/cloudrun/ stands up the fully-managed topology from the migration doc instead:
# every service (web, api, and every pipeline worker) on Cloud Run, Postgres on Cloud SQL,
# RabbitMQ on CloudAMQP, object storage on GCS, Redis on Memorystore.
#
# Cost note, stated because the VM path is explicitly $0 (deploy/README.md) and this one is
# not: Memorystore has no free tier (~$35/mo at the smallest basic-tier size), Cloud SQL and
# the always-on workers below are billed by the hour even idle (that is what
# --no-cpu-throttling + --min-instances=1 costs — see cloudrun/deploy.sh), and CloudAMQP's
# free plan is usually enough for a demo but is still an external account. Budget for it
# before running this against a real project.
#
# This script only provisions shared infrastructure (networking, Cloud SQL, Memorystore,
# Artifact Registry, GCS, service account, Cloud Build trigger). It does not deploy any
# Cloud Run service — that is cloudrun/deploy.sh — and it does not populate Secret Manager —
# that is cloudrun/secrets.sh. Run them in that order; see deploy/README.md.
#
# Nothing in this script is run by the assistant that authored it. Read it, adjust the
# sizing knobs below for your project, then run it yourself.
#
# Usage: deploy/gcp/cloudrun/provision.sh <gcp-project-id> [region]
set -euo pipefail

PROJECT="${1:?usage: cloudrun/provision.sh <gcp-project-id> [region]}"
# Same region as the VM path's us-east4-b zone (provision.sh), for the same reason: Supabase
# and CloudAMQP both have an us-east region, keeping cross-service latency down.
REGION="${2:-us-east4}"

# --- Sizing knobs. Cheap-but-real defaults for a demo-scale deploy, not production. ---
NETWORK="tenex-vpc"
SUBNET="tenex-subnet"
VPC_CONNECTOR="tenex-connector"
CONNECTOR_RANGE="10.8.0.0/28"          # must not overlap SUBNET_RANGE
SUBNET_RANGE="10.10.0.0/24"
SQL_INSTANCE="tenex-sql"
SQL_TIER="${SQL_TIER:-db-custom-2-4096}"   # 2 vCPU / 4 GB — bump via env if the corpus grows
REDIS_INSTANCE="tenex-redis"
REDIS_SIZE_GB="${REDIS_SIZE_GB:-1}"        # Memorystore basic tier minimum
ARTIFACT_REPO="tenex"
GCS_BUCKET="${PROJECT}-tenex-uploads"       # bucket names are globally unique; project-scoped
RUNTIME_SA="tenex-cloudrun"
GCS_HMAC_SA="tenex-gcs-hmac"

log() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }

log "Selecting project ${PROJECT}"
gcloud config set project "${PROJECT}" --quiet

log "Enabling required APIs (idempotent, slow the first time)"
gcloud services enable \
  run.googleapis.com \
  artifactregistry.googleapis.com \
  sqladmin.googleapis.com \
  redis.googleapis.com \
  secretmanager.googleapis.com \
  vpcaccess.googleapis.com \
  servicenetworking.googleapis.com \
  compute.googleapis.com \
  cloudbuild.googleapis.com \
  --quiet

# --- Networking: one VPC, one subnet, one Serverless VPC Access connector. -------------
# Cloud SQL (private IP) and Memorystore both require the Cloud Run services that reach
# them to be on the same VPC. There is no per-service alternative for Memorystore (it has
# no public IP option at all), so every worker below attaches to this connector, and Cloud
# SQL rides the same connector rather than the separate `--add-cloudsql-instances` Unix-
# socket mechanism, so there is exactly one connectivity story to reason about instead of
# two.
log "Creating VPC network and subnet"
gcloud compute networks describe "${NETWORK}" --quiet >/dev/null 2>&1 || \
  gcloud compute networks create "${NETWORK}" --subnet-mode=custom --quiet
gcloud compute networks subnets describe "${SUBNET}" --region="${REGION}" --quiet >/dev/null 2>&1 || \
  gcloud compute networks subnets create "${SUBNET}" \
    --network="${NETWORK}" --region="${REGION}" --range="${SUBNET_RANGE}" --quiet

log "Reserving a private-services-access range for Cloud SQL + Memorystore"
gcloud compute addresses describe "google-managed-services-${NETWORK}" --global --quiet >/dev/null 2>&1 || \
  gcloud compute addresses create "google-managed-services-${NETWORK}" \
    --global --purpose=VPC_PEERING --prefix-length=16 --network="${NETWORK}" --quiet
gcloud services vpc-peerings connect \
  --service=servicenetworking.googleapis.com \
  --ranges="google-managed-services-${NETWORK}" \
  --network="${NETWORK}" --quiet

log "Creating the Serverless VPC Access connector"
gcloud compute networks vpc-access connectors describe "${VPC_CONNECTOR}" --region="${REGION}" --quiet >/dev/null 2>&1 || \
  gcloud compute networks vpc-access connectors create "${VPC_CONNECTOR}" \
    --region="${REGION}" --network="${NETWORK}" --range="${CONNECTOR_RANGE}" \
    --min-instances=2 --max-instances=3 --quiet

# --- Artifact Registry -------------------------------------------------------------
log "Creating Artifact Registry repo ${ARTIFACT_REPO}"
gcloud artifacts repositories describe "${ARTIFACT_REPO}" --location="${REGION}" --quiet >/dev/null 2>&1 || \
  gcloud artifacts repositories create "${ARTIFACT_REPO}" \
    --repository-format=docker --location="${REGION}" \
    --description="tenex backend/frontend images" --quiet

# --- Cloud SQL for PostgreSQL 16, pgvector -----------------------------------------
# pgvector needs no special enable flag on Cloud SQL (unlike AlloyDB) — it is on Cloud
# SQL's extension allow-list, same as `citext`. The app's own migration already runs
# `CREATE EXTENSION IF NOT EXISTS vector` / `citext` (backend/alembic/versions/
# b67faee96cf5_core_tables.py) as part of `alembic upgrade head`, so no separate step is
# needed here beyond making sure the DB user alembic connects as can create extensions —
# Cloud SQL's default user can. `/api/health` (backend/app/core/db.py:ping) asserts
# `pgvector: true`, which is what actually proves this worked end to end.
log "Creating Cloud SQL instance ${SQL_INSTANCE} (Postgres 16, private IP only)"
gcloud sql instances describe "${SQL_INSTANCE}" --quiet >/dev/null 2>&1 || \
  gcloud sql instances create "${SQL_INSTANCE}" \
    --database-version=POSTGRES_16 \
    --tier="${SQL_TIER}" \
    --region="${REGION}" \
    --network="projects/${PROJECT}/global/networks/${NETWORK}" \
    --no-assign-ip \
    --enable-google-private-path \
    --quiet

gcloud sql databases describe tenex --instance="${SQL_INSTANCE}" --quiet >/dev/null 2>&1 || \
  gcloud sql databases create tenex --instance="${SQL_INSTANCE}" --quiet

log "Cloud SQL user 'tenex' — generating a fresh password now"
DB_PASSWORD="$(openssl rand -base64 32 | tr -d '\n=+/' | cut -c1-32)"
gcloud sql users create tenex --instance="${SQL_INSTANCE}" --password="${DB_PASSWORD}" --quiet 2>/dev/null || \
  gcloud sql users set-password tenex --instance="${SQL_INSTANCE}" --password="${DB_PASSWORD}" --quiet

SQL_PRIVATE_IP="$(gcloud sql instances describe "${SQL_INSTANCE}" --format='value(ipAddresses[0].ipAddress)')"
DATABASE_URL="postgresql+psycopg://tenex:${DB_PASSWORD}@${SQL_PRIVATE_IP}:5432/tenex?sslmode=require"
echo "DATABASE_URL is ready to hand to cloudrun/secrets.sh — it is only printed to your"
echo "terminal, never written to a file by this script:"
echo "  ${DATABASE_URL}"

# --- Memorystore Redis (SSE relay) --------------------------------------------------
log "Creating Memorystore Redis instance ${REDIS_INSTANCE}"
gcloud redis instances describe "${REDIS_INSTANCE}" --region="${REGION}" --quiet >/dev/null 2>&1 || \
  gcloud redis instances create "${REDIS_INSTANCE}" \
    --size="${REDIS_SIZE_GB}" --region="${REGION}" \
    --network="projects/${PROJECT}/global/networks/${NETWORK}" \
    --tier=basic --quiet

REDIS_HOST="$(gcloud redis instances describe "${REDIS_INSTANCE}" --region="${REGION}" --format='value(host)')"
echo "REDIS_URL=redis://${REDIS_HOST}:6379/0  (plain env var, not a secret — no AUTH configured)"

# --- Cloud Storage (replaces MinIO) -------------------------------------------------
# See deploy/README.md's "GCS and app/storage/" section for why the app needs no code
# change here: backend/app/storage/client.py already talks to an S3-compatible endpoint
# via boto3, and GCS's XML API (the "interoperability" surface) implements the exact
# operations that module calls — head_bucket, put_object, the four-call multipart
# sequence, get_object. The one thing worth doing at the infra layer rather than trusting
# the app's lazy `ensure_bucket()`: pre-create the bucket here, so `ensure_bucket()`'s
# `head_bucket` always succeeds and its `create_bucket` fallback (which maps onto GCS's
# own bucket-creation semantics, not S3's — location, uniform access, project billing —
# and is untested against GCS) is never exercised in production.
log "Creating GCS bucket gs://${GCS_BUCKET}"
gcloud storage buckets describe "gs://${GCS_BUCKET}" --quiet >/dev/null 2>&1 || \
  gcloud storage buckets create "gs://${GCS_BUCKET}" \
    --location="${REGION}" --uniform-bucket-level-access --quiet

log "Creating the service account whose HMAC keypair becomes S3_ACCESS_KEY/S3_SECRET_KEY"
gcloud iam service-accounts describe "${GCS_HMAC_SA}@${PROJECT}.iam.gserviceaccount.com" --quiet >/dev/null 2>&1 || \
  gcloud iam service-accounts create "${GCS_HMAC_SA}" \
    --display-name="Tenex GCS S3-interoperability access" --quiet
gcloud storage buckets add-iam-policy-binding "gs://${GCS_BUCKET}" \
  --member="serviceAccount:${GCS_HMAC_SA}@${PROJECT}.iam.gserviceaccount.com" \
  --role=roles/storage.objectAdmin --quiet

echo
echo "Run this once and hand the two printed values to cloudrun/secrets.sh"
echo "(S3_ACCESS_KEY / S3_SECRET_KEY). It is not run automatically because HMAC keys"
echo "print secret material to stdout and should go straight into Secret Manager:"
echo "  gcloud storage hmac create ${GCS_HMAC_SA}@${PROJECT}.iam.gserviceaccount.com"

# --- Runtime service account for every Cloud Run service ----------------------------
log "Creating the Cloud Run runtime service account ${RUNTIME_SA}"
gcloud iam service-accounts describe "${RUNTIME_SA}@${PROJECT}.iam.gserviceaccount.com" --quiet >/dev/null 2>&1 || \
  gcloud iam service-accounts create "${RUNTIME_SA}" \
    --display-name="Tenex Cloud Run runtime identity" --quiet

# --- CloudAMQP -------------------------------------------------------------------
# No `gcloud` step here: there is no managed RabbitMQ on GCP (the reason CloudAMQP is in
# the table at all — docs/v2_migration change 24). Provisioning it is an out-of-band,
# external-account step:
#   1. https://www.cloudamqp.com (or the GCP Marketplace listing) -> New instance
#   2. Choose a GCP region matching REGION above, so Cloud Run round trips stay local
#   3. Any plan works for a demo; check the instance reports RabbitMQ >= 3.8 so the
#      quorum queues this system relies on (deploy/README.md) are actually available
#   4. Copy the AMQPS URL it gives you (amqps://user:pass@host/vhost) into
#      cloudrun/secrets.sh as RABBITMQ_URL — aio-pika (backend/app/queue/topology.py)
#      already handles the amqps:// scheme with no code change, same as the plain
#      amqp:// URL it uses today.
echo
echo "CloudAMQP is external to GCP and cannot be provisioned by gcloud — see the comment"
echo "block above this line in provision.sh for the manual steps."

# --- Cloud Build trigger (CI/CD) ----------------------------------------------------
# The GitHub connection itself is a one-time console step (Cloud Build > Repositories >
# Connect Repository) that requires an interactive OAuth grant, so it is not scripted
# here. Once connected, this creates the trigger that gives change 24's "CI/CD | Cloud
# Build | build -> push -> deploy per service" row an actual home: every push to main
# runs cloudrun/cloudbuild.yaml, which builds, pushes to Artifact Registry, and calls
# cloudrun/deploy.sh — the same script a human runs by hand, so CI and a manual deploy
# can never drift apart.
echo
echo "Once the GitHub repo is connected in the Cloud Build console, create the trigger with:"
cat <<EOF
  gcloud builds triggers create github \\
    --name=tenex-deploy \\
    --repo-name=<your-repo-name> \\
    --repo-owner=<your-github-owner> \\
    --branch-pattern='^main\$' \\
    --build-config=deploy/gcp/cloudrun/cloudbuild.yaml \\
    --substitutions=_REGION=${REGION},_VPC_CONNECTOR=${VPC_CONNECTOR}
EOF

log "Infrastructure provisioned. Next: cloudrun/secrets.sh, then cloudrun/deploy.sh."
