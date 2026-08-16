#!/usr/bin/env bash
# Populate Secret Manager for the Cloud Run topology (docs/v2_migration change 24).
#
# Every secret currently living in deploy/gcp/.env.prod (the VM path) gets an equivalent
# here, plus a couple more that .env.prod is actually missing today (TIER2_INDICATOR_SALT,
# TIER2_READONLY_DB_PASSWORD, SUPABASE_*) but deploy/gcp/compose.prod.yml already requires
# — see deploy/README.md for that discrepancy. This script's list is the canonical one:
# it matches backend/app/core/config.py's `Settings` fields and deploy/gcp/compose.prod.yml's
# `x-worker-env` anchor, not the possibly-stale .env.prod file.
#
# This script NEVER embeds a secret value in itself. Every value is either generated on
# the spot (openssl rand) or read interactively from your terminal (`read -rs`), then
# piped straight into `gcloud secrets versions add ... --data-file=-` — it is never
# written to a shell variable that gets logged, echoed, or persisted to disk.
#
# Nothing here is run by the assistant that authored it. Run it yourself, once per
# environment, after cloudrun/provision.sh and before cloudrun/deploy.sh.
#
# Usage: deploy/gcp/cloudrun/secrets.sh <gcp-project-id>
set -euo pipefail

PROJECT="${1:?usage: cloudrun/secrets.sh <gcp-project-id>}"
RUNTIME_SA="tenex-cloudrun@${PROJECT}.iam.gserviceaccount.com"

log() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }

gcloud config set project "${PROJECT}" --quiet

# name:generate-or-prompt:description
# "generate" -> this script fills it with `openssl rand`, no prompt.
# "prompt"   -> you type/paste it (hidden input); used for values this script cannot
#               invent itself (API keys, the CloudAMQP/Cloud SQL/GCS connection strings
#               cloudrun/provision.sh printed to your terminal).
SECRETS=(
  "jwt-secret:generate:JWT_SECRET — python -c \"import secrets; print(secrets.token_urlsafe(48))\" equivalent"
  "pseudonym-salt:generate:PSEUDONYM_SALT — per-tenant HMAC pseudonymization salt"
  "tier2-indicator-salt:generate:TIER2_INDICATOR_SALT — deliberately shared across tenants, see app/tier2/__init__.py"
  "tier2-readonly-db-password:generate:TIER2_READONLY_DB_PASSWORD — password for the tier2_readonly Postgres role"
  "anthropic-api-key:prompt:ANTHROPIC_API_KEY — from console.anthropic.com"
  "supabase-url:prompt:SUPABASE_URL — Supabase project URL, used only for signup email verification (app/core/verification), not for Postgres — Cloud SQL owns that here"
  "supabase-service-role-key:prompt:SUPABASE_SERVICE_ROLE_KEY — Supabase service-role key, same purpose as above"
  "database-url:prompt:DATABASE_URL — the postgresql+psycopg://... URL cloudrun/provision.sh printed"
  "rabbitmq-url:prompt:RABBITMQ_URL — the amqps://... URL from your CloudAMQP instance"
  "s3-access-key:prompt:S3_ACCESS_KEY — the accessId from 'gcloud storage hmac create' (cloudrun/provision.sh)"
  "s3-secret-key:prompt:S3_SECRET_KEY — the secret from that same hmac create output"
)

generate_value() {
  openssl rand -base64 48 | tr -d '\n'
}

for entry in "${SECRETS[@]}"; do
  IFS=':' read -r name mode desc <<<"${entry}"
  log "${name} — ${desc}"

  if ! gcloud secrets describe "${name}" --quiet >/dev/null 2>&1; then
    gcloud secrets create "${name}" --replication-policy=automatic --quiet
  fi

  if [[ "${mode}" == "generate" ]]; then
    generate_value | gcloud secrets versions add "${name}" --data-file=- --quiet
  else
    printf 'Paste the value for %s (input hidden, Enter when done): ' "${name}"
    read -rs value
    printf '\n'
    printf '%s' "${value}" | gcloud secrets versions add "${name}" --data-file=- --quiet
    unset value
  fi

  gcloud secrets add-iam-policy-binding "${name}" \
    --member="serviceAccount:${RUNTIME_SA}" \
    --role=roles/secretmanager.secretAccessor --quiet
done

log "All secrets populated and readable by ${RUNTIME_SA}. Next: cloudrun/deploy.sh."
