#!/usr/bin/env bash
# Provision the GCE VM that runs the whole backend topology.
#
# Everything here stays inside the Google Cloud free trial ($300 / 90 days).
# e2-standard-2 is ~$50/mo list, so 90 days of it is roughly $150 of the credit —
# comfortably inside the allowance, with room for the rest.
#
# Usage:  ./provision.sh <gcp-project-id> [zone]
set -euo pipefail

PROJECT="${1:?usage: provision.sh <gcp-project-id> [zone]}"
# us-east4 sits beside Supabase's us-east-1, keeping database round trips ~5ms
# rather than ~70ms. This pipeline queries heavily, so it compounds over a run.
ZONE="${2:-us-east4-b}"
VM="tenex-soc"
MACHINE="e2-standard-2"   # 2 vCPU, 8 GB — enough for the API, MQ, MinIO, Redis and the M4 worker fleet

log() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }

log "Selecting project ${PROJECT}"
gcloud config set project "${PROJECT}" --quiet

log "Enabling required APIs (idempotent, slow the first time)"
gcloud services enable compute.googleapis.com --quiet

log "Creating firewall rules"
gcloud compute firewall-rules describe tenex-soc-web --quiet >/dev/null 2>&1 || \
  gcloud compute firewall-rules create tenex-soc-web \
    --allow=tcp:80,tcp:443 \
    --target-tags=tenex-soc \
    --description="HTTP/HTTPS to the SOC API; Caddy terminates TLS" \
    --quiet

log "Creating VM ${VM} (${MACHINE}) in ${ZONE}"
gcloud compute instances describe "${VM}" --zone "${ZONE}" --quiet >/dev/null 2>&1 || \
  gcloud compute instances create "${VM}" \
    --zone="${ZONE}" \
    --machine-type="${MACHINE}" \
    --image-family=ubuntu-2404-lts-amd64 \
    --image-project=ubuntu-os-cloud \
    --boot-disk-size=60GB \
    --boot-disk-type=pd-balanced \
    --tags=tenex-soc \
    --metadata=startup-script='#!/bin/bash
set -eux
# Docker from the official repo — Ubuntu ships an older engine without compose v2.
apt-get update
apt-get install -y ca-certificates curl git
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" \
  > /etc/apt/sources.list.d/docker.list
apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
systemctl enable --now docker
touch /var/log/tenex-provisioned
' \
    --quiet

log "Waiting for the startup script to finish installing Docker"
for _ in $(seq 1 60); do
  if gcloud compute ssh "${VM}" --zone "${ZONE}" --tunnel-through-iap --quiet \
       --command 'test -f /var/log/tenex-provisioned' >/dev/null 2>&1; then
    echo "docker ready"; break
  fi
  sleep 10
done

IP=$(gcloud compute instances describe "${VM}" --zone "${ZONE}" \
      --format='get(networkInterfaces[0].accessConfigs[0].natIP)')
SITE="${IP//./-}.sslip.io"

cat <<EOF

VM ready.
  external IP : ${IP}
  site address: ${SITE}      <- real Let's Encrypt cert, no domain purchase

Next:
  1. Put the production .env on the VM (never commit it)
  2. docker compose -f deploy/gcp/compose.prod.yml up -d --build
  3. Set CORS_ORIGINS to the Vercel domain and NEXT_PUBLIC_API_URL to https://${SITE}
EOF
