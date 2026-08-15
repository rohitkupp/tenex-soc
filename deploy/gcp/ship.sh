#!/usr/bin/env bash
# Ship the current committed tree to the GCE VM and restart the stack.
#
# `git archive HEAD` is deliberate: it packs **tracked files only**, so `backend/.env`,
# `deploy/gcp/.env.prod`, and anything else gitignored physically cannot reach the server by
# accident. The production `.env` is placed on the VM once, out of band, and is never overwritten
# by a deploy.
#
# Usage: deploy/gcp/ship.sh [--rebuild]
set -euo pipefail

VM="${VM:-tenex-soc}"
ZONE="${ZONE:-us-east4-b}"
REMOTE_DIR="tenex"
SSH=(gcloud compute ssh "${VM}" --zone "${ZONE}" --tunnel-through-iap --quiet)

log() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }

if [[ -n "$(git status --porcelain)" ]]; then
  echo "working tree is dirty — commit first, so what is deployed is what is in git" >&2
  exit 1
fi

log "Packing $(git rev-parse --short HEAD) (tracked files only)"
git archive --format=tar.gz -o /tmp/tenex-src.tar.gz HEAD

log "Uploading"
gcloud compute scp /tmp/tenex-src.tar.gz "${VM}":~/tenex-src.tar.gz \
  --zone "${ZONE}" --tunnel-through-iap --quiet

log "Unpacking and restarting"
"${SSH[@]}" --command "
  set -euo pipefail
  mkdir -p ${REMOTE_DIR}
  # --keep-newer-files would leave stale deletions behind; extract over the top instead, and
  # leave .env alone because it is not in the archive at all.
  tar -xzf ~/tenex-src.tar.gz -C ${REMOTE_DIR}
  cd ${REMOTE_DIR}
  sudo docker compose -f deploy/gcp/compose.prod.yml up -d --build
  sudo docker compose -f deploy/gcp/compose.prod.yml exec -T api alembic upgrade head
"

IP=$(gcloud compute instances describe "${VM}" --zone "${ZONE}" \
      --format='get(networkInterfaces[0].accessConfigs[0].natIP)')
URL="https://${IP//./-}.sslip.io/api/health"

# Poll rather than curl once. Caddy holds its upstream connection across the restart, so a
# request issued the instant the migration returns can reach it before uvicorn has finished
# starting and come back 502 — which reads like a failed deploy when it is a healthy one caught
# a second early. 60 s is generous; a real failure still surfaces, just as a timeout.
log "Waiting for ${URL}"
for _ in $(seq 1 30); do
  if BODY=$(curl -fsS --max-time 5 "${URL}" 2>/dev/null); then
    echo "${BODY}"
    log "Deployed."
    exit 0
  fi
  sleep 2
done

echo "health check never came up after 60s — check: sudo docker logs tenex-soc-api-1" >&2
exit 1
