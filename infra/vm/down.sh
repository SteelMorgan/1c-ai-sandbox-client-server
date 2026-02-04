#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
docker_() { sudo -n docker "$@"; }

docker_ compose \
  --env-file "${ROOT_DIR}/infra/vm/.env" \
  -f "${ROOT_DIR}/infra/vm/docker-compose.yml" \
  down

if command -v systemctl >/dev/null 2>&1; then
  sudo -n systemctl disable --now onec-infra.service >/dev/null 2>&1 || true
fi

