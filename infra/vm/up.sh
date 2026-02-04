#!/usr/bin/env bash
set -euo pipefail

# Run from repo root:
#   ./infra/vm/up.sh
#
# Uses canonical ONEC_VERSION from infra/vm/.env

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
docker_() { sudo -n docker "$@"; }

install_autostart_systemd() {
  # Configure infra autostart on VM boot via systemd.
  # Why: Docker restart policies are good, but this makes the behavior explicit and self-healing
  # (e.g. after upgrades, daemon restarts, manual stops).
  if ! command -v systemctl >/dev/null 2>&1; then
    echo "[WARN] systemctl not found; skipping autostart unit installation."
    return 0
  fi

  local unit="/etc/systemd/system/onec-infra.service"
  local tmp="/tmp/onec-infra.service.$$"

  cat > "${tmp}" <<EOF
[Unit]
Description=1C + Postgres (Docker Compose)
Requires=docker.service
After=docker.service network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=${ROOT_DIR}
ExecStart=/usr/bin/docker compose --env-file ${ROOT_DIR}/infra/vm/.env -f ${ROOT_DIR}/infra/vm/docker-compose.yml up -d
ExecStartPost=/usr/bin/env bash -lc 'test -s "${ROOT_DIR}/secrets/pg_password" && "${ROOT_DIR}/infra/vm/postgres/ensure-pg-user.sh" || true'
ExecStop=/usr/bin/docker compose --env-file ${ROOT_DIR}/infra/vm/.env -f ${ROOT_DIR}/infra/vm/docker-compose.yml down
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target
EOF

  sudo -n install -m 0644 "${tmp}" "${unit}"
  rm -f "${tmp}"

  # Best-effort enable. If docker is already enabled, it's a no-op.
  sudo -n systemctl daemon-reload || true
  sudo -n systemctl enable --now docker >/dev/null 2>&1 || true
  sudo -n systemctl enable --now onec-infra.service >/dev/null 2>&1 || true

  echo "[OK] Autostart configured: onec-infra.service"
}

docker_ compose \
  --env-file "${ROOT_DIR}/infra/vm/.env" \
  -f "${ROOT_DIR}/infra/vm/docker-compose.yml" \
  up -d --build

# Post-start fix for akocur/postgresql-1c-17: ensure role/password/db from secrets.
if [[ -s "${ROOT_DIR}/secrets/pg_password" ]]; then
  "${ROOT_DIR}/infra/vm/postgres/ensure-pg-user.sh"
else
  echo "[WARN] secrets/pg_password is missing/empty. Skipping Postgres role/password init."
fi

install_autostart_systemd

