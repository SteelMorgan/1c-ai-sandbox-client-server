#!/usr/bin/env bash
set -euo pipefail

# Entrypoint for 1C server container:
# - optional community activation (if DEV_LOGIN/DEV_PASSWORD are provided via secrets/env)
# - start ragent + ras (RAS on 1545 by default) to enable `rac` automation

export LANG="${LANG:-ru_RU.UTF-8}"
export LC_ALL="${LC_ALL:-ru_RU.UTF-8}"

RAGENT_PORT="${RAGENT_PORT:-1540}"
RAGENT_REGPORT="${RAGENT_REGPORT:-1541}"
RAGENT_RANGE="${RAGENT_RANGE:-1560:1591}"

RAS_PORT="${RAS_PORT:-1545}"

LOG_DIR="${LOG_DIR:-/var/log/onec}"
DATA_DIR="${DATA_DIR:-/var/lib/onec}"
mkdir -p "$LOG_DIR" "$DATA_DIR" /var/1C/licenses
chown -R usr1cv8:grp1cv8 "$LOG_DIR" "$DATA_DIR" /var/1C/licenses || true

echo "[INFO] Starting 1C cluster agent (ragent): port=${RAGENT_PORT} regport=${RAGENT_REGPORT} range=${RAGENT_RANGE}"
/opt/1cv8/current/ragent \
  -d "$DATA_DIR" \
  -port "$RAGENT_PORT" \
  -regport "$RAGENT_REGPORT" \
  -range "$RAGENT_RANGE" \
  >/var/log/onec/ragent.log 2>&1 &
RAGENT_PID=$!

# NOTE: In a typical (non-container) install, rmngr is started by the service manager.
# In this container we must start it explicitly, otherwise regport (1541) is never bound.
RMNGR_HOST="$(hostname)"
echo "[INFO] Starting 1C registration manager (rmngr): port=${RAGENT_REGPORT} host=${RMNGR_HOST} range=${RAGENT_RANGE}"
/opt/1cv8/current/rmngr \
  -d "$DATA_DIR" \
  -port "$RAGENT_REGPORT" \
  -host "$RMNGR_HOST" \
  -range "$RAGENT_RANGE" \
  >/var/log/onec/rmngr.log 2>&1 &
RMNGR_PID=$!

# RAS must connect to the cluster agent. Use loopback to avoid ambiguity with 0.0.0.0.
RAS_TARGET="127.0.0.1:${RAGENT_PORT}"

echo "[INFO] Starting 1C administration server (ras): port=${RAS_PORT} target=${RAS_TARGET}"
# Run RAS in background first, validate cluster, then wait in foreground.

cleanup() {
  kill -15 "${RAGENT_PID:-0}" 2>/dev/null || true
  kill -15 "${RMNGR_PID:-0}" 2>/dev/null || true
  kill -15 "${RAS_PID:-0}" 2>/dev/null || true
  wait "${RAS_PID:-}" 2>/dev/null || true
  wait "${RMNGR_PID:-}" 2>/dev/null || true
  wait "${RAGENT_PID:-}" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# If ragent dies early, fail fast.
sleep 0.2
if ! kill -0 "${RAGENT_PID}" 2>/dev/null; then
  echo "[ERROR] ragent exited early. See /var/log/onec/ragent.log"
  exit 2
fi

# If rmngr dies early, fail fast.
sleep 0.2
if ! kill -0 "${RMNGR_PID}" 2>/dev/null; then
  echo "[ERROR] rmngr exited early. See /var/log/onec/rmngr.log"
  exit 3
fi

#
# Start RAS and validate cluster config ("fail fast" on broken/empty cluster).
#
/opt/1cv8/current/ras cluster --port="${RAS_PORT}" "${RAS_TARGET}" \
  >/var/log/onec/ras.log 2>&1 &
RAS_PID=$!

sleep 0.2
if ! kill -0 "${RAS_PID}" 2>/dev/null; then
  echo "[ERROR] ras exited early. See /var/log/onec/ras.log"
  exit 4
fi

RAC="/opt/1cv8/current/rac"
RAC_ENDPOINT="127.0.0.1:${RAS_PORT}"

echo "[INFO] Waiting for RAS to accept connections at ${RAC_ENDPOINT}..."
for _ in $(seq 1 60); do
  if "$RAC" cluster list "${RAC_ENDPOINT}" >/tmp/rac_cluster.list 2>/tmp/rac_cluster.err; then
    break
  fi
  sleep 0.5
done

if ! "$RAC" cluster list "${RAC_ENDPOINT}" >/tmp/rac_cluster.list 2>/tmp/rac_cluster.err; then
  echo "[ERROR] RAS is running but rac cannot connect. rac error:"
  tail -n 50 /tmp/rac_cluster.err 2>/dev/null || true
  exit 5
fi

cluster_id="$(grep -Eo '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}' /tmp/rac_cluster.list | head -n1 || true)"
if [[ -z "${cluster_id}" || "${cluster_id}" == "00000000-0000-0000-0000-000000000000" ]]; then
  echo "[ERROR] Cluster id is empty/zero (cluster config is broken). rac output:"
  cat /tmp/rac_cluster.list 2>/dev/null || true
  exit 6
fi

cluster_host="$(grep -E '^host[[:space:]]*:[[:space:]]*' /tmp/rac_cluster.list | head -n1 | sed -E 's/^host[[:space:]]*:[[:space:]]*//' || true)"
cluster_port="$(grep -E '^port[[:space:]]*:[[:space:]]*' /tmp/rac_cluster.list | head -n1 | sed -E 's/^port[[:space:]]*:[[:space:]]*//' || true)"
if [[ -z "${cluster_host}" || -z "${cluster_port}" || "${cluster_port}" == "0" ]]; then
  echo "[ERROR] Cluster host/port is empty (cluster config is broken). rac output:"
  cat /tmp/rac_cluster.list 2>/dev/null || true
  exit 7
fi

echo "[OK] Cluster is ready: id=${cluster_id} host=${cluster_host} port=${cluster_port}"

# Optional: activate community license (no-op if secrets/env are missing or licenses exist).
# Run in background so ports/services are available while activation runs.
if command -v onec-activate-community.sh >/dev/null 2>&1; then
  echo "[INFO] Starting community activation in background (logs: /var/log/onec/activation.log)"
  /usr/local/bin/onec-activate-community.sh >/var/log/onec/activation.log 2>&1 &
  ACTIVATION_PID=$!
fi

# Foreground wait: keep container alive as a real service.
wait "${RAS_PID}"

