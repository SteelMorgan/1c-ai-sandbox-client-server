#!/bin/bash
set -euo pipefail

read_secret() {
  local name="$1"
  local p="/run/secrets/${name}"
  if [[ -f "$p" ]]; then
    cat "$p"
  fi
}

export DEV_LOGIN="${DEV_LOGIN:-$(read_secret dev_login || true)}"
export DEV_PASSWORD="${DEV_PASSWORD:-$(read_secret dev_password || true)}"

if [[ -z "${DEV_LOGIN:-}" || -z "${DEV_PASSWORD:-}" ]]; then
  echo "[ERROR] DEV_LOGIN/DEV_PASSWORD are required for community license activation"
  exit 1
fi

echo "[INFO] Community license activation started."

export DISPLAY=:99

ACTIVATION_DB_NAME=EmptyIB_Activation
ACTIVATION_DB_PATH="/home/usr1cv8/Documents/${ACTIVATION_DB_NAME}"
mkdir -p "/home/usr1cv8/Documents"

if [[ ! -d "$ACTIVATION_DB_PATH" ]]; then
  echo "[INFO] Creating empty infobase: $ACTIVATION_DB_PATH"
  /opt/1cv8/current/ibcmd infobase create --db-path="$ACTIVATION_DB_PATH"
fi

# Prevent "unsafe action / first time external processing" modal dialogs for this IB.
# This is the same idea used in onec-community-docker.
CONF_CFG="/opt/1cv8/conf/conf.cfg"
if [[ -f "$CONF_CFG" ]]; then
  if ! grep -q "DisableUnsafeActionProtection=.*${ACTIVATION_DB_NAME}.*" "$CONF_CFG" 2>/dev/null; then
    printf "\nDisableUnsafeActionProtection=.*%s.*\n" "$ACTIVATION_DB_NAME" >> "$CONF_CFG"
  fi
fi

ACTIVATION_IB_REGPORT=9141
ACTIVATION_IB_DIRECT_RANGE=9160:9161

echo "[INFO] Starting local ibsrv for activation..."
/opt/1cv8/current/ibsrv \
  --db-path="$ACTIVATION_DB_PATH" \
  --name="$ACTIVATION_DB_NAME" \
  --direct-regport="$ACTIVATION_IB_REGPORT" \
  --direct-range="$ACTIVATION_IB_DIRECT_RANGE" \
  </dev/null &
SERVER_PID=$!

cleanup() {
  kill -15 "${SERVER_PID:-0}" 2>/dev/null || true
  wait "${SERVER_PID:-}" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

echo "[INFO] Waiting for activation ibsrv (port=$ACTIVATION_IB_REGPORT)..."
until netstat -tln 2>/dev/null | grep -q "$ACTIVATION_IB_REGPORT"; do
  sleep 1
done

echo "[INFO] Running ActivateCommunity.epf..."
/opt/1cv8/current/1cv8c ENTERPRISE \
  /S "localhost:${ACTIVATION_IB_REGPORT}/${ACTIVATION_DB_NAME}" \
  /Execute "/opt/onec-client/ActivateCommunity.epf" \
  /C "login=${DEV_LOGIN};password=${DEV_PASSWORD};acceptLicense=true" \
  /DisableStartupMessages \
  /UseHwLicenses-

chown -R usr1cv8:grp1cv8 /var/1C/licenses || true
chmod -R 755 /var/1C/licenses || true

echo "[INFO] Community license activation finished."

