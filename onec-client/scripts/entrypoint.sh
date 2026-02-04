#!/bin/bash
set -euo pipefail

export USER=usr1cv8
export HOME=/home/usr1cv8

VNC_PORT=5901
NOVNC_PORT=6080
DISPLAY_NUM=:99

MACHINE_DIR="/var/lib/onec-machine"
FP_FILE="/var/1C/licenses/.license-fingerprint"

read_secret() {
  local name="$1"
  local p="/run/secrets/${name}"
  if [[ -f "$p" ]]; then
    cat "$p"
  fi
}

# Community license is tied to "hardware" identifiers. In containers these can change on recreate.
# We stabilize machine-id by persisting it in a volume and restoring into standard paths.
ensure_machine_id() {
  mkdir -p "$MACHINE_DIR" /var/lib/dbus || true

  local persisted="${MACHINE_DIR}/machine-id"
  if [[ ! -s "$persisted" ]]; then
    local uuid
    uuid="$(cat /proc/sys/kernel/random/uuid | tr -d '-' || true)"
    if [[ -z "${uuid:-}" ]]; then
      echo "[ERROR] Failed to generate machine-id"
      exit 1
    fi
    printf "%s" "$uuid" >"$persisted"
  fi

  # Restore into common locations used by different libs.
  cp -f "$persisted" /etc/machine-id 2>/dev/null || true
  cp -f "$persisted" /var/lib/dbus/machine-id 2>/dev/null || true
}

primary_mac() {
  # Prefer eth0 but fall back to the first non-loopback interface.
  local mac=""
  if command -v ip >/dev/null 2>&1; then
    mac="$(ip link show eth0 2>/dev/null | awk '/link\/ether/ {print $2; exit}' || true)"
    if [[ -z "${mac:-}" ]]; then
      mac="$(ip -o link show 2>/dev/null | awk -F'link/ether ' 'NF>1{print $2}' | awk '{print $1}' | head -n1 || true)"
    fi
  fi
  printf "%s" "${mac:-}"
}

license_fingerprint() {
  local mid mac
  mid="$(cat /etc/machine-id 2>/dev/null || true)"
  mac="$(primary_mac)"
  printf "%s|%s" "${mid:-}" "${mac:-}" | sha256sum | awk '{print $1}'
}

# Prefer secrets for credentials so "$" never breaks runtime.
export DEV_LOGIN="${DEV_LOGIN:-$(read_secret dev_login || true)}"
export DEV_PASSWORD="${DEV_PASSWORD:-$(read_secret dev_password || true)}"

mkdir -p /var/1C/licenses
chown -R usr1cv8:grp1cv8 /var/1C/licenses || true

ensure_machine_id

export DISPLAY="$DISPLAY_NUM"

ensure_xvfb() {
  local display="${DISPLAY_NUM:-:99}"
  local display_num="${display#*:}"
  display_num="${display_num%%.*}"
  local sock="/tmp/.X11-unix/X${display_num}"
  local lock="/tmp/.X${display_num}-lock"

  xvfb_running_for_display() {
    pgrep -f "Xvfb.*${display}" >/dev/null 2>&1
  }

  mkdir -p /tmp/.X11-unix
  chmod 1777 /tmp/.X11-unix || true

  if [ -S "$sock" ] && xvfb_running_for_display; then
    echo "[INFO] Xvfb already running on DISPLAY=${display}"
    return 0
  fi

  # Cleanup stale artifacts that prevent Xvfb from starting.
  if [ -S "$sock" ] && ! xvfb_running_for_display; then
    echo "[WARN] Stale X socket detected at ${sock}. Removing."
    rm -f "$sock" || true
  fi
  if [ -f "$lock" ] && ! xvfb_running_for_display; then
    echo "[WARN] Stale X lock detected at ${lock}. Removing."
    rm -f "$lock" || true
  fi

  echo "[INFO] Starting Xvfb on DISPLAY=${display}..."
  gosu usr1cv8 Xvfb "$display" -screen 0 1920x1080x24 -nolisten tcp >/tmp/xvfb.log 2>&1 &
  XVFB_PID=$!

  # Wait until the socket appears, otherwise GUI tools will fail later with GTK errors.
  for _ in $(seq 1 50); do
    [ -S "$sock" ] && return 0
    sleep 0.1
  done

  echo "[ERROR] Xvfb did not become ready (DISPLAY=${display}). See /tmp/xvfb.log"
  exit 1
}

ensure_xvfb

echo "[INFO] Starting desktop (xfce4-session)..."
gosu usr1cv8 dbus-launch --exit-with-session xfce4-session >/tmp/xfce.log 2>&1 &
XFCE_PID=$!

echo "[INFO] Starting x11vnc..."
if [[ -n "${VNC_PASSWORD:-}" ]]; then
  umask 077
  mkdir -p /tmp/vnc
  x11vnc -storepasswd "${VNC_PASSWORD}" /tmp/vnc/passwd >/dev/null 2>&1
  x11vnc -display "$DISPLAY" -rfbport "$VNC_PORT" -rfbauth /tmp/vnc/passwd -forever -shared -bg -o /tmp/x11vnc.log
else
  x11vnc -display "$DISPLAY" -rfbport "$VNC_PORT" -forever -shared -nopw -bg -o /tmp/x11vnc.log
fi

echo "[INFO] Starting noVNC on port ${NOVNC_PORT}..."
websockify --web=/usr/share/novnc/ --wrap-mode=ignore "${NOVNC_PORT}" "localhost:${VNC_PORT}" >/tmp/novnc.log 2>&1 &
NOVNC_PID=$!

need_activation=0

# Force flag for manual recovery (e.g. after license invalidation).
if [[ "${FORCE_COMMUNITY_ACTIVATION:-0}" =~ ^(1|true|yes|y|on)$ ]]; then
  need_activation=1
fi

# Auto-activate if missing/expiring soon (best-effort; depends on what .lic contains).
if [[ "$need_activation" == "0" ]] && /opt/onec-client/scripts/license_expiring_soon.sh >/dev/null 2>&1; then
  need_activation=1
fi

# If license files exist but belong to a different "machine" fingerprint, re-activate.
if [[ "$need_activation" == "0" ]]; then
  if find /var/1C/licenses -maxdepth 1 -type f -name '*.lic' -size +0 2>/dev/null | grep -q .; then
    cur_fp="$(license_fingerprint)"
    prev_fp="$(cat "$FP_FILE" 2>/dev/null || true)"
    if [[ -z "${prev_fp:-}" || "$prev_fp" != "$cur_fp" ]]; then
      echo "[WARN] License fingerprint mismatch (or missing). Will re-activate."
      need_activation=1
    fi
  fi
fi

if [[ "$need_activation" == "1" ]]; then
  echo "[INFO] Community license is missing or expiring soon. Activating..."
  gosu usr1cv8 /opt/onec-client/scripts/license_activator.sh
  # If activation produced license files, persist current fingerprint to avoid re-activation loops.
  if find /var/1C/licenses -maxdepth 1 -type f -name '*.lic' -size +0 2>/dev/null | grep -q .; then
    license_fingerprint >"$FP_FILE" 2>/dev/null || true
    chown usr1cv8:grp1cv8 "$FP_FILE" 2>/dev/null || true
    chmod 0644 "$FP_FILE" 2>/dev/null || true
  fi
else
  echo "[INFO] Community license looks OK."
fi

echo "[INFO] Ready. Open http://localhost:6080/vnc.html in your browser."
echo "[INFO] Host 1C server should be reachable as: ${HOST_1C_SERVER:-host.docker.internal}"

cleanup() {
  kill -15 "${NOVNC_PID:-0}" "${XFCE_PID:-0}" "${XVFB_PID:-0}" 2>/dev/null || true
  wait "${NOVNC_PID:-}" "${XFCE_PID:-}" "${XVFB_PID:-}" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

wait

