#!/bin/bash
set -euo pipefail

export USER=usr1cv8
export HOME=/home/usr1cv8

VNC_PORT=5901
NOVNC_PORT=6080
DISPLAY_NUM=:99

read_secret() {
  local name="$1"
  local p="/run/secrets/${name}"
  if [[ -f "$p" ]]; then
    cat "$p"
  fi
}

# Prefer secrets for credentials so "$" never breaks runtime.
export DEV_LOGIN="${DEV_LOGIN:-$(read_secret dev_login || true)}"
export DEV_PASSWORD="${DEV_PASSWORD:-$(read_secret dev_password || true)}"

mkdir -p /var/1C/licenses
chown -R usr1cv8:grp1cv8 /var/1C/licenses || true

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

# Auto-activate community license if needed (missing / expiring soon)
if /opt/onec-client/scripts/license_expiring_soon.sh >/dev/null 2>&1; then
  echo "[INFO] Community license is missing or expiring soon. Activating..."
  gosu usr1cv8 /opt/onec-client/scripts/license_activator.sh
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

