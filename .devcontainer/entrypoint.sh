#!/usr/bin/env bash
set -euo pipefail

# Dev Containers + Docker Desktop volumes often come in as root:root 755.
# We need the non-root user (vscode) to be able to write in the workspace.
# With --security-opt=no-new-privileges, sudo is blocked, so we must fix this as root here.

# 1C "batch" tools can still require an X server. Provide a minimal virtual display.
# - Keep it lightweight: only Xvfb (no window manager) is enough for most cases.
# - DISPLAY itself is injected via docker-compose.yml, but we also default it here.
export DISPLAY="${DISPLAY:-:99}"

# Conditionally expose backend URLs based on feature flags.
# .env stores URLs under _CLAUDE_BASE_URL / _OPENAI_BASE_URL (never leaked to children).
# The "public" names are only exported when the corresponding feature flag is enabled.
if [[ "${CUSTOM_CLAUDE_ENABLED:-0}" == "1" && -n "${_CLAUDE_BASE_URL:-}" ]]; then
  export CLAUDE_BASE_URL="${_CLAUDE_BASE_URL}"
fi
if [[ "${CUSTOM_CODEX_ENABLED:-0}" == "1" && -n "${_OPENAI_BASE_URL:-}" ]]; then
  export OPENAI_BASE_URL="${_OPENAI_BASE_URL}"
fi

# Write the same conditional logic into /etc/profile.d/ so that interactive shells
# (terminals, docker exec) also see the public names only when enabled.
cat > /etc/profile.d/custom-backends.sh << 'PROFILE_EOF'
if [ "${CUSTOM_CLAUDE_ENABLED:-0}" = "1" ] && [ -n "${_CLAUDE_BASE_URL:-}" ]; then
  export CLAUDE_BASE_URL="${_CLAUDE_BASE_URL}"
fi
if [ "${CUSTOM_CODEX_ENABLED:-0}" = "1" ] && [ -n "${_OPENAI_BASE_URL:-}" ]; then
  export OPENAI_BASE_URL="${_OPENAI_BASE_URL}"
fi
PROFILE_EOF

# Force UTF-8 locale for all child processes (1C tools included).
# This prevents Cyrillic file/folder names from being replaced with '???' under LANG=C.
export LANG="${LANG:-ru_RU.UTF-8}"
export LC_ALL="${LC_ALL:-ru_RU.UTF-8}"
export LC_CTYPE="${LC_CTYPE:-ru_RU.UTF-8}"
export LANGUAGE="${LANGUAGE:-ru_RU:ru}"

start_xvfb() {
  # Derive socket path from DISPLAY (e.g. :99 -> /tmp/.X11-unix/X99).
  # (If DISPLAY is something like :99.0, strip the screen suffix.)
  local display="${DISPLAY:-:99}"
  local display_num="${display#*:}"
  display_num="${display_num%%.*}"
  local sock="/tmp/.X11-unix/X${display_num}"
  local lock="/tmp/.X${display_num}-lock"
  local log="/tmp/xvfb-${display_num}.log"

  xvfb_running_for_display() {
    # Check that *our* display is served, not just "some Xvfb somewhere".
    pgrep -f "Xvfb.*${display}" >/dev/null 2>&1
  }

  # If the socket exists, it might be stale (e.g. unclean shutdown).
  # Don't trust the socket alone: verify Xvfb is actually running.
  if [ -S "$sock" ]; then
    if xvfb_running_for_display; then
      return 0
    fi
    echo "WARNING: stale X socket detected at ${sock} (Xvfb is not running). Recreating."
    rm -f "$sock" || true
  fi

  # If the lock exists but Xvfb is not running, it's stale and will prevent startup:
  #   Could not create server lock file: /tmp/.X99-lock
  if [ -f "$lock" ] && ! xvfb_running_for_display; then
    echo "WARNING: stale X lock detected at ${lock} (Xvfb is not running). Removing."
    rm -f "$lock" || true
  fi

  if ! command -v Xvfb >/dev/null 2>&1; then
    echo "WARNING: Xvfb is not installed; 1C may fail to start without a display."
    return 0
  fi

  mkdir -p /tmp/.X11-unix
  chmod 1777 /tmp/.X11-unix || true

  # Start a virtual framebuffer in background with auto-restart watchdog.
  # - 1920x1080x24 is plenty for headless needs.
  # - Write logs to a file to avoid polluting stdout.
  local xvfb_cmd="Xvfb \"${display}\" -screen 0 1920x1080x24 -nolisten tcp -ac -noreset"
  local watchdog='while true; do '"${xvfb_cmd}"' >>'"${log}"' 2>&1; echo "$(date): Xvfb exited, restarting in 1s..." >>'"${log}"'; sleep 1; done'
  if id -u vscode >/dev/null 2>&1; then
    su -s /bin/bash vscode -c "nohup bash -c '${watchdog}' >/dev/null 2>&1 &"
  else
    nohup bash -c "${watchdog}" >/dev/null 2>&1 &
  fi

  # Best-effort wait until the socket appears (fast fail avoids hiding issues).
  for _ in $(seq 1 50); do
    [ -S "$sock" ] && return 0
    sleep 0.1
  done

  # One more recovery attempt: lock may have been created by another user/root on the previous run.
  if [ -f "$lock" ] && ! xvfb_running_for_display; then
    echo "WARNING: Xvfb did not become ready (DISPLAY=${display}). Found ${lock} without a running Xvfb. Retrying after lock cleanup."
    rm -f "$lock" || true
    if id -u vscode >/dev/null 2>&1; then
      su -s /bin/bash vscode -c "nohup bash -c '${watchdog}' >/dev/null 2>&1 &"
    else
      nohup bash -c "${watchdog}" >/dev/null 2>&1 &
    fi
    for _ in $(seq 1 50); do
      [ -S "$sock" ] && return 0
      sleep 0.1
    done
  fi

  echo "ERROR: Xvfb did not become ready (DISPLAY=${display}). See ${log}"
  exit 1
}

start_xvfb

start_vnc_bridge() {
  # Bridge Xvfb (:99) to browser via noVNC.
  # - x11vnc exposes VNC on 5900
  # - websockify serves noVNC UI on 6080 and proxies to 5900
  local vnc_log="/tmp/x11vnc.log"
  local ws_log="/tmp/websockify.log"

  if ! command -v x11vnc >/dev/null 2>&1; then
    echo "WARNING: x11vnc is not installed; skipping VNC bridge startup."
    return 0
  fi

  if ! command -v websockify >/dev/null 2>&1; then
    echo "WARNING: websockify is not installed; skipping noVNC bridge startup."
    return 0
  fi

  # Restart bridge processes on each container start (idempotent).
  pkill x11vnc >/dev/null 2>&1 || true
  pkill -f '/usr/bin/websockify' >/dev/null 2>&1 || true

  nohup bash -c 'while true; do x11vnc -display "'"${DISPLAY}"'" -rfbport 5900 -localhost -nopw -forever -shared -noxdamage -noxfixes -noscr -nowf >>"'"${vnc_log}"'" 2>&1; echo "$(date): x11vnc exited, restarting in 1s..." >>"'"${vnc_log}"'"; sleep 1; done' >/dev/null 2>&1 &

  # Debian/Ubuntu websockify script has python shebang; run via python3 explicitly for stability.
  nohup /usr/bin/python3 /usr/bin/websockify \
    --web=/usr/share/novnc \
    6080 \
    127.0.0.1:5900 \
    >"${ws_log}" 2>&1 &
}

start_vnc_bridge

prepare_fontconfig_cache() {
  # 1C client checks fonts in user session context.
  # Ensure user fontconfig cache exists and is refreshed to avoid false "Core Fonts missing" errors.
  if id -u vscode >/dev/null 2>&1; then
    su -s /bin/bash vscode -c 'mkdir -p /home/vscode/.cache/fontconfig'
    su -s /bin/bash vscode -c 'fc-cache -fv >/tmp/fc-cache-vscode.log 2>&1' || true
  fi
}

prepare_fontconfig_cache

if [ -d "/workspaces/work" ]; then
  chmod 0777 /workspaces/work || true
  # Also ensure common subdirs are writable (best-effort)
  mkdir -p /workspaces/work/.config /workspaces/work/.githooks || true
  chmod 0777 /workspaces/work/.config /workspaces/work/.githooks || true
fi

# Ensure gh config dir is writable for vscode even when it's a named volume (can come in as root:root).
if id -u vscode >/dev/null 2>&1; then
  gh_dir="/home/vscode/.config/gh"
  mkdir -p "$gh_dir" 2>/dev/null || true
  chown -R vscode:vscode "$gh_dir" 2>/dev/null || true
  chmod 0700 "$gh_dir" 2>/dev/null || true
  chmod 0600 "$gh_dir"/*.yml 2>/dev/null || true
fi

# Optional: if docker.sock is mounted, allow vscode to talk to Docker without sudo.
# WARNING: access to docker.sock is effectively root-equivalent on the Docker host.
if [ -S "/var/run/docker.sock" ]; then
  sock_gid="$(stat -c %g /var/run/docker.sock 2>/dev/null || echo '')"

  # Preferred path: non-root gid from host socket.
  if [[ -n "$sock_gid" && "$sock_gid" != "0" ]]; then
    if ! getent group dockersock >/dev/null 2>&1; then
      groupadd -g "$sock_gid" dockersock 2>/dev/null || true
    fi
    usermod -aG dockersock vscode 2>/dev/null || usermod -aG "$sock_gid" vscode 2>/dev/null || true
    chgrp "$sock_gid" /var/run/docker.sock 2>/dev/null || chgrp dockersock /var/run/docker.sock 2>/dev/null || true
    chmod 0660 /var/run/docker.sock 2>/dev/null || true
  else
    # Avoid adding vscode to root group when socket gid is 0.
    # Try conventional docker group if present; otherwise fall back to permissive mode.
    if getent group docker >/dev/null 2>&1; then
      usermod -aG docker vscode 2>/dev/null || true
      chgrp docker /var/run/docker.sock 2>/dev/null || true
      chmod 0660 /var/run/docker.sock 2>/dev/null || true
    else
      chmod 0666 /var/run/docker.sock 2>/dev/null || true
    fi
  fi
fi

# Install a locked-down global pre-push hook (root-owned, read/exec only).
# This prevents accidental edits/deletes by the vscode user.
if command -v git >/dev/null 2>&1; then
  hooks_dir="/usr/local/share/agent-sandbox/githooks"
  mkdir -p "$hooks_dir"
  cat > "$hooks_dir/pre-push" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

remote_name="${1:-}"
remote_url="${2:-}"

blocked='refs/heads/main|refs/heads/master'

# stdin lines: <local ref> <local sha> <remote ref> <remote sha>
while read -r local_ref local_sha remote_ref remote_sha; do
  if [[ "$remote_ref" =~ $blocked ]]; then
    echo "BLOCKED: pushing directly to ${remote_ref} is not allowed in this environment."
    echo "Create a branch like agent/<task>-<yyyymmdd> and open a PR."
    echo "Remote: ${remote_name} (${remote_url})"
    exit 1
  fi
done
EOF
  chown root:root "$hooks_dir/pre-push" || true
  chmod 0555 "$hooks_dir/pre-push" || true
  chmod 0555 "$hooks_dir" || true
  # Set system-level hooksPath so it's not editable by vscode.
  git config --system core.hooksPath "$hooks_dir" >/dev/null 2>&1 || true
  # If an old global hooksPath exists in the volume-backed global gitconfig,
  # remove it so it can't override the system setting.
  git config --global --unset-all core.hooksPath >/dev/null 2>&1 || true
fi

# ---------------------------------------------------------------------------
# Fix ownership for vscode so it can install/update packages without sudo.
# Volumes and image layers can reset ownership to root between rebuilds.
# ---------------------------------------------------------------------------
if id -u vscode >/dev/null 2>&1; then
  # npm / node global dirs
  for d in /usr/lib/node_modules /usr/local/lib/node_modules \
           /usr/local/lib /usr/local/bin /usr/local/share /usr/local/include /usr/local; do
    [ -d "$d" ] && chown -R vscode:vscode "$d" 2>/dev/null || true
  done

  # pip install without sudo
  for d in /usr/lib/python3*/dist-packages /usr/local/lib/python3*; do
    # glob may expand to nothing — guard with test
    [ -d "$d" ] && chown -R vscode:vscode "$d" 2>/dev/null || true
  done

  # OneScript tooling lives in /opt/onescript (not touching /opt/1cv8 which belongs to usr1cv8)
  [ -d "/opt/onescript" ] && chown -R vscode:vscode /opt/onescript 2>/dev/null || true

  # Ensure tmp dirs have correct sticky-bit permissions
  chmod 1777 /tmp /var/tmp 2>/dev/null || true

  # Ensure vscode is in root group at runtime (belt-and-suspenders for volume mounts)
  usermod -aG root vscode 2>/dev/null || true
fi

exec "$@"
