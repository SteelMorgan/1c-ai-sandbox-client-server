#!/usr/bin/env bash
set -euo pipefail

# Dev Containers + Docker Desktop volumes often come in as root:root 755.
# We need the non-root user (vscode) to be able to write in the workspace.
# With --security-opt=no-new-privileges, sudo is blocked, so we must fix this as root here.

# 1C "batch" tools can still require an X server. Provide a minimal virtual display.
# - Keep it lightweight: only Xvfb (no window manager) is enough for most cases.
# - DISPLAY itself is injected via docker-compose.yml, but we also default it here.
export DISPLAY="${DISPLAY:-:99}"

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

  # Start a virtual framebuffer in background.
  # - 1280x720x24 is plenty for headless needs.
  # - Write logs to a file to avoid polluting stdout.
  if id -u vscode >/dev/null 2>&1; then
    su -s /bin/bash vscode -c "nohup Xvfb \"${display}\" -screen 0 1280x720x24 -nolisten tcp -ac -noreset >\"${log}\" 2>&1 &"
  else
    nohup Xvfb "${display}" -screen 0 1280x720x24 -nolisten tcp -ac -noreset \
      >"${log}" 2>&1 &
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
      su -s /bin/bash vscode -c "nohup Xvfb \"${display}\" -screen 0 1280x720x24 -nolisten tcp -ac -noreset >\"${log}\" 2>&1 &"
    else
      nohup Xvfb "${display}" -screen 0 1280x720x24 -nolisten tcp -ac -noreset \
        >"${log}" 2>&1 &
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

if [ -d "/workspaces/work" ]; then
  chmod 0777 /workspaces/work || true
  # Also ensure common subdirs are writable (best-effort)
  mkdir -p /workspaces/work/.config /workspaces/work/.githooks || true
  chmod 0777 /workspaces/work/.config /workspaces/work/.githooks || true
fi

# Optional: if docker.sock is mounted, allow vscode to talk to Docker without sudo.
# WARNING: access to docker.sock is effectively root-equivalent on the Docker host.
if [ -S "/var/run/docker.sock" ]; then
  sock_gid="$(stat -c %g /var/run/docker.sock 2>/dev/null || echo '')"
  if [[ -n "$sock_gid" ]]; then
    if ! getent group dockersock >/dev/null 2>&1; then
      groupadd -g "$sock_gid" dockersock 2>/dev/null || true
    fi
    usermod -aG "$sock_gid" vscode 2>/dev/null || usermod -aG dockersock vscode 2>/dev/null || true
    chgrp "$sock_gid" /var/run/docker.sock 2>/dev/null || chgrp dockersock /var/run/docker.sock 2>/dev/null || true
    chmod 0660 /var/run/docker.sock 2>/dev/null || true
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

exec "$@"

