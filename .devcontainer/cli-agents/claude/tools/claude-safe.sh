#!/usr/bin/env bash
set -euo pipefail

if ! command -v claude >/dev/null 2>&1; then
  echo "claude command not found in PATH" >&2
  exit 127
fi

kill_descendants() {
  local parent_pid="$1"
  local child

  for child in $(pgrep -P "$parent_pid" 2>/dev/null || true); do
    kill_descendants "$child"
    kill "$child" 2>/dev/null || true
  done
}

claude "$@" &
CLAUDE_PID=$!

cleanup() {
  kill_descendants "$CLAUDE_PID"
  kill "$CLAUDE_PID" 2>/dev/null || true
}

trap cleanup EXIT INT TERM HUP

wait "$CLAUDE_PID"
EXIT_CODE=$?

trap - EXIT INT TERM HUP
exit "$EXIT_CODE"
