#!/usr/bin/env bash
set -euo pipefail

if ! command -v claude >/dev/null 2>&1; then
  echo "claude command not found in PATH" >&2
  exit 127
fi

# ---------------------------------------------------------------------------
# Orchestrator profile injection
#
# By default we raise the orchestrator profile into the system prompt
# (Lead in the main thread). The path points at the English version of the
# profile (framework_eng). It can be overridden via ORCHESTRATOR_PROFILE.
#
# The profile is appended ONLY for an interactive/print session — service
# subcommands (mcp, config, update, doctor, ...) do not accept
# --append-system-prompt.
#
# NOTE: this is a runtime `cat`, not build-time. The profile path must be
# mounted/cloned and present by the time `cc` is invoked, otherwise the
# fallback warning fires and Claude starts without the orchestrator.
# ---------------------------------------------------------------------------
ORCHESTRATOR_PROFILE="${ORCHESTRATOR_PROFILE:-/workspaces/work/repos/1C Framework/1c-agent-based-dev-framework/framework_eng/subagents/orchestrator.md}"

CLAUDE_ARGS=()
first_arg="${1:-}"
case "$first_arg" in
  mcp|config|update|doctor|migrate-installer|setup-token|install|plugin|help)
    # service subcommand — do not mix in the profile
    ;;
  *)
    if [[ -f "$ORCHESTRATOR_PROFILE" ]]; then
      CLAUDE_ARGS+=(--append-system-prompt "$(cat "$ORCHESTRATOR_PROFILE")")
    else
      echo "warn: orchestrator profile not found at $ORCHESTRATOR_PROFILE — starting without it" >&2
    fi
    ;;
esac

kill_descendants() {
  local parent_pid="$1"
  local child

  for child in $(pgrep -P "$parent_pid" 2>/dev/null || true); do
    kill_descendants "$child"
    kill "$child" 2>/dev/null || true
  done
}

claude "${CLAUDE_ARGS[@]}" "$@" &
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
