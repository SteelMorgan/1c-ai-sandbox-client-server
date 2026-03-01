#!/usr/bin/env bash
set -eu

# Some environments/scripts end up with CRLF or non-bash shells in the chain.
# Enable pipefail only if supported and parsed correctly.
if (set -o pipefail) 2>/dev/null; then
  set -o pipefail
fi

# Workspace is a Docker volume and may be owned by root (755). If we can't chown
# (common on Docker Desktop), fall back to chmod to allow writes for vscode.
if [ -d "/workspaces/work" ] && [ ! -w "/workspaces/work" ]; then
  # With --security-opt=no-new-privileges, sudo is blocked. Permission fix is handled by entrypoint.
  echo "WARNING: /workspaces/work is not writable for current user."
  echo "If this persists, rebuild the container (entrypoint should chmod 0777)."
fi

echo "Devcontainer ready."
echo
echo "Next steps:"
echo "- Create/confirm Docker volume: agent-work-sandbox-1c"
echo "- Authenticate GitHub bot inside container (see docs/github-bot-setup.md)"
echo "- Work only on branches: agent/<task>-<yyyymmdd>"

# Make sure git doesn't complain about ownership in containerized volumes
if command -v git >/dev/null 2>&1; then
  git config --global --add safe.directory "*" >/dev/null 2>&1 || true
fi

# GitHub auth bootstrap (idempotent). Uses /run/secrets/github_token when present.
bash /usr/local/share/agent-sandbox/gh-auth-bootstrap.sh || true

# ---------------------------------------------------------------------------
# Helper: run a cli-agent bootstrap script.
# Prefers workspace-local copy; falls back to image-baked copy.
# ---------------------------------------------------------------------------
run_bootstrap() {
  local rel="$1"   # e.g. cli-agents/codex/bootstrap.sh
  local ws="/workspaces/work/.devcontainer/${rel}"
  local img="/usr/local/share/agent-sandbox/${rel}"
  if [[ -f "${ws}" ]]; then
    bash "${ws}" || bash "${img}" || true
  else
    bash "${img}" || true
  fi
}

# ---------------------------------------------------------------------------
# Claude Code bootstrap (idempotent).
# Sets up custom backend, statusLine, cc alias / symlink.
# ---------------------------------------------------------------------------
if [[ "${CUSTOM_OPENAI_ENABLED:-0}" == "1" ]]; then
  run_bootstrap cli-agents/claude/bootstrap.sh
else
  echo "[postCreate] CUSTOM_OPENAI_ENABLED is not 1 — skipping Claude custom backend bootstrap."
fi

# ---------------------------------------------------------------------------
# Codex bootstrap (idempotent). Uses /run/secrets/cc_api_key when present.
# ---------------------------------------------------------------------------
if [[ "${CUSTOM_OPENAI_ENABLED:-0}" == "1" ]]; then
  run_bootstrap cli-agents/codex/bootstrap.sh
else
  echo "[postCreate] CUSTOM_OPENAI_ENABLED is not 1 — skipping Codex custom backend bootstrap."
fi

# ---------------------------------------------------------------------------
# Gemini CLI bootstrap (idempotent). Uses /run/secrets/cc_api_key when present.
# ---------------------------------------------------------------------------
if [[ "${CUSTOM_OPENAI_ENABLED:-0}" == "1" ]]; then
  run_bootstrap cli-agents/gemini/bootstrap.sh
else
  echo "[postCreate] CUSTOM_OPENAI_ENABLED is not 1 — skipping Gemini CLI bootstrap."
fi

# Global pre-push hook is installed by entrypoint (root-owned, locked-down).
# (Still bypassable by a determined user; this is an anti-footgun.)
