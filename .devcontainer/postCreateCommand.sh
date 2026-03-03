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

# Python dependencies (idempotent, no rebuild required)
pip3 install --quiet --break-system-packages "python-xlib==0.33" "Pillow" "tiktoken" 2>/dev/null || pip3 install --quiet "python-xlib==0.33" "Pillow" "tiktoken" || true

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
run_bootstrap cli-agents/claude/bootstrap.sh
if [[ "${CUSTOM_CLAUDE_ENABLED:-0}" != "1" ]]; then
  echo "[postCreate] CUSTOM_CLAUDE_ENABLED is not 1 — Claude wrapper/aliases stay enabled, custom backend setup skipped."
fi

# ---------------------------------------------------------------------------
# Codex bootstrap (idempotent). Uses /run/secrets/cc_api_key when present.
# ---------------------------------------------------------------------------
run_bootstrap cli-agents/codex/bootstrap.sh
if [[ "${CUSTOM_CODEX_ENABLED:-0}" != "1" ]]; then
  echo "[postCreate] CUSTOM_CODEX_ENABLED is not 1 — Codex wrapper/aliases stay enabled, custom backend setup skipped."
fi

# ---------------------------------------------------------------------------
# Gemini CLI bootstrap (idempotent). Uses /run/secrets/cc_api_key when present.
# ---------------------------------------------------------------------------
run_bootstrap cli-agents/gemini/bootstrap.sh
if [[ "${CUSTOM_GEMINI_ENABLED:-0}" != "1" ]]; then
  echo "[postCreate] CUSTOM_GEMINI_ENABLED is not 1 — Gemini wrapper/aliases stay enabled, custom backend setup skipped."
fi

# Global pre-push hook is installed by entrypoint (root-owned, locked-down).
# (Still bypassable by a determined user; this is an anti-footgun.)
