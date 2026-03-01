#!/usr/bin/env bash
# Configures Claude Code for the current user.
#
# Reads non-secret settings from env vars (injected via .devcontainer/.env):
#   OPENAI_BASE_URL                    — base URL of the OpenAI-compatible server
#   CC_HELPER_VALIDATE_MODE            — validate mode (anthropic / openai)
#   CC_HELPER_MODEL                    — model alias (sonnet / opus / haiku)
#   CC_HELPER_ALIAS_OPUS/SONNET/HAIKU  — model name overrides
#   CC_HELPER_API_TIMEOUT_MS           — request timeout in ms
#   CC_HELPER_DISABLE_NONESSENTIAL_TRAFFIC — 0/1
#   CC_HELPER_SKIP_VALIDATE            — 0/1
#
# API key is read from Docker secret:
#   /run/secrets/cc_api_key
#
# Writes:
#   ~/.claude/settings.json  — statusLine + permissions (via helper.mjs)
#   ~/bin/claude-safe.sh     — wrapper with proper signal handling
#   /usr/local/bin/cc        — symlink to claude-safe.sh (system-wide, via sudo)
#   ~/.bashrc: PATH+=~/bin, alias cc / сс
#
set -euo pipefail

# ---------------------------------------------------------------------------
# Resolve paths: prefer workspace-local files, fall back to image-baked copies
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SANDBOX_DIR="/usr/local/share/agent-sandbox/cli-agents/claude"

resolve_file() {
  local rel="$1"
  if [[ -f "${SCRIPT_DIR}/${rel}" ]]; then
    echo "${SCRIPT_DIR}/${rel}"
  else
    echo "${SANDBOX_DIR}/${rel}"
  fi
}

HELPER_MJS="$(resolve_file helper.mjs)"
CLAUDE_SAFE_SH="$(resolve_file tools/claude-safe.sh)"
STATUSLINE_JS="$(resolve_file tools/statusline.js)"

# ---------------------------------------------------------------------------
# Read secrets and env
# ---------------------------------------------------------------------------
API_KEY=""
SECRET_FILE="/run/secrets/cc_api_key"
if [[ -f "${SECRET_FILE}" && -s "${SECRET_FILE}" ]]; then
  API_KEY="$(cat "${SECRET_FILE}")"
  echo "[claude-bootstrap] API key read from ${SECRET_FILE}"
fi

BASE_URL="${OPENAI_BASE_URL:-}"

if [[ -z "${BASE_URL}" ]]; then
  echo "[claude-bootstrap] OPENAI_BASE_URL is not set — skipping Claude custom backend config." >&2
  # Still set up wrapper and alias even without custom backend
fi

# ---------------------------------------------------------------------------
# Configure custom backend via helper.mjs (if enabled)
# ---------------------------------------------------------------------------
if [[ -n "${BASE_URL}" ]]; then
  if [[ ! -s "${SECRET_FILE}" ]]; then
    echo "[claude-bootstrap] WARNING: /run/secrets/cc_api_key is empty or missing" >&2
  fi

  if [[ ! -f "${HELPER_MJS}" ]]; then
    echo "[claude-bootstrap] WARNING: helper.mjs not found at ${HELPER_MJS}" >&2
  elif ! command -v node >/dev/null 2>&1; then
    echo "[claude-bootstrap] WARNING: node not found — cannot run helper.mjs" >&2
  else
    args=(
      setup
      --base-url "${BASE_URL}"
      --api-key "${API_KEY}"
      --model "${CC_HELPER_MODEL:-sonnet}"
      --validate-mode "${CC_HELPER_VALIDATE_MODE:-anthropic}"
      --timeout-ms "${CC_HELPER_API_TIMEOUT_MS:-30000}"
      --disable-nonessential "${CC_HELPER_DISABLE_NONESSENTIAL_TRAFFIC:-1}"
    )
    [[ -n "${CC_HELPER_ALIAS_OPUS:-}" ]]   && args+=(--alias-opus   "${CC_HELPER_ALIAS_OPUS}")
    [[ -n "${CC_HELPER_ALIAS_SONNET:-}" ]] && args+=(--alias-sonnet "${CC_HELPER_ALIAS_SONNET}")
    [[ -n "${CC_HELPER_ALIAS_HAIKU:-}" ]]  && args+=(--alias-haiku  "${CC_HELPER_ALIAS_HAIKU}")
    [[ "${CC_HELPER_SKIP_VALIDATE:-0}" == "1" ]] && args+=(--skip-validate)

    if node "${HELPER_MJS}" "${args[@]}"; then
      echo "[claude-bootstrap] Custom backend configured."
    else
      echo "[claude-bootstrap] WARNING: helper.mjs failed." >&2
    fi
  fi
fi

# ---------------------------------------------------------------------------
# Configure statusLine in ~/.claude/settings.json
# ---------------------------------------------------------------------------
if [[ -f "${STATUSLINE_JS}" ]] && command -v node >/dev/null 2>&1; then
  mkdir -p "${HOME}/.claude"
  settings_file="${HOME}/.claude/settings.json"
  node - "${settings_file}" "${STATUSLINE_JS}" <<'NODEJS'
const fs = require('fs');
const [,, settingsFile, statuslinePath] = process.argv;
let settings = {};
try { settings = JSON.parse(fs.readFileSync(settingsFile, 'utf8')); } catch {}
settings.statusLine = { type: 'command', command: `node "${statuslinePath}"` };
const permissions = settings.permissions && typeof settings.permissions === 'object' ? settings.permissions : {};
settings.permissions = { ...permissions, defaultMode: 'bypassPermissions', ask: [], deny: [] };
fs.writeFileSync(settingsFile, JSON.stringify(settings, null, 2), 'utf8');
console.log('[claude-bootstrap] statusLine written to', settingsFile);
NODEJS
fi

# ---------------------------------------------------------------------------
# ~/bin/claude-safe.sh — wrapper script
# ---------------------------------------------------------------------------
WRAPPER_DIR="${HOME}/bin"
mkdir -p "${WRAPPER_DIR}"
CLAUDE_WRAPPER="${WRAPPER_DIR}/claude-safe.sh"

cp "${CLAUDE_SAFE_SH}" "${CLAUDE_WRAPPER}"
chmod +x "${CLAUDE_WRAPPER}"
echo "[claude-bootstrap] ${CLAUDE_WRAPPER} installed."

# ---------------------------------------------------------------------------
# Ensure ~/bin is in PATH (idempotent)
# ---------------------------------------------------------------------------
BASHRC="${HOME}/.bashrc"
[[ -f "${BASHRC}" ]] || touch "${BASHRC}"

if ! grep -qF 'export PATH="${HOME}/bin:${PATH}"' "${BASHRC}" 2>/dev/null; then
  printf '\n# Added by claude-bootstrap.sh\nexport PATH="${HOME}/bin:${PATH}"\n' >> "${BASHRC}"
  echo "[claude-bootstrap] ~/bin added to PATH in ${BASHRC}."
fi

# ---------------------------------------------------------------------------
# Shell aliases in ~/.bashrc (idempotent)
# ---------------------------------------------------------------------------
add_alias() {
  local name="$1"
  local target="$2"
  if grep -qF "alias ${name}=" "${BASHRC}" 2>/dev/null; then
    echo "[claude-bootstrap] alias '${name}' already exists — skipping."
    return 0
  fi
  printf '\n# Added by claude-bootstrap.sh\nalias %s="%s"\n' "${name}" "${target}" >> "${BASHRC}"
  echo "[claude-bootstrap] alias '${name}' -> ${target} added."
}

add_alias "cc"  "${CLAUDE_WRAPPER}"
add_alias "сс"  "${CLAUDE_WRAPPER}"  # кириллица

# ---------------------------------------------------------------------------
# System-wide /usr/local/bin/cc symlink (via sudo — works in any shell)
# ---------------------------------------------------------------------------
if command -v sudo > /dev/null 2>&1 && sudo -n true 2>/dev/null; then
  sudo ln -sf "${CLAUDE_WRAPPER}" /usr/local/bin/cc 2>/dev/null \
    && echo "[claude-bootstrap] /usr/local/bin/cc -> ${CLAUDE_WRAPPER}" \
    || echo "[claude-bootstrap] WARNING: could not create /usr/local/bin/cc" >&2
else
  echo "[claude-bootstrap] sudo not available; /usr/local/bin/cc not created (alias in .bashrc still works)" >&2
fi

echo "[claude-bootstrap] Done."
