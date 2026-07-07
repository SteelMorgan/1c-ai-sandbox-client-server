#!/usr/bin/env bash
# Configures DeepSeek CLI (@sluisr/deepseek-cli) for the current user.
#
# Since this runs inside a devcontainer (isolated sandbox), we configure
# the CLI with full unrestricted access via CLI flags:
#   --approval-mode=yolo   — auto-approve all actions (YOLO mode)
#
# IMPORTANT: YOLO mode can ONLY be enabled via command-line flag
# (--approval-mode=yolo or -y/--yolo). There is no config.json setting
# to enable it — the settings file only supports 'default', 'auto_edit',
# and 'plan' for general.defaultApprovalMode.
#
# Reads non-secret settings from env vars (injected via .devcontainer/.env):
#   DEEPSEEK_MODEL  — default model name (optional, default: deepseek-chat)
#   DEEPSEEK_BASE_URL — custom API base URL (optional)
#
# API key is read from Docker secret:
#   /run/secrets/deepseek_api_key
#
# Writes:
#   ~/.deepseek/settings.json     — persistent DeepSeek CLI settings
#   ~/.deepseek/.env              — API key + base URL (chmod 0600)
#   ~/bin/ds                      — wrapper that exports env vars + YOLO flag, then exec deepseek
#   /usr/local/bin/ds             — symlink to ds wrapper (system-wide, via sudo)
#   ~/.bashrc: PATH+=~/bin, alias ds / вы
#
set -euo pipefail

DEEPSEEK_DIR="${HOME}/.deepseek"
mkdir -p "${DEEPSEEK_DIR}"

MODEL="${DEEPSEEK_MODEL:-deepseek-chat}"
BASE_URL="${DEEPSEEK_BASE_URL:-}"

# ---------------------------------------------------------------------------
# Read API key from Docker secret
# ---------------------------------------------------------------------------
API_KEY=""
SECRET_FILE="/run/secrets/deepseek_api_key"
if [[ -f "${SECRET_FILE}" && -s "${SECRET_FILE}" ]]; then
  API_KEY="$(cat "${SECRET_FILE}")"
fi

ENABLE_CUSTOM_DEEPSEEK=1
if [[ "${CUSTOM_DEEPSEEK_ENABLED:-0}" != "1" ]]; then
  echo "[deepseek-bootstrap] CUSTOM_DEEPSEEK_ENABLED is not set to 1 — skipping config." >&2
  ENABLE_CUSTOM_DEEPSEEK=0
fi

if [[ "${ENABLE_CUSTOM_DEEPSEEK}" == "1" && -z "${API_KEY}" ]]; then
  echo "[deepseek-bootstrap] WARNING: /run/secrets/deepseek_api_key is empty or missing" >&2
fi

# ---------------------------------------------------------------------------
# State tracking for idempotent bootstrap
# ---------------------------------------------------------------------------
STATE_DIR="${HOME}/.agent-sandbox"
STATE_FILE="${STATE_DIR}/bootstrap-state.env"
mkdir -p "${STATE_DIR}"

write_state_var() {
  local key="$1"
  local value="$2"
  local tmp
  tmp="$(mktemp)"
  if [[ -f "${STATE_FILE}" ]]; then
    awk -F= -v k="$key" '$1!=k{print}' "${STATE_FILE}" > "${tmp}"
  fi
  printf "%s=%s
" "$key" "$value" >> "${tmp}"
  mv -f "${tmp}" "${STATE_FILE}"
}

write_state_var DEEPSEEK_MODE "custom"

if [[ "${ENABLE_CUSTOM_DEEPSEEK}" == "1" ]]; then

# ---------------------------------------------------------------------------
# ~/.deepseek/settings.json
#
# NOTE: YOLO mode cannot be set here — it's only available via CLI flag
# (--approval-mode=yolo). We set permissive-but-reasonable defaults:
# - defaultApprovalMode: "auto_edit"  — auto-approve edit tools
# - toolSandboxing: false             — no sandbox isolation
# - telemetry disabled
# ---------------------------------------------------------------------------
cat > "${DEEPSEEK_DIR}/settings.json" << JSON
{
  "model": {
    "name": "${MODEL}"
  },
  "general": {
    "defaultApprovalMode": "auto_edit"
  },
  "security": {
    "toolSandboxing": false
  },
  "telemetry": {
    "enabled": false,
    "logPrompts": false
  },
  "usage": {
    "enabled": false
  }
}
JSON

# ---------------------------------------------------------------------------
# ~/.deepseek/.env  (chmod 0600 — contains secrets)
# ---------------------------------------------------------------------------
{
  printf "DEEPSEEK_API_KEY=%s
" "${API_KEY}"
  if [[ -n "${BASE_URL}" ]]; then
    printf "DEEPSEEK_BASE_URL=%s
" "${BASE_URL}"
  fi
} > "${DEEPSEEK_DIR}/.env"
chmod 0600 "${DEEPSEEK_DIR}/.env"

fi

# ---------------------------------------------------------------------------
# ~/bin/ds  — wrapper script (with YOLO flag for full access)
# ---------------------------------------------------------------------------
WRAPPER_DIR="${HOME}/bin"
mkdir -p "${WRAPPER_DIR}"
DEEPSEEK_WRAPPER="${WRAPPER_DIR}/ds"

cat > "${DEEPSEEK_WRAPPER}" << 'WRAPPER'
#!/usr/bin/env bash
set -euo pipefail

if ! command -v deepseek > /dev/null 2>&1; then
  echo "deepseek: command not found in PATH" >&2
  exit 127
fi

# Source ~/.deepseek/.env so vars are available even in non-login shells
DEEPSEEK_ENV_FILE="${HOME}/.deepseek/.env"
if [ -f "${DEEPSEEK_ENV_FILE}" ]; then
  while IFS='=' read -r key val; do
    if [ -z "$key" ] || [[ "$key" == \#* ]]; then
      continue
    fi
    export "${key}=${val}"
  done < "${DEEPSEEK_ENV_FILE}"
fi

# YOLO mode: auto-approve all actions (devcontainer = trusted environment)
exec deepseek --approval-mode=yolo "$@"
WRAPPER

chmod +x "${DEEPSEEK_WRAPPER}"

# ---------------------------------------------------------------------------
# Ensure ~/bin is in PATH  (idempotent)
# ---------------------------------------------------------------------------
BASHRC="${HOME}/.bashrc"
[ -f "${BASHRC}" ] || touch "${BASHRC}"

if ! grep -qF 'export PATH="${HOME}/bin:${PATH}"' "${BASHRC}" 2>/dev/null; then
  printf '
# Added by deepseek-bootstrap.sh
export PATH="${HOME}/bin:${PATH}"
' >> "${BASHRC}"
fi

# ---------------------------------------------------------------------------
# Shell aliases in ~/.bashrc  (idempotent)
# ---------------------------------------------------------------------------
add_alias() {
  local name="$1"
  local target="$2"
  if grep -qF "alias ${name}=" "${BASHRC}" 2>/dev/null; then
    return 0
  fi
  printf '
# Added by deepseek-bootstrap.sh
alias %s="%s"
' "${name}" "${target}" >> "${BASHRC}"
}

add_alias "ds"  "${DEEPSEEK_WRAPPER}"
add_alias "вы"  "${DEEPSEEK_WRAPPER}"  # кириллица (ds в русской раскладке)

# ---------------------------------------------------------------------------
# System-wide symlinks (via sudo — works in any shell)
# /usr/local/bin/ds for latin layout, /usr/local/bin/вы for cyrillic
# ---------------------------------------------------------------------------
if command -v sudo > /dev/null 2>&1 && sudo -n true 2>/dev/null; then
  sudo ln -sf "${DEEPSEEK_WRAPPER}" /usr/local/bin/ds 2>/dev/null \
    || echo "[deepseek-bootstrap] WARNING: could not create /usr/local/bin/ds" >&2
  sudo ln -sf "${DEEPSEEK_WRAPPER}" /usr/local/bin/вы 2>/dev/null \
    || echo "[deepseek-bootstrap] WARNING: could not create /usr/local/bin/вы" >&2
else
  echo "[deepseek-bootstrap] sudo not available; system symlinks not created (aliases in .bashrc still work)" >&2
fi

echo "[deepseek-bootstrap] Done."
