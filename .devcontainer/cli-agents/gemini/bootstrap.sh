#!/usr/bin/env bash
# Configures Gemini CLI for the current user.
#
# Reads non-secret settings from env vars (injected via .devcontainer/.env):
#   OPENAI_BASE_URL   — base URL of the OpenAI-compatible / Gemini-compatible server
#   GEMINI_MODEL      — default Gemini model name (e.g. ag/gemini-3.1-pro-high)
#   GEMINI_MODEL_FLASH — fast/cheap model (e.g. ag/gemini-3-flash)
#   GEMINI_MODEL_PRO_LOW — pro-low tier model (e.g. ag/gemini-3.1-pro-low)
#
# API key is read from Docker secret:
#   /run/secrets/cc_api_key
#
# Writes:
#   ~/.gemini/settings.json   — persistent Gemini CLI settings
#   ~/.gemini/.env            — API key + base URL (chmod 0600)
#   ~/bin/gemini-safe.sh      — wrapper that exports env vars then exec gemini
#   /usr/local/bin/gg         — symlink to gemini-safe.sh (system-wide, via sudo)
#   ~/.bashrc: PATH+=~/bin, aliases gg / пп
#
set -euo pipefail

GEMINI_DIR="${HOME}/.gemini"
mkdir -p "${GEMINI_DIR}"

BASE_URL="${OPENAI_BASE_URL:-}"
MODEL="${GEMINI_MODEL:-ag/gemini-3.1-pro-high}"
MODEL_FLASH="${GEMINI_MODEL_FLASH:-ag/gemini-3-flash}"
MODEL_PRO_LOW="${GEMINI_MODEL_PRO_LOW:-ag/gemini-3.1-pro-low}"

# Read API key from shared Docker secret
API_KEY=""
SECRET_FILE="/run/secrets/cc_api_key"
if [[ -f "${SECRET_FILE}" && -s "${SECRET_FILE}" ]]; then
  API_KEY="$(cat "${SECRET_FILE}")"
  echo "[gemini-bootstrap] API key read from ${SECRET_FILE}"
fi

if [[ -z "${BASE_URL}" ]]; then
  echo "[gemini-bootstrap] OPENAI_BASE_URL is not set — skipping Gemini CLI config." >&2
  exit 0
fi

if [[ -z "${API_KEY}" ]]; then
  echo "[gemini-bootstrap] WARNING: /run/secrets/cc_api_key is empty or missing" >&2
fi

# Build the Gemini API base URL.
# The OpenAI endpoint is .../v1, but the Gemini route on 9Router lives under /api/v1beta/...
# (Next.js App Router: src/app/api/v1beta/models/[...path]).
# next.config.mjs rewrites /v1/* -> /api/v1/* but has NO rewrite for /v1beta/*.
# So we must point the SDK at the /api prefix explicitly:
#   OPENAI_BASE_URL = https://ai.gbig.holdings/v1
#   -> strip /v1  -> https://ai.gbig.holdings
#   -> append /api -> https://ai.gbig.holdings/api
# SDK then constructs: https://ai.gbig.holdings/api/v1beta/models/{model}:generateContent (correct)
GEMINI_BASE_URL="${BASE_URL%/v1}/api"

# ---------------------------------------------------------------------------
# ~/.gemini/settings.json
#
# modelConfigs.customAliases  — user-facing short names for --model flag.
#   These go through ModelConfigService (not the hardcoded resolveModel()),
#   so they work as proper aliases that send our ag/* model names to the API.
#
# modelConfigs.customOverrides — redirect internal helper aliases that
#   default to stock gemini-* models (classifier, prompt-completion, web-*,
#   loop-detection, etc.) so they use our server's models instead.
# ---------------------------------------------------------------------------
cat > "${GEMINI_DIR}/settings.json" << JSON
{
  "selectedAuthType": "gemini-api-key",
  "model": {
    "name": "${MODEL}"
  },
  "sandbox": "none",
  "telemetry": {
    "enabled": false,
    "logPrompts": false
  },
  "usage": {
    "enabled": false
  },
  "modelConfigs": {
    "customAliases": {
      "ag-pro-high": {
        "modelConfig": { "model": "${MODEL}" }
      },
      "ag-pro-low": {
        "modelConfig": { "model": "${MODEL_PRO_LOW}" }
      },
      "ag-flash": {
        "modelConfig": { "model": "${MODEL_FLASH}" }
      }
    },
    "customOverrides": [
      {
        "match": { "model": "gemini-3-pro-preview" },
        "modelConfig": { "model": "${MODEL}" }
      },
      {
        "match": { "model": "gemini-3.1-pro-preview" },
        "modelConfig": { "model": "${MODEL}" }
      },
      {
        "match": { "model": "gemini-2.5-pro" },
        "modelConfig": { "model": "${MODEL}" }
      },
      {
        "match": { "model": "gemini-3-flash-preview" },
        "modelConfig": { "model": "${MODEL_FLASH}" }
      },
      {
        "match": { "model": "gemini-2.5-flash" },
        "modelConfig": { "model": "${MODEL_FLASH}" }
      },
      {
        "match": { "model": "gemini-2.5-flash-lite" },
        "modelConfig": { "model": "${MODEL_FLASH}" }
      }
    ]
  }
}
JSON

echo "[gemini-bootstrap] ~/.gemini/settings.json written (model=${MODEL}, flash=${MODEL_FLASH}, sandbox=none)"

# ---------------------------------------------------------------------------
# ~/.gemini/.env  (chmod 0600 — contains secrets)
# Gemini CLI natively loads this file on startup (settings.ts:findEnvFile)
# ---------------------------------------------------------------------------
printf "GEMINI_API_KEY=%s\n"         "${API_KEY}"         > "${GEMINI_DIR}/.env"
printf "GOOGLE_GEMINI_BASE_URL=%s\n" "${GEMINI_BASE_URL}" >> "${GEMINI_DIR}/.env"
chmod 0600 "${GEMINI_DIR}/.env"

echo "[gemini-bootstrap] ~/.gemini/.env written (GEMINI_API_KEY=***, GOOGLE_GEMINI_BASE_URL=${GEMINI_BASE_URL})"

# ---------------------------------------------------------------------------
# ~/bin/gemini-safe.sh  — wrapper script
# ---------------------------------------------------------------------------
WRAPPER_DIR="${HOME}/bin"
mkdir -p "${WRAPPER_DIR}"
GEMINI_WRAPPER="${WRAPPER_DIR}/gemini-safe.sh"

cat > "${GEMINI_WRAPPER}" << 'WRAPPER'
#!/usr/bin/env bash
set -euo pipefail

if ! command -v gemini > /dev/null 2>&1; then
  echo "gemini: command not found in PATH" >&2
  exit 127
fi

# Source ~/.gemini/.env so vars are available even in non-login shells
GEMINI_ENV_FILE="${HOME}/.gemini/.env"
if [ -f "${GEMINI_ENV_FILE}" ]; then
  while IFS='=' read -r key val; do
    case "${key}" in
      ''|\#*) continue ;;
    esac
    export "${key}=${val}"
  done < "${GEMINI_ENV_FILE}"
fi

exec gemini "$@"
WRAPPER

chmod +x "${GEMINI_WRAPPER}"
echo "[gemini-bootstrap] ${GEMINI_WRAPPER} created."

# ---------------------------------------------------------------------------
# Ensure ~/bin is in PATH  (idempotent)
# ---------------------------------------------------------------------------
BASHRC="${HOME}/.bashrc"
[ -f "${BASHRC}" ] || touch "${BASHRC}"

if ! grep -qF 'export PATH="${HOME}/bin:${PATH}"' "${BASHRC}" 2>/dev/null; then
  printf '\n# Added by gemini-bootstrap.sh\nexport PATH="${HOME}/bin:${PATH}"\n' >> "${BASHRC}"
  echo "[gemini-bootstrap] ~/bin added to PATH in ${BASHRC}."
fi

# ---------------------------------------------------------------------------
# Shell aliases in ~/.bashrc  (idempotent)
# ---------------------------------------------------------------------------
add_alias() {
  local name="$1"
  local target="$2"
  if grep -qF "alias ${name}=" "${BASHRC}" 2>/dev/null; then
    echo "[gemini-bootstrap] alias '${name}' already exists — skipping."
    return 0
  fi
  printf '\n# Added by gemini-bootstrap.sh\nalias %s="%s"\n' "${name}" "${target}" >> "${BASHRC}"
  echo "[gemini-bootstrap] alias '${name}' -> ${target} added."
}

add_alias "gg"  "${GEMINI_WRAPPER}"
add_alias "пп"  "${GEMINI_WRAPPER}"

# ---------------------------------------------------------------------------
# System-wide /usr/local/bin/gg symlink (via sudo — works in any shell)
# ---------------------------------------------------------------------------
if command -v sudo > /dev/null 2>&1 && sudo -n true 2>/dev/null; then
  sudo ln -sf "${GEMINI_WRAPPER}" /usr/local/bin/gg 2>/dev/null \
    && echo "[gemini-bootstrap] /usr/local/bin/gg -> ${GEMINI_WRAPPER}" \
    || echo "[gemini-bootstrap] WARNING: could not create /usr/local/bin/gg" >&2
else
  echo "[gemini-bootstrap] sudo not available; /usr/local/bin/gg not created (aliases in .bashrc still work)" >&2
fi

echo "[gemini-bootstrap] Done."
