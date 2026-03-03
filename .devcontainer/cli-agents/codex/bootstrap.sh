#!/usr/bin/env bash
# Configures Codex CLI (v0.105+) for the current user.
#
# Reads non-secret settings from env vars (injected via .devcontainer/.env):
#   OPENAI_BASE_URL         — base URL of the OpenAI-compatible server
#   CODEX_MODEL             — default model name (used when CODEX_MODELS is empty)
#   CODEX_MODELS            — optional comma-separated model list for profile generation
#   CODEX_MODEL_PROVIDER_ID — optional provider id in config.toml (default: myserver)
#   CODEX_MODEL_PROVIDER_NAME — optional provider display name (default: MyServer)
#   CODEX_WIRE_API          — optional wire API mode (default: responses)
#
# API key is written to ~/.codex/.env under OPENAI_API_KEY.
#
# Reads API token from Docker secret:
#   /run/secrets/cc_api_key
#
# Writes:
#   ~/.codex/config.toml
#   ~/.codex/.env
#   ~/bin/codex-safe.sh
set -euo pipefail

CODEX_DIR="${HOME}/.codex"
mkdir -p "${CODEX_DIR}"

BASE_URL="${OPENAI_BASE_URL:-}"
MODEL="${CODEX_MODEL:-}"
MODELS_CSV="${CODEX_MODELS:-}"
PROVIDER_ID="${CODEX_MODEL_PROVIDER_ID:-myserver}"
PROVIDER_NAME="${CODEX_MODEL_PROVIDER_NAME:-MyServer}"
PROVIDER_ENV_KEY="OPENAI_API_KEY"
WIRE_API="${CODEX_WIRE_API:-responses}"
SOURCE_MODELS_URL="${CODEX_SOURCE_MODELS_URL:-https://raw.githubusercontent.com/openai/codex/main/codex-rs/core/models.json}"
MODEL_MAP_FILE="${CODEX_MODEL_MAP_FILE:-/workspaces/work/.devcontainer/codex-model-map.json}"
MODEL_OVERRIDES_FILE="${CODEX_MODEL_OVERRIDES_FILE:-/workspaces/work/.devcontainer/codex-model-overrides.json}"
GEMINI_PROMPT_URL="${CODEX_GEMINI_PROMPT_URL:-https://raw.githubusercontent.com/openai/codex/main/codex-rs/core/prompt_with_apply_patch_instructions.md}"
GEMINI_PROMPT_FILE="$(mktemp /tmp/codex-gemini-prompt.XXXXXX.md)"

# Download the prompt from the cloud
if curl -fsSL --max-time 10 "${GEMINI_PROMPT_URL}" -o "${GEMINI_PROMPT_FILE}" 2>/dev/null; then
  echo "[codex-bootstrap] Gemini prompt downloaded from: ${GEMINI_PROMPT_URL}"
else
  echo "[codex-bootstrap] WARNING: could not download Gemini prompt, Gemini models will run without base_instructions" >&2
  rm -f "${GEMINI_PROMPT_FILE}"
  GEMINI_PROMPT_FILE=""
fi

if [[ ! -f "${MODEL_MAP_FILE}" && -f "/usr/local/share/agent-sandbox/codex-model-map.json" ]]; then
  MODEL_MAP_FILE="/usr/local/share/agent-sandbox/codex-model-map.json"
fi

if [[ ! -f "${MODEL_OVERRIDES_FILE}" && -f "/usr/local/share/agent-sandbox/codex-model-overrides.json" ]]; then
  MODEL_OVERRIDES_FILE="/usr/local/share/agent-sandbox/codex-model-overrides.json"
fi

if [[ -f "${MODEL_MAP_FILE}" ]]; then
  echo "[codex-bootstrap] using model map file: ${MODEL_MAP_FILE}"
else
  echo "[codex-bootstrap] WARNING: model map file not found: ${MODEL_MAP_FILE}" >&2
fi

if [[ -f "${MODEL_OVERRIDES_FILE}" ]]; then
  echo "[codex-bootstrap] using model overrides file: ${MODEL_OVERRIDES_FILE}"
else
  echo "[codex-bootstrap] INFO: model overrides file not found: ${MODEL_OVERRIDES_FILE}" >&2
fi

trim() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf "%s" "${value}"
}

toml_escape_basic() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  printf "%s" "${value}"
}

if [[ "${CUSTOM_CODEX_ENABLED:-0}" != "1" ]]; then
  echo "[codex-bootstrap] CUSTOM_CODEX_ENABLED is not 1 — skipping custom backend config; wrapper/aliases still applied."
  BASE_URL=""
elif [[ -z "${BASE_URL}" ]]; then
  echo "[codex-bootstrap] OPENAI_BASE_URL is not set — skipping Codex config." >&2
  BASE_URL=""
fi

ENABLE_CUSTOM_CODEX=1
if [[ -z "${BASE_URL}" ]]; then
  ENABLE_CUSTOM_CODEX=0
fi

if [[ "${ENABLE_CUSTOM_CODEX}" == "1" ]]; then
  echo "[codex-bootstrap] CUSTOM_CODEX_ENABLED=1 — applying custom backend config."
fi

if [[ "${ENABLE_CUSTOM_CODEX}" == "1" ]]; then
MODELS=()
if [[ -n "${MODELS_CSV}" ]]; then
  IFS=',' read -r -a RAW_MODELS <<< "${MODELS_CSV}"
  for raw_model in "${RAW_MODELS[@]}"; do
    parsed_model="$(trim "${raw_model}")"
    if [[ -n "${parsed_model}" ]]; then
      MODELS+=("${parsed_model}")
    fi
  done
fi

if [[ -z "${MODEL}" && ${#MODELS[@]} -gt 0 ]]; then
  MODEL="${MODELS[0]}"
fi

if [[ -z "${MODEL}" ]]; then
  echo "[codex-bootstrap] Neither CODEX_MODEL nor CODEX_MODELS is set — skipping Codex config." >&2
else
  CATALOG_MODELS=()
  if [[ ${#MODELS[@]} -gt 0 ]]; then
    CATALOG_MODELS=("${MODELS[@]}")
  else
    CATALOG_MODELS=("${MODEL}")
  fi

PYTHON_BIN="$(command -v python3 || command -v python || true)"

if [[ -z "${PYTHON_BIN}" ]]; then
  echo "[codex-bootstrap] WARNING: neither python3 nor python is available — cloud metadata disabled." >&2
fi

fetch_cloud_models() {
  local url="$1"
  local output_path="$2"
  "${PYTHON_BIN}" - "$url" "$output_path" << 'PY'
import json
import sys
from urllib.request import urlopen
from urllib.error import URLError, HTTPError
from pathlib import Path

url = sys.argv[1]
output_path = Path(sys.argv[2])
try:
    with urlopen(url, timeout=20) as resp:
        body = resp.read().decode("utf-8")
    payload = json.loads(body)
    if not isinstance(payload, dict) or not isinstance(payload.get("models"), list):
        raise ValueError("unexpected JSON shape")
    output_path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
except (URLError, HTTPError, ValueError, json.JSONDecodeError) as exc:
    print(f"[codex-bootstrap] WARNING: failed to load cloud models from {url}: {exc}", file=sys.stderr)
    sys.exit(1)
PY
}

build_catalog_from_cloud() {
  local cloud_path="$1"
  local map_path="$2"
  local overrides_path="$3"
  local models_file="$4"
  local gemini_prompt_path="$5"
  "${PYTHON_BIN}" - "$cloud_path" "$map_path" "$overrides_path" "$models_file" "$gemini_prompt_path" << 'PY'
import json
import sys
from pathlib import Path

cloud_path = Path(sys.argv[1])
map_path = Path(sys.argv[2])
overrides_path = Path(sys.argv[3])
models_file = Path(sys.argv[4])
gemini_prompt_path = Path(sys.argv[5])
cloud = json.loads(cloud_path.read_text(encoding="utf-8"))
requested = [line.strip() for line in models_file.read_text(encoding="utf-8").splitlines() if line.strip()]
gemini_base_instructions = None
if gemini_prompt_path.exists():
    gemini_raw = gemini_prompt_path.read_text(encoding="utf-8")
    gemini_base_instructions = gemini_raw.strip() or None

mapping = {}
if map_path.exists():
    mapping = json.loads(map_path.read_text(encoding="utf-8"))

overrides = {}
if overrides_path.exists():
    overrides = json.loads(overrides_path.read_text(encoding="utf-8"))

cloud_models = {m.get("slug"): m for m in cloud.get("models", []) if isinstance(m, dict) and m.get("slug")}

fallback_base_instructions = "You are Codex, based on GPT-5. You are running as a coding agent in the Codex CLI on a user's computer."

result = []
mapped_count = 0
cloud_hit_count = 0
overrides_count = 0
fallback_count = 0

for i, model_slug in enumerate(requested):
    upstream_slug = mapping.get(model_slug, model_slug)
    if model_slug in mapping:
        mapped_count += 1

    source = dict(cloud_models.get(upstream_slug, {}))
    had_cloud_source = bool(source)
    if had_cloud_source:
        cloud_hit_count += 1

    override = overrides.get(model_slug, {})
    if override:
        overrides_count += 1

    source.update(override)

    if not had_cloud_source and not override:
        fallback_count += 1

    source_kind = "fallback"
    if had_cloud_source and override:
        source_kind = "cloud+override"
    elif override:
        source_kind = "override"
    elif had_cloud_source:
        source_kind = "cloud"

    print(f"[codex-bootstrap] model-meta: model={model_slug} upstream={upstream_slug} source={source_kind}", file=sys.stderr)

    if source:
        entry = dict(source)
    else:
        entry = {
            "display_name": model_slug,
            "description": f"Custom model alias for {upstream_slug}",
            "default_reasoning_level": "medium",
            "supported_reasoning_levels": [{"effort": "medium", "description": "Default reasoning"}],
            "shell_type": "shell_command",
            "visibility": "list",
            "supported_in_api": True,
            "priority": i,
            "availability_nux": None,
            "upgrade": None,
            "base_instructions": fallback_base_instructions,
            "model_messages": None,
            "supports_reasoning_summaries": False,
            "default_reasoning_summary": "auto",
            "support_verbosity": False,
            "default_verbosity": None,
            "apply_patch_tool_type": None,
            "truncation_policy": {"mode": "tokens", "limit": 10000},
            "supports_parallel_tool_calls": False,
            "context_window": 272000,
            "auto_compact_token_limit": None,
            "effective_context_window_percent": 95,
            "experimental_supported_tools": [],
            "input_modalities": ["text", "image"],
            "prefer_websockets": False,
        }

    if model_slug in mapping:
        entry["supported_reasoning_levels"] = [{
            "effort": "medium",
            "description": "Balances speed and reasoning depth for everyday tasks"
        }]
        entry["default_reasoning_level"] = "medium"

    if "gemini" in model_slug.lower() and gemini_base_instructions:
        entry["base_instructions"] = gemini_base_instructions

    # Keep upstream fields as-is; only override slug for local alias.
    entry["slug"] = model_slug

    result.append(entry)

summary = {
    "requested": len(requested),
    "mapped": mapped_count,
    "cloud_hits": cloud_hit_count,
    "overrides": overrides_count,
    "fallback": fallback_count,
}
print(f"[codex-bootstrap] model-meta-summary: requested={summary['requested']} mapped={summary['mapped']} cloud_hits={summary['cloud_hits']} overrides={summary['overrides']} fallback={summary['fallback']}", file=sys.stderr)
print(json.dumps({"models": result}, ensure_ascii=False, indent=2))
PY
}

SECRET_FILE="/run/secrets/cc_api_key"
API_KEY=""
if [[ -f "${SECRET_FILE}" ]]; then
  API_KEY="$(cat "${SECRET_FILE}")"
fi

if [[ -z "${API_KEY}" ]]; then
  echo "[codex-bootstrap] WARNING: /run/secrets/cc_api_key is empty — Codex will start without an API key." >&2
fi

# Codex CLI >=0.105 reads TOML config.
rm -f "${CODEX_DIR}/config.yaml"
ESCAPED_MODEL="$(toml_escape_basic "${MODEL}")"
ESCAPED_PROVIDER_ID="$(toml_escape_basic "${PROVIDER_ID}")"
ESCAPED_PROVIDER_NAME="$(toml_escape_basic "${PROVIDER_NAME}")"
ESCAPED_BASE_URL="$(toml_escape_basic "${BASE_URL}")"
ESCAPED_PROVIDER_ENV_KEY="$(toml_escape_basic "${PROVIDER_ENV_KEY}")"
ESCAPED_WIRE_API="$(toml_escape_basic "${WIRE_API}")"
CATALOG_PATH="${CODEX_DIR}/model-catalog.json"
ESCAPED_CATALOG_PATH="$(toml_escape_basic "${CATALOG_PATH}")"

cat > "${CODEX_DIR}/config.toml" << TOML
# Auto-generated by .devcontainer/codex-bootstrap.sh — do not edit manually.

model = "${ESCAPED_MODEL}"
model_provider = "${ESCAPED_PROVIDER_ID}"
approval_policy = "never"
model_catalog_json = "${ESCAPED_CATALOG_PATH}"

[model_providers."${ESCAPED_PROVIDER_ID}"]
name = "${ESCAPED_PROVIDER_NAME}"
base_url = "${ESCAPED_BASE_URL}"
env_key = "${ESCAPED_PROVIDER_ENV_KEY}"
wire_api = "${ESCAPED_WIRE_API}"
TOML

if [[ ${#MODELS[@]} -gt 0 ]]; then
  {
    for i in "${!MODELS[@]}"; do
      listed_model="${MODELS[$i]}"
      safe_key="${listed_model//[^a-zA-Z0-9_-]/_}"
      safe_key="${safe_key#_}"
      safe_key="${safe_key%_}"
      if [[ -z "${safe_key}" ]]; then
        safe_key="model_$((i + 1))"
      fi
      escaped_listed_model="$(toml_escape_basic "${listed_model}")"
      printf "\n[profiles.%s]\n" "${safe_key}"
      printf "model = \"%s\"\n" "${escaped_listed_model}"
      printf "model_provider = \"%s\"\n" "${ESCAPED_PROVIDER_ID}"
    done
  } >> "${CODEX_DIR}/config.toml"
fi

MODELS_LIST_FILE="${CODEX_DIR}/models.list"
printf "%s\n" "${CATALOG_MODELS[@]}" > "${MODELS_LIST_FILE}"

CLOUD_MODELS_FILE="${CODEX_DIR}/cloud-models.json"
if [[ -n "${PYTHON_BIN}" ]] && fetch_cloud_models "${SOURCE_MODELS_URL}" "${CLOUD_MODELS_FILE}"; then
  build_catalog_from_cloud "${CLOUD_MODELS_FILE}" "${MODEL_MAP_FILE}" "${MODEL_OVERRIDES_FILE}" "${MODELS_LIST_FILE}" "${GEMINI_PROMPT_FILE}" > "${CATALOG_PATH}"
  echo "[codex-bootstrap] model catalog generated from cloud source: ${SOURCE_MODELS_URL}"
else
  echo "[codex-bootstrap] WARNING: cloud model source unavailable, using fallback catalog generation." >&2
  if [[ -n "${PYTHON_BIN}" ]]; then
    echo "[codex-bootstrap] cloud URL: ${SOURCE_MODELS_URL}" >&2
    echo "[codex-bootstrap] hint: check DNS/proxy/firewall access to raw.githubusercontent.com from inside container." >&2
  fi
  {
    printf "{\n  \"models\": [\n"
    for i in "${!CATALOG_MODELS[@]}"; do
      catalog_model="${CATALOG_MODELS[$i]}"
      escaped_catalog_model="$(toml_escape_basic "${catalog_model}")"
      comma=","
      if [[ "$i" -eq $((${#CATALOG_MODELS[@]} - 1)) ]]; then
        comma=""
      fi
      printf "    {\n"
      printf "      \"slug\": \"%s\",\n" "${escaped_catalog_model}"
      printf "      \"display_name\": \"%s\",\n" "${escaped_catalog_model}"
      printf "      \"description\": \"Custom model from CODEX_MODELS\",\n"
      printf "      \"default_reasoning_level\": \"medium\",\n"
      printf "      \"supported_reasoning_levels\": [{\"effort\": \"medium\", \"description\": \"Default reasoning\"}],\n"
      printf "      \"shell_type\": \"shell_command\",\n"
      printf "      \"visibility\": \"list\",\n"
      printf "      \"supported_in_api\": true,\n"
      printf "      \"priority\": %s,\n" "$i"
      printf "      \"availability_nux\": null,\n"
      printf "      \"upgrade\": null,\n"
      printf "      \"base_instructions\": \"You are Codex, based on GPT-5. You are running as a coding agent in the Codex CLI on a user's computer.\",\n"
      printf "      \"model_messages\": null,\n"
      printf "      \"supports_reasoning_summaries\": false,\n"
      printf "      \"default_reasoning_summary\": \"auto\",\n"
      printf "      \"support_verbosity\": false,\n"
      printf "      \"default_verbosity\": null,\n"
      printf "      \"apply_patch_tool_type\": null,\n"
      printf "      \"truncation_policy\": {\"mode\": \"tokens\", \"limit\": 10000},\n"
      printf "      \"supports_parallel_tool_calls\": false,\n"
      printf "      \"context_window\": 272000,\n"
      printf "      \"auto_compact_token_limit\": null,\n"
      printf "      \"effective_context_window_percent\": 95,\n"
      printf "      \"experimental_supported_tools\": [],\n"
      printf "      \"input_modalities\": [\"text\", \"image\"],\n"
      printf "      \"prefer_websockets\": false\n"
      printf "    }%s\n" "${comma}"
    done
    printf "  ]\n}\n"
  } > "${CATALOG_PATH}"
fi

printf "%s=%s\n" "${PROVIDER_ENV_KEY}" "${API_KEY}" > "${CODEX_DIR}/.env"
chmod 0600 "${CODEX_DIR}/.env"

echo "[codex-bootstrap] ~/.codex/config.toml written (model_provider=${PROVIDER_ID}, model=${MODEL}, base_url=${BASE_URL}, profiles=${#MODELS[@]})"
if [[ ${#MODELS[@]} -gt 0 ]]; then
  echo "[codex-bootstrap] profiles generated: ${MODELS[*]}"
fi
echo "[codex-bootstrap] ~/.codex/.env written (key=${PROVIDER_ENV_KEY})"
fi
fi

WRAPPER_DIR="${HOME}/bin"
CODEX_WRAPPER="${WRAPPER_DIR}/codex-safe.sh"
mkdir -p "${WRAPPER_DIR}"

cat > "${CODEX_WRAPPER}" << 'WRAPPER'
#!/usr/bin/env bash
set -euo pipefail

if ! command -v codex >/dev/null 2>&1; then
  echo "codex command not found in PATH" >&2
  exit 127
fi

CODEX_ENV_FILE="${HOME}/.codex/.env"
if [ -f "${CODEX_ENV_FILE}" ]; then
  while IFS='=' read -r key val; do
    case "${key}" in
      ''|\#*) continue ;;
    esac
    export "${key}=${val}"
  done < "${CODEX_ENV_FILE}"
fi

exec codex "$@"
WRAPPER

chmod +x "${CODEX_WRAPPER}"
echo "[codex-bootstrap] ${CODEX_WRAPPER} created."

BASHRC="${HOME}/.bashrc"
add_alias() {
  local name="$1"
  local target="$2"
  local rc_file="$3"
  local prefix="$4"
  [ -f "${rc_file}" ] || touch "${rc_file}"
  if grep -qF "alias ${name}=" "${rc_file}" 2>/dev/null; then
    echo "[${prefix}] alias '${name}' already exists in ${rc_file} — skipping."
    return 0
  fi
  printf '\n# Added by cli-agents/codex/bootstrap.sh\nalias %s="%s"\n' "${name}" "${target}" >> "${rc_file}"
  echo "[${prefix}] alias '${name}' added to ${rc_file}."
}

add_alias "cx" "${CODEX_WRAPPER}" "${BASHRC}" "codex-bootstrap"
add_alias "сч" "${CODEX_WRAPPER}" "${BASHRC}" "codex-bootstrap"

echo "[codex-bootstrap] Done. Aliases active after: source ~/.bashrc"
