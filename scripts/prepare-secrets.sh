#!/usr/bin/env bash
set -euo pipefail

# Generates ./secrets/* files from ./secrets/.env
# (The .env itself is NOT committed; see .gitignore)
#
# IMPORTANT:
# - Do NOT `source` secrets/.env. Values may contain `$` and other characters that would be expanded by bash.
# - Parse the file as dotenv (KEY=VALUE) and write raw values into ./secrets/*.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SECRETS_DIR="${ROOT_DIR}/secrets"
ENV_FILE="${SECRETS_DIR}/.env"

if [[ ! -d "$SECRETS_DIR" ]]; then
  echo "[ERROR] secrets dir not found: $SECRETS_DIR"
  exit 1
fi

if [[ ! -f "$ENV_FILE" ]]; then
  echo "[ERROR] Missing secrets env file: $ENV_FILE"
  echo "Copy secrets/.env.example -> secrets/.env and fill values."
  exit 1
fi

get_env() {
  local want="$1"
  local line key val
  # Read .env safely without shell expansion. Keep value as-is (no newline).
  while IFS= read -r line || [[ -n "$line" ]]; do
    # Strip trailing CR (Windows CRLF)
    line="${line%$'\r'}"
    # Skip comments/empty
    [[ -z "$line" ]] && continue
    [[ "$line" =~ ^[[:space:]]*# ]] && continue
    [[ "$line" != *"="* ]] && continue

    key="${line%%=*}"
    val="${line#*=}"

    # Trim key spaces
    key="${key#"${key%%[![:space:]]*}"}"
    key="${key%"${key##*[![:space:]]}"}"

    if [[ "$key" == "$want" ]]; then
      # Optional: unwrap simple quotes
      if [[ "$val" =~ ^\".*\"$ ]]; then
        val="${val:1:${#val}-2}"
        val="${val//\\\"/\"}"
        val="${val//\\\\/\\}"
      elif [[ "$val" =~ ^\'.*\'$ ]]; then
        val="${val:1:${#val}-2}"
      fi
      printf "%s" "$val"
      return 0
    fi
  done < "$ENV_FILE"
  return 0
}

ONEC_USERNAME="$(get_env ONEC_USERNAME || true)"
ONEC_PASSWORD="$(get_env ONEC_PASSWORD || true)"
DEV_LOGIN="$(get_env DEV_LOGIN || true)"
DEV_PASSWORD="$(get_env DEV_PASSWORD || true)"
GITHUB_TOKEN="$(get_env GITHUB_TOKEN || true)"
PG_PASSWORD="$(get_env PG_PASSWORD || true)"
FORCE_OVERWRITE_PG_PASSWORD="$(get_env FORCE_OVERWRITE_PG_PASSWORD || true)"

umask 077
mkdir -p "$SECRETS_DIR"

write_secret() {
  local name="$1"
  local value="$2"
  local path="${SECRETS_DIR}/${name}"
  printf "%s" "$value" > "$path"
  chmod 0600 "$path" || true
}

write_secret "onec_username" "${ONEC_USERNAME:-}"
write_secret "onec_password" "${ONEC_PASSWORD:-}"
write_secret "dev_login" "${DEV_LOGIN:-}"
write_secret "dev_password" "${DEV_PASSWORD:-}"
write_secret "github_token" "${GITHUB_TOKEN:-}"

# pg_password must be stable across re-deploys, otherwise existing Postgres volume becomes unusable
# ("password authentication failed") and 1C infobase creation breaks.
#
# Rules:
# - if PG_PASSWORD is set in secrets/.env, write it (but refuse to overwrite a different existing value unless forced)
# - if PG_PASSWORD is empty, keep existing non-empty pg_password; otherwise generate once
pg_path="${SECRETS_DIR}/pg_password"
existing_pg=""
if [[ -f "$pg_path" ]]; then
  existing_pg="$(cat "$pg_path" || true)"
fi

if [[ -n "${PG_PASSWORD:-}" ]]; then
  if [[ -n "$existing_pg" && "$existing_pg" != "$PG_PASSWORD" && "${FORCE_OVERWRITE_PG_PASSWORD:-}" != "1" ]]; then
    echo "[ERROR] Refusing to overwrite existing secrets/pg_password with a different PG_PASSWORD."
    echo "        This would break an already initialized Postgres volume (pgdata)."
    echo "        Fix: keep current PG_PASSWORD, or reset pgdata and set FORCE_OVERWRITE_PG_PASSWORD=1."
    exit 1
  fi
  write_secret "pg_password" "${PG_PASSWORD}"
else
  if [[ -s "$pg_path" ]]; then
    chmod 0600 "$pg_path" || true
  else
    umask 077
    if command -v python3 >/dev/null 2>&1; then
      python3 - <<'PY' > "$pg_path"
import secrets
print(secrets.token_urlsafe(24), end="")
PY
    else
      # fallback without python3
      head -c 32 /dev/urandom | base64 | tr -d '\n' > "$pg_path"
    fi
    chmod 0600 "$pg_path" || true
  fi
fi

# TEMPORARY / DEBUG NOTE:
# Some images run Postgres as a non-root UID that may be unable to read a 0600 secret file
# mounted into the container (Docker Compose secrets can preserve host ownership).
# For the sandbox we relax permissions to make the password readable inside the container.
# If you care about hardening, switch to a proper secrets mechanism/ownership mapping.
chmod 0644 "$pg_path" 2>/dev/null || true

echo "[OK] Secrets written to ${SECRETS_DIR}"
echo "     - onec_username/onec_password (releases.1c.ru, optional if local installer exists)"
echo "     - dev_login/dev_password (developer.1c.ru, community activation)"
echo "     - github_token (GitHub PAT for gh CLI, optional)"
echo "     - pg_password (Postgres password, optional)"

