#!/usr/bin/env bash
set -euo pipefail

# DEBUG PURPOSES ONLY.
# When PG_DEBUG_DUMP_PASSWORD=1 and PGDATA is not initialized yet, write the plaintext
# password (read from POSTGRES_PASSWORD_FILE) into PGDATA for inspection.
#
# After you confirm what value is used during init, REMOVE this wrapper and wipe pgdata again.

ORIG_ENTRYPOINT="/usr/local/bin/docker-entrypoint.sh"

PGDATA_DIR="${PGDATA:-/var/lib/pgpro/1c-17/data}"
DEBUG_FLAG="${PG_DEBUG_DUMP_PASSWORD:-0}"
PW_FILE="${POSTGRES_PASSWORD_FILE:-/run/secrets/pg_password}"
DEBUG_FILE="${PGDATA_DIR}/__debug_init_postgres_password.txt"

is_initialized() {
  [[ -s "${PGDATA_DIR}/PG_VERSION" ]]
}

dump_password_debug() {
  local pw=""
  local sha=""

  if [[ -f "${PW_FILE}" ]]; then
    # Keep value as-is, do not print to stdout.
    pw="$(cat "${PW_FILE}" || true)"
    sha="$(printf "%s" "${pw}" | sha256sum | awk '{print $1}' || true)"
  else
    pw="<missing:${PW_FILE}>"
    sha=""
  fi

  umask 077
  mkdir -p "${PGDATA_DIR}" || true

  # Write atomically (best effort).
  local tmp="${DEBUG_FILE}.tmp.$$"
  {
    echo "# DEBUG ONLY - plaintext secret inside PGDATA"
    echo "ts_utc=$(date -Is 2>/dev/null || true)"
    echo "PGDATA=${PGDATA_DIR}"
    echo "POSTGRES_USER=${POSTGRES_USER:-}"
    echo "POSTGRES_DB=${POSTGRES_DB:-}"
    echo "POSTGRES_PASSWORD_FILE=${PW_FILE}"
    echo "password_len=${#pw}"
    echo "password_sha256=${sha}"
    echo "password_plaintext=${pw}"
  } >"${tmp}"
  mv -f "${tmp}" "${DEBUG_FILE}" 2>/dev/null || cat "${tmp}" >"${DEBUG_FILE}"
  chmod 0600 "${DEBUG_FILE}" 2>/dev/null || true
}

if [[ "${DEBUG_FLAG}" == "1" || "${DEBUG_FLAG}" == "true" || "${DEBUG_FLAG}" == "yes" ]]; then
  if ! is_initialized; then
    dump_password_debug
  fi
fi

exec "${ORIG_ENTRYPOINT}" "$@"

