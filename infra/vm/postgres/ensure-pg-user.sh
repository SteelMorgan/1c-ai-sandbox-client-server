#!/usr/bin/env bash
set -euo pipefail

# Ensure Postgres role/password/db exist using project secrets.
# Runs on the VM host (not inside containers) and uses `docker exec` into onec-postgres.
#
# Why: akocur/postgresql-1c-17 ignores POSTGRES_PASSWORD(_FILE) and does not create/alter roles.

# Script location: <repo>/infra/vm/postgres/ensure-pg-user.sh
# Repo root is 3 levels up.
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
docker_() { sudo -n docker "$@"; }

POSTGRES_CONTAINER="${POSTGRES_CONTAINER:-onec-postgres}"
POSTGRES_USER_DEFAULT="${POSTGRES_USER_DEFAULT:-onec}"
POSTGRES_DB_DEFAULT="${POSTGRES_DB_DEFAULT:-postgres}"

PGUSER="${PGUSER:-}"
PGDATABASE="${PGDATABASE:-}"

if [[ -z "${PGUSER}" ]]; then PGUSER="${POSTGRES_USER_DEFAULT}"; fi
if [[ -z "${PGDATABASE}" ]]; then PGDATABASE="${POSTGRES_DB_DEFAULT}"; fi

PW_FILE="${PW_FILE:-${ROOT_DIR}/secrets/pg_password}"
if [[ ! -f "${PW_FILE}" || ! -s "${PW_FILE}" ]]; then
  echo "[pg-init] ERROR: password file missing or empty: ${PW_FILE}" >&2
  exit 2
fi

pw="$(cat "${PW_FILE}")"
pw="${pw%$'\n'}"; pw="${pw%$'\r'}"

sql_quote_literal() {
  local s="${1:-}"
  s="${s//\'/\'\'}"
  printf "'%s'" "${s}"
}

sql_quote_ident() {
  local s="${1:-}"
  s="${s//\"/\"\"}"
  printf "\"%s\"" "${s}"
}

echo "[pg-init] Waiting for Postgres container '${POSTGRES_CONTAINER}'..."
for _ in {1..120}; do
  if docker_ ps --format '{{.Names}}' | grep -qx "${POSTGRES_CONTAINER}"; then
    break
  fi
  sleep 0.5
done

if ! docker_ ps --format '{{.Names}}' | grep -qx "${POSTGRES_CONTAINER}"; then
  echo "[pg-init] ERROR: container '${POSTGRES_CONTAINER}' is not running." >&2
  exit 3
fi

echo "[pg-init] Waiting for Postgres readiness..."
for _ in {1..120}; do
  if docker_ exec "${POSTGRES_CONTAINER}" /opt/pgpro/1c-17/bin/pg_isready -U postgres >/dev/null 2>&1; then
    break
  fi
  sleep 0.5
done

if ! docker_ exec "${POSTGRES_CONTAINER}" /opt/pgpro/1c-17/bin/pg_isready -U postgres >/dev/null 2>&1; then
  echo "[pg-init] ERROR: Postgres is not ready inside container." >&2
  exit 4
fi

echo "[pg-init] Ensuring role '${PGUSER}' password is set (db '${PGDATABASE}')."

# Use local socket access inside the container as OS user postgres.
# Do NOT print the password.
docker_ exec -u postgres "${POSTGRES_CONTAINER}" bash -lc \
  "/opt/pgpro/1c-17/bin/psql -v ON_ERROR_STOP=1 --username=postgres --dbname=postgres -c \
  \"DO \\$\\$ BEGIN \
     IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname=$(sql_quote_literal "${PGUSER}")) THEN \
       EXECUTE 'CREATE ROLE ' || quote_ident($(sql_quote_literal "${PGUSER}")) || ' LOGIN'; \
     END IF; \
   END \\$\\$;\""

docker_ exec -u postgres "${POSTGRES_CONTAINER}" bash -lc \
  "/opt/pgpro/1c-17/bin/psql -v ON_ERROR_STOP=1 --username=postgres --dbname=postgres -c \
  \"ALTER ROLE $(sql_quote_ident "${PGUSER}") WITH PASSWORD $(sql_quote_literal "${pw}") SUPERUSER CREATEDB;\""

if [[ "${PGDATABASE}" != "postgres" ]]; then
  docker_ exec -u postgres "${POSTGRES_CONTAINER}" bash -lc \
    "/opt/pgpro/1c-17/bin/psql -v ON_ERROR_STOP=1 --username=postgres --dbname=postgres -c \
    \"DO \\$\\$ BEGIN \
       IF NOT EXISTS (SELECT 1 FROM pg_database WHERE datname=$(sql_quote_literal "${PGDATABASE}")) THEN \
         EXECUTE 'CREATE DATABASE ' || quote_ident($(sql_quote_literal "${PGDATABASE}")) || ' OWNER ' || quote_ident($(sql_quote_literal "${PGUSER}")); \
       END IF; \
     END \\$\\$;\""
fi

echo "[pg-init] OK"

