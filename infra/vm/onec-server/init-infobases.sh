#!/usr/bin/env bash
set -euo pipefail

# One-shot init: register infobases in 1C cluster via RAS/rac.
#
# Inputs:
# - INFOBASES_JSON: path to JSON file (mounted) with array of infobases (default: /etc/onec/infobases.json)
# - RAS_ENDPOINT: host:port for RAS (default: onec-server:1545)
#
# JSON format example:
# [
#   {"name":"demo","db_name":"demo","db_server":"db","db_user":"onec","db_password":"onec","locale":"ru_RU"}
# ]

INFOBASES_JSON="${INFOBASES_JSON:-/etc/onec/infobases.json}"
RAS_ENDPOINT="${RAS_ENDPOINT:-onec-server:1545}"

read_secret() {
  local name="$1"
  local p="/run/secrets/${name}"
  if [[ -f "$p" ]]; then
    cat "$p"
  fi
}

# Allow defaults from secrets/env so passwords are not stored in infobases.json
export PGUSER="${PGUSER:-$(read_secret pg_user || true)}"
export PGPASSWORD="${PGPASSWORD:-$(read_secret pg_password || true)}"

if ! command -v rac >/dev/null 2>&1; then
  echo "[ERROR] rac not found in PATH. Check server_admin component installation."
  exit 2
fi

if [[ ! -f "$INFOBASES_JSON" ]]; then
  echo "[INFO] No infobases config at ${INFOBASES_JSON}. Nothing to do."
  exit 0
fi

echo "[INFO] Waiting for RAS at ${RAS_ENDPOINT}..."
for _ in $(seq 1 180); do
  if rac cluster list "$RAS_ENDPOINT" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

cluster_out="$(rac cluster list "$RAS_ENDPOINT" || true)"
cluster_id="$(printf "%s" "$cluster_out" | grep -Eo '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}' | head -n1 || true)"
if [[ -z "$cluster_id" ]]; then
  echo "[ERROR] Cannot detect cluster id from: rac cluster list ${RAS_ENDPOINT}"
  echo "$cluster_out"
  exit 3
fi

export CLUSTER_ID="$cluster_id"
echo "[INFO] Cluster id: ${CLUSTER_ID}"

python3 - <<'PY'
import json, os, subprocess, sys

cfg_path = os.environ.get("INFOBASES_JSON", "/etc/onec/infobases.json")
ras = os.environ.get("RAS_ENDPOINT", "onec-server:1545")
cluster_id = os.environ.get("CLUSTER_ID")
if not cluster_id:
  print("[ERROR] CLUSTER_ID is not set", file=sys.stderr)
  sys.exit(10)

with open(cfg_path, "r", encoding="utf-8") as f:
  items = json.load(f)

if not isinstance(items, list):
  print("[ERROR] INFOBASES_JSON must be a JSON array", file=sys.stderr)
  sys.exit(11)

def run(cmd):
  p = subprocess.run(cmd, text=True, capture_output=True)
  return p.returncode, p.stdout, p.stderr

def infobase_exists(name: str) -> bool:
  code, out, err = run(["rac", "infobase", "summary", "list", ras, f"--cluster={cluster_id}"])
  if code != 0:
    # If this command is unsupported, fall back to create-and-ignore "exists" errors.
    return False
  return name.lower() in out.lower()

for ib in items:
  if not isinstance(ib, dict):
    print("[WARN] skipping non-object entry", file=sys.stderr)
    continue

  name = ib.get("name")
  if not name:
    print("[WARN] skipping entry without name", file=sys.stderr)
    continue

  if infobase_exists(name):
    print(f"[INFO] Infobase '{name}' already exists. Skipping.")
    continue

  dbms = ib.get("dbms", "PostgreSQL")
  # When infra runs with host networking, Postgres is on localhost.
  db_server = ib.get("db_server", "127.0.0.1")
  db_name = ib.get("db_name", name)
  db_user = ib.get("db_user") or os.environ.get("PGUSER") or "onec"
  db_password = ib.get("db_password") or os.environ.get("PGPASSWORD") or ""
  locale = ib.get("locale", "ru_RU")

  cmd = [
    "rac", "infobase", "create", ras,
    f"--cluster={cluster_id}",
    f"--name={name}",
    f"--dbms={dbms}",
    f"--db-server={db_server}",
    f"--db-name={db_name}",
    f"--db-user={db_user}",
    f"--db-pwd={db_password}",
    f"--locale={locale}",
    "--create-database"
  ]

  code, out, err = run(cmd)
  if code == 0:
    print(f"[OK] Created/registered infobase '{name}'")
    continue

  low = (out + "\n" + err).lower()
  if "already" in low or "существ" in low or "exists" in low:
    print(f"[INFO] Infobase '{name}' seems to already exist (non-fatal).")
    continue

  print(f"[ERROR] Failed to create infobase '{name}' (exit={code})", file=sys.stderr)
  if out:
    print(out, file=sys.stderr)
  if err:
    print(err, file=sys.stderr)
  sys.exit(code or 12)

print("[INFO] Infobase init finished.")
PY

