#!/usr/bin/env bash
set -euo pipefail

# Sync /etc/hosts inside devcontainer so 1C admin console/tools can reach the VM by name.
#
# Source of truth: infra/vm/.env (MGMT_VM_IP) if present in the workspace.
# Target: /etc/hosts entry "MGMT_VM_IP onec-infra"
#
# Notes:
# - Must be safe to run repeatedly (idempotent).
# - Do NOT print secrets (none used here).

ROOT="${WORKSPACE_FOLDER:-/workspaces/work}"
ENV_FILE="${ROOT}/infra/vm/.env"
DEFAULT_HOSTNAME_TO_SET="onec-infra"

if [[ ! -f "$ENV_FILE" ]]; then
  exit 0
fi

read_env() {
  local key="$1"
  awk -F= -v k="$key" '
    BEGIN{v=""}
    /^[[:space:]]*#/ {next}
    $1 ~ ("^[[:space:]]*" k "[[:space:]]*$") {
      val=$2
      sub(/^[[:space:]]+/, "", val); sub(/[[:space:]]+$/, "", val)
      gsub(/\r$/, "", val)
      v=val
    }
    END{print v}
  ' "$ENV_FILE"
}

mgmt_ip="$(read_env MGMT_VM_IP)"
hostname_to_set="$(read_env VM_NAME)"
if [[ -z "${hostname_to_set}" ]]; then
  hostname_to_set="$DEFAULT_HOSTNAME_TO_SET"
fi

# Basic hostname sanity check (for /etc/hosts).
if [[ ! "${hostname_to_set}" =~ ^[A-Za-z0-9_.-]{1,64}$ ]]; then
  echo "[WARN] VM_NAME has unexpected value: ${hostname_to_set}. Falling back to ${DEFAULT_HOSTNAME_TO_SET}." >&2
  hostname_to_set="$DEFAULT_HOSTNAME_TO_SET"
fi

if [[ -z "${mgmt_ip}" ]]; then
  exit 0
fi

# Basic IPv4 sanity check.
if [[ ! "${mgmt_ip}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
  echo "[WARN] MGMT_VM_IP has unexpected value: ${mgmt_ip}. Skipping /etc/hosts update." >&2
  exit 0
fi

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

# Remove old mapping lines for the hostname to keep it deterministic.
awk -v h="$hostname_to_set" '
  $0 ~ ("(^|[[:space:]])" h "([[:space:]]|$)") { next }
  { print }
' /etc/hosts > "$tmp"

printf "%s\t%s\n" "$mgmt_ip" "$hostname_to_set" >> "$tmp"

# Need root to update /etc/hosts.
if [[ "$(id -u)" -ne 0 ]]; then
  sudo -n cp "$tmp" /etc/hosts
else
  cp "$tmp" /etc/hosts
fi

