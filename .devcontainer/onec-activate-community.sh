#!/usr/bin/env bash
set -euo pipefail

# Community license activation for 1C platform inside the sandbox container.
# Idempotent: if license files exist, does nothing.
#
# Requires:
# - /opt/1cv8/current/ibcmd, /opt/1cv8/current/ibsrv, /opt/1cv8/current/1cv8c
# - /opt/onec-client/ActivateCommunity.epf
# - secrets mounted at /run/secrets/dev_login and /run/secrets/dev_password

LOG_DIR="/var/log/onec"
STATUS_FILE="${LOG_DIR}/activation.status"
DONE_FILE="${LOG_DIR}/activation.done"
mkdir -p "$LOG_DIR"

started_at="$(date -Is 2>/dev/null || true)"
ACTIVATION_STATE="running"
ACTIVATION_REASON=""
ACTIVATION_ERROR_SUMMARY=""

write_status() {
  local state="$1"
  local rc="$2"
  local reason="$3"
  local error_summary="$4"
  local finished_at
  finished_at="$(date -Is 2>/dev/null || true)"

  # key=value format (easy to parse from bash/PowerShell). Never include secrets.
  local tmp="${STATUS_FILE}.tmp.$$"
  {
    printf "state=%s\n" "$state"
    printf "exit_code=%s\n" "$rc"
    printf "started_at=%s\n" "${started_at:-}"
    printf "finished_at=%s\n" "${finished_at:-}"
    printf "reason=%s\n" "${reason:-}"
    printf "error_summary=%s\n" "${error_summary:-}"
    if find /var/1C/licenses -maxdepth 1 -type f -size +0 2>/dev/null | grep -q .; then
      printf "licenses_present=1\n"
    else
      printf "licenses_present=0\n"
    fi
  } >"$tmp"
  mv -f "$tmp" "$STATUS_FILE" 2>/dev/null || cat "$tmp" >"$STATUS_FILE"
}

latest_ibsrv_log() {
  # ibsrv log file path differs by PID/session; pick the newest one.
  ls -1t /root/.1cv8/1C/1cv8/logs/ibsrv_*/*.log 2>/dev/null | head -n 1 || true
}

normalize_one_line() {
  # Collapse CR/LF and excessive whitespace to a single line (status file friendly).
  # Also avoid leaking secrets (DEV_PASSWORD etc) — best effort redact.
  local s="${1:-}"
  s="$(printf "%s" "$s" | tr -d '\r' | tr '\n' ' ' | sed -E 's/[[:space:]]+/ /g' | sed -E 's/[[:space:]]+$//')"
  # Redact obvious password forms (we never print DEV_PASSWORD elsewhere, but keep safety net).
  s="$(printf "%s" "$s" | sed -E 's/(password=)[^; ]+/\1<redacted>/gi')"
  # Keep status line reasonably short.
  printf "%.600s" "$s"
}

collect_error_summary() {
  # Try to extract a meaningful error from ibsrv log first, then fall back to last lines in activation.log.
  local log
  log="$(latest_ibsrv_log)"
  if [[ -n "${log:-}" && -f "$log" ]]; then
    # Prefer the last exception-ish block.
    local tail_block
    tail_block="$(grep -n -E 'EXCP|Exception=|Descr=|ERROR|Error|Ошибка|Лиценз|License|актив' "$log" 2>/dev/null | tail -n 8 || true)"
    if [[ -n "${tail_block:-}" ]]; then
      printf "%s" "$(normalize_one_line "ibsrv:${tail_block}")"
      return 0
    fi
    # If no matches, still point to the log file.
    printf "%s" "$(normalize_one_line "ibsrv_log:${log}")"
    return 0
  fi

  # Fallback: last non-empty line of our own log file (if exists).
  if [[ -f "${LOG_DIR}/activation.log" ]]; then
    local last
    last="$(grep -v '^[[:space:]]*$' "${LOG_DIR}/activation.log" 2>/dev/null | tail -n 1 || true)"
    if [[ -n "${last:-}" ]]; then
      printf "%s" "$(normalize_one_line "log:${last}")"
      return 0
    fi
  fi

  printf "%s" "unknown"
}

on_exit() {
  local rc=$?
  local final_state="$ACTIVATION_STATE"

  if [[ -z "${final_state:-}" || "${final_state}" == "running" ]]; then
    if [[ "$rc" -eq 0 ]]; then
      final_state="success"
    else
      final_state="failed"
    fi
  fi

  # If we failed without a reason/details (e.g. set -e short-circuit), try to extract something useful.
  if [[ "${final_state}" != "success" ]]; then
    if [[ -z "${ACTIVATION_REASON:-}" ]]; then ACTIVATION_REASON="unknown_error"; fi
    if [[ -z "${ACTIVATION_ERROR_SUMMARY:-}" ]]; then ACTIVATION_ERROR_SUMMARY="$(collect_error_summary)"; fi
  fi

  write_status "$final_state" "$rc" "${ACTIVATION_REASON:-}" "${ACTIVATION_ERROR_SUMMARY:-}"
  # Deterministic completion marker (existence == script finished).
  : >"$DONE_FILE" 2>/dev/null || true
}
trap on_exit EXIT

read_secret() {
  local name="$1"
  local p="/run/secrets/${name}"
  if [[ -f "$p" ]]; then
    cat "$p"
  fi
}

export DEV_LOGIN="${DEV_LOGIN:-$(read_secret dev_login || true)}"
export DEV_PASSWORD="${DEV_PASSWORD:-$(read_secret dev_password || true)}"

if [[ -z "${DEV_LOGIN:-}" || -z "${DEV_PASSWORD:-}" ]]; then
  echo "[WARN] DEV_LOGIN/DEV_PASSWORD are not provided. Skipping community activation."
  ACTIVATION_STATE="skipped"
  ACTIVATION_REASON="missing_credentials"
  exit 0
fi

# Do not print secrets. Print only lengths for diagnostics.
echo "[INFO] Activation credentials: login_len=${#DEV_LOGIN} password_len=${#DEV_PASSWORD}"

mkdir -p /var/1C/licenses
if find /var/1C/licenses -maxdepth 1 -type f -size +0 2>/dev/null | grep -q .; then
  echo "[INFO] Licenses already exist in /var/1C/licenses. Skipping activation."
  ACTIVATION_STATE="success"
  ACTIVATION_REASON="licenses_already_exist"
  exit 0
fi

# Basic network preflight (activation typically requires outbound HTTPS).
if command -v curl >/dev/null 2>&1; then
  if ! curl -fsSI --max-time 10 https://developer.1c.ru/ >/dev/null 2>&1; then
    echo "[WARN] Cannot reach https://developer.1c.ru/ (DNS/HTTPS/proxy?). Activation may fail."
  fi
fi

ACTIVATION_DB_NAME="EmptyIB_Activation"
ACTIVATION_DB_PATH="/home/usr1cv8/Documents/${ACTIVATION_DB_NAME}"
mkdir -p "/home/usr1cv8/Documents"

if [[ ! -d "$ACTIVATION_DB_PATH" ]]; then
  echo "[INFO] Creating empty infobase: $ACTIVATION_DB_PATH"
  /opt/1cv8/current/ibcmd infobase create --db-path="$ACTIVATION_DB_PATH"
fi

# Avoid "unsafe action / first time external processing" modal dialogs.
CONF_CFG="/opt/1cv8/conf/conf.cfg"
if [[ -f "$CONF_CFG" ]]; then
  if ! grep -q "DisableUnsafeActionProtection=.*${ACTIVATION_DB_NAME}.*" "$CONF_CFG" 2>/dev/null; then
    printf "\nDisableUnsafeActionProtection=.*%s.*\n" "$ACTIVATION_DB_NAME" >> "$CONF_CFG"
  fi
fi

ACTIVATION_IB_REGPORT=9141
ACTIVATION_IB_DIRECT_RANGE=9160:9161

echo "[INFO] Starting local ibsrv for activation..."
/opt/1cv8/current/ibsrv \
  --db-path="$ACTIVATION_DB_PATH" \
  --name="$ACTIVATION_DB_NAME" \
  --direct-regport="$ACTIVATION_IB_REGPORT" \
  --direct-range="$ACTIVATION_IB_DIRECT_RANGE" \
  </dev/null &
SERVER_PID=$!

cleanup() {
  kill -15 "${SERVER_PID:-0}" 2>/dev/null || true
  # Don't hang forever if ibsrv refuses to die (we want container startup to proceed).
  for _ in $(seq 1 10); do
    if [[ -z "${SERVER_PID:-}" ]]; then break; fi
    if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
      SERVER_PID=""
      break
    fi
    sleep 0.3
  done
  if [[ -n "${SERVER_PID:-}" ]] && kill -0 "${SERVER_PID}" 2>/dev/null; then
    kill -9 "${SERVER_PID}" 2>/dev/null || true
  fi
  wait "${SERVER_PID:-}" 2>/dev/null || true
}
trap cleanup INT TERM

echo "[INFO] Waiting for activation ibsrv (port=$ACTIVATION_IB_REGPORT)..."
deadline=$(( $(date +%s) + 120 ))
until ss -tln 2>/dev/null | grep -q ":${ACTIVATION_IB_REGPORT}"; do
  if [[ "$(date +%s)" -gt "$deadline" ]]; then
    echo "[ERROR] Activation ibsrv did not start listening on ${ACTIVATION_IB_REGPORT} within 120s"
    ACTIVATION_STATE="failed"
    ACTIVATION_REASON="ibsrv_not_listening"
    ACTIVATION_ERROR_SUMMARY="$(normalize_one_line "ibsrv_port=${ACTIVATION_IB_REGPORT} not_listening")"
    exit 10
  fi
  sleep 1
done

echo "[INFO] Running ActivateCommunity.epf (headless)..."
# Use xvfb-run to avoid DISPLAY issues in batch mode.
set +e
timeout 600s xvfb-run -a /opt/1cv8/current/1cv8c ENTERPRISE \
  /S "localhost:${ACTIVATION_IB_REGPORT}/${ACTIVATION_DB_NAME}" \
  /Execute "/opt/onec-client/ActivateCommunity.epf" \
  /C "login=${DEV_LOGIN};password=${DEV_PASSWORD};acceptLicense=true;forAllUsers=true" \
  /DisableStartupMessages \
  /UseHwLicenses-
rc=$?
set -e
if [[ "$rc" -ne 0 ]]; then
  echo "[ERROR] Activation command failed (rc=$rc)"
  ACTIVATION_STATE="failed"
  if [[ "$rc" -eq 124 ]]; then
    ACTIVATION_REASON="activation_timeout"
  else
    ACTIVATION_REASON="activation_command_failed"
  fi
  # Pull a useful snippet from ibsrv log (often contains the actual EPF error).
  ACTIVATION_ERROR_SUMMARY="$(collect_error_summary)"
  echo "[DIAG] error_summary=${ACTIVATION_ERROR_SUMMARY}"
  log="$(latest_ibsrv_log)"
  if [[ -n "${log:-}" && -f "$log" ]]; then
    echo "[DIAG] latest_ibsrv_log=${log}"
    echo "[DIAG] ibsrv tail (last 120):"
    tail -n 120 "$log" 2>/dev/null || true
  fi
  exit 12
fi

chown -R usr1cv8:grp1cv8 /var/1C/licenses || true
chmod -R 755 /var/1C/licenses || true

if ! find /var/1C/licenses -maxdepth 1 -type f -size +0 2>/dev/null | grep -q .; then
  echo "[ERROR] Activation finished but no license files were created in /var/1C/licenses"
  ACTIVATION_STATE="failed"
  ACTIVATION_REASON="no_license_files_created"
  ACTIVATION_ERROR_SUMMARY="$(collect_error_summary)"
  echo "[DIAG] error_summary=${ACTIVATION_ERROR_SUMMARY}"
  log="$(latest_ibsrv_log)"
  if [[ -n "${log:-}" && -f "$log" ]]; then
    echo "[DIAG] latest_ibsrv_log=${log}"
    echo "[DIAG] ibsrv tail (last 120):"
    tail -n 120 "$log" 2>/dev/null || true
  fi
  echo "[DIAG] /var/1C/licenses listing:"
  ls -la /var/1C/licenses 2>/dev/null || true
  echo "[DIAG] Recent files in /root/.1cv8 (may contain logs):"
  find /root/.1cv8 -maxdepth 5 -type f -mmin -60 -printf "%TY-%Tm-%Td %TH:%TM %s %p\n" 2>/dev/null | tail -n 40 || true
  echo "[DIAG] Recent files in /home/usr1cv8 (activation IB):"
  find /home/usr1cv8 -maxdepth 5 -type f -mmin -60 -printf "%TY-%Tm-%Td %TH:%TM %s %p\n" 2>/dev/null | tail -n 40 || true
  exit 11
fi

echo "[INFO] Community license activation finished."
ACTIVATION_STATE="success"
ACTIVATION_REASON="activated"

