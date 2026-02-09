#!/usr/bin/env bash
set -euo pipefail

# onec-webinst.sh — wrapper for 1C webinst utility inside onec-web container.
#
# Actions:
#   publish   - create/update publication
#   unpublish - delete publication
#   update   - alias for publish
#
# Inputs (prefer env vars to avoid quoting issues over SSH):
#   ONEC_ALIAS             publication alias (Ref == alias)
#   ONEC_CONNSTR           infobase connection string (for publish/update)
#   ONEC_CONNSTR_B64       base64(utf-8) connection string (decoded if ONEC_CONNSTR is empty)
#   ONEC_WEB_APACHE_FRAGMENT  optional override for apache fragment path
#   ONEC_WEB_WWW              optional override for publications root
#
# Notes:
# - Uses Apache 2.4 mode by default (-apache24), falls back to -apache2 if needed.
# - Writes publication directives into a persistent fragment (volume), which Apache includes.

action="${1:-}"
if [[ -z "${action}" ]]; then
  echo "Usage: $0 <publish|unpublish|update>"
  exit 2
fi

alias="$(printf "%s" "${ONEC_ALIAS:-}" | tr -d '\r\n' || true)"
if [[ -z "${alias}" ]]; then
  echo "[ERROR] ONEC_ALIAS is required"
  exit 2
fi

# Validation without bash-regex edge cases: only [A-Za-z0-9_.-], 1..64 chars.
if [[ "${alias}" == *[^A-Za-z0-9_.-]* ]] || [[ "${#alias}" -lt 1 ]] || [[ "${#alias}" -gt 64 ]]; then
  echo "[ERROR] ONEC_ALIAS must be 1..64 chars and contain only [A-Za-z0-9_.-] (got '${alias}')"
  exit 2
fi

ONEC_WEB_ROOT="${ONEC_WEB_ROOT:-/var/lib/onec-web}"
ONEC_WEB_WWW="${ONEC_WEB_WWW:-${ONEC_WEB_ROOT}/www}"
ONEC_WEB_APACHE_FRAGMENT="${ONEC_WEB_APACHE_FRAGMENT:-${ONEC_WEB_ROOT}/apache/onec.conf}"

pub_dir="${ONEC_WEB_WWW}/${alias}"
mkdir -p "${pub_dir}" "$(dirname "${ONEC_WEB_APACHE_FRAGMENT}")"
touch "${ONEC_WEB_APACHE_FRAGMENT}"
chown -R www-data:www-data "${ONEC_WEB_WWW}" 2>/dev/null || true

connstr="${ONEC_CONNSTR:-}"
if [[ -z "${connstr}" && -n "${ONEC_CONNSTR_B64:-}" ]]; then
  connstr="$(printf "%s" "${ONEC_CONNSTR_B64}" | base64 -d 2>/dev/null || true)"
fi

detect_webinst() {
  local p="/opt/1cv8/current/webinst"
  if [[ -x "${p}" ]]; then
    echo "${p}"
    return 0
  fi
  p="$(ls -1 /opt/1cv8/*/*/webinst 2>/dev/null | head -n1 || true)"
  if [[ -n "${p}" && -x "${p}" ]]; then
    echo "${p}"
    return 0
  fi
  return 1
}

WEBINST="$(detect_webinst || true)"
if [[ -z "${WEBINST}" ]]; then
  echo "[ERROR] webinst not found. Ensure 1C component 'ws' is installed in the image."
  exit 3
fi

apache_flag="-apache24"

ensure_vrd_features() {
  # webinst generates a minimal VRD (web client only). For /hs (HTTP services) and REST endpoints,
  # VRD must include <httpServices/> and <rest/> sections.
  #
  # Idempotent: adds sections only if they are missing.
  local vrd_path="$1"
  if [[ -z "${vrd_path}" || ! -f "${vrd_path}" ]]; then
    return 0
  fi

  local changed=0

  if ! grep -qE '<httpServices\b' "${vrd_path}" 2>/dev/null; then
    perl -0777 -i -pe 's#</point>\s*$#\t<httpServices publishExtensionsByDefault="true"/>\n</point>#s' "${vrd_path}" || true
    changed=1
  fi

  if ! grep -qE '<rest\b' "${vrd_path}" 2>/dev/null; then
    perl -0777 -i -pe 's#</point>\s*$#\t<rest publishExtensionsByDefault="true"/>\n</point>#s' "${vrd_path}" || true
    changed=1
  fi

  if [[ "${changed}" == "1" ]]; then
    echo "[INFO] Updated VRD to enable HTTP/REST services: ${vrd_path}"
  fi
}

normalize_wsap_paths() {
  # Persisted fragment can survive ONEC_VERSION bumps; normalize module paths to /opt/1cv8/current/*
  # Best-effort: cover typical wsap module names.
  sed -i -E \
    -e 's#/opt/1cv8/(x86_64|amd64)/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/wsap24\.so#/opt/1cv8/current/wsap24.so#g' \
    -e 's#/opt/1cv8/(x86_64|amd64)/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/wsap22\.so#/opt/1cv8/current/wsap22.so#g' \
    "${ONEC_WEB_APACHE_FRAGMENT}" 2>/dev/null || true
}

case "${action}" in
  publish|update)
    if [[ -z "${connstr}" ]]; then
      echo "[ERROR] ONEC_CONNSTR (or ONEC_CONNSTR_B64) is required for '${action}'"
      exit 2
    fi
    echo "[INFO] Publishing '${alias}' into ${pub_dir}"
    set +e
    out="$("${WEBINST}" -publish "${apache_flag}" \
      -wsdir "${alias}" \
      -dir "${pub_dir}" \
      -connstr "${connstr}" \
      -confpath "${ONEC_WEB_APACHE_FRAGMENT}" 2>&1)"
    ec=$?
    set -e
    if [[ $ec -ne 0 ]]; then
      # Some platform builds may not recognize -apache24; retry with -apache2.
      if printf "%s" "${out}" | grep -qi "apache24"; then
        apache_flag="-apache2"
        set +e
        out2="$("${WEBINST}" -publish "${apache_flag}" \
          -wsdir "${alias}" \
          -dir "${pub_dir}" \
          -connstr "${connstr}" \
          -confpath "${ONEC_WEB_APACHE_FRAGMENT}" 2>&1)"
        ec2=$?
        set -e
        if [[ -n "${out2:-}" ]]; then echo "${out2}"; fi
        if [[ $ec2 -ne 0 ]]; then exit $ec2; fi
      else
        echo "${out}"
        exit $ec
      fi
    else
      if [[ -n "${out:-}" ]]; then echo "${out}"; fi
    fi
    # Ensure /hs (HTTP services) works for services in configuration + extensions.
    ensure_vrd_features "${pub_dir}/default.vrd"
    normalize_wsap_paths
    apache2ctl -k graceful >/dev/null 2>&1 || true
    echo "[OK] Published '${alias}'"
    ;;
  unpublish|delete|remove)
    echo "[INFO] Unpublishing '${alias}'"
    # NOTE (1C docs): for delete it is enough to pass -wsdir, but we pass extra params to keep it deterministic.
    set +e
    out="$("${WEBINST}" -delete "${apache_flag}" \
      -wsdir "${alias}" \
      -dir "${pub_dir}" \
      -confpath "${ONEC_WEB_APACHE_FRAGMENT}" 2>&1)"
    ec=$?
    set -e
    if [[ $ec -ne 0 ]]; then
      if printf "%s" "${out}" | grep -qi "apache24"; then
        apache_flag="-apache2"
        set +e
        out2="$("${WEBINST}" -delete "${apache_flag}" \
          -wsdir "${alias}" \
          -dir "${pub_dir}" \
          -confpath "${ONEC_WEB_APACHE_FRAGMENT}" 2>&1)"
        ec2=$?
        set -e
        if [[ -n "${out2:-}" ]]; then echo "${out2}"; fi
        if [[ $ec2 -ne 0 ]]; then exit $ec2; fi
      else
        echo "${out}"
        exit $ec
      fi
    else
      if [[ -n "${out:-}" ]]; then echo "${out}"; fi
    fi
    normalize_wsap_paths
    rm -rf "${pub_dir}" 2>/dev/null || true
    apache2ctl -k graceful >/dev/null 2>&1 || true
    echo "[OK] Unpublished '${alias}'"
    ;;
  *)
    echo "[ERROR] Unknown action: '${action}'. Expected: publish|unpublish|update"
    exit 2
    ;;
esac

