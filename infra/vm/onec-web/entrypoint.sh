#!/usr/bin/env bash
set -euo pipefail

# Entrypoint for Apache web publication container.
# - Ensures persistent directories exist
# - Normalizes Apache listen port
# - Creates a stable wsap module symlink (so persisted config survives ONEC_VERSION changes)
# - Starts Apache in foreground

APACHE_LISTEN_PORT="${APACHE_LISTEN_PORT:-8080}"
ONEC_WEB_ROOT="${ONEC_WEB_ROOT:-/var/lib/onec-web}"
ONEC_WEB_WWW="${ONEC_WEB_WWW:-${ONEC_WEB_ROOT}/www}"
ONEC_WEB_APACHE_FRAGMENT="${ONEC_WEB_APACHE_FRAGMENT:-${ONEC_WEB_ROOT}/apache/onec.conf}"

mkdir -p "${ONEC_WEB_WWW}" "$(dirname "${ONEC_WEB_APACHE_FRAGMENT}")"
touch "${ONEC_WEB_APACHE_FRAGMENT}"

ensure_wsap_symlink() {
  local mod=""

  # Prefer Apache 2.4 module name.
  if [[ -f "/opt/1cv8/current/wsap24.so" ]]; then
    mod="/opt/1cv8/current/wsap24.so"
  else
    # Try common locations in 1C installation tree.
    mod="$(ls -1 /opt/1cv8/*/*/wsap24.so 2>/dev/null | head -n1 || true)"
    if [[ -z "${mod}" ]]; then
      mod="$(ls -1 /opt/1cv8/*/*/wsap22.so 2>/dev/null | head -n1 || true)"
    fi
  fi

  if [[ -z "${mod}" ]]; then
    echo "[WARN] wsap module not found under /opt/1cv8. Web publications may not work until 1C 'ws' component is installed."
    return 0
  fi

  if [[ "${mod}" == *"/wsap24.so" ]]; then
    ln -sfn "${mod}" /opt/1cv8/current/wsap24.so || true
  fi
  if [[ "${mod}" == *"/wsap22.so" ]]; then
    ln -sfn "${mod}" /opt/1cv8/current/wsap22.so || true
  fi
}

configure_apache_port() {
  local port="${1}"
  if [[ ! "${port}" =~ ^[0-9]{1,5}$ ]]; then
    echo "[ERROR] APACHE_LISTEN_PORT must be a number (1-65535). Got: '${port}'"
    exit 2
  fi
  if (( port < 1 || port > 65535 )); then
    echo "[ERROR] APACHE_LISTEN_PORT out of range (1-65535). Got: '${port}'"
    exit 2
  fi

  # Ubuntu apache2 uses /etc/apache2/ports.conf
  cat > /etc/apache2/ports.conf <<EOF
Listen ${port}

<IfModule ssl_module>
    Listen 443
</IfModule>

<IfModule mod_gnutls.c>
    Listen 443
</IfModule>
EOF

  # Ensure default vhost matches the listen port (Debian/Ubuntu ships <VirtualHost *:80>).
  # If we listen on a non-80 port and keep *:80 vhost, Apache starts but doesn't serve requests as expected.
  if [[ "${port}" != "80" ]]; then
    for f in /etc/apache2/sites-available/*.conf /etc/apache2/sites-enabled/*.conf; do
      [[ -f "$f" ]] || continue
      sed -i -E "s#<VirtualHost \\*:80>#<VirtualHost *:${port}>#g" "$f" || true
    done
  fi

  # Silence "ServerName" warning.
  if [[ ! -f /etc/apache2/conf-available/servername.conf ]]; then
    echo "ServerName localhost" > /etc/apache2/conf-available/servername.conf
  fi
  a2enconf servername >/dev/null 2>&1 || true
}

ensure_wsap_symlink
configure_apache_port "${APACHE_LISTEN_PORT}"

echo "[INFO] Starting Apache for 1C web publications"
echo "[INFO] Listen port: ${APACHE_LISTEN_PORT}"
echo "[INFO] Publications root: ${ONEC_WEB_WWW}"
echo "[INFO] Apache fragment: ${ONEC_WEB_APACHE_FRAGMENT}"

exec apache2ctl -D FOREGROUND

