#!/usr/bin/env bash
set -euo pipefail

# This script creates a "fake" 1C platform layout inside the sandbox container
# so tools (like mcp-onec-test-runner / YaXUnit runner) can find DESIGNER
# via their built-in filesystem search logic.
#
# It creates:
#   /opt/1cv8/x86_64/<ONEC_VERSION>/1cv8
# where 1cv8 is a thin wrapper that proxies to the real 1cv8 inside the
# `onec-client` container via `docker exec`.

ONEC_CLIENT_CONTAINER_NAME="${ONEC_CLIENT_CONTAINER_NAME:-onec-client}"
ONEC_VERSION="${ONEC_VERSION:-}"

if [[ -z "${ONEC_VERSION}" ]]; then
  # Try to read from canonical version file in the shared workspace
  ENV_FILE="${ONEC_ENV_FILE:-/workspaces/work/infra/vm/.env}"
  if [[ -f "${ENV_FILE}" ]]; then
    # shellcheck disable=SC2002
    ONEC_VERSION="$(
      cat "${ENV_FILE}" \
        | awk -F= '/^ONEC_VERSION=/{print $2; exit}' \
        | tr -d '\r' \
        | xargs
    )"
  fi
fi

if [[ -z "${ONEC_VERSION}" ]]; then
  echo "[ERROR] ONEC_VERSION is not set and was not found in /workspaces/work/infra/vm/.env"
  exit 1
fi

# The runner's Linux search strategy expects /opt/1cv8/x86_64/<version>/1cv8
TARGET_DIR="/opt/1cv8/x86_64/${ONEC_VERSION}"
TARGET_BIN="${TARGET_DIR}/1cv8"

SUDO=""
if [[ "$(id -u)" != "0" ]]; then
  if command -v sudo >/dev/null 2>&1; then
    SUDO="sudo"
  else
    echo "[ERROR] Need root (or sudo) to create ${TARGET_BIN}"
    exit 1
  fi
fi

${SUDO} mkdir -p "${TARGET_DIR}"

# Write wrapper script
${SUDO} tee "${TARGET_BIN}" >/dev/null <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

ONEC_CLIENT_CONTAINER_NAME="${ONEC_CLIENT_CONTAINER_NAME:-onec-client}"

# 1cv8 on Linux may rely on DISPLAY and HOME; run as usr1cv8.
exec docker exec -i \
  -u usr1cv8 \
  -e DISPLAY=:99 \
  -e HOME=/home/usr1cv8 \
  "${ONEC_CLIENT_CONTAINER_NAME}" \
  /opt/1cv8/current/1cv8 "$@"
EOF

${SUDO} chmod +x "${TARGET_BIN}"

echo "[INFO] DESIGNER wrapper installed: ${TARGET_BIN}"
echo "[INFO] It proxies to: docker exec ${ONEC_CLIENT_CONTAINER_NAME} /opt/1cv8/current/1cv8"

