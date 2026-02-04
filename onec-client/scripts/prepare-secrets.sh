#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# Deprecated: secrets are now managed in the top-level ./secrets directory.
exec "${ROOT_DIR}/scripts/prepare-secrets.sh"

