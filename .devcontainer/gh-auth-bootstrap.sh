#!/usr/bin/env bash
set -euo pipefail

# Idempotent GitHub auth bootstrap for Dev Containers.
# - Reads PAT from /run/secrets/github_token (Docker secret)
# - Logs in only if not already authenticated
# - Sets up git HTTPS credential helper via gh
#
# IMPORTANT:
# - Must run as the dev user (vscode), not as root, so auth is stored in /home/vscode/.config/gh.
# - Never prints the token.

if ! command -v gh >/dev/null 2>&1; then
  echo "[WARN] gh CLI is not installed; skipping GitHub auth bootstrap."
  exit 0
fi

host="${GITHUB_HOSTNAME:-github.com}"
token_file="/run/secrets/github_token"

if [[ ! -s "$token_file" ]]; then
  echo "[WARN] ${token_file} is missing or empty. Set GITHUB_TOKEN in secrets/.env and run scripts/prepare-secrets.* to generate secrets/github_token. Skipping GitHub auth bootstrap."
  exit 0
fi

# If already authenticated, do nothing.
if gh auth status -h "$host" >/dev/null 2>&1; then
  exit 0
fi

echo "[INFO] GitHub auth is missing. Logging in to ${host} via token secret..."
set +x
gh auth login --hostname "$host" --with-token <"$token_file" >/dev/null
set -x 2>/dev/null || true

# Configure git to use gh credential helper (HTTPS).
if command -v git >/dev/null 2>&1; then
  gh auth setup-git -h "$host" >/dev/null 2>&1 || true
fi

echo "[INFO] GitHub auth bootstrap completed."

