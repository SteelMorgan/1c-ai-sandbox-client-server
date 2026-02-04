#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   ./scripts/agent-new-branch.sh <task-slug>
#
# Creates and switches to: agent/<task-slug>-<yyyymmdd>

task="${1:-}"
if [[ -z "$task" ]]; then
  echo "Usage: $0 <task-slug>" >&2
  exit 2
fi

if ! command -v git >/dev/null 2>&1; then
  echo "git not found" >&2
  exit 1
fi

# Basic slug sanitization
task="$(echo "$task" | tr '[:upper:]' '[:lower:]' | sed -E 's/[^a-z0-9._-]+/-/g; s/^-+|-+$//g; s/-{2,}/-/g')"
if [[ -z "$task" ]]; then
  echo "Task slug became empty after sanitization." >&2
  exit 2
fi

date_utc="$(date -u +%Y%m%d)"
branch="agent/${task}-${date_utc}"

git rev-parse --is-inside-work-tree >/dev/null 2>&1 || { echo "Not a git repo." >&2; exit 1; }

current="$(git branch --show-current || true)"
if [[ "$current" == "main" || "$current" == "master" ]]; then
  echo "You're on $current. This environment expects work in agent/* branches." >&2
fi

git checkout -B "$branch"
echo "OK: switched to $branch"

