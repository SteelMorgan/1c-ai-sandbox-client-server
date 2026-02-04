#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   ./scripts/agent-open-pr.sh [base-branch]
#
# Creates a PR from current branch to base (default: main).

base="${1:-main}"

if ! command -v gh >/dev/null 2>&1; then
  echo "gh not found (GitHub CLI)." >&2
  exit 1
fi
if ! command -v git >/dev/null 2>&1; then
  echo "git not found." >&2
  exit 1
fi

git rev-parse --is-inside-work-tree >/dev/null 2>&1 || { echo "Not a git repo." >&2; exit 1; }

head="$(git branch --show-current)"
if [[ -z "$head" ]]; then
  echo "Couldn't determine current branch." >&2
  exit 1
fi
if [[ "$head" == "$base" ]]; then
  echo "You're on $base; create an agent/* branch first." >&2
  exit 2
fi

# Policy enforcement:
# - PRs into main/master are allowed only from the integration branch "agent".
if [[ "$base" == "main" || "$base" == "master" ]]; then
  if [[ "$head" != "agent" ]]; then
    echo "BLOCKED: PR into $base is allowed only from 'agent' (current: '$head')." >&2
    echo "Merge your agent/<task>-<yyyymmdd> branch into 'agent' first, then open PR: agent -> $base." >&2
    exit 2
  fi
fi

title="agent: ${head}"

gh pr create \
  --base "$base" \
  --head "$head" \
  --title "$title" \
  --body "$(cat <<'EOF'
## Summary
- TODO

## Test plan
- [ ] TODO
EOF
)"

