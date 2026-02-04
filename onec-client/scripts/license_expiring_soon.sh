#!/bin/bash
set -euo pipefail

LICENSE_DIR="/var/1C/licenses"
LICENSE_FILES=("${LICENSE_DIR}"/*.lic)
if [ ! -e "${LICENSE_FILES[0]}" ]; then
  exit 0
fi

MIN_DAYS_LEFT=9999
for LICENSE in "${LICENSE_FILES[@]}"; do
  EXPIRATION_LINE=$(grep -i "Срок действия:" "$LICENSE" | head -n1 || true)
  [ -z "$EXPIRATION_LINE" ] && continue

  EXP_DATE=$(echo "$EXPIRATION_LINE" | awk '{print $3, $4}')
  EXP_TS=$(date -d "$EXP_DATE" +%s 2>/dev/null) || continue
  NOW_TS=$(date +%s)
  DAYS_LEFT=$(( (EXP_TS - NOW_TS) / 86400 ))

  if [ "$DAYS_LEFT" -lt "$MIN_DAYS_LEFT" ]; then
    MIN_DAYS_LEFT=$DAYS_LEFT
  fi
done

[ "$MIN_DAYS_LEFT" -le 1 ]

