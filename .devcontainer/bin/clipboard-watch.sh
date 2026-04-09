#!/usr/bin/env bash
# Watches /tmp/cb-x11-sync/img.png for changes and loads it into X11 clipboard.
# Runs inside the container as a background daemon (started by entrypoint).
# Requires: xclip.

WATCH_FILE="/tmp/cb-x11-sync/img.png"
LAST_STAMP=""

while true; do
    if [ -f "$WATCH_FILE" ]; then
        # stat is nearly free vs md5sum which reads the entire file
        STAMP=$(stat -c '%Y %s' "$WATCH_FILE" 2>/dev/null)
        if [ -n "$STAMP" ] && [ "$STAMP" != "$LAST_STAMP" ]; then
            # load into X11 clipboard asynchronously — don't block the poll loop
            xclip -selection clipboard -t image/png -i "$WATCH_FILE" 2>/dev/null &
            LAST_STAMP="$STAMP"
        fi
    fi
    sleep 0.1
done
