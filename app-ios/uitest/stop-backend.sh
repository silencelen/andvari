#!/usr/bin/env bash
# Stops what start-backend.sh started. Usage: stop-backend.sh <work dir>
WORK="${1:?usage: stop-backend.sh <work dir>}"
for name in server site; do
  [ -f "$WORK/$name.pid" ] && kill "$(cat "$WORK/$name.pid")" 2> /dev/null
done
exit 0
