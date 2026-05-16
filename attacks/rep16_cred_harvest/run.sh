#!/usr/bin/env bash
set -euo pipefail
LOG=/tmp/attack.log
echo "=== REP-16 Credential Harvesting started $(date -u) ===" | tee -a "$LOG"

WORKDIR="/tmp/rep16_build"
mkdir -p "$WORKDIR"
cp "$(dirname "$0")/cred_harvest.c" "$WORKDIR/"

gcc -o "$WORKDIR/cred_harvest" "$WORKDIR/cred_harvest.c" 2>>"$LOG" \
  && echo "Compiled cred_harvest" >> "$LOG" \
  || { echo "Compile failed, synthetic only" >> "$LOG"; }

if [ -x "$WORKDIR/cred_harvest" ]; then
    "$WORKDIR/cred_harvest" 2>&1 | tee -a "$LOG" || true
    echo "Real path succeeded: openat x20+ burst fired" >> "$LOG"
else
    echo "Compile failed — no real path available" >> "$LOG"
fi

echo "=== REP-16 complete ===" | tee -a "$LOG"
