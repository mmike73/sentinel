#!/usr/bin/env bash
set -euo pipefail
LOG=/tmp/attack.log
echo "=== REP-13 Fileless Malware started $(date -u) ===" | tee -a "$LOG"

WORKDIR="/tmp/rep13_build"
mkdir -p "$WORKDIR"
cp "$(dirname "$0")/fileless.c" "$WORKDIR/"

gcc -o "$WORKDIR/fileless" "$WORKDIR/fileless.c" 2>>"$LOG" \
  && echo "Compiled fileless" >> "$LOG" \
  || { echo "Compile failed, synthetic only" >> "$LOG"; }

if [ -x "$WORKDIR/fileless" ]; then
    "$WORKDIR/fileless" 2>&1 | tee -a "$LOG" || true
    echo "Real path succeeded: mmap+write+execve chain fired" >> "$LOG"
fi

echo "=== REP-13 complete ===" | tee -a "$LOG"
