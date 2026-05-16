#!/usr/bin/env bash
set -euo pipefail
LOG=/tmp/attack.log
echo "=== REP-12 SSH Brute-force started $(date -u) ===" | tee -a "$LOG"

WORKDIR="/tmp/rep12_build"
mkdir -p "$WORKDIR"
cp "$(dirname "$0")/ssh_brute.c" "$WORKDIR/"

gcc -o "$WORKDIR/ssh_brute" "$WORKDIR/ssh_brute.c" 2>>"$LOG" \
  && echo "Compiled ssh_brute" >> "$LOG" \
  || echo "Compile failed, synthetic only" >> "$LOG"

if [ -x "$WORKDIR/ssh_brute" ]; then
    "$WORKDIR/ssh_brute" 2>&1 | tee -a "$LOG" || true
    echo "Real path: burst socket+connect x20 from single PID fired" >> "$LOG"
else
    echo "Compile failed — no real path available" >> "$LOG"
fi

echo "=== REP-12 complete ===" | tee -a "$LOG"
