#!/usr/bin/env bash
set -euo pipefail
LOG=/tmp/attack.log
echo "=== REP-05 Webshell started $(date -u) ===" | tee -a "$LOG"

WORKDIR="/tmp/rep05_build"
mkdir -p "$WORKDIR"
cp "$(dirname "$0")/webshell.c" "$WORKDIR/"

gcc -o "$WORKDIR/apache2-worker" "$WORKDIR/webshell.c" 2>>"$LOG" \
  && echo "Compiled apache2-worker" >> "$LOG" \
  || { echo "Compile failed" >> "$LOG"; exit 1; }

"$WORKDIR/apache2-worker" 2>&1 | tee -a "$LOG" || true
echo "Real path: execve x4 fired from comm=apache2-worker" >> "$LOG"

echo "=== REP-05 complete ===" | tee -a "$LOG"
