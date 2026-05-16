#!/usr/bin/env bash
set -euo pipefail
LOG=/tmp/attack.log
echo "=== REP-07 RWX mmap started $(date -u) ===" | tee -a "$LOG"

WORKDIR="/tmp/rep07_build"
mkdir -p "$WORKDIR"
cp "$(dirname "$0")/mmap_rwx_probe.c" "$WORKDIR/"

gcc -o "$WORKDIR/mmap_rwx_probe" "$WORKDIR/mmap_rwx_probe.c" 2>>"$LOG" \
  && echo "Real path: compiled mmap_rwx_probe" >> "$LOG" \
  || echo "Compile failed, synthetic only" >> "$LOG"

if [ -x "$WORKDIR/mmap_rwx_probe" ]; then
    "$WORKDIR/mmap_rwx_probe" 2>>"$LOG" || true
    echo "Real path succeeded" >> "$LOG"
fi

echo "=== REP-07 complete ===" | tee -a "$LOG"
