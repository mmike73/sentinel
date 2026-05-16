#!/usr/bin/env bash
set -euo pipefail
LOG=/tmp/attack.log
echo "=== REP-01 Diamorphine Rootkit started $(date -u) ===" | tee -a "$LOG"

WORKDIR="/tmp/diamorphine_rootkit_build"
mkdir -p "$WORKDIR"
cp "$(dirname "$0")/harmless_kernel_module.c" "$WORKDIR/"
cp "$(dirname "$0")/Makefile" "$WORKDIR/"

make -C "$WORKDIR" 2>>"$LOG" && echo "Real path: compiled harmless_kernel_module.ko" >> "$LOG" \
  || { echo "Compile failed, synthetic only" >> "$LOG"; }

if [ -f "$WORKDIR/harmless_kernel_module.ko" ]; then
    insmod "$WORKDIR/harmless_kernel_module.ko" 2>>"$LOG" && echo "Real path: insmod fired" >> "$LOG" || true
    sleep 1
    rmmod harmless_kernel_module 2>/dev/null || true
    echo "Real path succeeded" >> "$LOG"
fi

echo "=== REP-01 complete ===" | tee -a "$LOG"
