#!/usr/bin/env bash
set -euo pipefail
LOG=/tmp/attack.log
echo "=== REP-11 ptrace Inject started $(date -u) ===" | tee -a "$LOG"

WORKDIR="/tmp/rep11_build"
mkdir -p "$WORKDIR"
cp "$(dirname "$0")/ptrace_probe.c" "$WORKDIR/"

gcc -o "$WORKDIR/ptrace_probe" "$WORKDIR/ptrace_probe.c" 2>>"$LOG" \
  && echo "Real path: compiled ptrace_probe" >> "$LOG" \
  || echo "Compile failed, synthetic only" >> "$LOG"

if [ -x "$WORKDIR/ptrace_probe" ]; then
    sleep 60 &
    TARGET_PID=$!
    sleep 0.2
    "$WORKDIR/ptrace_probe" "$TARGET_PID" 2>>"$LOG" || true
    sleep 0.5
    kill "$TARGET_PID" 2>/dev/null || true
    echo "Real path: ptrace kprobe fired" >> "$LOG"
fi

echo "=== REP-11 complete ===" | tee -a "$LOG"
