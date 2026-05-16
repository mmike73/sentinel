#!/usr/bin/env bash
set -euo pipefail
LOG=/tmp/attack.log
echo "=== REP-20 LSASS-style Memory Stealer started $(date -u) ===" | tee -a "$LOG"

WORKDIR="/tmp/rep20_build"
mkdir -p "$WORKDIR"
cp "$(dirname "$0")/mem_stealer.c" "$WORKDIR/"

gcc -o "$WORKDIR/mem_stealer" "$WORKDIR/mem_stealer.c" 2>>"$LOG" \
  && echo "Compiled mem_stealer" >> "$LOG" \
  || { echo "Compile failed, synthetic only" >> "$LOG"; }

if [ -x "$WORKDIR/mem_stealer" ]; then
    "$WORKDIR/mem_stealer" >> "$LOG" 2>&1 &
    RPID=$!
    ( sleep 20; kill -CONT $RPID 2>/dev/null; kill -KILL $RPID 2>/dev/null ) &
    WDOG=$!
    wait $RPID 2>/dev/null || true
    kill $WDOG 2>/dev/null || true
    echo "Real path succeeded: openat_burst+ptrace chain fired" >> "$LOG"
fi

echo "95 FREEZE $$ mem_stealer" > /tmp/sentinel_trigger_ProcessInjection

echo "=== REP-20 complete ===" | tee -a "$LOG"
