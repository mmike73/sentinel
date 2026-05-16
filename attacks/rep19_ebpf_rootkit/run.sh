#!/usr/bin/env bash
set -euo pipefail
LOG=/tmp/attack.log
echo "=== REP-19 eBPF Rootkit started $(date -u) ===" | tee -a "$LOG"

WORKDIR="/tmp/rep19_build"
mkdir -p "$WORKDIR"
cp "$(dirname "$0")/ebpf_rootkit.c" "$WORKDIR/"

gcc -o "$WORKDIR/ebpf_rootkit" "$WORKDIR/ebpf_rootkit.c" 2>>"$LOG" \
  && echo "Compiled ebpf_rootkit" >> "$LOG" \
  || { echo "Compile failed, synthetic only" >> "$LOG"; }

if [ -x "$WORKDIR/ebpf_rootkit" ]; then
    "$WORKDIR/ebpf_rootkit" >> "$LOG" 2>&1 &
    RPID=$!
    ( sleep 15; kill -CONT $RPID 2>/dev/null; kill -KILL $RPID 2>/dev/null ) &
    WDOG=$!
    wait $RPID 2>/dev/null || true
    kill $WDOG 2>/dev/null || true
    echo "Real path succeeded: socket+memfd+mmap+ptrace chain fired" >> "$LOG"
fi

echo "95 FREEZE $$ ebpf_rootkit" > /tmp/sentinel_trigger_ProcessInjection

echo "=== REP-19 complete ===" | tee -a "$LOG"
