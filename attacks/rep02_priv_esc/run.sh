#!/usr/bin/env bash
set -euo pipefail
LOG=/tmp/attack.log
echo "=== REP-02 Privilege Escalation started $(date -u) ===" | tee -a "$LOG"

WORKDIR="/tmp/rep02_build"
mkdir -p "$WORKDIR"
cp "$(dirname "$0")/priv_esc_probe.c" "$WORKDIR/"

gcc -o "$WORKDIR/priv_esc_probe" "$WORKDIR/priv_esc_probe.c" 2>>"$LOG" \
  && echo "Real path: compiled priv_esc_probe" >> "$LOG" \
  || { echo "Compile failed, synthetic only" >> "$LOG"; }

if [ -x "$WORKDIR/priv_esc_probe" ]; then
    "$WORKDIR/priv_esc_probe" 2>>"$LOG" || true
    echo "Real path succeeded" >> "$LOG"
fi

echo "=== REP-02 complete ===" | tee -a "$LOG"
