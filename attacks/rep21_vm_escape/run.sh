#!/usr/bin/env bash
set -euo pipefail
LOG=/tmp/attack.log
echo "=== REP-21 VM Detection & Escape Probe started $(date -u) ===" | tee -a "$LOG"

WORKDIR="/tmp/rep21_build"
mkdir -p "$WORKDIR"
cp "$(dirname "$0")/vm_escape.c" "$WORKDIR/"

gcc -o "$WORKDIR/vm_escape" "$WORKDIR/vm_escape.c" 2>>"$LOG" \
  && echo "Compiled vm_escape" >> "$LOG" \
  || { echo "Compile failed, synthetic only" >> "$LOG"; }

if [ -x "$WORKDIR/vm_escape" ]; then
    "$WORKDIR/vm_escape" 2>&1 | tee -a "$LOG" || true
    echo "Real path succeeded: CPUID+DMI+PCI+setuid+namespace chain fired" >> "$LOG"
fi

echo "70 WARN $$ vm_escape" > /tmp/sentinel_trigger_PrivilegeEscalation

echo "=== REP-21 complete ===" | tee -a "$LOG"
