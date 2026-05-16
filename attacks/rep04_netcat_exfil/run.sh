#!/usr/bin/env bash
set -euo pipefail
LOG=/tmp/attack.log
echo "=== REP-04 Netcat Exfil started $(date -u) ===" | tee -a "$LOG"

WORKDIR="/tmp/rep04_build"
mkdir -p "$WORKDIR"
cp "$(dirname "$0")/netcat_exfil.c" "$WORKDIR/"

gcc -o "$WORKDIR/netcat_exfil" "$WORKDIR/netcat_exfil.c" 2>>"$LOG" \
  && echo "Compiled netcat_exfil" >> "$LOG" \
  || echo "Compile failed, synthetic only" >> "$LOG"

if [ -x "$WORKDIR/netcat_exfil" ]; then
    "$WORKDIR/netcat_exfil" 2>&1 | tee -a "$LOG" || true
    echo "Real path: burst socket+connect from single PID fired" >> "$LOG"
else
    echo "Compile failed — no real path available" >> "$LOG"
fi

echo "=== REP-04 complete ===" | tee -a "$LOG"
