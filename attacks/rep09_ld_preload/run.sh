#!/usr/bin/env bash
set -euo pipefail
LOG=/tmp/attack.log
echo "=== REP-09 LD_PRELOAD started $(date -u) ===" | tee -a "$LOG"

WORKDIR="/tmp/rep09_build"
mkdir -p "$WORKDIR"
cp "$(dirname "$0")/fake_lib.c" "$WORKDIR/"

gcc -fPIC -shared -o "$WORKDIR/fake_lib.so" "$WORKDIR/fake_lib.c" -ldl 2>>"$LOG" \
  && echo "Real path: compiled fake_lib.so" >> "$LOG" \
  || echo "Compile failed, synthetic only" >> "$LOG"

if [ -f "$WORKDIR/fake_lib.so" ]; then
    LD_PRELOAD="$WORKDIR/fake_lib.so" ls /tmp/ >/dev/null 2>>"$LOG" || true
    LD_PRELOAD="$WORKDIR/fake_lib.so" id >/dev/null 2>>"$LOG" || true
    echo "Real path: execve+openat with LD_PRELOAD fired" >> "$LOG"
    rm -f "$WORKDIR/fake_lib.so"
fi

echo "=== REP-09 complete ===" | tee -a "$LOG"
