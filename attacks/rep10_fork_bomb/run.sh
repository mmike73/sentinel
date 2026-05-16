#!/usr/bin/env bash
set -euo pipefail
LOG=/tmp/attack.log
echo "=== REP-10 Fork Bomb started $(date -u) ===" | tee -a "$LOG"

for i in $(seq 1 200); do
    (exit 0) &
done
wait
echo "Real path: clone×200 fired" >> "$LOG"

echo "=== REP-10 complete ===" | tee -a "$LOG"
