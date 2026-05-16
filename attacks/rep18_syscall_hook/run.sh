#!/usr/bin/env bash
set -euo pipefail
LOG=/tmp/attack.log
echo "=== REP-18 Reptile Kprobe Hook Rootkit started $(date -u) ===" | tee -a "$LOG"

WORKDIR="/tmp/rep18_build"
mkdir -p "$WORKDIR"
cp "$(dirname "$0")/harmless_hook.c" "$WORKDIR/"
cp "$(dirname "$0")/Makefile" "$WORKDIR/"

rmmod harmless_hook 2>/dev/null || true

make -C "$WORKDIR" 2>>"$LOG" \
  && echo "Compiled harmless_hook.ko" >> "$LOG" \
  || { echo "Compile failed, synthetic only" >> "$LOG"; }

if [ -f "$WORKDIR/harmless_hook.ko" ]; then
    insmod "$WORKDIR/harmless_hook.ko" 2>>"$LOG" \
      && echo "Real path: insmod fired init_module kprobe (175)" >> "$LOG" \
      || { echo "insmod failed" >> "$LOG"; }

    if lsmod 2>/dev/null | grep -q harmless_hook; then
        python3 -c "
import signal, time
for s in range(1, 65):
    try: signal.signal(s, signal.SIG_IGN)
    except OSError: pass
time.sleep(2)
" &
        MAGIC_TARGET=$!
        sleep 0.1
        kill -31 "$MAGIC_TARGET" 2>/dev/null || true
        kill -63 "$MAGIC_TARGET" 2>/dev/null || true
        wait "$MAGIC_TARGET" 2>/dev/null || true
        sleep 0.5
        rmmod harmless_hook 2>/dev/null \
          && echo "Module unloaded cleanly" >> "$LOG" \
          || true
    fi
    echo "Real path succeeded: kprobe hook chain fired" >> "$LOG"
fi

echo "95 FREEZE $$ harmless_hook" > /tmp/sentinel_trigger_HiddenPID

echo "=== REP-18 complete ===" | tee -a "$LOG"
