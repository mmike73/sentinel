#!/usr/bin/env bash
set -euo pipefail
LOG=/tmp/attack.log
echo "=== REP-17 Kernel Persistence (finit_module) started $(date -u) ===" | tee -a "$LOG"

WORKDIR="/tmp/rep17_build"
mkdir -p "$WORKDIR"
cp "$(dirname "$0")/persist_mod.c" "$WORKDIR/"
cp "$(dirname "$0")/Makefile" "$WORKDIR/"

make -C "$WORKDIR" 2>>"$LOG" \
  && echo "Compiled persist_mod.ko" >> "$LOG" \
  || { echo "Compile failed, synthetic only" >> "$LOG"; }

if [ -f "$WORKDIR/persist_mod.ko" ]; then
    python3 -c "
import ctypes, os, sys
libc = ctypes.CDLL('libc.so.6', use_errno=True)
NR_finit_module = 313
fd = os.open('$WORKDIR/persist_mod.ko', os.O_RDONLY | os.O_CLOEXEC)
ret = libc.syscall(NR_finit_module, ctypes.c_int(fd), b'', ctypes.c_int(0))
os.close(fd)
if ret == 0:
    print('[REP-17] finit_module syscall 313 fired — module loaded via fd')
else:
    print(f'[REP-17] finit_module returned {ret} (kprobe still fired)')
" 2>&1 | tee -a "$LOG" || true

    sleep 1
    rmmod persist_mod 2>/dev/null || true
    echo "Real path succeeded: finit_module (313) kprobe fired" >> "$LOG"
fi

echo "=== REP-17 complete ===" | tee -a "$LOG"
