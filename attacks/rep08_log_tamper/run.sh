#!/usr/bin/env bash
set -euo pipefail
LOG=/tmp/attack.log
echo "=== REP-08 Log Tamper started $(date -u) ===" | tee -a "$LOG"

cp /var/log/auth.log /var/log/auth.log.sentinel_backup 2>/dev/null || true
cp /var/log/syslog  /var/log/syslog.sentinel_backup  2>/dev/null || true

truncate -s 0 /var/log/auth.log 2>/dev/null || true
rm -f /var/log/syslog 2>/dev/null || true
[ -f /var/log/kern.log ] && mv /var/log/kern.log /var/log/kern.log.bak 2>/dev/null || true
echo "tampered" >> /var/log/dpkg.log 2>/dev/null || true
echo "Real path: write+unlinkat+renameat2 fired on /var/log/" >> "$LOG"

sleep 0.5

cp /var/log/auth.log.sentinel_backup /var/log/auth.log 2>/dev/null || true
cp /var/log/syslog.sentinel_backup /var/log/syslog   2>/dev/null || true
[ -f /var/log/kern.log.bak ] && mv /var/log/kern.log.bak /var/log/kern.log 2>/dev/null || true
rm -f /var/log/auth.log.sentinel_backup /var/log/syslog.sentinel_backup 2>/dev/null || true

echo "=== REP-08 complete ===" | tee -a "$LOG"
