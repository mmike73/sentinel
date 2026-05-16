#!/usr/bin/env bash
set -euo pipefail
LOG=/tmp/attack.log
echo "=== REP-06 Cron Persistence started $(date -u) ===" | tee -a "$LOG"

echo "# sentinel_rep06 test — harmless" > /etc/cron.d/sentinel_test_persistence 2>>"$LOG" || true
echo "#!/bin/sh" > /etc/cron.daily/sentinel_rep06_test 2>>"$LOG" || true
chmod +x /etc/cron.daily/sentinel_rep06_test 2>/dev/null || true
echo "Real path: openat+write to /etc/cron.d/ fired" >> "$LOG"

sleep 0.5

rm -f /etc/cron.d/sentinel_test_persistence /etc/cron.daily/sentinel_rep06_test 2>/dev/null || true

echo "=== REP-06 complete ===" | tee -a "$LOG"
