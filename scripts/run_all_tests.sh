#!/usr/bin/env bash
set -euo pipefail

RESULTS_BASE="results/full_run_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$RESULTS_BASE"

PASS=0
FAIL=0

run_attack() {
    local dir="$1"
    local expected_alert="$2"
    local expected_state="$3"
    local name
    name="$(basename "$dir")"

    echo ""
    echo "══════════════════════════════════════"
    echo "Testing: $name"
    echo "══════════════════════════════════════"

    RUN_DIR="$RESULTS_BASE/$name"
    mkdir -p "$RUN_DIR"

    vagrant scp "$dir/" ":/tmp/${name}/" 2>&1 | grep -v WARNING
    vagrant ssh -- "sudo bash /tmp/${name}/run.sh" 2>&1 | grep -v WARNING | tee "$RUN_DIR/attack.log" || true

    sleep 3

    vagrant ssh -- "sqlite3 /var/sentinel/events.db 'PRAGMA wal_checkpoint(TRUNCATE);'" 2>&1 | grep -v WARNING || true
    vagrant scp ":/var/sentinel/events.db" "$RUN_DIR/events.db" 2>&1 | grep -v WARNING || true

    COUNT=$(sqlite3 "$RUN_DIR/events.db" \
        "SELECT COUNT(*) FROM events WHERE alert_type='$expected_alert';" 2>/dev/null || echo "0")

    if [ "$COUNT" -gt 0 ]; then
        STATE=$(sqlite3 "$RUN_DIR/events.db" \
            "SELECT state FROM events WHERE alert_type='$expected_alert' ORDER BY id DESC LIMIT 1;" 2>/dev/null || echo "")
        echo "PASS: $name — alert=$expected_alert state=$STATE (expected=$expected_state) events=$COUNT"
        PASS=$((PASS+1))
    else
        echo "FAIL: $name — no '$expected_alert' events in DB"
        FAIL=$((FAIL+1))
    fi
}

echo "=== Sentinel Integration Tests ==="
echo "Results: $RESULTS_BASE"

run_attack "attacks/diamorphine_rootkit"  "HiddenPID"              "FREEZE"
run_attack "attacks/rep02_priv_esc"       "PrivilegeEscalation"    "WARN"
run_attack "attacks/rep04_netcat_exfil"   "NetworkAnomaly"         "THROTTLE"
run_attack "attacks/rep05_webshell"       "ParentChildAnomaly"     "WARN"
run_attack "attacks/rep06_cron_persist"   "LSMFileWrite"           "WARN"
run_attack "attacks/rep07_mmap_rwx"       "MemoryInjection"        "WARN"
run_attack "attacks/rep08_log_tamper"     "LogTamper"              "WARN"
run_attack "attacks/rep09_ld_preload"     "LSMFileWrite"           "WARN"
run_attack "attacks/rep10_fork_bomb"      "SyscallAnomaly"         "WATCH"
run_attack "attacks/rep11_ptrace"         "ProcessInjection"       "FREEZE"
run_attack "attacks/rep12_ssh_brute"      "NetworkAnomaly"         "THROTTLE"

echo ""
echo "══════════════════════════════════════"
echo "RESULTS: PASS=$PASS  FAIL=$FAIL  TOTAL=$((PASS+FAIL))"
echo "══════════════════════════════════════"
