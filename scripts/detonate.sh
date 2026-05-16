#!/usr/bin/env bash
set -euo pipefail

ATTACK="${1:-}"
if [ -z "$ATTACK" ]; then
    echo "Usage: $0 <attack_dir> [run_id]"
    echo "Example: $0 attacks/rep06_cron_persist"
    exit 1
fi

ATTACK_NAME="$(basename "$ATTACK")"
RUN_ID="${2:-${ATTACK_NAME}_$(date +%Y%m%d_%H%M%S)}"
RESULTS_DIR="results/$RUN_ID"
mkdir -p "$RESULTS_DIR"

echo "=== Detonating $ATTACK_NAME (run: $RUN_ID) ==="

echo "[1/5] Uploading attack files..."
vagrant scp "$ATTACK/" ":/tmp/${ATTACK_NAME}/" 2>&1 | grep -v WARNING

echo "[2/5] Checking injector..."
vagrant ssh -- "sudo systemctl is-active sentinel-synthetic || sudo systemctl start sentinel-synthetic" 2>&1 | grep -v WARNING

echo "[3/5] Detonating..."
vagrant ssh -- "sudo bash /tmp/${ATTACK_NAME}/run.sh" 2>&1 | grep -v WARNING | tee "$RESULTS_DIR/attack_output.txt" || true

echo "[4/5] Waiting for events (3s)..."
sleep 3

echo "[5/5] Collecting results..."
vagrant ssh -- "sqlite3 /var/sentinel/events.db 'PRAGMA wal_checkpoint(TRUNCATE);'" 2>&1 | grep -v WARNING || true
vagrant scp ":/var/sentinel/events.db"  "$RESULTS_DIR/events.db"  2>&1 | grep -v WARNING || true
vagrant scp ":/var/sentinel/sentinel.log" "$RESULTS_DIR/sentinel.log" 2>&1 | grep -v WARNING || true

echo ""
echo "=== Results for $ATTACK_NAME ==="
sqlite3 "$RESULTS_DIR/events.db" ".headers on" ".mode column" \
    "SELECT id,alert_type,ROUND(score,1) score,state,comm,timestamp FROM events ORDER BY id DESC LIMIT 10;" 2>/dev/null || echo "(no events)"

echo ""
echo "Results saved to: $RESULTS_DIR/"
