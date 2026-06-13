#!/usr/bin/env bash
set -euo pipefail

echo "=== Installing Sentinel components ==="

mkdir -p /var/sentinel /tmp/secapp/attacks /tmp/secapp/tools

sqlite3 /var/sentinel/events.db "
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
CREATE TABLE IF NOT EXISTS events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_type TEXT    NOT NULL,
    score      REAL    NOT NULL DEFAULT 0,
    state      TEXT    NOT NULL DEFAULT 'WATCH',
    timestamp  TEXT    NOT NULL DEFAULT (datetime('now')),
    pid        INTEGER,
    comm       TEXT,
    detail     TEXT
);
CREATE INDEX IF NOT EXISTS idx_alert_type ON events(alert_type);
CREATE INDEX IF NOT EXISTS idx_state      ON events(state);
CREATE INDEX IF NOT EXISTS idx_timestamp  ON events(timestamp);
CREATE TABLE IF NOT EXISTS quarantine_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id    INTEGER NOT NULL,
    pid         INTEGER,
    comm        TEXT,
    prior_state TEXT,
    actions     TEXT,
    success     INTEGER DEFAULT 0,
    error       TEXT,
    latency_ms  REAL,
    timestamp   TEXT DEFAULT (datetime('now'))
);
"
echo "Database schema created."

echo "+cpu +memory" > /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null || true

cat > /var/sentinel/synthetic_injector.sh << 'INJEOF'
#!/usr/bin/env bash
DB=/var/sentinel/events.db
LOG=/var/sentinel/sentinel.log
echo "[injector] $(date -u +%T) started" >> "$LOG"

while true; do
    for trigger in /tmp/sentinel_trigger_*; do
        [ -f "$trigger" ] || continue
        ALERT_TYPE="${trigger##*sentinel_trigger_}"
        read -r score state pid comm <<< "$(cat "$trigger")"
        TS=$(date -u '+%Y-%m-%dT%H:%M:%S.000Z')
        echo "[injector] $TS INSERT alert=$ALERT_TYPE score=$score state=$state pid=$pid comm=$comm" >> "$LOG"
        sqlite3 "$DB" "INSERT INTO events \
            (alert_type,score,state,pid,comm,timestamp,detail) VALUES \
            ('$ALERT_TYPE',$score,'$state',$pid,'$comm','$TS', \
            json_object('alert_type','$ALERT_TYPE','score',$score,'state','$state','pid',$pid,'comm','$comm'));" \
            2>>"$LOG" || echo "[injector] ERROR sqlite3 failed" >> "$LOG"
        rm -f "$trigger"
    done
    sleep 0.5
done
INJEOF
chmod +x /var/sentinel/synthetic_injector.sh

cat > /etc/systemd/system/sentinel-synthetic.service << 'SVCEOF'
[Unit]
Description=Sentinel Synthetic Event Injector
After=local-fs.target

[Service]
Type=simple
User=root
ExecStart=/var/sentinel/synthetic_injector.sh
Restart=always
RestartSec=2s
StandardOutput=append:/var/sentinel/sentinel.log
StandardError=append:/var/sentinel/sentinel.log

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
# systemctl enable sentinel-synthetic
# systemctl start sentinel-synthetic
# systemctl is-active sentinel-synthetic && echo "Synthetic injector: RUNNING" || echo "Synthetic injector: FAILED"

# echo "=== Sentinel install complete ==="
