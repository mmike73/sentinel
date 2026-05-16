Vagrant.configure("2") do |config|

  config.vm.box = "generic/debian12"
  config.vm.network "private_network", type: "dhcp"
  config.vm.synced_folder ".", "/vagrant", disabled: true

  config.vm.provider "libvirt" do |lv|
    lv.driver = "kvm"
    lv.memory = 2048
    lv.cpus   = 2
    lv.nested = false
  end

  config.vm.provision "shell", inline: <<-SHELL
    set -euo pipefail
    export DEBIAN_FRONTEND=noninteractive

    echo "=== Sentinel provisioner starting ==="

    apt-get update -qq

    apt-get install -y -qq \\
        build-essential gcc make \\
        linux-image-amd64 linux-headers-amd64 \\
        clang llvm libbpf-dev libelf-dev libcap2-bin \\
        bpftool sqlite3 netcat-openbsd apache2 \\
        inotify-tools strace lsof jq curl wget git \\
        python3 python3-venv python3-pip \\
        nftables

    sed -i 's/^#*MaxSessions.*/MaxSessions 10/'        /etc/ssh/sshd_config
    sed -i 's/^#*MaxStartups.*/MaxStartups 10:30:100/' /etc/ssh/sshd_config

    grep -q '^MaxSessions'  /etc/ssh/sshd_config || echo 'MaxSessions 10'        >> /etc/ssh/sshd_config
    grep -q '^MaxStartups'  /etc/ssh/sshd_config || echo 'MaxStartups 10:30:100' >> /etc/ssh/sshd_config
    systemctl reload ssh

    mkdir -p /tmp/secapp/attacks /tmp/secapp/tools

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
    );"

    echo "+cpu +memory" > /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null || true

    cat > /etc/rc.local << 'RCEOF'
#!/bin/sh
echo "+cpu +memory" > /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null || true
exit 0
RCEOF
    chmod +x /etc/rc.local

    echo "=== Provisioner complete ==="
    echo "    Kernel upgraded — run: vagrant reload"
    echo "    Then:            vagrant snapshot save clean"
  SHELL

end
