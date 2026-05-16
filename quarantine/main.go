package main

import (
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type unfreezeEntry struct {
	pid      int
	cgPath   string
	deadline time.Time
}

var (
	unfreezeMu      sync.Mutex
	pendingUnfreeze = make(map[int]*unfreezeEntry)
	unfreezeAfter   time.Duration
)

func scheduleUnfreeze(pid int, cgPath string, timeout time.Duration) {
	unfreezeMu.Lock()
	defer unfreezeMu.Unlock()
	pendingUnfreeze[pid] = &unfreezeEntry{
		pid:      pid,
		cgPath:   cgPath,
		deadline: time.Now().Add(timeout),
	}
	log.Printf("scheduled unfreeze: PID %d in %.0fs", pid, timeout.Seconds())
}

func doUnfreeze(e *unfreezeEntry) {
	freezePath := filepath.Join(e.cgPath, "cgroup.freeze")
	if err := os.WriteFile(freezePath, []byte("0"), 0644); err != nil {
		log.Printf("unfreeze cgroup PID %d: %v", e.pid, err)
	}
	if err := syscall.Kill(e.pid, syscall.SIGCONT); err != nil {
		log.Printf("SIGCONT PID %d: %v (may have exited)", e.pid, err)
	}
	os.WriteFile(filepath.Join(e.cgPath, "cgroup.procs"), []byte(""), 0644)
	os.Remove(e.cgPath)
	cleanupNetworkIsolation()
	log.Printf("unfroze PID %d", e.pid)
}

func unfreezeWatcher() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		unfreezeMu.Lock()
		for pid, entry := range pendingUnfreeze {
			if now.After(entry.deadline) {
				delete(pendingUnfreeze, pid)
				go doUnfreeze(entry)
			}
		}
		unfreezeMu.Unlock()
	}
}

func createCgroupBase(pid int) (string, error) {
	path := fmt.Sprintf("/sys/fs/cgroup/sentinel/quarantine_%d", pid)
	if err := os.MkdirAll(path, 0755); err != nil {
		return "", fmt.Errorf("mkdir cgroup: %w", err)
	}
	if err := os.WriteFile(filepath.Join(path, "cgroup.procs"),
		[]byte(strconv.Itoa(pid)), 0644); err != nil {
		return "", fmt.Errorf("write cgroup.procs: %w", err)
	}
	return path, nil
}

func createCgroupThrottle(pid int, quota, period string) (string, error) {
	path, err := createCgroupBase(pid)
	if err != nil {
		return "", err
	}
	os.WriteFile(filepath.Join(path, "cpu.max"), []byte(quota+" "+period), 0644)
	return path, nil
}

func createCgroupIsolate(pid int, memBytes int64) (string, error) {
	path, err := createCgroupBase(pid)
	if err != nil {
		return "", err
	}
	os.WriteFile(filepath.Join(path, "memory.max"),
		[]byte(strconv.FormatInt(memBytes, 10)), 0644)
	return path, nil
}

func isolateNetwork(pid int) error {
	cgPath := fmt.Sprintf("/sys/fs/cgroup/sentinel/quarantine_%d", pid)
	var st syscall.Stat_t
	if err := syscall.Stat(cgPath, &st); err != nil {
		return fmt.Errorf("stat cgroup %s: %w (process must be in cgroup first)", cgPath, err)
	}
	cgID := fmt.Sprintf("%d", st.Ino)

	exec.Command("nft", "add", "table", "inet", "sentinel_quarantine").Run()
	exec.Command("nft", "add", "chain", "inet", "sentinel_quarantine", "output",
		"{ type filter hook output priority 0; policy accept; }").Run()
	exec.Command("nft", "add", "chain", "inet", "sentinel_quarantine", "input",
		"{ type filter hook input priority 0; policy accept; }").Run()

	if err := exec.Command("nft", "add", "rule", "inet", "sentinel_quarantine",
		"output", "meta", "cgroup", cgID, "drop").Run(); err != nil {
		return fmt.Errorf("nft output drop rule for cgroup %s: %w", cgID, err)
	}
	if err := exec.Command("nft", "add", "rule", "inet", "sentinel_quarantine",
		"input", "meta", "cgroup", cgID, "drop").Run(); err != nil {
		return fmt.Errorf("nft input drop rule for cgroup %s: %w", cgID, err)
	}
	log.Printf("network isolated: PID %d cgroup inode=%s", pid, cgID)
	return nil
}

func cleanupNetworkIsolation() {
	exec.Command("nft", "flush", "chain", "inet", "sentinel_quarantine", "output").Run()
	exec.Command("nft", "flush", "chain", "inet", "sentinel_quarantine", "input").Run()
}

func freezeProcess(pid int, cgPath string) error {
	syscall.Kill(pid, syscall.SIGSTOP)
	freezePath := filepath.Join(cgPath, "cgroup.freeze")
	os.WriteFile(freezePath, []byte("1"), 0644)
	return nil
}

type Event struct {
	ID        int64   `db:"id"`
	AlertType string  `db:"alert_type"`
	Score     float64 `db:"score"`
	State     string  `db:"state"`
	PID       int     `db:"pid"`
	Comm      string  `db:"comm"`
}

func handleEvent(db *sql.DB, ev Event) {
	start := time.Now()
	var actions []string
	var errStr string

	switch ev.State {

	case "FREEZE":
		cgPath, err := createCgroupBase(ev.PID)
		if err != nil {
			log.Printf("cgroup for PID %d: %v", ev.PID, err)
			errStr = err.Error()
		} else {
			actions = append(actions, "cgroup_created")
		}
		if err := freezeProcess(ev.PID, cgPath); err != nil {
			log.Printf("freeze PID %d: %v", ev.PID, err)
			errStr = err.Error()
		} else {
			actions = append(actions, "sigstop_sent", "cgroup_frozen")
			log.Printf("FREEZE: PID %d (%s) stopped", ev.PID, ev.Comm)
			if unfreezeAfter > 0 {
				scheduleUnfreeze(ev.PID, cgPath, unfreezeAfter)
				actions = append(actions, fmt.Sprintf("unfreeze_in_%.0fs", unfreezeAfter.Seconds()))
			}
		}

	case "ISOLATE":
		cgPath, err := createCgroupIsolate(ev.PID, 268435456)
		if err != nil {
			log.Printf("cgroup for PID %d: %v", ev.PID, err)
			errStr = err.Error()
		} else {
			actions = append(actions, "cgroup_created", "memory_limit_256mb")
			log.Printf("cgroup created: %s", cgPath)
		}
		if err := isolateNetwork(ev.PID); err != nil {
			log.Printf("net isolate PID %d: %v", ev.PID, err)
			errStr = err.Error()
		} else {
			actions = append(actions, "network_isolated")
			log.Printf("ISOLATE: PID %d (%s) network blocked", ev.PID, ev.Comm)
		}

	case "THROTTLE":
		if _, err := createCgroupThrottle(ev.PID, "10000", "100000"); err != nil {
			log.Printf("throttle cgroup PID %d: %v", ev.PID, err)
			errStr = err.Error()
		} else {
			actions = append(actions, "cgroup_created", "cpu_throttled_10pct")
			log.Printf("THROTTLE: PID %d (%s) CPU limited to 10%%", ev.PID, ev.Comm)
		}
	}

	latencyMs := float64(time.Since(start).Microseconds()) / 1000.0
	actJSON, _ := json.Marshal(actions)
	success := 0
	if len(actions) > 0 {
		success = 1
	}

	db.Exec(`INSERT INTO quarantine_log
		(event_id,pid,comm,prior_state,actions,success,error,latency_ms)
		VALUES (?,?,?,?,?,?,?,?)`,
		ev.ID, ev.PID, ev.Comm, ev.State,
		string(actJSON), success, errStr, latencyMs)

	log.Printf("quarantine: event=%d pid=%d state=%s actions=%v latency=%.1fms",
		ev.ID, ev.PID, ev.State, actions, latencyMs)
}

func validateCgroupV2() {
	const cgroup2Magic = 0x63677270
	var st syscall.Statfs_t
	if err := syscall.Statfs("/sys/fs/cgroup", &st); err != nil {
		log.Fatalf("FATAL: cannot stat /sys/fs/cgroup: %v", err)
	}
	if st.Type != cgroup2Magic {
		log.Fatalf("FATAL: /sys/fs/cgroup is not cgroup v2 (magic=0x%x, want 0x%x). "+
			"Add 'systemd.unified_cgroup_hierarchy=1' to GRUB_CMDLINE_LINUX_DEFAULT "+
			"and reboot, or use a Debian 12+ VM which enables cgroup v2 by default.",
			st.Type, cgroup2Magic)
	}
	data, err := os.ReadFile("/sys/fs/cgroup/cgroup.controllers")
	if err != nil {
		log.Fatalf("FATAL: cannot read cgroup.controllers: %v", err)
	}
	for _, ctrl := range []string{"cpu", "memory"} {
		if !strings.Contains(string(data), ctrl) {
			log.Fatalf("FATAL: cgroup v2 controller %q not available (have: %s). "+
				"Enable with: echo '+%s' | sudo tee /sys/fs/cgroup/cgroup.subtree_control",
				ctrl, strings.TrimSpace(string(data)), ctrl)
		}
	}
	log.Printf("cgroup v2 validated: cpu and memory controllers available")
}

func main() {
	dbPath         := flag.String("db",             "/var/sentinel/events.db", "SQLite DB path")
	pollMs         := flag.Int("poll-ms",           500,                       "poll interval ms")
	unfreezeAfterF := flag.Duration("unfreeze-after", 5*time.Minute,
		"auto-unfreeze FREEZE processes after this duration (0 = never)")
	flag.Parse()
	unfreezeAfter = *unfreezeAfterF

	validateCgroupV2()

	if unfreezeAfter > 0 {
		go unfreezeWatcher()
		log.Printf("auto-unfreeze enabled: processes unfrozen after %s", unfreezeAfter)
	}

	if err := os.MkdirAll("/sys/fs/cgroup/sentinel", 0755); err != nil {
		log.Printf("WARNING: could not create sentinel cgroup root: %v", err)
	}
	os.WriteFile("/sys/fs/cgroup/sentinel/cgroup.subtree_control",
		[]byte("+cpu +memory"), 0644)

	db, err := sql.Open("sqlite3", *dbPath+"?_journal_mode=WAL&_synchronous=NORMAL")
	if err != nil {
		log.Fatalf("sql.Open: %v", err)
	}
	defer db.Close()

	var lastID int64
	if err := db.QueryRow("SELECT COALESCE(MAX(id),0) FROM events").Scan(&lastID); err != nil {
		log.Printf("WARNING: could not get max event ID: %v", err)
	}
	log.Printf("Quarantine manager started, watching events after ID %d", lastID)

	for {
		rows, err := db.Query(`
			SELECT id, alert_type, score, state, COALESCE(pid,0), COALESCE(comm,'')
			FROM events
			WHERE id > ? AND state IN ('ISOLATE','FREEZE','THROTTLE')
			ORDER BY id ASC`, lastID)
		if err != nil {
			log.Printf("query error: %v", err)
			time.Sleep(time.Duration(*pollMs) * time.Millisecond)
			continue
		}
		for rows.Next() {
			var ev Event
			if err := rows.Scan(&ev.ID, &ev.AlertType, &ev.Score,
				&ev.State, &ev.PID, &ev.Comm); err != nil {
				log.Printf("scan: %v", err)
				continue
			}
			lastID = ev.ID
			handleEvent(db, ev)
		}
		rows.Close()
		time.Sleep(time.Duration(*pollMs) * time.Millisecond)
	}
}
