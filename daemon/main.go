package main

import (
	"bytes"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	_ "github.com/mattn/go-sqlite3"
)

type bpfEvent struct {
	TsNs      uint64
	Pid       uint32
	Uid       uint32
	SyscallNr uint32
	Comm      [16]byte
	Fname     [128]byte
}

var SYSCALL_NAMES = map[uint32]string{
	1: "write", 9: "mmap", 10: "mprotect", 41: "socket",
	42: "connect", 49: "bind", 56: "clone", 59: "execve",
	62: "kill", 101: "ptrace", 105: "setuid",
	106: "setgid", 126: "capset", 175: "init_module",
	176: "delete_module", 257: "openat", 263: "unlinkat",
	313: "finit_module", 316: "renameat2", 322: "execveat",
}

var RISK_WEIGHTS = map[uint32]float64{
	1: 25, 9: 40, 10: 45, 41: 10, 42: 15, 49: 10,
	56: 5, 59: 50, 62: 5, 101: 75, 105: 70,
	106: 70, 126: 70, 175: 95, 176: 85,
	257: 5, 263: 5, 313: 95, 316: 5, 322: 20,
}

var ALERT_TYPES = map[uint32]string{
	175: "HiddenPID", 313: "HiddenPID", 176: "HiddenPID",
	105: "PrivilegeEscalation", 106: "PrivilegeEscalation", 126: "PrivilegeEscalation",
	41: "NetworkAnomaly", 42: "NetworkAnomaly", 49: "NetworkAnomaly",
	59: "ParentChildAnomaly", 322: "ParentChildAnomaly",
	257: "LSMFileWrite", 1: "LSMFileWrite",
	9: "MemoryInjection", 10: "MemoryInjection",
	263: "LogTamper", 316: "LogTamper",
	101: "ProcessInjection",
	56: "SyscallAnomaly", 62: "SyscallAnomaly",
}

type burstTracker struct {
	mu       sync.Mutex
	windows  map[uint64][]int64
	lastFire map[uint64]int64
}

func newBurstTracker() *burstTracker {
	return &burstTracker{
		windows:  make(map[uint64][]int64),
		lastFire: make(map[uint64]int64),
	}
}

func pidStartTime(pid uint32) uint64 {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0
	}
	s := string(data)
	rp := strings.LastIndex(s, ")")
	if rp < 0 {
		return 0
	}
	fields := strings.Fields(s[rp+2:])
	if len(fields) < 20 {
		return 0
	}
	v, _ := strconv.ParseUint(fields[19], 10, 64)
	return v
}

func burstKey(pid, nr uint32) uint64 {
	st := pidStartTime(pid)
	return (uint64(pid) << 32) | (uint64(nr) << 16) | (st & 0xFFFF)
}

func (b *burstTracker) check(pid, nr uint32,
	threshold int, windowNs, cooldownNs int64) (float64, string, bool) {

	k := burstKey(pid, nr)
	now := time.Now().UnixNano()
	cutoff := now - windowNs

	b.mu.Lock()
	defer b.mu.Unlock()

	ts := b.windows[k]
	pruned := ts[:0]
	for _, t := range ts {
		if t >= cutoff {
			pruned = append(pruned, t)
		}
	}
	pruned = append(pruned, now)
	b.windows[k] = pruned

	if len(pruned) < threshold {
		return 0, "", false
	}
	if last, ok := b.lastFire[k]; ok && now-last < cooldownNs {
		return 0, "", false
	}
	b.lastFire[k] = now

	switch nr {
	case 41, 42:
		return 75.0, "NetworkAnomaly", true
	case 56:
		return 35.0, "SyscallAnomaly", true
	case 257:
		return 60.0, "LSMFileWrite", true
	}
	return 0, "", false
}

func (b *burstTracker) prune() {
	cutoff := time.Now().Add(-60 * time.Second).UnixNano()
	b.mu.Lock()
	defer b.mu.Unlock()
	for k, ts := range b.windows {
		filtered := ts[:0]
		for _, t := range ts {
			if t >= cutoff {
				filtered = append(filtered, t)
			}
		}
		if len(filtered) == 0 {
			delete(b.windows, k)
			delete(b.lastFire, k)
		} else {
			b.windows[k] = filtered
		}
	}
}

func resolveFd(pid uint32, fdStr string) string {
	fd := strings.TrimPrefix(fdStr, "fd:")
	target, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", pid, fd))
	if err != nil {
		return ""
	}
	return target
}

func pathAlert(nr uint32, fname string) (score float64, aType string, ok bool) {
	if fname == "" {
		return
	}
	switch nr {
	case 1:
		if strings.HasPrefix(fname, "/var/log/") {
			return 50.0, "LogTamper", true
		}
		if strings.HasPrefix(fname, "/etc/cron") {
			return 50.0, "LSMFileWrite", true
		}
		if strings.HasPrefix(fname, "/etc/passwd") ||
			strings.HasPrefix(fname, "/etc/shadow") ||
			strings.HasPrefix(fname, "/etc/sudoers") {
			return 65.0, "PrivilegeEscalation", true
		}
	case 257:
		if strings.HasPrefix(fname, "/etc/cron") {
			return 50.0, "LSMFileWrite", true
		}
		if strings.HasSuffix(fname, ".so") &&
			(strings.HasPrefix(fname, "/tmp/") ||
				strings.HasPrefix(fname, "/dev/shm/") ||
				strings.HasPrefix(fname, "/run/")) {
			return 50.0, "LSMFileWrite", true
		}
	case 263, 316:
		if strings.HasPrefix(fname, "/var/log/") {
			return 50.0, "LogTamper", true
		}
	}
	return
}

func staticScore(nr uint32, uid uint32) float64 {
	w, ok := RISK_WEIGHTS[nr]
	if !ok {
		w = 5
	}
	if uid == 0 {
		w *= 1.3
	}
	return w
}

func scoreToState(score float64) string {
	switch {
	case score >= 95:
		return "FREEZE"
	case score >= 85:
		return "ISOLATE"
	case score >= 70:
		return "THROTTLE"
	case score >= 50:
		return "WARN"
	case score >= 30:
		return "WATCH"
	default:
		return "OK"
	}
}

func alertType(nr uint32) string {
	if a, ok := ALERT_TYPES[nr]; ok {
		return a
	}
	return "SyscallAnomaly"
}

func syscallName(nr uint32) string {
	if n, ok := SYSCALL_NAMES[nr]; ok {
		return n
	}
	return fmt.Sprintf("syscall_%d", nr)
}

func scorerWeight(nr uint32) float64 {
	w := RISK_WEIGHTS[nr]
	switch {
	case w >= 85:
		return 0.1
	case w >= 60:
		return 0.2
	case w >= 30:
		return 0.5
	default:
		return 0.7
	}
}

func callScorer(baseURL string, e bpfEvent, comm string) float64 {
	body, _ := json.Marshal(map[string]interface{}{
		"syscall_nr": e.SyscallNr, "uid": e.Uid,
		"pid": e.Pid, "comm": comm,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
	client := &http.Client{Timeout: 50 * time.Millisecond}
	resp, err := client.Post(baseURL+"/score", "application/json", bytes.NewReader(body))
	if err != nil {
		return -1
	}
	defer resp.Body.Close()
	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return -1
	}
	if ts, ok := result["threat_score"].(float64); ok {
		return ts
	}
	return -1
}

func main() {
	dbPath    := flag.String("db",         "/var/sentinel/events.db",    "SQLite DB path")
	objPath   := flag.String("obj",        "/var/sentinel/tracer.bpf.o", "eBPF object file")
	scorerURL := flag.String("scorer-url", "",                           "IF scorer URL (optional)")
	minScore  := flag.Float64("min-score", 30,                           "minimum score to write to DB")
	flag.Parse()

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("RemoveMemlock: %v", err)
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	spec, err := ebpf.LoadCollectionSpec(*objPath)
	if err != nil {
		log.Fatalf("LoadCollectionSpec %q: %v", *objPath, err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("NewCollection: %v", err)
	}
	defer coll.Close()

	pid := uint32(os.Getpid())
	one := uint8(1)
	if err := coll.Maps["pid_blacklist"].Put(&pid, &one); err != nil {
		log.Printf("WARNING: pid_blacklist: %v", err)
	}

	var links []link.Link
	for name, prog := range coll.Programs {
		if !strings.HasPrefix(name, "kp_") {
			continue
		}
		suffix := strings.TrimPrefix(name, "kp_")
		fnName := "__x64_sys_" + suffix
		l, err := link.Kprobe(fnName, prog, nil)
		if err != nil {
			log.Printf("WARNING: attach %s (%s): %v", name, fnName, err)
			continue
		}
		links = append(links, l)
	}
	defer func() {
		for _, l := range links {
			l.Close()
		}
	}()
	log.Printf("Attached %d kprobes", len(links))

	rb, err := ringbuf.NewReader(coll.Maps["events"])
	if err != nil {
		log.Fatalf("ringbuf.NewReader: %v", err)
	}
	defer rb.Close()

	db, err := sql.Open("sqlite3", *dbPath+"?_journal_mode=WAL&_synchronous=NORMAL&_busy_timeout=5000")
	if err != nil {
		log.Fatalf("sql.Open: %v", err)
	}
	defer db.Close()

	stmt, err := db.Prepare(`INSERT INTO events
		(alert_type,score,state,pid,comm,timestamp,detail)
		VALUES (?,?,?,?,?,datetime('now'),?)`)
	if err != nil {
		log.Fatalf("Prepare: %v", err)
	}
	defer stmt.Close()

	bursts := newBurstTracker()
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for range t.C {
			bursts.prune()
		}
	}()

	go func() {
		dropMap, ok := coll.Maps["drop_count"]
		if !ok {
			return
		}
		var lastTotal uint64
		t := time.NewTicker(10 * time.Second)
		defer t.Stop()
		for range t.C {
			var key uint32
			var perCPU []uint64
			if err := dropMap.Lookup(&key, &perCPU); err != nil {
				continue
			}
			var total uint64
			for _, v := range perCPU {
				total += v
			}
			if total > lastTotal {
				log.Printf("WARNING: ring buffer drops: +%d (total %d)",
					total-lastTotal, total)
				lastTotal = total
			}
		}
	}()

	enc := json.NewEncoder(os.Stdout)
	log.Println("Sentinel daemon running. Waiting for events...")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() { <-sig; rb.Close() }()

	for {
		record, err := rb.Read()
		if err != nil {
			break
		}

		var e bpfEvent
		if err := binary.Read(bytes.NewReader(record.RawSample),
			binary.LittleEndian, &e); err != nil {
			log.Printf("parse error: %v", err)
			continue
		}

		comm  := string(bytes.TrimRight(e.Comm[:], "\x00"))
		fname := string(bytes.TrimRight(e.Fname[:], "\x00"))
		nr    := e.SyscallNr

		if nr == 1 && strings.HasPrefix(fname, "fd:") {
			fname = resolveFd(e.Pid, fname)
		}

		var bScore float64
		var bType  string
		var isBurst bool
		switch nr {
		case 41, 42:
			bScore, bType, isBurst = bursts.check(e.Pid, nr, 5, 3e9, 10e9)
		case 56:
			bScore, bType, isBurst = bursts.check(e.Pid, nr, 20, 2e9, 10e9)
		case 257:
			bScore, bType, isBurst = bursts.check(e.Pid, nr, 8, 3e9, 10e9)
		}

		score := staticScore(nr, e.Uid)

		aType := alertType(nr)

		if isBurst {
			score = bScore
			aType = bType
		} else if pScore, pType, isPath := pathAlert(nr, fname); isPath {
			score = pScore
			aType = pType
		}

		if score < *minScore {
			continue
		}

		state   := scoreToState(score)
		sysName := syscallName(nr)

		detail, _ := json.Marshal(map[string]interface{}{
			"ts_ns": e.TsNs, "pid": e.Pid, "uid": e.Uid,
			"syscall_nr": nr, "syscall_name": sysName,
			"comm": comm, "fname": fname, "score": score, "state": state,
			"source": "kprobe",
		})

		var eventID int64
		if res, err := stmt.Exec(aType, score, state, e.Pid, comm, string(detail)); err != nil {
			log.Printf("DB insert error: %v", err)
		} else {
			eventID, _ = res.LastInsertId()
		}

		if *scorerURL != "" && score >= 10 && eventID > 0 {
			go func(eid int64, baseScore float64, snr uint32, ev bpfEvent, c string) {
				ifScore := callScorer(*scorerURL, ev, c)
				if ifScore < 0 {
					return
				}
				w := scorerWeight(snr)
				blended := (1-w)*baseScore + w*ifScore
				if floor := baseScore * 0.5; blended < floor {
					blended = floor
				}
				refinedState := scoreToState(blended)
				if refinedState == scoreToState(baseScore) && blended == baseScore {
					return
				}
				db.Exec("UPDATE events SET score=?, state=? WHERE id=?",
					blended, refinedState, eid)
				if refinedState != scoreToState(baseScore) {
					log.Printf("score refined: event=%d %.1f→%.1f %s→%s",
						eid, baseScore, blended, scoreToState(baseScore), refinedState)
				}
			}(eventID, score, nr, e, comm)
		}

		_ = enc.Encode(map[string]interface{}{
			"ts_ns": e.TsNs, "pid": e.Pid, "uid": e.Uid,
			"syscall_nr":   nr,
			"syscall_name": sysName,
			"comm":         comm,
			"fname":        fname,
			"alert_type":   aType,
			"score":        score,
			"state":        state,
			"source":       "kprobe",
		})
	}
	log.Println("Daemon shutdown")
}
