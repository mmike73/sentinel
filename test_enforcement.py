#!/usr/bin/env python3
"""
Enforcement verification test: starts a fresh Vagrant VM state, detonates a
benign target process for each action tier, and asserts the action was
actually applied (not just logged).

Checks:
  FREEZE  — process state=T (stopped) + cgroup.freeze=1
  THROTTLE — cgroup cpu.max="10000 100000" + measured CPU reduction ≥ 50 %
  ISOLATE — cgroup memory.max=268435456 + nftables drop rule by cgroup inode
"""

import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).parent
_TTY = sys.stdout.isatty()

def _c(code, t): return f"\033[{code}m{t}\033[0m" if _TTY else t
def ok(m):    print(f"  {_c('1;32','✓')} {m}", flush=True)
def fail(m):  print(f"  {_c('1;31','✗')} {m}", flush=True)
def info(m):  print(f"    {m}", flush=True)
def step(m):  print(f"\n{_c('1;36','▶')} {_c('1',m)}", flush=True)
def banner(m): print(f"\n{'═'*54}\n  {m}\n{'═'*54}", flush=True)

RESULTS: list[tuple[bool, str]] = []

def check(name: str, cond: bool, detail: str = "") -> bool:
    if cond:
        ok(f"{name}" + (f" — {detail}" if detail else ""))
    else:
        fail(f"{name}" + (f" — {detail}" if detail else ""))
    RESULTS.append((cond, name))
    return cond


def vm(cmd: str, *, check_rc: bool = True, timeout: int = 60) -> subprocess.CompletedProcess:
    r = subprocess.run(
        ["vagrant", "ssh", "--", cmd],
        capture_output=True, text=True, timeout=timeout, cwd=REPO,
    )
    if check_rc and r.returncode != 0:
        raise RuntimeError(f"VM command failed (rc={r.returncode}):\n  {cmd}\n  {r.stderr.strip()}")
    return r


def vmc(cmd: str, timeout: int = 45) -> str:
    return vm(cmd, check_rc=False, timeout=timeout).stdout.strip()


def vm_script(script: str, timeout: int = 45) -> str:
    """Run a bash script on the VM via stdin — no quoting/expansion surprises."""
    r = subprocess.run(
        ["vagrant", "ssh", "--", "sudo bash -s"],
        input=script,
        capture_output=True, text=True, timeout=timeout, cwd=REPO,
    )
    return r.stdout.strip()


def inject(alert_type: str, score: float, state: str, pid: int, comm: str) -> None:
    """Insert event directly into the DB — bypasses the synthetic injector."""
    vm_script(
        f"sqlite3 /var/sentinel/events.db \""
        f"INSERT INTO events (alert_type,score,state,pid,comm,timestamp,detail) "
        f"VALUES ('{alert_type}',{score},'{state}',{pid},'{comm}',datetime('now'),'{{}}');\""
    )
    time.sleep(3.0)


def start_process(shell_cmd: str) -> int:
    out = vm_script(f"{shell_cmd} </dev/null >/dev/null 2>&1 & echo $!")
    for line in reversed(out.splitlines()):
        s = line.strip()
        if s.isdigit():
            return int(s)
    raise RuntimeError(f"Could not parse PID from output: {out!r}")


def kill_process(pid: int) -> None:
    vmc(f"sudo kill -CONT {pid} 2>/dev/null || true")
    vmc(f"sudo kill -9 {pid} 2>/dev/null || true")
    vmc(f"sudo rm -rf /sys/fs/cgroup/sentinel/quarantine_{pid} 2>/dev/null || true")


def cg(pid: int, fname: str) -> str:
    return vmc(f"cat /sys/fs/cgroup/sentinel/quarantine_{pid}/{fname} 2>/dev/null || echo NOT_SET")


def cpu_ticks(pid: int, secs: int = 1) -> int:
    """Sample utime+stime delta over secs seconds, run entirely on VM via stdin."""
    script = f"""
T0=$(awk '{{print $14+$15}}' /proc/{pid}/stat 2>/dev/null || echo 0)
sleep {secs}
T1=$(awk '{{print $14+$15}}' /proc/{pid}/stat 2>/dev/null || echo 0)
echo $((T1 - T0))
"""
    out = vm_script(script, timeout=secs + 15)
    for line in reversed(out.splitlines()):
        s = line.strip()
        if s.lstrip("-").isdigit():
            return max(0, int(s))
    return 0


def quarantine_log(pid: int) -> dict:
    row = vmc(
        f"sudo sqlite3 /var/sentinel/events.db "
        f"'SELECT actions,success,error FROM quarantine_log WHERE pid={pid} "
        f"ORDER BY id DESC LIMIT 1;'"
    )
    if not row:
        return {}
    parts = row.split("|")
    return {"actions": parts[0] if parts else "", "success": parts[1] if len(parts) > 1 else "0"}


def ensure_stack() -> None:
    step("Phase 0 — fresh sentinel stack")

    vmc("sudo pkill sentinel-daemon 2>/dev/null || true")
    vmc("sudo pkill -f sentinel-quarantine 2>/dev/null || true")
    time.sleep(1)

    vmc(
        "sudo sqlite3 /var/sentinel/events.db "
        "'PRAGMA busy_timeout=5000; DELETE FROM events; DELETE FROM quarantine_log; "
        "PRAGMA wal_checkpoint(TRUNCATE);'"
    )
    vmc("sudo rm -rf /sys/fs/cgroup/sentinel/quarantine_* 2>/dev/null || true")
    vmc("sudo nft flush table inet sentinel_quarantine 2>/dev/null || true")

    vmc(
        "sudo bash -c 'nohup /usr/local/bin/sentinel-daemon "
        "-db /var/sentinel/events.db "
        "-obj /var/sentinel/tracer.bpf.o "
        ">> /var/sentinel/daemon.log 2>&1 &'"
    )
    time.sleep(3)

    vmc(
        "sudo bash -c 'nohup /usr/local/bin/sentinel-quarantine "
        "-db /var/sentinel/events.db "
        "-unfreeze-after 120s "
        ">> /var/sentinel/quarantine.log 2>&1 &'"
    )
    time.sleep(1)

    daemon = vmc("pgrep sentinel-daemon 2>/dev/null || echo DEAD")
    qm = vmc("pgrep -f sentinel-quarantine 2>/dev/null || echo DEAD")
    info(f"sentinel-daemon PID: {daemon}   sentinel-quarantine PID: {qm}")
    if "DEAD" in daemon or "DEAD" in qm:
        raise RuntimeError("Sentinel stack failed to start")
    ok("Stack running")


def test_freeze() -> None:
    step("TEST FREEZE — benign 'sleep 300' detonated, expect SIGSTOP + cgroup.freeze=1")

    pid = start_process("sleep 300")
    info(f"target PID={pid}")

    inject("ProcessInjection", 97.5, "FREEZE", pid, "sleep")

    proc_state = vmc(f"cat /proc/{pid}/status 2>/dev/null | grep '^State:' || echo GONE")
    cg_freeze   = cg(pid, "cgroup.freeze")
    qlog        = quarantine_log(pid)

    info(f"/proc/{pid}/status → {proc_state}")
    info(f"cgroup.freeze     → {cg_freeze}")
    info(f"quarantine_log    → {qlog}")

    check("FREEZE proc state=T",
          "T (stopped)" in proc_state or "T (tracing stop)" in proc_state,
          proc_state.strip())
    check("FREEZE cgroup.freeze=1", cg_freeze.strip() == "1", f"cgroup.freeze={cg_freeze.strip()}")
    check("FREEZE quarantine_log success",
          qlog.get("success", "0") == "1",
          f"actions={qlog.get('actions','')}")

    kill_process(pid)


def test_throttle() -> None:
    step("TEST THROTTLE — CPU burner detonated, expect cpu.max=10000 100000 + ≥50% reduction")

    pid = start_process("while true; do :; done")
    info(f"target PID={pid} (busy-loop)")
    time.sleep(0.5)  # let the loop accumulate CPU ticks before sampling

    cpu_before = cpu_ticks(pid, secs=1)
    info(f"CPU ticks/s before throttle: {cpu_before}")

    inject("NetworkAnomaly", 75, "THROTTLE", pid, "cpu_burner")

    cpu_max = cg(pid, "cpu.max")
    qlog    = quarantine_log(pid)
    info(f"cgroup cpu.max    → {cpu_max.strip()}")
    info(f"quarantine_log    → {qlog}")

    time.sleep(1)
    cpu_after = cpu_ticks(pid, secs=1)
    info(f"CPU ticks/s after throttle: {cpu_after}")

    check("THROTTLE cpu.max=10000 100000",
          cpu_max.strip() == "10000 100000",
          f"cpu.max={cpu_max.strip()}")
    check("THROTTLE quarantine_log success",
          qlog.get("success", "0") == "1",
          f"actions={qlog.get('actions','')}")
    if cpu_before > 5:
        reduction = (1 - cpu_after / max(cpu_before, 1)) * 100
        check("THROTTLE CPU reduced ≥50%", reduction >= 50,
              f"before={cpu_before} after={cpu_after} reduction={reduction:.0f}%")
    else:
        info("CPU baseline too low to measure reduction (skipping CPU check)")

    kill_process(pid)


def test_isolate() -> None:
    step("TEST ISOLATE — benign 'sleep 300' detonated, expect 256 MB cap + nftables drop")

    pid = start_process("sleep 300")
    info(f"target PID={pid}")

    inject("PrivilegeEscalation", 91, "ISOLATE", pid, "sleep")

    mem_max  = cg(pid, "memory.max")
    qlog     = quarantine_log(pid)
    cg_inode = vmc(f"stat -c %i /sys/fs/cgroup/sentinel/quarantine_{pid} 2>/dev/null || echo NONE")
    nft_out  = vmc("sudo nft list chain inet sentinel_quarantine output 2>/dev/null || echo NO_TABLE")

    info(f"memory.max        → {mem_max.strip()}")
    info(f"cgroup inode       → {cg_inode.strip()}")
    info(f"nft output chain  →\n      {nft_out.strip()}")
    info(f"quarantine_log    → {qlog}")

    check("ISOLATE memory.max=268435456",
          mem_max.strip() == "268435456",
          f"memory.max={mem_max.strip()}")
    check("ISOLATE quarantine_log success",
          qlog.get("success", "0") == "1",
          f"actions={qlog.get('actions','')}")

    inode_ok = (
        cg_inode.strip().isdigit()
        and "NO_TABLE" not in nft_out
        and cg_inode.strip() in nft_out
    )
    check("ISOLATE nftables cgroup drop rule present", inode_ok,
          f"cgroup inode {cg_inode.strip()} in nft rules")

    kill_process(pid)


def main() -> None:
    banner("Sentinel Enforcement Verification Test")

    step("Phase — vagrant up")
    subprocess.run(["vagrant", "up"], cwd=REPO, check=True)

    ensure_stack()
    test_freeze()
    test_throttle()
    test_isolate()

    banner("Results")
    passed = sum(1 for p, _ in RESULTS if p)
    total = len(RESULTS)
    color = "1;32" if passed == total else "1;31"
    print(f"  {_c(color, f'{passed}/{total} checks passed')}\n")
    for p, name in RESULTS:
        mark, c = ("✓", "1;32") if p else ("✗", "1;31")
        print(f"  {_c(c, mark)} {name}")
    print()
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
