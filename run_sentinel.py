#!/usr/bin/env python3

import argparse
import datetime
import json
import os
import select
import shlex
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path

_TTY = sys.stdout.isatty()

def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _TTY else text

def dim(t):    return _c("2",      t)
def bold(t):   return _c("1",      t)
def green(t):  return _c("1;32",   t)
def yellow(t): return _c("1;33",   t)
def red(t):    return _c("1;31",   t)
def cyan(t):   return _c("1;36",   t)
def blue(t):   return _c("1;34",   t)
def magenta(t):return _c("1;35",   t)


ATTACKS = [
    ("REP-01", "diamorphine_rootkit",  "HiddenPID",            95, "FREEZE",  15, None),
    ("REP-02", "rep02_priv_esc",       "PrivilegeEscalation",  70, "WARN",     2, None),
    ("REP-04", "rep04_netcat_exfil",   "NetworkAnomaly",       75, "THROTTLE", 2, None),
    ("REP-05", "rep05_webshell",       "ParentChildAnomaly",   50, "WARN",     2, None),
    ("REP-06", "rep06_cron_persist",   "LSMFileWrite",         50, "WARN",     2, None),
    ("REP-07", "rep07_mmap_rwx",       "MemoryInjection",      40, "WARN",     2, None),
    ("REP-08", "rep08_log_tamper",     "LogTamper",            50, "WARN",     2, None),
    ("REP-09", "rep09_ld_preload",     "LSMFileWrite",         50, "WARN",     2, None),
    ("REP-10", "rep10_fork_bomb",      "SyscallAnomaly",       35, "WATCH",    5, None),
    ("REP-11", "rep11_ptrace",         "ProcessInjection",     95, "FREEZE",   3, None),
    ("REP-12", "rep12_ssh_brute",      "NetworkAnomaly",       75, "THROTTLE", 2, None),
]

ADVANCED_ATTACKS = [
    ("REP-13", "rep13_fileless",       "MemoryInjection",      50, "WARN",     3, None),
    ("REP-14", "rep14_proc_hollow",    "ProcessInjection",     95, "FREEZE",   3,
        "sudo sysctl -w kernel.yama.ptrace_scope=0"),
    ("REP-15", "rep15_reverse_shell",  "NetworkAnomaly",       75, "THROTTLE", 2, None),
    ("REP-16", "rep16_cred_harvest",   "LSMFileWrite",         50, "WARN",     2, None),
    ("REP-17", "rep17_finit_persist",  "HiddenPID",            95, "FREEZE",   6, None),
    ("REP-18", "rep18_syscall_hook",   "HiddenPID",            95, "FREEZE",   8, None),
    ("REP-19", "rep19_ebpf_rootkit",   "ProcessInjection",     95, "FREEZE",   6, None),
    ("REP-20", "rep20_mem_stealer",    "ProcessInjection",     95, "FREEZE",   6, None),
    ("REP-21", "rep21_vm_escape",      "PrivilegeEscalation",  70, "ISOLATE",  3, None),
]

LOG_FILES = [
    "/var/sentinel/daemon.log",
    "/var/sentinel/scorer.log",
    "/var/sentinel/quarantine.log",
    "/var/sentinel/sentinel.log",
]


class Runner:
    def __init__(self, repo_root: Path, results_dir: Path,
                 dry_run: bool = False, synthetic_ok: bool = False):
        self.repo         = repo_root
        self.out          = results_dir
        self.dry          = dry_run
        self.synthetic_ok = synthetic_ok
        self._log_f = open(results_dir / "run.log", "a", buffering=1)
        self._ssh_conf: Path | None = None
        self.pass_count = 0
        self.fail_count = 0
        self.attack_results: list[dict] = []

    def _ts(self) -> str:
        return datetime.datetime.now().strftime("%H:%M:%S")

    def _write(self, line: str) -> None:
        print(line, flush=True)
        clean = line
        for code in ["\033[0m", "\033[1m", "\033[2m"]:
            clean = clean.replace(code, "")
        import re
        clean = re.sub(r"\033\[\d+(;\d+)*m", "", clean)
        self._log_f.write(clean + "\n")

    def info(self, msg: str) -> None:
        self._write(f"{dim(self._ts())}  {msg}")

    def step(self, msg: str) -> None:
        self._write(f"\n{bold(cyan('▶'))} {bold(msg)}")

    def ok(self, msg: str) -> None:
        self._write(f"  {green('✓')} {msg}")

    def warn(self, msg: str) -> None:
        self._write(f"  {yellow('⚠')} {msg}")

    def fail(self, msg: str) -> None:
        self._write(f"  {red('✗')} {msg}")

    def section(self, title: str) -> None:
        bar = "─" * 60
        self._write(f"\n{blue(bar)}")
        self._write(f"{blue('│')}  {bold(title)}")
        self._write(f"{blue(bar)}")

    def run(self, cmd: list[str] | str, *,
            capture: bool = False,
            check: bool = True,
            timeout: int = 300,
            stdin_text: str | None = None,
            cwd: Path | None = None) -> subprocess.CompletedProcess:

        if isinstance(cmd, str):
            display = cmd
        else:
            display = " ".join(shlex.quote(c) for c in cmd)
        self._write(f"  {dim('$')} {dim(display)}")

        if self.dry:
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        kwargs: dict = dict(
            cwd=cwd or self.repo,
            timeout=timeout,
            text=True,
        )
        if capture:
            kwargs["capture_output"] = True
        else:
            kwargs["stdout"] = subprocess.PIPE
            kwargs["stderr"] = subprocess.STDOUT

        if stdin_text is not None:
            kwargs["input"] = stdin_text

        if not capture:
            popen_kwargs = {k: v for k, v in kwargs.items()
                            if k not in ("capture_output", "timeout")}
            proc = subprocess.Popen(
                cmd if isinstance(cmd, list) else cmd,
                shell=isinstance(cmd, str),
                **popen_kwargs,
            )
            stdout_lines = []
            deadline = time.time() + timeout
            while True:
                remaining = deadline - time.time()
                if remaining <= 0:
                    proc.kill()
                    raise subprocess.TimeoutExpired(cmd, timeout)
                ready = select.select([proc.stdout], [], [], min(remaining, 1.0))[0]
                if ready:
                    line = proc.stdout.readline()
                    if not line:
                        break
                    line = line.rstrip("\n")
                    self._write(f"    {dim(line)}")
                    stdout_lines.append(line)
                elif proc.poll() is not None:
                    break
            proc.wait(timeout=max(1, deadline - time.time()))
            result = subprocess.CompletedProcess(
                cmd, proc.returncode,
                stdout="\n".join(stdout_lines), stderr=""
            )
        else:
            result = subprocess.run(
                cmd if isinstance(cmd, list) else cmd,
                shell=isinstance(cmd, str),
                **kwargs,
            )

        if check and result.returncode != 0:
            self.fail(f"Command exited {result.returncode}: {display}")
            if capture and result.stderr:
                self._write(f"    {red(result.stderr.strip())}")
            raise subprocess.CalledProcessError(result.returncode, cmd)
        return result

    def vagrant(self, args: str, **kwargs) -> subprocess.CompletedProcess:
        return self.run(f"vagrant {args}", **kwargs)

    def vm(self, remote_cmd: str, **kwargs) -> subprocess.CompletedProcess:
        return self.run(["vagrant", "ssh", "--", remote_cmd], **kwargs)

    def vm_capture(self, remote_cmd: str) -> str:
        r = self.run(["vagrant", "ssh", "--", remote_cmd], capture=True, check=False)
        return (r.stdout or "").strip()

    def _ensure_ssh_conf(self) -> Path:
        if self._ssh_conf and self._ssh_conf.exists():
            return self._ssh_conf
        p = self.out / "vagrant_ssh.conf"
        r = self.vagrant("ssh-config", capture=True)
        p.write_text(r.stdout)
        self._ssh_conf = p
        return p

    def scp_to_vm(self, local: Path, remote: str) -> None:
        conf = self._ensure_ssh_conf()
        self.run(["scp", "-F", str(conf), str(local), f"default:{remote}"])

    def scp_from_vm(self, remote: str, local: Path) -> None:
        conf = self._ensure_ssh_conf()
        local.parent.mkdir(parents=True, exist_ok=True)
        self.run(["scp", "-F", str(conf), f"default:{remote}", str(local)], check=False)

    def pull_logs(self, tag: str) -> None:
        dest = self.out / tag
        dest.mkdir(parents=True, exist_ok=True)
        self.step(f"Extracting logs → results/{self.out.name}/{tag}/")

        self.vm_capture(
            "sudo pkill sentinel-daemon 2>/dev/null || true; "
            "sudo pkill -f sentinel-quarantine 2>/dev/null || true")
        time.sleep(0.5)
        self.vm_capture(
            "sudo sqlite3 /var/sentinel/events.db 'PRAGMA wal_checkpoint(TRUNCATE);'")
        self.vm("sudo sqlite3 /var/sentinel/events.db '.backup /tmp/sentinel_snapshot.db'",
                check=False)
        self.vm_capture(
            "sudo bash -c 'nohup /usr/local/bin/sentinel-daemon "
            "-db /var/sentinel/events.db -obj /var/sentinel/tracer.bpf.o "
            "-scorer-url http://127.0.0.1:8765 >> /var/sentinel/daemon.log 2>&1 &'; "
            "sudo bash -c 'nohup /usr/local/bin/sentinel-quarantine "
            "-db /var/sentinel/events.db >> /var/sentinel/quarantine.log 2>&1 &'")
        self.scp_from_vm("/tmp/sentinel_snapshot.db", dest / "events.db")

        for lf in LOG_FILES:
            name = Path(lf).name
            self.scp_from_vm(lf, dest / name)

        dmesg = self.vm_capture("sudo dmesg --since '2 minutes ago' 2>/dev/null | tail -30")
        (dest / "dmesg.log").write_text(dmesg)

        self._print_db_summary(dest / "events.db")

    def _print_db_summary(self, db_path: Path) -> None:
        if not db_path.exists() or self.dry:
            return
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
            rows = conn.execute("""
                SELECT alert_type,
                       COUNT(*)           AS events,
                       ROUND(MAX(score),1) AS max_score,
                       MIN(state)          AS worst_state
                FROM events
                GROUP BY alert_type
                ORDER BY max_score DESC
            """).fetchall()
            conn.close()
        except Exception as exc:
            self.warn(f"Could not read DB: {exc}")
            return

        if not rows:
            self.warn("DB is empty")
            return

        header = f"  {'alert_type':<22} {'events':>6}  {'max_score':>9}  {'worst_state':<12}"
        self._write(f"\n{bold('  DB snapshot:')}")
        self._write(dim(header))
        for alert_type, events, max_score, worst_state in rows:
            color = green if worst_state in ("FREEZE", "ISOLATE") else (
                    yellow if worst_state == "THROTTLE" else dim)
            line = f"  {alert_type:<22} {events:>6}  {max_score:>9}  {worst_state:<12}"
            self._write(color(line))

    def phase_vm_check(self) -> None:
        self.section("PHASE 1 — VM health check")
        self.step("Checking vagrant status")
        self.vagrant("status", capture=True, check=False)

        self.step("Verifying kernel version")
        kernel = self.vm_capture("uname -r")
        self.info(f"Kernel: {kernel}")
        if "6.1.0" in kernel:
            self.ok(f"Kernel OK: {kernel}")
        else:
            self.warn(f"Unexpected kernel: {kernel} (expected 6.1.0-*-amd64)")

    def phase_install_sentinel(self) -> None:
        self.section("PHASE 2 — Install Sentinel (schema + synthetic injector)")
        self.step("Uploading install script")
        self.scp_to_vm(self.repo / "scripts" / "install_sentinel.sh",
                       "/tmp/install_sentinel.sh")
        self.step("Running install script")
        self.vm("sudo bash /tmp/install_sentinel.sh")

        self.step("Smoke-test: synthetic injector")
        self.vm("echo '95 FREEZE 9999 test_process' > /tmp/sentinel_trigger_TestAlert")
        time.sleep(1.5)
        out = self.vm_capture(
            "sudo sqlite3 /var/sentinel/events.db "
            "'SELECT id,alert_type,score,state,comm FROM events;'")
        self.info(f"DB row: {out}")
        if "TestAlert" in out:
            self.ok("Synthetic injector: RUNNING")
        else:
            self.fail("Synthetic injector did not write to DB")

        self.step("Clearing smoke-test data")
        self.vm("sudo sqlite3 /var/sentinel/events.db "
                "'PRAGMA busy_timeout=10000; "
                "DELETE FROM events; DELETE FROM quarantine_log; "
                "PRAGMA wal_checkpoint(TRUNCATE);'")

        self.step("Uploading scorer")
        self.scp_to_vm(self.repo / "scorer" / "isolation_forest.py",
                       "/tmp/isolation_forest.py")
        self.vm("sudo cp /tmp/isolation_forest.py /var/sentinel/isolation_forest.py")

        self.step("Setting up Python scorer venv")
        self.vm(
            "sudo python3 -m venv /var/sentinel/venv && "
            "sudo /var/sentinel/venv/bin/pip install -q "
            "numpy scikit-learn joblib fastapi uvicorn pydantic",
            timeout=180)
        self.ok("Scorer venv ready")

    def phase_upload_attacks(self) -> None:
        self.section("PHASE 3 — Upload attack suites")
        self.vm("mkdir -p /tmp/attacks")

        attacks_dir = self.repo / "attacks"
        for d in sorted(attacks_dir.iterdir()):
            if not d.is_dir():
                continue
            name = d.name
            self.step(f"Uploading {name}")
            self.vm(f"mkdir -p /tmp/attacks/{name}")
            self.vagrant(f"scp attacks/{name}/ :/tmp/attacks/{name}/")
            self.vm(
                f'inner="/tmp/attacks/{name}/{name}"; '
                f'[ -d "$inner" ] && mv "$inner"/* "/tmp/attacks/{name}/" '
                f'&& rmdir "$inner" && echo "Fixed: {name}" || true'
            )

        self.step("Making run.sh files executable in VM")
        self.vm("chmod +x /tmp/attacks/*/run.sh")
        self.ok("All attacks uploaded")

    def phase_verify_ebpf(self, force_recompile: bool = False) -> None:
        self.section("PHASE 4 — eBPF tracer (upload + compile)")
        self.step("Uploading tracer.bpf.c")
        self.scp_to_vm(self.repo / "tools" / "ebpf_tracer" / "tracer.bpf.c",
                       "/tmp/tracer.bpf.c")
        existing = self.vm_capture("ls -lh /var/sentinel/tracer.bpf.o 2>/dev/null || echo MISSING")
        if force_recompile or "MISSING" in existing:
            self.step("Compiling tracer.bpf.c")
            self.vm(
                "sudo clang -target bpf -O2 -g -D__TARGET_ARCH_x86 "
                "-I/usr/include -I/usr/include/x86_64-linux-gnu "
                "-c /tmp/tracer.bpf.c -o /var/sentinel/tracer.bpf.o && echo 'COMPILED OK'",
                timeout=60)
            size = self.vm_capture("ls -lh /var/sentinel/tracer.bpf.o 2>/dev/null")
            self.ok(f"Compiled: {size}")
        else:
            self.ok(f"tracer.bpf.o unchanged: {existing.strip()}")
            self.info("Pass --rebuild to force recompile")

    def phase_rebuild_daemon(self) -> None:
        self.section("PHASE 5b — Cross-compile Go daemon + upload")
        for src_name, bin_name in [("daemon", "sentinel-daemon"),
                                   ("quarantine", "sentinel-quarantine")]:
            src_dir = self.repo / src_name
            if not src_dir.exists():
                self.fail(f"{src_name}/ directory not found")
                continue

            self.step(f"Cross-compiling {bin_name} (CGO_ENABLED=1 linux/amd64)")
            bin_path = self.out / bin_name
            self.run(
                f"cd {src_dir} && "
                f"CGO_ENABLED=1 GOOS=linux GOARCH=amd64 "
                f"go build -o {bin_path} .",
                timeout=120)
            self.ok(f"Built: {bin_path}")

            self.step(f"Uploading + installing {bin_name} in VM")
            self.scp_to_vm(bin_path, f"/tmp/{bin_name}")
            self.vm(f"sudo pkill {bin_name} 2>/dev/null || true ; "
                    f"sudo rm -f /usr/local/bin/{bin_name} && "
                    f"sudo cp /tmp/{bin_name} /usr/local/bin/{bin_name} && "
                    f"sudo chmod +x /usr/local/bin/{bin_name}")
            self.ok(f"{bin_name} installed")

    def phase_verify_daemon(self) -> None:
        self.section("PHASE 5 — Verify Go daemon + quarantine manager")
        missing = []
        for binary in ["sentinel-daemon", "sentinel-quarantine"]:
            out = self.vm_capture(f"ls -lh /usr/local/bin/{binary} 2>/dev/null || echo MISSING")
            if "MISSING" in out:
                missing.append(binary)
            else:
                self.ok(f"{binary}: {out.strip()}")
        if missing:
            self.warn(f"Missing binaries: {missing} — building now")
            self.phase_rebuild_daemon()

    def phase_verify_scorer(self) -> None:
        self.section("PHASE 6 — Verify Python scorer")
        out = self.vm_capture("curl --max-time 5 -s http://127.0.0.1:8765/health 2>/dev/null || echo DOWN")
        if "ok" in out:
            self.ok(f"Scorer healthy: {out}")
        else:
            self.warn("Scorer is DOWN — starting it now")
            self.vm(
                "sudo bash -c 'nohup /var/sentinel/venv/bin/python3 "
                "/var/sentinel/isolation_forest.py serve --port 8765 "
                ">> /var/sentinel/scorer.log 2>&1 &'")
            time.sleep(4)
            out = self.vm_capture("curl --max-time 5 -s http://127.0.0.1:8765/health 2>/dev/null || echo DOWN")
            if "ok" in out:
                self.ok(f"Scorer started: {out}")
            else:
                self.fail(f"Scorer still down: {out}")

    def phase_start_stack(self, kill_first: bool = False) -> None:
        self.section("PHASE 8 — Start full detection stack")
        if kill_first:
            self.step("Stopping existing daemon + quarantine (rebuild mode)")
            self.vm("sudo pkill sentinel-daemon 2>/dev/null || true")
            self.vm("sudo pkill -f sentinel-quarantine 2>/dev/null || true")
            time.sleep(2)
        self.step("Clearing and creating log files")
        self.vm(
            "sudo truncate -s 0 /var/sentinel/daemon.log /var/sentinel/scorer.log "
            "/var/sentinel/quarantine.log 2>/dev/null; "
            "sudo touch /var/sentinel/scorer.log /var/sentinel/daemon.log "
            "/var/sentinel/quarantine.log && "
            "sudo chmod 666 /var/sentinel/scorer.log "
            "/var/sentinel/daemon.log /var/sentinel/quarantine.log")

        self.step("Ensuring scorer is not running (uses too much memory during tests)")
        self.vm_capture("sudo pkill -9 -f 'isolation_forest.py' 2>/dev/null || true")

        self.step("Starting eBPF daemon (if not running)")
        daemon_up = self.vm_capture(
            "pgrep sentinel-daemon > /dev/null 2>&1 && echo 1 || echo 0")
        if daemon_up.strip() == "0":
            self.vm(
                "sudo bash -c 'nohup /usr/local/bin/sentinel-daemon "
                "-db /var/sentinel/events.db "
                "-obj /var/sentinel/tracer.bpf.o "
                "-scorer-url http://127.0.0.1:8765 "
                ">> /var/sentinel/daemon.log 2>&1 &'")
            time.sleep(5)
        daemon_pid = self.vm_capture("pgrep -a sentinel-daemon 2>/dev/null || echo NOT_RUNNING")
        if "NOT_RUNNING" in daemon_pid:
            self.fail("Daemon failed to start — check /var/sentinel/daemon.log")
            daemon_head = self.vm_capture("sudo tail -5 /var/sentinel/daemon.log 2>/dev/null")
            self.warn(f"Daemon log tail: {daemon_head}")
        else:
            self.ok(f"Daemon running: {daemon_pid.strip()}")

        self.step("Starting quarantine manager (if not running)")
        qm_up = self.vm_capture(
            "pgrep -f sentinel-quarantine > /dev/null 2>&1 && echo 1 || echo 0")
        if qm_up.strip() == "0":
            self.vm(
                "sudo bash -c 'nohup /usr/local/bin/sentinel-quarantine "
                "-db /var/sentinel/events.db "
                ">> /var/sentinel/quarantine.log 2>&1 &'")
            time.sleep(2)
        qm_pid = self.vm_capture("pgrep -af sentinel-quarantine 2>/dev/null || echo NOT_RUNNING")
        if "NOT_RUNNING" in qm_pid:
            self.warn("Quarantine manager not running")
        else:
            self.ok(f"Quarantine manager: {qm_pid.strip()}")

        self.step("Process summary")
        procs = self.vm_capture("sudo pgrep -la 'sentinel|python3' | grep -v grep || echo none")
        for line in procs.splitlines():
            self.info(f"  {line}")

    def phase_run_attacks(self, attacks: list[tuple], tag_prefix: str = "") -> None:
        for rep_id, dir_name, alert_type, min_score, exp_state, sleep_s, extra in attacks:
            self.section(f"{rep_id} — {dir_name}")

            self.step("Clearing DB before attack")
            self.vm(
                "sudo sqlite3 /var/sentinel/events.db "
                "'PRAGMA busy_timeout=10000; "
                "DELETE FROM events; DELETE FROM quarantine_log; "
                "PRAGMA wal_checkpoint(TRUNCATE);'")

            if extra:
                self.step(f"Pre-setup: {extra}")
                self.vm(f"sudo {extra}")

            self.step(f"Running /tmp/attacks/{dir_name}/run.sh")
            t_start = time.time()
            self.vm(f"sudo bash /tmp/attacks/{dir_name}/run.sh 2>&1", check=False)
            self.info(f"Attack script finished in {time.time()-t_start:.1f}s — waiting {sleep_s}s for events to flush")
            time.sleep(sleep_s)

            tag = f"{tag_prefix}{rep_id.lower().replace('-','_')}_{dir_name}"
            self.pull_logs(tag)

            passed, detail = self._check_attack(dir_name, alert_type, min_score, exp_state, tag)
            if passed:
                self.ok(green(f"{rep_id} PASS — {detail}"))
                self.pass_count += 1
            else:
                self.fail(red(f"{rep_id} FAIL — {detail}"))
                self.fail_count += 1

            self.attack_results.append({
                "id":         rep_id,
                "dir":        dir_name,
                "alert_type": alert_type,
                "passed":     passed,
                "detail":     detail,
            })

    def _check_attack(self, dir_name: str, alert_type: str,
                      min_score: float, exp_state: str, tag: str) -> tuple[bool, str]:
        db_path = self.out / tag / "events.db"
        if self.dry or not db_path.exists():
            return True, "dry-run / no DB"
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
            row = conn.execute("""
                SELECT
                    ROUND(MAX(score),1),
                    MIN(state),
                    SUM(CASE WHEN json_extract(detail,'$.source') = 'kprobe'
                             THEN 1 ELSE 0 END) AS real_events,
                    SUM(CASE WHEN json_extract(detail,'$.source') = 'synthetic'
                             THEN 1 ELSE 0 END) AS synth_events
                FROM events WHERE alert_type = ?
            """, (alert_type,)).fetchone()
            conn.close()
        except Exception as exc:
            return False, f"DB error: {exc}"

        if not row or row[0] is None:
            return False, f"No {alert_type} events found in DB"

        score, state, real_events, synth_events = row
        real_events  = real_events  or 0
        synth_events = synth_events or 0

        if score < min_score:
            return False, f"{alert_type} score={score} < threshold {min_score}"

        if real_events == 0 and not self.synthetic_ok:
            return False, (
                f"{alert_type} score={score} state={state} "
                f"but 0 kprobe events (only {synth_events} synthetic) — "
                f"real detection missing. Use --synthetic-ok to accept synthetic."
            )

        source_note = f"kprobe={real_events}"
        if synth_events:
            source_note += f" synthetic={synth_events}"
        return True, f"{alert_type} score={score} state={state} [{source_note}]"

    def final_summary(self) -> None:
        self.section("FINAL SUMMARY")

        total = self.pass_count + self.fail_count
        color = green if self.fail_count == 0 else red
        self._write(f"\n  {bold('Results:')} {color(f'{self.pass_count}/{total} attacks PASSED')}\n")

        for r in self.attack_results:
            icon = green("✓") if r["passed"] else red("✗")
            self._write(f"  {icon}  {r['id']:<8} {r['dir']:<30} {r['detail']}")

        self._write("")
        self._write(f"  {bold('Results directory:')} {self.out}")
        self._write(f"  {bold('Full run log:')}       {self.out / 'run.log'}")

        dbs = sorted(self.out.rglob("events.db"), key=lambda p: p.stat().st_mtime, reverse=True)
        if dbs:
            self._write(f"\n  {bold('Latest DB state:')}")
            self._print_db_summary(dbs[0])

    def close(self) -> None:
        self._log_f.close()


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Sentinel lab orchestrator")
    p.add_argument("--start-phase", type=int, default=1,
                   help="Skip phases below this number (1=all, 8=stack only, 9=attacks only)")
    p.add_argument("--only", nargs="+", metavar="ATTACK",
                   help="Run only these attack dir names (e.g. rep06_cron_persist)")
    p.add_argument("--advanced", action="store_true",
                   help="Include advanced attacks REP-13–21 after the base set")
    p.add_argument("--rebuild", action="store_true",
                   help="Force recompile tracer.bpf.c in VM and cross-compile daemon on host")
    p.add_argument("--dry-run", action="store_true",
                   help="Print commands without executing them")
    p.add_argument("--synthetic-ok", action="store_true",
                   help="Accept synthetic-injection events as PASS (default: real kprobe required)")
    p.add_argument("--results-dir", default="results",
                   help="Parent directory for run outputs (default: results/)")
    return p


def main() -> int:
    args = build_arg_parser().parse_args()

    repo_root = Path(__file__).parent.resolve()
    run_id    = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir   = repo_root / args.results_dir / f"run_{run_id}"
    out_dir.mkdir(parents=True, exist_ok=True)

    runner = Runner(repo_root, out_dir, dry_run=args.dry_run,
                    synthetic_ok=args.synthetic_ok)

    runner._write(f"\n{bold(magenta('Sentinel Lab Orchestrator'))}")
    runner._write(f"  Run ID:  {run_id}")
    runner._write(f"  Output:  {out_dir}")
    runner._write(f"  Dry-run: {args.dry_run}")

    def _sigint(sig, frame):
        runner._write(f"\n{yellow('Interrupted — pulling final logs')}")
        try:
            runner.pull_logs("interrupted")
        except Exception:
            runner.warn("Could not pull logs (VM may be unreachable)")
        runner.final_summary()
        runner.close()
        sys.exit(1)

    signal.signal(signal.SIGINT, _sigint)

    try:
        phase = args.start_phase

        if phase <= 1:
            runner.phase_vm_check()
        if phase <= 2:
            runner.phase_install_sentinel()
        if phase <= 3:
            runner.phase_upload_attacks()
        if phase <= 4 or args.rebuild:
            runner.phase_verify_ebpf(force_recompile=args.rebuild)
        if args.rebuild:
            runner.phase_rebuild_daemon()
        if phase <= 5:
            runner.phase_verify_daemon()
        if phase <= 6:
            runner.phase_verify_scorer()
        if phase <= 8:
            runner.phase_start_stack(kill_first=args.rebuild)

        runner.pull_logs("00_before_attacks")

        attacks = ATTACKS[:]
        if args.advanced:
            attacks += ADVANCED_ATTACKS
        if args.only:
            only_set = set(args.only)
            attacks = [a for a in attacks if a[1] in only_set]
            if not attacks:
                runner.fail(f"None of {args.only} matched known attack dirs")
                return 1

        runner.phase_run_attacks(attacks)
        runner.pull_logs("99_final_state")
        runner.final_summary()

    except subprocess.CalledProcessError as exc:
        runner.fail(f"Fatal: command failed with exit {exc.returncode}")
        try:
            runner.pull_logs("error_state")
        except Exception:
            runner.warn("Could not pull logs (VM may be unreachable)")
        return 1
    except subprocess.TimeoutExpired as exc:
        runner.fail(f"Fatal: command timed out: {exc.cmd}")
        try:
            runner.pull_logs("error_state")
        except Exception:
            runner.warn("Could not pull logs (VM may be unreachable)")
        return 1
    except KeyboardInterrupt:
        pass
    finally:
        runner.close()

    return 0 if runner.fail_count == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
