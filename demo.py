#!/usr/bin/env python3
"""
Sentinel Demo — detonates attacks in the VM and streams live detections.
Usage:  source .venv/bin/activate && python demo.py
"""
import asyncio
import json
import shlex
import subprocess
import threading
import time
from pathlib import Path
from typing import AsyncIterator

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, StreamingResponse

# ── attack catalogue ────────────────────────────────────────────────────────
ATTACKS = [
    ("REP-01", "diamorphine_rootkit",  "Hidden PID",          "HiddenPID",           "FREEZE"),
    ("REP-02", "rep02_priv_esc",       "Priv Escalation",     "PrivilegeEscalation", "ISOLATE"),
    ("REP-04", "rep04_netcat_exfil",   "Network Exfil",       "NetworkAnomaly",      "THROTTLE"),
    ("REP-05", "rep05_webshell",       "Web Shell",           "ParentChildAnomaly",  "WARN"),
    ("REP-06", "rep06_cron_persist",   "Cron Persist",        "LSMFileWrite",        "WARN"),
    ("REP-07", "rep07_mmap_rwx",       "mmap RWX",            "MemoryInjection",     "WARN"),
    ("REP-08", "rep08_log_tamper",     "Log Tamper",          "LogTamper",           "WARN"),
    ("REP-09", "rep09_ld_preload",     "LD_PRELOAD Hijack",   "LSMFileWrite",        "WARN"),
    ("REP-10", "rep10_fork_bomb",      "Fork Bomb",           "SyscallAnomaly",      "WATCH"),
    ("REP-11", "rep11_ptrace",         "ptrace Inject",       "ProcessInjection",    "FREEZE"),
    ("REP-12", "rep12_ssh_brute",      "SSH Brute Force",     "NetworkAnomaly",      "THROTTLE"),
    ("REP-13", "rep13_fileless",       "Fileless Exec",       "MemoryInjection",     "WARN"),
    ("REP-14", "rep14_proc_hollow",    "Process Hollow",      "ProcessInjection",    "FREEZE"),
    ("REP-15", "rep15_reverse_shell",  "Reverse Shell",       "NetworkAnomaly",      "THROTTLE"),
    ("REP-16", "rep16_cred_harvest",   "Cred Harvest",        "LSMFileWrite",        "WARN"),
    ("REP-17", "rep17_finit_persist",  "Finit Persist",       "HiddenPID",           "FREEZE"),
    ("REP-18", "rep18_syscall_hook",   "Syscall Hook",        "HiddenPID",           "FREEZE"),
    ("REP-19", "rep19_ebpf_rootkit",   "eBPF Rootkit",        "ProcessInjection",    "FREEZE"),
    ("REP-20", "rep20_mem_stealer",    "Memory Stealer",      "ProcessInjection",    "FREEZE"),
    ("REP-21", "rep21_vm_escape",      "VM Escape",           "PrivilegeEscalation", "ISOLATE"),
]

STATE_COLOR = {
    "FREEZE":   "#ff3b30",
    "ISOLATE":  "#ff6b2b",
    "THROTTLE": "#ffcc00",
    "WARN":     "#0a84ff",
    "WATCH":    "#636366",
    "OK":       "#30d158",
}

# ── shared event bus ────────────────────────────────────────────────────────
_subscribers: list[asyncio.Queue] = []
_lock = threading.Lock()

def broadcast(msg: dict) -> None:
    payload = json.dumps(msg)
    with _lock:
        dead = []
        for q in _subscribers:
            try:
                q.put_nowait(payload)
            except asyncio.QueueFull:
                dead.append(q)
        for q in dead:
            _subscribers.remove(q)

# ── VM polling thread ───────────────────────────────────────────────────────
_last_event_id   = 0
_last_qlog_id    = 0

def _vm_sql(query: str) -> str:
    try:
        r = subprocess.run(
            ["vagrant", "ssh", "--", f"sudo sqlite3 /var/sentinel/events.db {shlex.quote(query)}"],
            capture_output=True, text=True, timeout=8,
            cwd=Path(__file__).parent,
        )
        return r.stdout.strip()
    except Exception:
        return ""

def _poll_vm() -> None:
    global _last_event_id, _last_qlog_id

    # seed IDs so we only show new events after the server starts
    out = _vm_sql("SELECT COALESCE(MAX(id),0) FROM events;")
    _last_event_id = int(out) if out.isdigit() else 0
    out = _vm_sql("SELECT COALESCE(MAX(id),0) FROM quarantine_log;")
    _last_qlog_id = int(out) if out.isdigit() else 0

    while True:
        time.sleep(1.5)
        try:
            _poll_events()
            _poll_qlog()
        except Exception:
            pass

def _poll_events() -> None:
    global _last_event_id
    q = (
        f"SELECT id,alert_type,score,state,pid,comm,detail "
        f"FROM events WHERE id > {_last_event_id} ORDER BY id LIMIT 30;"
    )
    raw = _vm_sql(q)
    if not raw:
        return
    for line in raw.splitlines():
        parts = line.split("|", 6)
        if len(parts) < 6:
            continue
        eid, alert, score, state, pid, comm = parts[:6]
        detail_raw = parts[6] if len(parts) > 6 else "{}"
        try:
            detail = json.loads(detail_raw)
        except Exception:
            detail = {}
        broadcast({
            "type":       "event",
            "id":         int(eid),
            "alert_type": alert,
            "score":      float(score),
            "state":      state,
            "pid":        pid,
            "comm":       comm,
            "syscall":    detail.get("syscall_name", ""),
            "source":     detail.get("source", "kprobe"),
            "color":      STATE_COLOR.get(state, "#636366"),
        })
        _last_event_id = max(_last_event_id, int(eid))

def _poll_qlog() -> None:
    global _last_qlog_id
    q = (
        f"SELECT id,event_id,pid,comm,prior_state,actions,success,latency_ms "
        f"FROM quarantine_log WHERE id > {_last_qlog_id} ORDER BY id LIMIT 30;"
    )
    raw = _vm_sql(q)
    if not raw:
        return
    for line in raw.splitlines():
        parts = line.split("|", 7)
        if len(parts) < 6:
            continue
        qid, evid, pid, comm, prior, actions = parts[:6]
        success  = parts[6] if len(parts) > 6 else "0"
        latency  = parts[7] if len(parts) > 7 else "0"
        try:
            action_list = json.loads(actions)
        except Exception:
            action_list = [actions]
        broadcast({
            "type":       "quarantine",
            "id":         int(qid),
            "event_id":   evid,
            "pid":        pid,
            "comm":       comm,
            "prior_state": prior,
            "actions":    action_list,
            "success":    success == "1",
            "latency_ms": latency,
        })
        _last_qlog_id = max(_last_qlog_id, int(qid))

# ── attack runner ───────────────────────────────────────────────────────────
_running_attacks: dict[str, bool] = {}

def _run_attack(dir_name: str) -> None:
    broadcast({"type": "attack_start", "attack": dir_name})
    try:
        proc = subprocess.Popen(
            ["vagrant", "ssh", "--",
             f"sudo bash /tmp/attacks/{dir_name}/run.sh 2>&1"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, cwd=Path(__file__).parent,
        )
        for line in proc.stdout:
            line = line.rstrip()
            if line and not line.startswith("[fog]"):
                broadcast({"type": "attack_log", "attack": dir_name, "line": line})
        proc.wait(timeout=60)
    except Exception as exc:
        broadcast({"type": "attack_log", "attack": dir_name, "line": f"[error] {exc}"})
    finally:
        _running_attacks.pop(dir_name, None)
        broadcast({"type": "attack_done", "attack": dir_name})

# ── FastAPI app ─────────────────────────────────────────────────────────────
app = FastAPI()

@app.on_event("startup")
def startup() -> None:
    t = threading.Thread(target=_poll_vm, daemon=True)
    t.start()

@app.get("/api/attacks")
def list_attacks():
    return [
        {"id": a[0], "dir": a[1], "label": a[2],
         "alert_type": a[3], "expected_state": a[4],
         "color": STATE_COLOR.get(a[4], "#636366")}
        for a in ATTACKS
    ]

@app.post("/api/trigger/{dir_name}")
def trigger(dir_name: str):
    if dir_name in _running_attacks:
        return {"status": "already_running"}
    valid = {a[1] for a in ATTACKS}
    if dir_name not in valid:
        return {"status": "unknown_attack"}
    _running_attacks[dir_name] = True
    t = threading.Thread(target=_run_attack, args=(dir_name,), daemon=True)
    t.start()
    return {"status": "started"}

@app.get("/api/stream")
async def stream(request) -> StreamingResponse:
    q: asyncio.Queue = asyncio.Queue(maxsize=200)
    with _lock:
        _subscribers.append(q)

    async def generator() -> AsyncIterator[str]:
        try:
            yield "data: {\"type\":\"connected\"}\n\n"
            while True:
                if await request.is_disconnected():
                    break
                try:
                    msg = q.get_nowait()
                    yield f"data: {msg}\n\n"
                except asyncio.QueueEmpty:
                    await asyncio.sleep(0.2)
        finally:
            with _lock:
                _subscribers.remove(q) if q in _subscribers else None

    return StreamingResponse(generator(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache",
                                      "X-Accel-Buffering": "no"})

# ── HTML page ───────────────────────────────────────────────────────────────
HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Sentinel Demo</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:#0d0d0f;color:#e5e5ea;font-family:'SF Mono',ui-monospace,monospace;font-size:13px;height:100vh;display:flex;flex-direction:column}
  header{padding:14px 20px;border-bottom:1px solid #2c2c2e;display:flex;align-items:center;gap:12px;flex-shrink:0}
  header h1{font-size:16px;font-weight:600;letter-spacing:.04em;color:#fff}
  #vm-status{font-size:11px;padding:3px 8px;border-radius:4px;background:#1c1c1e;color:#636366}
  #vm-status.live{color:#30d158}
  .main{display:flex;flex:1;overflow:hidden}

  /* ── attack grid ── */
  .attacks{width:380px;flex-shrink:0;padding:14px;overflow-y:auto;border-right:1px solid #2c2c2e;display:flex;flex-direction:column;gap:8px}
  .atk{border:1px solid #2c2c2e;border-radius:8px;padding:10px 12px;cursor:pointer;transition:border-color .15s,background .15s;display:flex;align-items:center;gap:10px;background:#1c1c1e}
  .atk:hover{background:#2c2c2e}
  .atk.running{border-color:#0a84ff;background:#0a84ff18;animation:pulse 1.2s ease-in-out infinite}
  .atk.done{border-color:#30d158}
  @keyframes pulse{0%,100%{opacity:1}50%{opacity:.6}}
  .atk-id{font-size:10px;color:#636366;width:44px;flex-shrink:0}
  .atk-body{flex:1;min-width:0}
  .atk-label{font-weight:500;font-size:12px;color:#e5e5ea;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  .atk-meta{font-size:10px;color:#636366;margin-top:2px}
  .badge{font-size:9px;font-weight:700;letter-spacing:.06em;padding:2px 6px;border-radius:3px;flex-shrink:0;color:#000}

  /* ── right panel ── */
  .panel{flex:1;display:flex;flex-direction:column;overflow:hidden}
  .tabs{display:flex;border-bottom:1px solid #2c2c2e;flex-shrink:0}
  .tab{padding:10px 18px;cursor:pointer;font-size:12px;color:#636366;border-bottom:2px solid transparent;margin-bottom:-1px}
  .tab.active{color:#e5e5ea;border-bottom-color:#0a84ff}
  .feed{flex:1;overflow-y:auto;padding:10px}
  .feed-tab{display:none}
  .feed-tab.active{display:block}

  /* ── event cards ── */
  .ev{border-left:3px solid;border-radius:0 6px 6px 0;background:#1c1c1e;margin-bottom:6px;padding:8px 10px;display:grid;grid-template-columns:1fr auto;gap:2px}
  .ev-top{display:flex;align-items:center;gap:8px}
  .ev-alert{font-weight:600;font-size:12px}
  .ev-state{font-size:9px;font-weight:700;letter-spacing:.06em;padding:2px 6px;border-radius:3px;color:#000}
  .ev-score{font-size:10px;color:#636366}
  .ev-meta{font-size:10px;color:#636366;grid-column:1/-1;margin-top:3px}

  /* ── quarantine cards ── */
  .qv{border-left:3px solid #ff6b2b;border-radius:0 6px 6px 0;background:#1c1c1e;margin-bottom:6px;padding:8px 10px}
  .qv-top{display:flex;align-items:center;gap:8px;font-size:12px;font-weight:500}
  .qv-actions{display:flex;flex-wrap:wrap;gap:4px;margin-top:5px}
  .action-chip{font-size:10px;padding:2px 7px;border-radius:10px;background:#2c2c2e;color:#e5e5ea}
  .action-chip.highlight{background:#ff6b2b22;color:#ff6b2b;border:1px solid #ff6b2b55}

  /* ── attack log ── */
  .log-line{font-size:11px;color:#8e8e93;padding:1px 0;line-height:1.5}
  .log-line.start{color:#0a84ff;font-weight:600}
  .log-line.done{color:#30d158;font-weight:600}
  .log-line.err{color:#ff3b30}

  /* ── empty state ── */
  .empty{color:#3a3a3c;text-align:center;margin-top:60px;font-size:12px;line-height:2}

  ::-webkit-scrollbar{width:6px}
  ::-webkit-scrollbar-track{background:transparent}
  ::-webkit-scrollbar-thumb{background:#3a3a3c;border-radius:3px}
</style>
</head>
<body>
<header>
  <h1>⬡ Sentinel Demo</h1>
  <span id="vm-status">connecting…</span>
  <span style="flex:1"></span>
  <button onclick="clearAll()" style="background:#2c2c2e;border:none;color:#8e8e93;padding:4px 12px;border-radius:5px;cursor:pointer;font-size:11px">Clear</button>
</header>
<div class="main">
  <div class="attacks" id="attack-list"><!-- populated by JS --></div>
  <div class="panel">
    <div class="tabs">
      <div class="tab active" onclick="switchTab('events',this)">Detections</div>
      <div class="tab" onclick="switchTab('quarantine',this)">Quarantine Actions</div>
      <div class="tab" onclick="switchTab('log',this)">Attack Log</div>
    </div>
    <div class="feed">
      <div class="feed-tab active" id="tab-events">
        <div class="empty" id="ev-empty">← Detonate an attack to see live detections</div>
      </div>
      <div class="feed-tab" id="tab-quarantine">
        <div class="empty" id="qv-empty">Quarantine actions will appear here</div>
      </div>
      <div class="feed-tab" id="tab-log">
        <div class="empty" id="log-empty">Attack stdout will stream here</div>
      </div>
    </div>
  </div>
</div>
<script>
const STATE_COLOR = {
  FREEZE:"#ff3b30", ISOLATE:"#ff6b2b", THROTTLE:"#ffcc00",
  WARN:"#0a84ff", WATCH:"#636366", OK:"#30d158"
};

let attacks = [];
let sse = null;

async function init() {
  const res = await fetch('/api/attacks');
  attacks = await res.json();
  renderAttacks();
  connectSSE();
}

function renderAttacks() {
  const el = document.getElementById('attack-list');
  el.innerHTML = attacks.map(a => `
    <div class="atk" id="btn-${a.dir}" onclick="trigger('${a.dir}')">
      <span class="atk-id">${a.id}</span>
      <div class="atk-body">
        <div class="atk-label">${a.label}</div>
        <div class="atk-meta">${a.alert_type}</div>
      </div>
      <span class="badge" style="background:${a.color}">${a.expected_state}</span>
    </div>`).join('');
}

async function trigger(dir) {
  const btn = document.getElementById('btn-'+dir);
  if(btn.classList.contains('running')) return;
  btn.classList.add('running');
  btn.classList.remove('done');
  await fetch('/api/trigger/'+dir, {method:'POST'});
  switchTabByName('log');
}

function switchTab(name, el) {
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  document.querySelectorAll('.feed-tab').forEach(t=>t.classList.remove('active'));
  el.classList.add('active');
  document.getElementById('tab-'+name).classList.add('active');
}

function switchTabByName(name) {
  const tabs = document.querySelectorAll('.tab');
  const names = ['events','quarantine','log'];
  const idx = names.indexOf(name);
  if(idx>=0) switchTab(name, tabs[idx]);
}

function connectSSE() {
  if(sse) sse.close();
  sse = new EventSource('/api/stream');
  sse.onopen = () => {
    const s = document.getElementById('vm-status');
    s.textContent = '● live';
    s.className = 'live';
  };
  sse.onerror = () => {
    const s = document.getElementById('vm-status');
    s.textContent = 'reconnecting…';
    s.className = '';
    setTimeout(connectSSE, 3000);
  };
  sse.onmessage = e => {
    const msg = JSON.parse(e.data);
    if(msg.type==='event')      appendEvent(msg);
    if(msg.type==='quarantine') appendQuarantine(msg);
    if(msg.type==='attack_log') appendLog(msg);
    if(msg.type==='attack_start') appendLog({attack:msg.attack, line:`▶ Detonating ${msg.attack}…`, _cls:'start'});
    if(msg.type==='attack_done') {
      appendLog({attack:msg.attack, line:`✓ Attack complete`, _cls:'done'});
      const btn = document.getElementById('btn-'+msg.attack);
      if(btn){ btn.classList.remove('running'); btn.classList.add('done'); }
    }
  };
}

function appendEvent(msg) {
  document.getElementById('ev-empty').style.display='none';
  const col = STATE_COLOR[msg.state] || '#636366';
  const div = document.createElement('div');
  div.className = 'ev';
  div.style.borderColor = col;
  div.innerHTML = `
    <div class="ev-top">
      <span class="ev-alert">${msg.alert_type}</span>
      <span class="ev-state" style="background:${col}">${msg.state}</span>
      <span class="ev-score">score ${msg.score.toFixed(1)}</span>
    </div>
    <span class="ev-score" style="text-align:right">pid ${msg.pid}</span>
    <div class="ev-meta">comm: <b>${msg.comm}</b>${msg.syscall ? '  syscall: '+msg.syscall : ''}  source: ${msg.source}</div>`;
  const feed = document.getElementById('tab-events');
  feed.prepend(div);
}

function appendQuarantine(msg) {
  document.getElementById('qv-empty').style.display='none';
  const actions = msg.actions || [];
  const chips = actions.map(a => {
    const hi = a.includes('cgroup') || a.includes('throttl') || a.includes('freeze') || a.includes('kill');
    return `<span class="action-chip ${hi?'highlight':''}">${a}</span>`;
  }).join('');
  const div = document.createElement('div');
  div.className = 'qv';
  div.innerHTML = `
    <div class="qv-top">
      <span>pid ${msg.pid}</span>
      <span style="color:#636366">comm: <b style="color:#e5e5ea">${msg.comm}</b></span>
      <span style="color:#636366">${msg.prior_state} → quarantined</span>
      ${msg.success ? '<span style="color:#30d158">✓</span>' : '<span style="color:#ff3b30">✗</span>'}
      <span style="color:#636366;margin-left:auto">${parseFloat(msg.latency_ms).toFixed(1)}ms</span>
    </div>
    <div class="qv-actions">${chips || '<span class="action-chip">no actions</span>'}</div>`;
  const feed = document.getElementById('tab-quarantine');
  feed.prepend(div);
}

function appendLog(msg) {
  document.getElementById('log-empty').style.display='none';
  const div = document.createElement('div');
  div.className = 'log-line' + (msg._cls ? ' '+msg._cls : '');
  div.textContent = msg.line || '';
  const feed = document.getElementById('tab-log');
  feed.appendChild(div);
  feed.scrollTop = feed.scrollHeight;
}

function clearAll() {
  ['tab-events','tab-quarantine','tab-log'].forEach(id => {
    document.getElementById(id).innerHTML =
      `<div class="empty" id="${id.replace('tab-','')}-empty" style="display:block">Cleared</div>`;
  });
  document.querySelectorAll('.atk').forEach(b => b.classList.remove('done'));
}

init();
</script>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
def index():
    return HTML

# ── entrypoint ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    print("Sentinel Demo → http://localhost:8000")
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="warning")
