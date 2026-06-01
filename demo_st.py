#!/usr/bin/env python3
"""
Sentinel Demo  —  Streamlit
Usage:  source .venv/bin/activate && streamlit run demo_st.py
"""
import json
import os
import shlex
import subprocess
import tempfile
import threading
import time
from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

REPO = Path(__file__).parent

# ── attack catalogue ─────────────────────────────────────────────────────────
ATTACKS = [
    ("REP-01", "diamorphine_rootkit",  "Hidden PID",         "HiddenPID",           "FREEZE"),
    ("REP-02", "rep02_priv_esc",       "Priv Escalation",    "PrivilegeEscalation", "ISOLATE"),
    ("REP-04", "rep04_netcat_exfil",   "Network Exfil",      "NetworkAnomaly",      "THROTTLE"),
    ("REP-05", "rep05_webshell",       "Web Shell",          "ParentChildAnomaly",  "WARN"),
    ("REP-06", "rep06_cron_persist",   "Cron Persist",       "LSMFileWrite",        "WARN"),
    ("REP-07", "rep07_mmap_rwx",       "mmap RWX",           "MemoryInjection",     "WARN"),
    ("REP-08", "rep08_log_tamper",     "Log Tamper",         "LogTamper",           "WARN"),
    ("REP-09", "rep09_ld_preload",     "LD_PRELOAD Hijack",  "LSMFileWrite",        "WARN"),
    ("REP-10", "rep10_fork_bomb",      "Fork Bomb",          "SyscallAnomaly",      "WATCH"),
    ("REP-11", "rep11_ptrace",         "ptrace Inject",      "ProcessInjection",    "FREEZE"),
    ("REP-12", "rep12_ssh_brute",      "SSH Brute Force",    "NetworkAnomaly",      "THROTTLE"),
    ("REP-13", "rep13_fileless",       "Fileless Exec",      "MemoryInjection",     "WARN"),
    ("REP-14", "rep14_proc_hollow",    "Process Hollow",     "ProcessInjection",    "FREEZE"),
    ("REP-15", "rep15_reverse_shell",  "Reverse Shell",      "NetworkAnomaly",      "THROTTLE"),
    ("REP-16", "rep16_cred_harvest",   "Cred Harvest",       "LSMFileWrite",        "WARN"),
    ("REP-17", "rep17_finit_persist",  "Finit Persist",      "HiddenPID",           "FREEZE"),
    ("REP-18", "rep18_syscall_hook",   "Syscall Hook",       "HiddenPID",           "FREEZE"),
    ("REP-19", "rep19_ebpf_rootkit",   "eBPF Rootkit",       "ProcessInjection",    "FREEZE"),
    ("REP-20", "rep20_mem_stealer",    "Memory Stealer",     "ProcessInjection",    "FREEZE"),
    ("REP-21", "rep21_vm_escape",      "VM Escape",          "PrivilegeEscalation", "ISOLATE"),
]

STATE_COLOR = {
    "FREEZE":   "#ff3b30",
    "ISOLATE":  "#ff6b2b",
    "THROTTLE": "#f5a623",
    "WARN":     "#0a84ff",
    "WATCH":    "#8e8e93",
    "OK":       "#30d158",
}
# score thresholds that define each state band
STATE_THRESHOLDS = [
    (95,  100, "FREEZE",   "rgba(255,59,48,0.1)"),
    (85,  95,  "ISOLATE",  "rgba(255,107,43,0.1)"),
    (70,  85,  "THROTTLE", "rgba(245,166,35,0.1)"),
    (50,  70,  "WARN",     "rgba(10,132,255,0.09)"),
    (30,  50,  "WATCH",    "rgba(142,142,147,0.09)"),
    (0,   30,  "OK",       "rgba(48,209,88,0.09)"),
]

# ── SSH / VM helpers ──────────────────────────────────────────────────────────
@st.cache_resource(show_spinner="Connecting to VM…")
def setup_ssh():
    r = subprocess.run(
        ["vagrant", "ssh-config"],
        capture_output=True, text=True, cwd=REPO,
    )
    if r.returncode != 0 or not r.stdout.strip():
        return None, None

    tmp = tempfile.NamedTemporaryFile(
        mode="w", suffix=".conf", delete=False, prefix="sentinel_st_"
    )
    tmp.write(r.stdout)
    tmp.close()
    conf = tmp.name

    ctl = f"/tmp/sentinel_st_cm_{os.getpid()}.sock"
    subprocess.Popen(
        ["ssh", "-F", conf,
         "-o", "ControlMaster=yes",
         "-o", f"ControlPath={ctl}",
         "-o", "ControlPersist=yes",
         "-N", "default"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    time.sleep(1.2)
    return conf, ctl


def vm(cmd: str, timeout: int = 10) -> str:
    conf, ctl = setup_ssh()
    if not conf:
        return ""
    try:
        r = subprocess.run(
            ["ssh", "-F", conf,
             "-o", f"ControlPath={ctl}",
             "-o", "ControlMaster=no",
             "default", cmd],
            capture_output=True, text=True, timeout=timeout,
        )
        return r.stdout.strip()
    except Exception:
        return ""


def vm_sql(query: str) -> str:
    return vm(f"sudo sqlite3 /var/sentinel/events.db {shlex.quote(query)}")


def current_max_id() -> int:
    raw = vm_sql("SELECT COALESCE(MAX(id),0) FROM events;")
    return int(raw) if raw.isdigit() else 0


# ── data loaders ─────────────────────────────────────────────────────────────
def load_events(start_id: int) -> pd.DataFrame:
    raw = vm_sql(
        f"SELECT id, alert_type, score, state, pid, comm, timestamp, "
        f"COALESCE(json_extract(detail,'$.syscall_name'),'') AS syscall "
        f"FROM events WHERE id > {start_id} ORDER BY id;"
    )
    if not raw:
        return pd.DataFrame()
    rows = []
    for line in raw.splitlines():
        p = line.split("|", 7)
        if len(p) < 7:
            continue
        rows.append({
            "id":         int(p[0]),
            "alert_type": p[1],
            "score":      float(p[2]),
            "state":      p[3],
            "pid":        p[4],
            "comm":       p[5],
            "timestamp":  p[6],
            "syscall":    p[7] if len(p) > 7 else "",
        })
    return pd.DataFrame(rows) if rows else pd.DataFrame()


def load_quarantine(start_id: int) -> pd.DataFrame:
    raw = vm_sql(
        f"SELECT q.pid, q.comm, q.prior_state, q.actions, q.success, q.latency_ms "
        f"FROM quarantine_log q WHERE q.event_id > {start_id} ORDER BY q.id;"
    )
    if not raw:
        return pd.DataFrame()
    rows = []
    for line in raw.splitlines():
        p = line.split("|", 5)
        if len(p) < 5:
            continue
        try:
            actions = json.loads(p[3]) if p[3] and p[3] != "null" else []
        except Exception:
            actions = [p[3]] if p[3] else []
        rows.append({
            "pid":         p[0],
            "comm":        p[1],
            "prior_state": p[2],
            "actions":     ", ".join(actions) if actions else "—",
            "ok":          p[4] == "1",
            "latency_ms":  float(p[5]) if len(p) > 5 and p[5] else 0.0,
        })
    return pd.DataFrame(rows) if rows else pd.DataFrame()


# ── background attack runner ──────────────────────────────────────────────────
def _attack_thread(dir_name: str, conf: str, ctl: str,
                   log_lines: list, done_flag: list) -> None:
    try:
        proc = subprocess.Popen(
            ["ssh", "-F", conf,
             "-o", f"ControlPath={ctl}",
             "-o", "ControlMaster=no",
             "default",
             f"sudo bash /tmp/attacks/{dir_name}/run.sh 2>&1"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        for raw in proc.stdout:
            log_lines.append(raw.rstrip())
        proc.wait(timeout=120)
    except Exception as exc:
        log_lines.append(f"[error] {exc}")
    finally:
        done_flag[0] = True


# ── charts ────────────────────────────────────────────────────────────────────
def score_timeline(df: pd.DataFrame) -> go.Figure:
    fig = go.Figure()

    # state bands
    for lo, hi, label, fill in STATE_THRESHOLDS:
        fig.add_hrect(
            y0=lo, y1=hi,
            fillcolor=fill, line_width=0,
            annotation_text=label,
            annotation_position="right",
            annotation_font_size=9,
            annotation_font_color=STATE_COLOR.get(label, "#8e8e93"),
        )

    # one trace per pid so they're individually colored
    for pid, grp in df.groupby("pid"):
        comm = grp["comm"].iloc[0]
        fig.add_trace(go.Scatter(
            x=grp["id"],
            y=grp["score"],
            mode="lines+markers",
            name=f"pid {pid} ({comm})",
            line=dict(width=1.5),
            marker=dict(
                size=5,
                color=grp["score"],
                colorscale=[[0, "#30d158"], [0.3, "#0a84ff"],
                            [0.5, "#f5a623"], [0.7, "#ff6b2b"], [1, "#ff3b30"]],
                cmin=0, cmax=100,
            ),
            hovertemplate=(
                "event %{x}<br>score %{y:.1f}<br>"
                "syscall %{customdata[0]}<br>state %{customdata[1]}"
                "<extra>pid " + str(pid) + "</extra>"
            ),
            customdata=grp[["syscall", "state"]].values,
        ))

    fig.update_layout(
        height=300,
        margin=dict(l=0, r=80, t=10, b=0),
        plot_bgcolor="#0d0d0f",
        paper_bgcolor="#0d0d0f",
        font_color="#8e8e93",
        xaxis=dict(showgrid=False, title="event #", color="#48484a"),
        yaxis=dict(range=[0, 105], title="score", gridcolor="#2c2c2e",
                   color="#48484a"),
        legend=dict(bgcolor="#1c1c1e", font_size=10),
        showlegend=len(df["pid"].unique()) <= 8,
    )
    return fig


def syscall_chart(df: pd.DataFrame) -> go.Figure:
    sc = df[df["syscall"] != ""][["syscall", "score", "pid", "comm"]].copy()
    if sc.empty:
        return None
    agg = (
        sc.groupby("syscall")
        .agg(count=("syscall", "count"), avg_score=("score", "mean"))
        .reset_index()
        .sort_values("count", ascending=True)
    )
    fig = px.bar(
        agg, x="count", y="syscall", orientation="h",
        color="avg_score",
        color_continuous_scale=["#30d158", "#0a84ff", "#f5a623", "#ff6b2b", "#ff3b30"],
        range_color=[0, 100],
        labels={"count": "events", "avg_score": "avg score"},
    )
    fig.update_layout(
        height=max(180, len(agg) * 28 + 40),
        margin=dict(l=0, r=0, t=10, b=0),
        plot_bgcolor="#0d0d0f",
        paper_bgcolor="#0d0d0f",
        font_color="#8e8e93",
        xaxis=dict(showgrid=False, color="#48484a"),
        yaxis=dict(showgrid=False, color="#e5e5ea"),
        coloraxis_showscale=False,
    )
    return fig


def state_breakdown(df: pd.DataFrame) -> go.Figure:
    counts = df["state"].value_counts().reset_index()
    counts.columns = ["state", "n"]
    colors = [STATE_COLOR.get(s, "#636366") for s in counts["state"]]
    fig = go.Figure(go.Pie(
        labels=counts["state"], values=counts["n"],
        marker_colors=colors,
        hole=0.55,
        textinfo="label+percent",
        textfont_size=11,
    ))
    fig.update_layout(
        height=220,
        margin=dict(l=0, r=0, t=10, b=0),
        paper_bgcolor="#0d0d0f",
        font_color="#8e8e93",
        showlegend=False,
    )
    return fig


# ── page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Sentinel Demo",
    layout="wide",
    page_icon="⬡",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
[data-testid="stAppViewContainer"]{background:#0d0d0f}
[data-testid="stSidebar"]{background:#111113}
[data-testid="stSidebar"] *{color:#e5e5ea}
.stButton button{background:#1c1c1e;border:1px solid #2c2c2e;color:#e5e5ea;
  font-family:'SF Mono',monospace;font-size:12px;text-align:left;
  border-radius:6px;padding:6px 10px}
.stButton button:hover{border-color:#3a3a3c;background:#252528}
.stTabs [data-baseweb="tab"]{color:#636366;font-size:12px}
.stTabs [aria-selected="true"]{color:#e5e5ea}
div[data-testid="metric-container"]{background:#1c1c1e;border:1px solid #2c2c2e;
  border-radius:8px;padding:12px}
</style>
""", unsafe_allow_html=True)

# ── session state ─────────────────────────────────────────────────────────────
defaults = dict(selected=None, running=False, start_id=0, log=[], done=[False])
for k, v in defaults.items():
    if k not in st.session_state:
        st.session_state[k] = v

conf, ctl = setup_ssh()

# ── sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("### ⬡ Sentinel Demo")
    st.caption("eBPF · IsolationForest · cgroup enforcement")
    st.divider()

    busy = st.session_state.running
    if busy:
        atk_name = st.session_state.selected["label"]
        st.info(f"Running: **{atk_name}**…", icon="⏳")

    for atk_id, dir_name, label, alert_type, exp_state in ATTACKS:
        col_btn, col_badge = st.columns([5, 2])
        with col_btn:
            clicked = st.button(
                f"{atk_id}  {label}",
                key=f"btn_{dir_name}",
                use_container_width=True,
                disabled=busy,
            )
        with col_badge:
            c = STATE_COLOR.get(exp_state, "#636366")
            st.markdown(
                f'<p style="background:{c};color:#000;font-size:9px;font-weight:700;'
                f'padding:3px 5px;border-radius:3px;text-align:center;margin-top:6px">'
                f'{exp_state}</p>',
                unsafe_allow_html=True,
            )

        if clicked and not busy:
            st.session_state.start_id = current_max_id()
            st.session_state.log      = []
            st.session_state.done     = [False]
            st.session_state.running  = True
            st.session_state.selected = {
                "id": atk_id, "dir": dir_name, "label": label,
                "alert_type": alert_type, "exp_state": exp_state,
            }
            threading.Thread(
                target=_attack_thread,
                args=(dir_name, conf, ctl,
                      st.session_state.log, st.session_state.done),
                daemon=True,
            ).start()
            st.rerun()

# ── main panel ────────────────────────────────────────────────────────────────
if st.session_state.selected is None:
    st.markdown("## Select an attack →")
    st.caption(
        "Each button detonates a real attack inside the Vagrant VM. "
        "The eBPF daemon detects the syscalls in real time, scores them with "
        "Isolation Forest, and the quarantine manager constrains the process via cgroups."
    )
    st.stop()

atk   = st.session_state.selected
ecol  = STATE_COLOR.get(atk["exp_state"], "#8e8e93")

# header
st.markdown(
    f"## {atk['id']} — {atk['label']}"
    f"<span style='font-size:13px;color:{ecol};margin-left:12px'>"
    f"● {atk['exp_state']}</span>",
    unsafe_allow_html=True,
)
st.caption(f"Watching for **{atk['alert_type']}** events since the attack started")

# live data fetch
df   = load_events(st.session_state.start_id)
qdf  = load_quarantine(st.session_state.start_id)

# ── metrics ───────────────────────────────────────────────────────────────────
max_score  = float(df["score"].max())          if not df.empty else 0.0
top_state  = df.loc[df["score"].idxmax(), "state"] if not df.empty else "—"
top_alert  = df.loc[df["score"].idxmax(), "alert_type"] if not df.empty else "—"
n_ev       = len(df)
n_q        = len(qdf)
n_q_ok     = int(qdf["ok"].sum())              if not qdf.empty else 0

m1, m2, m3, m4, m5 = st.columns(5)
m1.metric("Max score",           f"{max_score:.1f}")
m2.metric("State reached",       top_state)
m3.metric("Alert type",          top_alert)
m4.metric("Total events",        n_ev)
m5.metric("Quarantine actions",  f"{n_q_ok} / {n_q}")

st.divider()

# ── tabs ──────────────────────────────────────────────────────────────────────
t1, t2, t3, t4 = st.tabs(["📈 Score timeline", "⚙️ Syscall breakdown",
                            "🔒 Quarantine", "📋 Attack log"])

with t1:
    if df.empty:
        st.caption("No events yet — waiting for detections…")
    else:
        st.plotly_chart(score_timeline(df), use_container_width=True)
        # state distribution alongside
        pie_col, _ = st.columns([1, 2])
        with pie_col:
            st.plotly_chart(state_breakdown(df), use_container_width=True)

with t2:
    if df.empty:
        st.caption("No events yet.")
    else:
        fig_sc = syscall_chart(df)
        if fig_sc:
            st.plotly_chart(fig_sc, use_container_width=True)
        else:
            st.caption("No syscall data in these events.")

        # top PIDs table
        st.markdown("**Top processes**")
        top_pids = (
            df.groupby(["pid", "comm"])
            .agg(events=("id", "count"), max_score=("score", "max"),
                 worst_state=("state", lambda s: s.iloc[s.map(
                     lambda x: ["OK","WATCH","WARN","THROTTLE","ISOLATE","FREEZE"]
                     .index(x) if x in ["OK","WATCH","WARN","THROTTLE","ISOLATE","FREEZE"]
                     else 0).argmax()]))
            .reset_index()
            .sort_values("max_score", ascending=False)
            .head(10)
        )
        st.dataframe(
            top_pids.rename(columns={
                "pid": "PID", "comm": "process", "events": "events",
                "max_score": "max score", "worst_state": "state"
            }),
            use_container_width=True, hide_index=True,
        )

with t3:
    if qdf.empty:
        st.caption("No quarantine actions yet.")
    else:
        # summary chips
        all_actions = []
        for row in qdf["actions"]:
            all_actions.extend([a.strip() for a in row.split(",") if a.strip()])
        from collections import Counter
        action_counts = Counter(all_actions)

        cols = st.columns(min(len(action_counts), 4))
        for i, (action, count) in enumerate(action_counts.most_common()):
            hot = any(k in action for k in ["cgroup", "throttl", "freeze", "kill", "isolat"])
            color = "#ff6b2b" if hot else "#30d158"
            cols[i % len(cols)].markdown(
                f'<div style="background:{color}22;border:1px solid {color}55;'
                f'border-radius:6px;padding:8px 12px;text-align:center;margin-bottom:8px">'
                f'<div style="font-size:18px;font-weight:700;color:{color}">{count}</div>'
                f'<div style="font-size:10px;color:#8e8e93">{action}</div></div>',
                unsafe_allow_html=True,
            )

        st.markdown("**Full quarantine log**")
        display_qdf = qdf.copy()
        display_qdf["ok"] = display_qdf["ok"].map({True: "✓", False: "✗ miss"})
        display_qdf["latency_ms"] = display_qdf["latency_ms"].map(lambda x: f"{x:.1f} ms")
        st.dataframe(
            display_qdf.rename(columns={
                "pid": "PID", "comm": "process", "prior_state": "state when caught",
                "actions": "actions taken", "ok": "result", "latency_ms": "latency"
            }),
            use_container_width=True, hide_index=True,
        )

with t4:
    log = st.session_state.log
    if log:
        st.code("\n".join(log), language="bash")
    else:
        if st.session_state.running:
            st.caption("Attack is starting…")
        else:
            st.caption("No log output.")

# ── live rerun while attack is running ────────────────────────────────────────
if st.session_state.running:
    if st.session_state.done[0]:
        st.session_state.running = False
        st.rerun()
    else:
        with st.spinner("Attack running in VM…"):
            time.sleep(1.5)
        st.rerun()
