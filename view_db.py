#!/usr/bin/env python3

from __future__ import annotations

import argparse
import curses
import sqlite3
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

P_HEADER    = 1
P_FOOTER    = 2
P_SB_SEL    = 3
P_SB_CUR    = 4
P_FREEZE    = 5
P_THROTTLE  = 6
P_WARN      = 7
P_WATCH     = 8
P_ISOLATE   = 9
P_COL_HDR   = 10
P_ROW_SEL   = 11
P_SCORE_HI  = 12
P_SCORE_MED = 13
P_SCORE_LO  = 14
P_RED_TEXT  = 15
P_MAG_TEXT  = 16
P_YEL_TEXT  = 17
P_NORM      = 18

TABS = ["Events", "Quarantine", "Summary"]

SIDEBAR_W = 27

STATE_PAIR = {
    "FREEZE":   P_FREEZE,
    "ISOLATE":  P_ISOLATE,
    "THROTTLE": P_THROTTLE,
    "WARN":     P_WARN,
    "WATCH":    P_WATCH,
}

STATE_ICON = {
    "FREEZE":   "●",
    "ISOLATE":  "●",
    "THROTTLE": "▲",
    "WARN":     "▼",
    "WATCH":    "○",
}

ALERT_PAIR = {
    "HiddenPID":           P_RED_TEXT,
    "ProcessInjection":    P_RED_TEXT,
    "MemoryInjection":     P_MAG_TEXT,
    "NetworkAnomaly":      P_YEL_TEXT,
    "PrivilegeEscalation": P_SCORE_LO,
    "LSMFileWrite":        P_SCORE_LO,
    "LogTamper":           P_SCORE_LO,
    "ParentChildAnomaly":  P_MAG_TEXT,
    "SyscallAnomaly":      P_WATCH,
}


def _setup_colours() -> None:
    curses.start_color()
    curses.use_default_colors()
    bg = -1
    curses.init_pair(P_HEADER,    curses.COLOR_WHITE,   curses.COLOR_BLUE)
    curses.init_pair(P_FOOTER,    curses.COLOR_WHITE,   curses.COLOR_BLUE)
    curses.init_pair(P_SB_SEL,    curses.COLOR_BLACK,   curses.COLOR_CYAN)
    curses.init_pair(P_SB_CUR,    curses.COLOR_BLACK,   curses.COLOR_GREEN)
    curses.init_pair(P_FREEZE,    curses.COLOR_WHITE,   curses.COLOR_RED)
    curses.init_pair(P_THROTTLE,  curses.COLOR_BLACK,   curses.COLOR_YELLOW)
    curses.init_pair(P_WARN,      curses.COLOR_WHITE,   curses.COLOR_BLUE)
    curses.init_pair(P_WATCH,     curses.COLOR_WHITE,   bg)
    curses.init_pair(P_ISOLATE,   curses.COLOR_YELLOW,  curses.COLOR_RED)
    curses.init_pair(P_COL_HDR,   curses.COLOR_BLACK,   curses.COLOR_WHITE)
    curses.init_pair(P_ROW_SEL,   curses.COLOR_WHITE,   curses.COLOR_BLUE)
    curses.init_pair(P_SCORE_HI,  curses.COLOR_RED,     bg)
    curses.init_pair(P_SCORE_MED, curses.COLOR_YELLOW,  bg)
    curses.init_pair(P_SCORE_LO,  curses.COLOR_CYAN,    bg)
    curses.init_pair(P_RED_TEXT,  curses.COLOR_RED,     bg)
    curses.init_pair(P_MAG_TEXT,  curses.COLOR_MAGENTA, bg)
    curses.init_pair(P_YEL_TEXT,  curses.COLOR_YELLOW,  bg)
    curses.init_pair(P_NORM,      curses.COLOR_WHITE,   bg)


def cp(pid: int) -> int:
    return curses.color_pair(pid)


def wstr(win, y: int, x: int, text: str, attr: int = 0, maxw: int = 0) -> None:
    try:
        h, w = win.getmaxyx()
        if y < 0 or y >= h or x < 0 or x >= w:
            return
        avail = min(w - x - 1, maxw) if maxw > 0 else w - x - 1
        if avail <= 0:
            return
        win.addstr(y, x, text[:avail], attr)
    except curses.error:
        pass


def hfill(win, y: int, x: int, w: int, attr: int) -> None:
    try:
        _, sw = win.getmaxyx()
        avail = min(w, sw - x - 1)
        if avail > 0:
            win.addstr(y, x, " " * avail, attr)
    except curses.error:
        pass


def score_bar(score: float, width: int = 8) -> str:
    filled = max(0, min(width, int(score / 100 * width)))
    return "█" * filled + "░" * (width - filled)


def fmt_ts(raw: str) -> str:
    try:
        return datetime.fromisoformat(raw).strftime("%m-%d %H:%M:%S")
    except Exception:
        return str(raw)[:14]


def _query(db: Path, sql: str) -> list[dict]:
    if not db.exists():
        return []
    try:
        conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(sql).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception:
        return []


def load_events(db: Path) -> list[dict]:
    return _query(db, "SELECT * FROM events ORDER BY id")


def load_quarantine(db: Path) -> list[dict]:
    return _query(db, "SELECT * FROM quarantine_log ORDER BY id")


def find_dbs(path: Path) -> list[tuple[str, Path]]:
    if path.is_file():
        return [(path.name, path)]
    if path.is_dir():
        dbs = sorted(path.rglob("events.db"))
        if dbs:
            return [(db.parent.name, db) for db in dbs]
        runs = sorted(path.glob("run_*/"), reverse=True)
        result = []
        for r in runs:
            last = sorted(r.rglob("events.db"))
            if last:
                result.append((r.name, last[-1]))
        return result
    return []


def find_latest() -> list[tuple[str, Path]]:
    results = Path("results")
    if not results.exists():
        return []
    runs = sorted(results.glob("run_*/"), reverse=True)
    return find_dbs(runs[0]) if runs else []


class Viewer:
    EV_COLS = [
        ("ID",         5,  "id"),
        ("TIME",      14,  "timestamp"),
        ("ALERT_TYPE",22,  "alert_type"),
        ("SCORE",     15,  "score"),
        ("STATE",     10,  "state"),
        ("PID",        7,  "pid"),
        ("COMM",      14,  "comm"),
    ]

    QR_COLS = [
        ("EV",     5,  "event_id"),
        ("PID",    7,  "pid"),
        ("COMM",  14,  "comm"),
        ("STATE", 10,  "prior_state"),
        ("ACTIONS",32, "actions"),
        ("OK",     3,  "success"),
        ("MS",     8,  "latency_ms"),
    ]

    def __init__(self, db_files: list[tuple[str, Path]]) -> None:
        self.db_files    = db_files
        self.db_idx      = 0
        self.tab         = 0
        self.focus       = "table"
        self.row         = 0
        self.offset      = 0
        self.sb_row      = 0
        self.sb_off      = 0
        self.events:     list[dict] = []
        self.quarantine: list[dict] = []
        self.status      = ""

        for i, (lbl, _) in enumerate(db_files):
            if "99_final" in lbl or "final" in lbl.lower():
                self.db_idx = self.sb_row = i
                break

    def run(self) -> None:
        curses.wrapper(self._main)

    def _main(self, scr: curses.window) -> None:
        _setup_colours()
        curses.curs_set(0)
        try:
            curses.set_escdelay(25)
        except Exception:
            pass
        scr.keypad(True)
        self._scr = scr
        self._load()
        while True:
            h, w = scr.getmaxyx()
            scr.erase()
            self._draw(scr, h, w)
            scr.refresh()
            key = scr.getch()
            if not self._handle(key):
                break

    def _load(self) -> None:
        _, db = self.db_files[self.db_idx]
        self.events     = load_events(db)
        self.quarantine = load_quarantine(db)
        self.row = self.offset = 0
        lbl, _ = self.db_files[self.db_idx]
        self.status = f"{lbl} — {len(self.events)} event(s)"

    def _cur_rows(self) -> list[dict]:
        return self.events if self.tab == 0 else self.quarantine

    def _draw(self, scr: curses.window, h: int, w: int) -> None:
        self._draw_header(scr, w)
        self._draw_footer(scr, h, w)

        has_sb  = len(self.db_files) > 1
        main_x  = SIDEBAR_W if has_sb else 0
        main_w  = w - main_x

        if has_sb:
            self._draw_sidebar(scr, h)
            for y in range(1, h - 1):
                wstr(scr, y, SIDEBAR_W - 1, "│", cp(P_NORM))

        self._draw_tabbar(scr, 1, main_x, main_w)

        detail_y = h - 6
        wstr(scr, detail_y - 1, main_x, "─" * (main_w - 1), cp(P_NORM) | curses.A_DIM)
        self._draw_detail(scr, detail_y, main_x, main_w)

        t_top = 2
        t_h   = detail_y - 1 - t_top
        if   self.tab == 0: self._draw_events(scr, t_top, main_x, t_h, main_w)
        elif self.tab == 1: self._draw_table(scr, t_top, main_x, t_h, main_w,
                                              self.QR_COLS, self.quarantine, self.tab)
        else:               self._draw_summary(scr, t_top, main_x, t_h, main_w)

    def _draw_header(self, scr, w):
        a = cp(P_HEADER) | curses.A_BOLD
        hfill(scr, 0, 0, w, a)
        lbl, db = self.db_files[self.db_idx]
        wstr(scr, 0, 1, "SENTINEL DB VIEWER", a)
        wstr(scr, 0, 20, f"  {lbl}", cp(P_HEADER))
        counts = f"ev:{len(self.events)}  q:{len(self.quarantine)}"
        wstr(scr, 0, w - len(counts) - 2, counts, cp(P_HEADER))

    def _draw_footer(self, scr, h, w):
        a = cp(P_FOOTER)
        hfill(scr, h - 1, 0, w, a)
        keys = " q:quit  Tab:focus  ↑↓:nav  PgUp/Dn  1-3:tab  r:reload  Enter:load"
        wstr(scr, h - 1, 0, keys, a)
        if self.status:
            wstr(scr, h - 1, w - len(self.status) - 2, self.status, a | curses.A_BOLD)

    def _draw_sidebar(self, scr, h):
        ta = cp(P_COL_HDR) | curses.A_BOLD
        hfill(scr, 1, 0, SIDEBAR_W - 1, ta)
        wstr(scr, 1, 1, "DB FILES", ta)

        visible = h - 3
        if self.sb_row < self.sb_off:
            self.sb_off = self.sb_row
        elif self.sb_row >= self.sb_off + visible:
            self.sb_off = self.sb_row - visible + 1

        for i, (lbl, _) in enumerate(self.db_files):
            vi = i - self.sb_off
            if vi < 0 or vi >= visible:
                continue
            y = 2 + vi
            is_cur  = (i == self.db_idx)
            is_curs = (i == self.sb_row and self.focus == "sidebar")
            if is_curs:
                a = cp(P_SB_SEL) | curses.A_BOLD
            elif is_cur:
                a = cp(P_SB_CUR) | curses.A_BOLD
            else:
                a = cp(P_NORM)
            hfill(scr, y, 0, SIDEBAR_W - 1, a)
            prefix = "▶ " if is_cur else "  "
            wstr(scr, y, 0, prefix + lbl[:SIDEBAR_W - 4], a, SIDEBAR_W - 1)

    def _draw_tabbar(self, scr, y, x, w):
        ba = cp(P_COL_HDR)
        hfill(scr, y, x, w, ba)
        cx = x + 1
        for i, tab in enumerate(TABS):
            lbl = f" {tab} "
            a = cp(P_ROW_SEL) | curses.A_BOLD if i == self.tab else ba
            wstr(scr, y, cx, lbl, a)
            cx += len(lbl) + 1

    def _draw_events(self, scr, top_y, x, h, w):
        cols = self.EV_COLS
        ha = cp(P_COL_HDR) | curses.A_BOLD
        hfill(scr, top_y, x, w, ha)
        cx = x
        for hdr, cw, _ in cols:
            wstr(scr, top_y, cx, hdr[:cw].ljust(cw), ha, cw)
            cx += cw

        rows   = self.events
        vis    = h - 1
        self._clamp_scroll(len(rows), vis)

        for vi in range(vis):
            ri = vi + self.offset
            if ri >= len(rows):
                break
            ev  = rows[ri]
            ry  = top_y + 1 + vi
            sel = (self.focus == "table" and self.tab == 0 and ri == self.row)
            base = cp(P_ROW_SEL) if sel else cp(P_NORM)
            hfill(scr, ry, x, w, base)
            cx = x
            for _, cw, key in cols:
                self._ev_cell(scr, ry, cx, cw, key, ev, base, sel)
                cx += cw

        self._scrollbar(scr, top_y + 1, x + w - 2, vis, len(rows), self.offset)

    def _ev_cell(self, scr, y, x, cw, key, ev, base, sel):
        v = ev.get(key, "")
        if key == "id":
            wstr(scr, y, x, str(v).rjust(4), base | curses.A_DIM, cw)

        elif key == "timestamp":
            wstr(scr, y, x, fmt_ts(str(v)), base | curses.A_DIM, cw)

        elif key == "alert_type":
            a = base | curses.A_BOLD if sel else cp(ALERT_PAIR.get(str(v), P_NORM)) | curses.A_BOLD
            wstr(scr, y, x, str(v)[:cw].ljust(cw), a, cw)

        elif key == "score":
            score = float(v or 0)
            bar   = score_bar(score, 8)
            if sel:
                sa = base
            elif score >= 90:
                sa = cp(P_SCORE_HI) | curses.A_BOLD
            elif score >= 70:
                sa = cp(P_SCORE_MED)
            else:
                sa = cp(P_SCORE_LO)
            wstr(scr, y, x,     bar,             sa, 8)
            wstr(scr, y, x + 9, f"{score:5.1f}", sa, 5)

        elif key == "state":
            state = str(v)
            icon  = STATE_ICON.get(state, " ")
            sp    = STATE_PAIR.get(state, P_NORM)
            sa    = base | curses.A_BOLD if sel else cp(sp) | curses.A_BOLD
            wstr(scr, y, x, f"{icon}{state}"[:cw].ljust(cw), sa, cw)

        elif key == "pid":
            wstr(scr, y, x, str(v).rjust(6), base | curses.A_DIM, cw)

        elif key == "comm":
            wstr(scr, y, x, str(v)[:cw], base | curses.A_BOLD, cw)

    def _draw_table(self, scr, top_y, x, h, w, cols, rows, tab_id):
        ha = cp(P_COL_HDR) | curses.A_BOLD
        hfill(scr, top_y, x, w, ha)
        cx = x
        for hdr, cw, _ in cols:
            wstr(scr, top_y, cx, hdr[:cw].ljust(cw), ha, cw)
            cx += cw

        vis = h - 1
        self._clamp_scroll(len(rows), vis)

        for vi in range(vis):
            ri = vi + self.offset
            if ri >= len(rows):
                break
            r   = rows[ri]
            ry  = top_y + 1 + vi
            sel = (self.focus == "table" and self.tab == tab_id and ri == self.row)
            base = cp(P_ROW_SEL) if sel else cp(P_NORM)
            hfill(scr, ry, x, w, base)
            cx = x
            for _, cw, key in cols:
                self._qr_cell(scr, ry, cx, cw, key, r, base, sel)
                cx += cw

        self._scrollbar(scr, top_y + 1, x + w - 2, vis, len(rows), self.offset)

    def _qr_cell(self, scr, y, x, cw, key, r, base, sel):
        v = r.get(key, "")
        if key == "prior_state":
            state = str(v)
            sp = STATE_PAIR.get(state, P_NORM)
            sa = base | curses.A_BOLD if sel else cp(sp) | curses.A_BOLD
            wstr(scr, y, x, state[:cw].ljust(cw), sa, cw)
        elif key == "success":
            ok = bool(v)
            sa = base if sel else (cp(P_SCORE_LO) | curses.A_BOLD if ok else cp(P_SCORE_HI))
            wstr(scr, y, x, "✓" if ok else "✗", sa, cw)
        elif key == "latency_ms":
            wstr(scr, y, x, f"{float(v or 0):.1f}ms"[:cw], base | curses.A_DIM, cw)
        else:
            wstr(scr, y, x, str(v or "")[:cw], base | curses.A_DIM if key != "comm" else base | curses.A_BOLD, cw)

    def _draw_summary(self, scr, top_y, x, h, w):
        n  = cp(P_NORM)
        bo = n | curses.A_BOLD
        di = n | curses.A_DIM
        y  = top_y

        if not self.events:
            wstr(scr, y, x + 2, "No events.", di)
            return

        by_type  = Counter(e["alert_type"] for e in self.events)
        by_state = Counter(e["state"]      for e in self.events)
        scores   = [float(e.get("score", 0)) for e in self.events]
        max_s, avg_s = max(scores), sum(scores) / len(scores)

        def row(label, val, va=None):
            nonlocal y
            if y >= top_y + h: return
            wstr(scr, y, x + 2, f"{label:<16}", bo)
            wstr(scr, y, x + 18, str(val), va or n)
            y += 1

        row("Total events :", len(self.events))
        row("Peak score   :", f"{max_s:.1f}",
            cp(P_SCORE_HI) | curses.A_BOLD if max_s >= 90 else
            cp(P_SCORE_MED) if max_s >= 70 else cp(P_SCORE_LO))
        row("Avg score    :", f"{avg_s:.1f}")
        row("Quarantine   :", f"{len(self.quarantine)} actions")
        y += 1

        if y < top_y + h:
            wstr(scr, y, x + 2, "── By Alert Type ──────────────────", bo)
            y += 1
        for atype, count in by_type.most_common():
            if y >= top_y + h: break
            aa = cp(ALERT_PAIR.get(atype, P_NORM)) | curses.A_BOLD
            wstr(scr, y, x + 4,  f"{atype:<24}", aa, 24)
            wstr(scr, y, x + 29, f"× {count}", n)
            y += 1

        y += 1
        if y < top_y + h:
            wstr(scr, y, x + 2, "── By State ────────────────────────", bo)
            y += 1
        for state in ("FREEZE", "ISOLATE", "THROTTLE", "WARN", "WATCH"):
            cnt = by_state.get(state, 0)
            if cnt and y < top_y + h:
                sa = cp(STATE_PAIR.get(state, P_NORM)) | curses.A_BOLD
                icon = STATE_ICON.get(state, " ")
                wstr(scr, y, x + 4,  f"{icon} {state:<10}", sa, 14)
                wstr(scr, y, x + 19, f"× {cnt}", n)
                y += 1

    def _draw_detail(self, scr, y, x, w):
        rows = self._cur_rows()
        n  = cp(P_NORM)
        bo = n | curses.A_BOLD
        di = n | curses.A_DIM

        if not rows or self.row >= len(rows):
            wstr(scr, y, x + 1, "[ select a row to see details ]", di)
            return

        ev = rows[self.row]

        if self.tab == 0:
            state = ev.get("state", "")
            sp    = STATE_PAIR.get(state, P_NORM)
            score = float(ev.get("score", 0))
            if score >= 90:   sa = cp(P_SCORE_HI)  | curses.A_BOLD
            elif score >= 70: sa = cp(P_SCORE_MED)
            else:             sa = cp(P_SCORE_LO)

            wstr(scr, y,   x+1, f"id={ev.get('id','')}  ", bo)
            atype = str(ev.get("alert_type", ""))
            wstr(scr, y,   x+9, atype,
                 cp(ALERT_PAIR.get(atype, P_NORM)) | curses.A_BOLD)
            wstr(scr, y,   x+9+len(atype)+2, f"score={score:.1f}", sa)
            wstr(scr, y,   x+9+len(atype)+16, "state=", bo)
            wstr(scr, y,   x+9+len(atype)+22, f" {state} ",
                 cp(sp) | curses.A_BOLD)

            wstr(scr, y+1, x+1, f"pid={ev.get('pid','')}  "
                 f"comm={ev.get('comm','')}  "
                 f"uid={ev.get('uid','')}  "
                 f"ts={fmt_ts(str(ev.get('timestamp','')))}",
                 di, w - 3)

            detail = str(ev.get("detail") or "")
            wstr(scr, y+2, x+1, f"detail: {detail}", di, w - 3)

            fname = str(ev.get("fname") or "")
            if fname:
                wstr(scr, y+3, x+1, f"fname:  {fname}", di, w - 3)

        else:
            state = ev.get("prior_state", "")
            sp    = STATE_PAIR.get(str(state), P_NORM)
            wstr(scr, y,   x+1, f"event_id={ev.get('event_id','')}  "
                 f"pid={ev.get('pid','')}  comm={ev.get('comm','')}", bo)
            wstr(scr, y+1, x+1, f"prior_state=",         bo)
            wstr(scr, y+1, x+13, f" {state} ",
                 cp(sp) | curses.A_BOLD)
            wstr(scr, y+2, x+1, f"actions: {ev.get('actions','')}", di, w - 3)
            ok = bool(ev.get("success"))
            lat = float(ev.get("latency_ms") or 0)
            wstr(scr, y+3, x+1,
                 f"success={'yes' if ok else 'no'}  latency={lat:.1f}ms  "
                 f"ts={fmt_ts(str(ev.get('timestamp','')))}",
                 (cp(P_SCORE_LO) if ok else cp(P_SCORE_HI)) | curses.A_BOLD)

    def _scrollbar(self, scr, y, x, vis, total, offset):
        if total <= vis or vis <= 0:
            return
        bar_h = max(1, vis * vis // total)
        bar_y = offset * (vis - bar_h) // max(1, total - vis)
        for i in range(vis):
            ch = "▓" if bar_y <= i < bar_y + bar_h else "░"
            wstr(scr, y + i, x, ch, cp(P_NORM) | curses.A_DIM)

    def _clamp_scroll(self, n: int, vis: int) -> None:
        if self.row < self.offset:
            self.offset = self.row
        elif self.row >= self.offset + vis:
            self.offset = self.row - vis + 1
        self.offset = max(0, min(self.offset, max(0, n - vis)))

    def _handle(self, key: int) -> bool:
        if key in (ord("q"), ord("Q"), 27):
            return False

        if key == ord("\t"):
            self.focus = "table" if self.focus == "sidebar" else "sidebar"
            return True

        if key == ord("r"):
            self._load()
            return True

        if key in (ord("1"), ord("2"), ord("3")):
            self.tab    = key - ord("1")
            self.row    = 0
            self.offset = 0
            self.focus  = "table"
            return True

        n = len(self._cur_rows())

        if self.focus == "sidebar":
            if key == curses.KEY_UP:
                self.sb_row = max(0, self.sb_row - 1)
            elif key == curses.KEY_DOWN:
                self.sb_row = min(len(self.db_files) - 1, self.sb_row + 1)
            elif key in (curses.KEY_ENTER, 10, 13):
                if self.sb_row != self.db_idx:
                    self.db_idx = self.sb_row
                    self._load()
                self.focus = "table"
        else:
            if key == curses.KEY_UP:
                self.row = max(0, self.row - 1)
            elif key == curses.KEY_DOWN:
                self.row = min(n - 1, self.row + 1)
            elif key == curses.KEY_PPAGE:
                self.row = max(0, self.row - 10)
            elif key == curses.KEY_NPAGE:
                self.row = min(max(0, n - 1), self.row + 10)
            elif key == curses.KEY_HOME:
                self.row = self.offset = 0
            elif key == curses.KEY_END:
                self.row = max(0, n - 1)

        return True


def main() -> None:
    ap = argparse.ArgumentParser(description="Sentinel SQLite DB Viewer")
    ap.add_argument("path", nargs="?", help="Run dir, results root, or .db file")
    ap.add_argument("--all", action="store_true",
                    help="Show all runs from results/ in the sidebar")
    args = ap.parse_args()

    if args.all:
        dbs = find_dbs(Path("results"))
    elif args.path:
        dbs = find_dbs(Path(args.path))
    else:
        dbs = find_latest()

    if not dbs:
        print("No events.db found. Specify a path or run attacks first.")
        sys.exit(1)

    Viewer(dbs).run()


if __name__ == "__main__":
    main()
