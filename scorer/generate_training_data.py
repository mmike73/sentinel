#!/usr/bin/env python3
import argparse
import csv
import math
import os
import random
import sys
import urllib.request
import urllib.error
from datetime import datetime, timedelta
from pathlib import Path

SYSCALL_INDEX = {
    1: 0, 9: 1, 10: 2, 41: 3, 42: 4, 49: 5, 56: 6, 59: 7,
    62: 8, 101: 9, 103: 10, 105: 11, 106: 12, 126: 13, 175: 14,
    176: 15, 257: 16, 263: 17, 313: 18, 316: 19, 322: 20,
}

RISK_WEIGHTS = {
    1: 5, 9: 40, 10: 45, 41: 10, 42: 15, 49: 10, 56: 5, 59: 20,
    62: 5, 101: 75, 103: 5, 105: 70, 106: 70, 126: 70, 175: 95,
    176: 85, 257: 5, 263: 5, 313: 95, 316: 5, 322: 20,
}

FIELDNAMES = [
    "syscall_nr", "uid", "pid", "hour", "is_weekend",
    "log_pid", "risk_weight", "label", "source",
]

ADFA_LD_MIRRORS = [
    "https://raw.githubusercontent.com/verazuo/a-label-for-ADFA-LD-dataset/master/ADFA-LD/Attack_Data_Master/Adduser_1",
    "https://raw.githubusercontent.com/verazuo/a-label-for-ADFA-LD-dataset/master/ADFA-LD/Attack_Data_Master/Hydra_FTP_1",
    "https://raw.githubusercontent.com/verazuo/a-label-for-ADFA-LD-dataset/master/ADFA-LD/Attack_Data_Master/Hydra_SSH_1",
    "https://raw.githubusercontent.com/verazuo/a-label-for-ADFA-LD-dataset/master/ADFA-LD/Attack_Data_Master/Java_Meterpreter_1",
    "https://raw.githubusercontent.com/verazuo/a-label-for-ADFA-LD-dataset/master/ADFA-LD/Attack_Data_Master/Meterpreter_1",
    "https://raw.githubusercontent.com/verazuo/a-label-for-ADFA-LD-dataset/master/ADFA-LD/Training_Data_Master/0",
    "https://raw.githubusercontent.com/verazuo/a-label-for-ADFA-LD-dataset/master/ADFA-LD/Training_Data_Master/1",
    "https://raw.githubusercontent.com/verazuo/a-label-for-ADFA-LD-dataset/master/ADFA-LD/Training_Data_Master/2",
    "https://raw.githubusercontent.com/verazuo/a-label-for-ADFA-LD-dataset/master/ADFA-LD/Training_Data_Master/3",
    "https://raw.githubusercontent.com/verazuo/a-label-for-ADFA-LD-dataset/master/ADFA-LD/Training_Data_Master/4",
]

def _is_attack_url(url: str) -> bool:
    return "Attack_Data_Master" in url


def _fetch_url(url: str, timeout: int = 10) -> list[int]:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            text = resp.read().decode("utf-8", errors="replace")
        return [int(t) for t in text.split() if t.isdigit()]
    except (urllib.error.URLError, ValueError, TimeoutError) as exc:
        print(f"  [skip] {url.split('/')[-1]}: {exc}", file=sys.stderr)
        return []


def make_row(syscall_nr: int, uid: int, pid: int,
             ts: datetime, label: int, source: str) -> dict:
    return {
        "syscall_nr":   syscall_nr,
        "uid":          uid,
        "pid":          pid,
        "hour":         ts.hour,
        "is_weekend":   1 if ts.weekday() >= 5 else 0,
        "log_pid":      round(math.log10(max(pid, 1)) / 6.0, 6),
        "risk_weight":  RISK_WEIGHTS.get(syscall_nr, 5),
        "label":        label,
        "source":       source,
    }


NORMAL_PROFILES = [
    (30, 59,  [1000, 1001, 1002], (1000, 30000), (7, 22)),
    (25, 257, [1000, 0],          (500, 30000),  (0, 23)),
    (15, 1,   [1000, 0],          (500, 30000),  (0, 23)),
    (10, 56,  [1000, 0],          (1000, 20000), (8, 18)),
    ( 8, 42,  [0, 1000],          (1000, 20000), (8, 18)),
    ( 5, 41,  [0, 1000],          (1000, 20000), (8, 18)),
    ( 4, 103, [0],                (500, 5000),   (0, 23)),
    ( 3, 49,  [0],                (500, 5000),   (0, 23)),
]

_PROFILE_WEIGHTS = [p[0] for p in NORMAL_PROFILES]
_PROFILE_SUM     = sum(_PROFILE_WEIGHTS)


def synthetic_normal(n: int = 5000, seed: int = 42) -> list[dict]:
    rng = random.Random(seed)
    base = datetime(2026, 1, 1, 8, 0, 0)
    rows = []
    for i in range(n):
        r = rng.random() * _PROFILE_SUM
        cumul = 0.0
        profile = NORMAL_PROFILES[-1]
        for p in NORMAL_PROFILES:
            cumul += p[0]
            if r < cumul:
                profile = p
                break
        _, nr, uids, pid_range, hour_range = profile
        uid  = rng.choice(uids)
        pid  = rng.randint(*pid_range)
        hour = rng.randint(*hour_range)
        ts   = base + timedelta(days=i // 200, hours=hour, minutes=rng.randint(0, 59))
        rows.append(make_row(nr, uid, pid, ts, label=0, source="synthetic_normal"))
    return rows


ATTACK_PROFILES = [
    (15, 175, 0,    "insmod → HiddenPID"),
    (15, 313, 0,    "finit_module → HiddenPID"),
    (10, 101, 1000, "ptrace → ProcessInjection"),
    (10, 105, 1000, "setuid → PrivilegeEscalation"),
    (10, 126, 1000, "capset → PrivilegeEscalation"),
    (10, 9,   1000, "mmap RWX → MemoryInjection"),
    (10, 10,  1000, "mprotect → MemoryInjection"),
    ( 8, 41,  0,    "socket burst → NetworkAnomaly"),
    ( 8, 42,  0,    "connect burst → NetworkAnomaly"),
    ( 4, 316, 0,    "renameat2 → LogTamper"),
    ( 4, 263, 0,    "unlinkat → LogTamper"),
    ( 4, 322, 1000, "memfd_create → FilelessMalware"),
    ( 2, 176, 0,    "delete_module → Rootkit"),
]

_ATTACK_WEIGHTS = [p[0] for p in ATTACK_PROFILES]
_ATTACK_SUM     = sum(_ATTACK_WEIGHTS)


def synthetic_attack(n: int = 1000, seed: int = 99) -> list[dict]:
    rng = random.Random(seed)
    base = datetime(2026, 1, 15, 2, 0, 0)
    rows = []
    for i in range(n):
        r = rng.random() * _ATTACK_SUM
        cumul = 0.0
        profile = ATTACK_PROFILES[-1]
        for p in ATTACK_PROFILES:
            cumul += p[0]
            if r < cumul:
                profile = p
                break
        _, nr, uid, _ = profile
        pid = rng.randint(1000, 15000)
        ts  = base + timedelta(hours=i // 50, minutes=rng.randint(0, 59))
        rows.append(make_row(nr, uid, pid, ts, label=1, source="synthetic_attack"))
    return rows


def adfa_ld_rows(timeout: int = 10) -> tuple[list[dict], list[dict]]:
    normal_rows: list[dict] = []
    attack_rows: list[dict] = []
    base = datetime(2025, 6, 1, 3, 0, 0)

    for url in ADFA_LD_MIRRORS:
        print(f"  Fetching {url.split('/')[-1]} ...", end=" ", flush=True)
        syscalls = _fetch_url(url, timeout=timeout)
        if not syscalls:
            continue
        print(f"{len(syscalls)} syscalls")
        is_attack = _is_attack_url(url)
        uid  = 0 if is_attack else random.randint(1000, 1002)
        pid  = random.randint(2000, 25000)
        for j, nr in enumerate(syscalls):
            if nr not in SYSCALL_INDEX:
                nr = 0
            ts = base + timedelta(seconds=j * 0.01)
            row = make_row(nr, uid, pid, ts, label=1 if is_attack else 0, source="adfa_ld")
            if is_attack:
                attack_rows.append(row)
            else:
                normal_rows.append(row)

    return normal_rows, attack_rows


def write_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDNAMES)
        w.writeheader()
        w.writerows(rows)
    print(f"Wrote {len(rows):,} rows → {path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate Sentinel training data")
    parser.add_argument("--no-download", action="store_true",
                        help="Skip ADFA-LD download; use synthetic attack data only")
    parser.add_argument("--out-dir", default="data",
                        help="Output directory (default: data/)")
    parser.add_argument("--normal-n", type=int, default=5000)
    parser.add_argument("--attack-n", type=int, default=1000)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    out = Path(args.out_dir)

    print(f"\n[1/3] Generating {args.normal_n:,} synthetic normal events ...")
    normal_rows = synthetic_normal(n=args.normal_n, seed=args.seed)

    adfa_normal: list[dict] = []
    adfa_attack: list[dict] = []

    if not args.no_download:
        print("\n[2/3] Downloading ADFA-LD traces ...")
        adfa_normal, adfa_attack = adfa_ld_rows()
        if adfa_attack:
            print(f"  Downloaded {len(adfa_attack):,} ADFA-LD attack events, "
                  f"{len(adfa_normal):,} ADFA-LD normal events")
        else:
            print("  ADFA-LD unavailable — falling back to synthetic attack data")
    else:
        print("\n[2/3] --no-download set; skipping ADFA-LD")

    if not adfa_attack:
        print(f"  Generating {args.attack_n:,} synthetic attack events ...")
        adfa_attack = synthetic_attack(n=args.attack_n, seed=args.seed + 1)

    all_normal = normal_rows + adfa_normal
    all_attack = adfa_attack

    print("\n[3/3] Writing CSVs ...")
    rng = random.Random(args.seed)
    rng.shuffle(all_normal)
    rng.shuffle(all_attack)

    write_csv(out / "training_normal.csv", all_normal)
    write_csv(out / "training_attack.csv", all_attack)

    combined = all_normal + all_attack
    rng.shuffle(combined)
    write_csv(out / "training_combined.csv", combined)

    print(f"\nDone. Normal={len(all_normal):,}  Attack={len(all_attack):,}  "
          f"Combined={len(combined):,}")
    print(f"Next step: python3 scorer/train_advanced.py --data-dir {out}")


if __name__ == "__main__":
    main()
