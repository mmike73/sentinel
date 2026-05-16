#!/usr/bin/env python3
import argparse, json, math, os, sqlite3, sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

SYSCALL_INDEX = {
    1:0, 9:1, 10:2, 41:3, 42:4, 49:5, 56:6, 59:7,
    62:8, 101:9, 103:10, 105:11, 106:12, 126:13, 175:14,
    176:15, 257:16, 263:17, 313:18, 316:19, 322:20,
}

RISK_WEIGHTS = {
    1:5, 9:40, 10:45, 41:10, 42:15, 49:10, 56:5, 59:50,
    62:5, 101:75, 103:5, 105:70, 106:70, 126:70, 175:95,
    176:85, 257:5, 263:5, 313:95, 316:5, 322:20,
}


def event_to_vector(event: dict) -> np.ndarray:
    v = np.zeros(26, dtype=np.float32)
    nr = event.get("syscall_nr", 0)
    idx = SYSCALL_INDEX.get(nr, -1)
    if idx >= 0:
        v[idx] = 1.0
    v[21] = 1.0 if event.get("uid", 1) == 0 else 0.0
    v[22] = RISK_WEIGHTS.get(nr, 5) / 100.0
    try:
        ts = event.get("timestamp", "")
        if isinstance(ts, str) and ts:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            v[23] = dt.hour / 23.0
            v[24] = 1.0 if dt.weekday() >= 5 else 0.0
    except Exception:
        pass
    pid = max(event.get("pid", 1), 1)
    v[25] = math.log10(pid) / 6.0
    return v


@dataclass
class ModelBundle:
    model: IsolationForest
    scaler: StandardScaler
    n_samples: int
    trained_at: str


def raw_to_threat_score(raw: float) -> float:
    inverted = -raw
    prob = 1.0 / (1.0 + math.exp(-25.0 * inverted))
    return round(min(max(prob * 100.0, 0.0), 100.0), 2)


def score_to_state(score: float) -> str:
    if score >= 95: return "FREEZE"
    if score >= 85: return "ISOLATE"
    if score >= 70: return "THROTTLE"
    if score >= 50: return "WARN"
    if score >= 30: return "WATCH"
    return "OK"


def load_events_from_db(db_path: str, limit: int = 50000) -> list:
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("""
        SELECT
            CAST(COALESCE(json_extract(detail,'$.syscall_nr'), 0) AS INTEGER) AS syscall_nr,
            CAST(COALESCE(json_extract(detail,'$.uid'), 1000)    AS INTEGER) AS uid,
            COALESCE(pid, 1000)  AS pid,
            COALESCE(timestamp, datetime('now')) AS timestamp
        FROM events
        WHERE score < 30
        ORDER BY RANDOM()
        LIMIT ?
    """, (limit,)).fetchall()
    conn.close()
    print(f"Loaded {len(rows)} real baseline events (score < 30) from {db_path}")
    return [dict(r) for r in rows]


def train(db_path: str, model_path: str,
          n_estimators: int = 200, contamination: float = 0.01,
          min_samples: int = 1000) -> ModelBundle:
    events = load_events_from_db(db_path)
    if len(events) < min_samples:
        raise RuntimeError(
            f"Only {len(events)} baseline events found (need {min_samples}). "
            f"Run the daemon with -min-score 0 for ≥10 minutes on a clean snapshot first."
        )

    X = np.array([event_to_vector(e) for e in events])
    print(f"Training on {len(X)} events, {X.shape[1]} features ...")

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = IsolationForest(
        n_estimators=n_estimators,
        contamination=contamination,
        max_samples="auto",
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_scaled)

    bundle = ModelBundle(
        model=model,
        scaler=scaler,
        n_samples=len(X),
        trained_at=datetime.utcnow().isoformat() + "Z",
    )
    joblib.dump(bundle, model_path)
    print(f"Model saved to {model_path}")
    return bundle


def serve(model_path: str, db_path: str, port: int = 8765):
    from fastapi import FastAPI
    from pydantic import BaseModel
    import uvicorn

    app = FastAPI(title="Sentinel IF Scorer", version="1.0.0")
    bundle: Optional[ModelBundle] = None

    def get_bundle() -> ModelBundle:
        nonlocal bundle
        if bundle is None:
            if Path(model_path).exists():
                bundle = joblib.load(model_path)
                print(f"Loaded model: trained on {bundle.n_samples} events")
            else:
                print("No model found, training on DB ...")
                bundle = train(db_path, model_path)
        return bundle

    class EventRequest(BaseModel):
        syscall_nr: int = 59
        uid: int = 1000
        pid: int = 1000
        comm: str = "bash"
        timestamp: str = ""

    @app.get("/health")
    def health():
        b = get_bundle()
        return {"status": "ok", "model_trained_at": b.trained_at, "n_samples": b.n_samples}

    @app.post("/score")
    def score(event: EventRequest):
        b = get_bundle()
        e = event.model_dump()
        vec = event_to_vector(e).reshape(1, -1)
        scaled = b.scaler.transform(vec)
        raw = b.model.decision_function(scaled)[0]
        threat = raw_to_threat_score(raw)
        state = score_to_state(threat)
        return {
            "threat_score": threat,
            "state": state,
            "if_raw": round(raw, 6),
            "syscall_nr": e["syscall_nr"],
        }

    @app.post("/model/train")
    def retrain():
        nonlocal bundle
        bundle = train(db_path, model_path)
        return {"status": "trained", "n_samples": bundle.n_samples}

    uvicorn.run(app, host="127.0.0.1", port=port)


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("command", choices=["train", "serve"])
    p.add_argument("--db",           default="/var/sentinel/events.db")
    p.add_argument("--model",        default="/var/sentinel/model.pkl")
    p.add_argument("--port",         type=int, default=8765)
    p.add_argument("--estimators",   type=int, default=200)
    p.add_argument("--contamination",type=float, default=0.05)
    args = p.parse_args()

    if args.command == "train":
        train(args.db, args.model, args.estimators, args.contamination)
    elif args.command == "serve":
        serve(args.model, args.db, args.port)
