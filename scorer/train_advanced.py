#!/usr/bin/env python3
import argparse
import csv
import json
import math
import os
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.model_selection import StratifiedKFold, cross_val_score
from sklearn.preprocessing import StandardScaler

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


def row_to_vector(row: dict) -> np.ndarray:
    v = np.zeros(26, dtype=np.float32)
    nr = int(row.get("syscall_nr", 0))
    idx = SYSCALL_INDEX.get(nr, -1)
    if idx >= 0:
        v[idx] = 1.0
    v[21] = 1.0 if int(row.get("uid", 1)) == 0 else 0.0
    v[22] = RISK_WEIGHTS.get(nr, 5) / 100.0
    try:
        hour = int(row.get("hour", 12))
        v[23] = hour / 23.0
        v[24] = float(row.get("is_weekend", 0))
    except (TypeError, ValueError):
        pass
    try:
        log_pid = float(row.get("log_pid", 0))
        v[25] = log_pid
    except (TypeError, ValueError):
        pass
    return v


def load_csv(path: Path) -> tuple[np.ndarray, np.ndarray]:
    X_list, y_list = [], []
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            X_list.append(row_to_vector(row))
            y_list.append(int(row.get("label", 0)))
    return np.array(X_list, dtype=np.float32), np.array(y_list, dtype=np.int32)


@dataclass
class ModelBundle:
    model: object
    scaler: StandardScaler
    n_samples: int
    trained_at: str
    model_type: str
    metrics: dict


def train_isolation_forest(
    X_normal: np.ndarray,
    n_estimators: int = 300,
    contamination: float = 0.05,
) -> tuple[IsolationForest, StandardScaler]:
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_normal)
    print(f"  Fitting IsolationForest: {len(X_normal):,} normal events, "
          f"{n_estimators} trees, contamination={contamination}")
    model = IsolationForest(
        n_estimators=n_estimators,
        contamination=contamination,
        max_samples=min(256, len(X_normal)),
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_scaled)
    train_scores = model.decision_function(X_scaled)
    print(f"  Decision function stats (higher=more normal): "
          f"min={train_scores.min():.3f}  mean={train_scores.mean():.3f}  "
          f"max={train_scores.max():.3f}")
    return model, scaler


def train_random_forest(
    X: np.ndarray,
    y: np.ndarray,
    n_estimators: int = 300,
) -> tuple[RandomForestClassifier, StandardScaler, dict]:
    n_attack = int(y.sum())
    n_normal = len(y) - n_attack
    print(f"  Fitting RandomForest: {n_normal:,} normal, {n_attack:,} attack, "
          f"{n_estimators} trees")

    if n_attack == 0:
        raise ValueError("No attack-labeled rows found — cannot train RF classifier. "
                         "Run generate_training_data.py first.")

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    class_weight = {0: 1.0, 1: n_normal / max(n_attack, 1)}
    model = RandomForestClassifier(
        n_estimators=n_estimators,
        class_weight=class_weight,
        max_depth=10,
        min_samples_leaf=5,
        random_state=42,
        n_jobs=-1,
    )

    cv = StratifiedKFold(n_splits=min(5, n_attack), shuffle=True, random_state=42)
    cv_auc = cross_val_score(model, X_scaled, y, cv=cv, scoring="roc_auc", n_jobs=-1)
    print(f"  CV ROC-AUC: {cv_auc.mean():.3f} ± {cv_auc.std():.3f}")

    model.fit(X_scaled, y)
    y_pred = model.predict(X_scaled)
    y_prob = model.predict_proba(X_scaled)[:, 1]

    report = classification_report(y, y_pred, target_names=["normal", "attack"])
    auc = roc_auc_score(y, y_prob)
    print(f"\n  Training classification report:\n{report}")
    print(f"  Train ROC-AUC: {auc:.4f}")

    top_features = np.argsort(model.feature_importances_)[::-1][:5]
    print(f"  Top-5 feature indices by importance: {top_features.tolist()}")

    metrics = {
        "cv_auc_mean": float(cv_auc.mean()),
        "cv_auc_std":  float(cv_auc.std()),
        "train_auc":   float(auc),
        "n_normal":    n_normal,
        "n_attack":    n_attack,
    }
    return model, scaler, metrics


def main() -> None:
    parser = argparse.ArgumentParser(description="Train advanced Sentinel models")
    parser.add_argument("--data-dir",  default="data")
    parser.add_argument("--model-dir", default="/var/sentinel")
    parser.add_argument("--if-trees",  type=int, default=300)
    parser.add_argument("--rf-trees",  type=int, default=300)
    parser.add_argument("--contamination", type=float, default=0.05)
    parser.add_argument("--skip-rf",   action="store_true")
    args = parser.parse_args()

    data_dir  = Path(args.data_dir)
    model_dir = Path(args.model_dir)
    model_dir.mkdir(parents=True, exist_ok=True)

    normal_csv   = data_dir / "training_normal.csv"
    attack_csv   = data_dir / "training_attack.csv"
    combined_csv = data_dir / "training_combined.csv"

    for p in [normal_csv, combined_csv]:
        if not p.exists():
            sys.exit(f"Missing {p}. Run: python3 scorer/generate_training_data.py first.")

    print("\n=== Isolation Forest (anomaly detector) ===")
    X_normal, _ = load_csv(normal_csv)
    if_model, if_scaler = train_isolation_forest(
        X_normal,
        n_estimators=args.if_trees,
        contamination=args.contamination,
    )
    if_path = model_dir / "model.pkl"
    joblib.dump(
        ModelBundle(
            model=if_model,
            scaler=if_scaler,
            n_samples=len(X_normal),
            trained_at=datetime.utcnow().isoformat() + "Z",
            model_type="isolation_forest",
            metrics={"n_normal": len(X_normal)},
        ),
        if_path,
    )
    print(f"\n  Saved → {if_path}")

    if not args.skip_rf:
        print("\n=== Random Forest (supervised classifier) ===")
        X_all, y_all = load_csv(combined_csv)
        try:
            rf_model, rf_scaler, rf_metrics = train_random_forest(
                X_all, y_all, n_estimators=args.rf_trees
            )
            rf_path = model_dir / "model_rf.pkl"
            joblib.dump(
                ModelBundle(
                    model=rf_model,
                    scaler=rf_scaler,
                    n_samples=len(X_all),
                    trained_at=datetime.utcnow().isoformat() + "Z",
                    model_type="random_forest",
                    metrics=rf_metrics,
                ),
                rf_path,
            )
            print(f"\n  Saved → {rf_path}")
        except ValueError as exc:
            print(f"  Skipping RF: {exc}", file=sys.stderr)

    print("\n=== Summary ===")
    for p in [model_dir / "model.pkl", model_dir / "model_rf.pkl"]:
        if p.exists():
            mb = joblib.load(p)
            print(f"  {p.name}: type={mb.model_type}, "
                  f"samples={mb.n_samples:,}, trained_at={mb.trained_at}")

    print("\nDeploy the Isolation Forest model (model.pkl) to the VM:")
    print("  vagrant scp /var/sentinel/model.pkl :/var/sentinel/model.pkl")
    print("  vagrant ssh -- 'sudo systemctl restart sentinel-scorer 2>/dev/null || true'")


if __name__ == "__main__":
    main()
