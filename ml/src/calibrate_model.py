"""
Phase 2 Model Probability Calibration Pipeline
Loads raw LightGBM model and X_cal.npz matrix, fits Platt scaling (sigmoid calibration)
on raw decision margins, measures Brier score & Expected Calibration Error (ECE),
and exports calibration.json mapping parameters.
"""

import argparse
import json
import os
import sys
import time
from typing import Dict, Any, Tuple

import lightgbm as lgb
import numpy as np
import pandas as pd
from scipy.sparse import load_npz
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import brier_score_loss

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)


def compute_expected_calibration_error(y_true: np.ndarray, y_prob: np.ndarray, n_bins: int = 10) -> float:
    bins = np.linspace(0.0, 1.0, n_bins + 1)
    binids = np.clip(np.digitize(y_prob, bins) - 1, 0, n_bins - 1)

    ece = 0.0
    total_samples = len(y_true)

    for i in range(n_bins):
        mask = binids == i
        if np.any(mask):
            bin_acc = np.mean(y_true[mask])
            bin_conf = np.mean(y_prob[mask])
            bin_size = np.sum(mask)
            ece += (bin_size / total_samples) * abs(bin_acc - bin_conf)

    return float(ece)


def run_calibration(config_path: str):
    t0 = time.time()
    print(f"[*] Loading configuration from {config_path}...", flush=True)
    with open(config_path, "r", encoding="utf-8") as f:
        cfg = json.load(f)

    matrices_dir = os.path.join(BASE_DIR, cfg.get("matrices_dir", "data/derived/matrices"))
    partitions_dir = os.path.join(BASE_DIR, cfg.get("partitions_dir", "data/derived/partitions"))
    models_dir = os.path.join(BASE_DIR, cfg.get("models_dir", "data/derived/models"))

    raw_model_path = os.path.join(models_dir, "domain_threat_lgbm_raw.txt")
    if not os.path.exists(raw_model_path):
        raise FileNotFoundError(f"Raw LightGBM model text missing: {raw_model_path}")

    cal_matrix_path = os.path.join(matrices_dir, "X_cal.npz")
    cal_partition_path = os.path.join(partitions_dir, "cal.parquet")

    if not os.path.exists(cal_matrix_path) or not os.path.exists(cal_partition_path):
        raise FileNotFoundError("Calibration matrix X_cal.npz or partition cal.parquet missing")

    print("[*] Loading Calibration partition (X_cal.npz)...", flush=True)
    X_cal = load_npz(cal_matrix_path)
    df_cal = pd.read_parquet(cal_partition_path)
    y_cal = df_cal["label"].to_numpy().astype(int)
    sample_weight = (
        df_cal["sample_weight"].to_numpy().astype(float)
        if "sample_weight" in df_cal.columns
        else np.ones(len(df_cal), dtype=float)
    )

    print(f"[*] Loading raw LightGBM booster from {raw_model_path}...", flush=True)
    booster = lgb.Booster(model_file=raw_model_path)

    # Predict raw margins (raw decision logits)
    raw_margins = booster.predict(X_cal, raw_score=True)
    raw_probs = 1.0 / (1.0 + np.exp(-raw_margins))

    brier_before = float(brier_score_loss(y_cal, raw_probs))
    ece_before = compute_expected_calibration_error(y_cal, raw_probs)
    print(f"    Raw LightGBM Calibration metrics on X_cal: Brier Score = {brier_before:.6f}, ECE = {ece_before:.6f}", flush=True)

    # Fit Platt Scaling (Logistic Regression on raw margin z: P(y=1|z) = 1 / (1 + exp(A*z + B)))
    print("[*] Fitting Platt Scaling (logistic regression calibration)...", flush=True)
    platt_lr = LogisticRegression(solver="lbfgs", max_iter=200, C=1.0, random_state=42)
    platt_lr.fit(
        raw_margins.reshape(-1, 1), y_cal, sample_weight=sample_weight
    )

    calibrated_probs = platt_lr.predict_proba(raw_margins.reshape(-1, 1))[:, 1]
    brier_after = float(brier_score_loss(y_cal, calibrated_probs))
    ece_after = compute_expected_calibration_error(y_cal, calibrated_probs)

    print(f"    Calibrated Metrics on X_cal: Brier Score = {brier_after:.6f}, ECE = {ece_after:.6f}", flush=True)

    w = float(platt_lr.coef_[0][0])
    c = float(platt_lr.intercept_[0])
    A = float(-w)
    B = float(-c)

    calibration_artifact = {
        "calibration_version": "1.0.0",
        "method": "platt_sigmoid",
        "fitted_on_partition": "calibration",
        "num_samples": len(y_cal),
        "parameters": {
            "A": A,
            "B": B,
            "slope_w": w,
            "intercept_c": c,
            "formula": "P(malicious|raw_margin) = 1.0 / (1.0 + exp(A * raw_margin + B))",
            "clip_eps": 1e-15,
        },
        "metrics": {
            "uncalibrated_brier_score": brier_before,
            "uncalibrated_ece": ece_before,
            "calibrated_brier_score": brier_after,
            "calibrated_ece": ece_after,
            "brier_improvement_pct": round((brier_before - brier_after) / brier_before * 100, 2),
            "ece_improvement_pct": round((ece_before - ece_after) / ece_before * 100, 2),
        },
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

    cal_out_path = os.path.join(models_dir, "calibration.json")
    with open(cal_out_path, "w", encoding="utf-8") as f:
        json.dump(calibration_artifact, f, indent=2)
    print(f"[+] Saved calibration parameters & metrics to {cal_out_path}", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Calibrate LightGBM Model Probabilities")
    parser.add_argument("--config", type=str, default=os.path.join(BASE_DIR, "configs/v1.json"), help="Config path")
    args = parser.parse_args()
    run_calibration(args.config)
