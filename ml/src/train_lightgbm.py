"""
Phase 2 LightGBM Training & Baseline Evaluation Pipeline
Loads X_train.npz and X_val.npz sparse matrices, trains baseline models,
tunes LightGBM with early stopping, and exports raw model text and baseline metrics report.
"""

import argparse
import json
import os
import sys
import time
from typing import Dict, Any, List, Tuple

import lightgbm as lgb
import numpy as np
import pandas as pd
from scipy.sparse import load_npz
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score, average_precision_score, log_loss, f1_score, accuracy_score

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)


def load_data_split(
    matrices_dir: str, partitions_dir: str, split_name: str
) -> Tuple[Any, np.ndarray, np.ndarray, pd.DataFrame]:
    matrix_path = os.path.join(matrices_dir, f"X_{split_name if split_name != 'validation' else 'val'}.npz")
    partition_path = os.path.join(partitions_dir, f"{split_name if split_name != 'validation' else 'val'}.parquet")

    if not os.path.exists(matrix_path):
        raise FileNotFoundError(f"Matrix file missing: {matrix_path}")
    if not os.path.exists(partition_path):
        raise FileNotFoundError(f"Partition file missing: {partition_path}")

    X = load_npz(matrix_path)
    df = pd.read_parquet(partition_path)
    y = df["label"].to_numpy().astype(int)
    sample_weight = (
        df["sample_weight"].to_numpy().astype(float)
        if "sample_weight" in df.columns
        else np.ones(len(df), dtype=float)
    )
    if (
        not np.all(np.isfinite(sample_weight))
        or np.any(sample_weight <= 0)
        or np.any(sample_weight > 10)
    ):
        raise ValueError(f"invalid sample weights in {partition_path}")

    return X, y, sample_weight, df


def evaluate_predictions(y_true: np.ndarray, y_prob: np.ndarray, threshold: float = 0.5) -> Dict[str, float]:
    y_pred = (y_prob >= threshold).astype(int)
    roc_auc = float(roc_auc_score(y_true, y_prob))
    pr_auc = float(average_precision_score(y_true, y_prob))
    loss = float(log_loss(y_true, np.clip(y_prob, 1e-15, 1 - 1e-15)))
    f1 = float(f1_score(y_true, y_pred, zero_division=0))
    acc = float(accuracy_score(y_true, y_pred))

    return {
        "roc_auc": roc_auc,
        "pr_auc": pr_auc,
        "log_loss": loss,
        "f1": f1,
        "accuracy": acc,
    }


def apply_training_weight_policy(
    df_train: pd.DataFrame,
    base_weights: np.ndarray,
    training_cfg: Dict[str, Any],
) -> Tuple[np.ndarray, Dict[str, Any]]:
    weights = np.asarray(base_weights, dtype=float).copy()
    proxy_cfg = training_cfg.get("source_proxy", {})
    proxy_enabled = bool(proxy_cfg.get("enabled", False))
    proxy_mask = np.zeros(len(df_train), dtype=bool)
    if proxy_enabled:
        proxy_weight = float(proxy_cfg.get("weight", 1.5))
        if not 1.0 < proxy_weight <= 10.0:
            raise ValueError("source-proxy weight must be in (1, 10]")
        proxy_mask = (
            (df_train["label"].to_numpy() == int(proxy_cfg.get("label", 0)))
            & (df_train["is_ml_candidate"].to_numpy() == True)  # noqa: E712
            & (
                df_train["source"].astype(str).to_numpy()
                == str(proxy_cfg.get("source", "vietnam_whitelist"))
            )
        )
        weights[proxy_mask] = np.maximum(weights[proxy_mask], proxy_weight)
    if not np.all(np.isfinite(weights)) or np.any(weights <= 0) or np.any(weights > 10):
        raise ValueError("effective training weights must be finite and in (0, 10]")
    evidence_mask = (
        df_train.get("training_role", pd.Series("", index=df_train.index))
        .astype(str)
        .eq("weighted_hard_negative")
        .to_numpy()
    )
    hard_positive_cfg = training_cfg.get("time_forward_hard_positive", {})
    hard_positive_enabled = bool(hard_positive_cfg.get("enabled", False))
    hard_positive_mask = (
        df_train.get("training_role", pd.Series("", index=df_train.index))
        .astype(str)
        .eq("time_forward_hard_positive")
        .to_numpy()
    )
    if hard_positive_enabled:
        hard_positive_weight = float(hard_positive_cfg.get("weight", 1.0))
        if not 1.0 <= hard_positive_weight <= 10.0:
            raise ValueError("time-forward hard-positive weight must be in [1, 10]")
        if not hard_positive_mask.any():
            raise ValueError("time-forward hard-positive weighting matched no rows")
        weights[hard_positive_mask] = np.maximum(
            weights[hard_positive_mask], hard_positive_weight
        )
    return weights, {
        "source_proxy_enabled": proxy_enabled,
        "source_proxy_rows": int(proxy_mask.sum()),
        "evidence_hard_negative_rows": int(evidence_mask.sum()),
        "time_forward_hard_positive_enabled": hard_positive_enabled,
        "time_forward_hard_positive_rows": int(hard_positive_mask.sum()),
        "time_forward_hard_positive_weight": (
            float(hard_positive_cfg.get("weight", 1.0))
            if hard_positive_enabled
            else 1.0
        ),
        "weighted_rows": int(np.sum(weights != 1.0)),
        "max_weight": float(np.max(weights)),
        "effective_train_weight": float(np.sum(weights)),
    }


def apply_monotone_feature_policy(
    lgb_params: Dict[str, Any],
    training_cfg: Dict[str, Any],
    feature_names: List[str],
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Resolve named monotone constraints against the frozen feature order."""

    params = dict(lgb_params)
    names = [str(name) for name in training_cfg.get("monotone_increasing_features", [])]
    if len(names) != len(set(names)):
        raise ValueError("monotone feature policy contains duplicates")
    unknown = sorted(set(names) - set(feature_names))
    if unknown:
        raise ValueError(f"unknown monotone features: {unknown}")
    if names and "monotone_constraints" in params:
        raise ValueError(
            "use named monotone_increasing_features instead of raw monotone_constraints"
        )
    if names:
        selected = set(names)
        params["monotone_constraints"] = [
            1 if feature in selected else 0 for feature in feature_names
        ]
        params.setdefault("monotone_constraints_method", "intermediate")
    return params, {
        "enabled": bool(names),
        "increasing_features": names,
        "method": params.get("monotone_constraints_method", ""),
    }


def train_and_eval_baselines(
    X_train: Any,
    y_train: np.ndarray,
    X_val: Any,
    y_val: np.ndarray,
    train_weight: np.ndarray,
    val_weight: np.ndarray,
    df_val: pd.DataFrame,
    lgb_params: Dict[str, Any],
) -> Tuple[Dict[str, Any], lgb.LGBMClassifier]:
    print("\n--- 1. Evaluating Baselines ---", flush=True)
    results = {}

    # Baseline 1: Deterministic Lexical Analyzer Baseline
    print("[*] Baseline 1: Deterministic Lexical Analyzer...", flush=True)
    verdict_map = {"MALICIOUS": 1.0, "SUSPICIOUS": 0.7, "SAFE": 0.0, "INVALID": 0.0}
    b1_prob = df_val["lexical_verdict"].map(verdict_map).fillna(0.0).to_numpy()
    results["1_deterministic_lexical"] = evaluate_predictions(y_val, b1_prob)
    print(f"    ROC-AUC: {results['1_deterministic_lexical']['roc_auc']:.4f}, PR-AUC: {results['1_deterministic_lexical']['pr_auc']:.4f}", flush=True)

    # Baseline 2: Logistic Regression (TF-IDF features only: cols 22..533)
    print("[*] Baseline 2: Logistic Regression (TF-IDF features only)...", flush=True)
    X_train_tfidf = X_train[:, 22:]
    X_val_tfidf = X_val[:, 22:]
    lr_model = LogisticRegression(max_iter=200, random_state=42, solver="lbfgs")
    lr_model.fit(X_train_tfidf, y_train, sample_weight=train_weight)
    b2_prob = lr_model.predict_proba(X_val_tfidf)[:, 1]
    results["2_logistic_regression_tfidf"] = evaluate_predictions(y_val, b2_prob)
    print(f"    ROC-AUC: {results['2_logistic_regression_tfidf']['roc_auc']:.4f}, PR-AUC: {results['2_logistic_regression_tfidf']['pr_auc']:.4f}", flush=True)

    # Baseline 3: LightGBM (Handcrafted features only: cols 0..21)
    print("[*] Baseline 3: LightGBM (Handcrafted features only)...", flush=True)
    X_train_hc = X_train[:, :22].toarray()
    X_val_hc = X_val[:, :22].toarray()
    lgb_hc = lgb.LGBMClassifier(**lgb_params)
    lgb_hc.fit(
        X_train_hc,
        y_train,
        sample_weight=train_weight,
        eval_set=[(X_val_hc, y_val)],
        eval_sample_weight=[val_weight],
        callbacks=[lgb.early_stopping(50, verbose=False)],
    )
    b3_prob = lgb_hc.predict_proba(X_val_hc)[:, 1]
    results["3_lightgbm_handcrafted_only"] = evaluate_predictions(y_val, b3_prob)
    print(f"    ROC-AUC: {results['3_lightgbm_handcrafted_only']['roc_auc']:.4f}, PR-AUC: {results['3_lightgbm_handcrafted_only']['pr_auc']:.4f}", flush=True)

    # Baseline 4: LightGBM (TF-IDF features only: cols 22..533)
    print("[*] Baseline 4: LightGBM (TF-IDF features only)...", flush=True)
    lgb_tfidf = lgb.LGBMClassifier(**lgb_params)
    lgb_tfidf.fit(
        X_train_tfidf,
        y_train,
        sample_weight=train_weight,
        eval_set=[(X_val_tfidf, y_val)],
        eval_sample_weight=[val_weight],
        callbacks=[lgb.early_stopping(50, verbose=False)],
    )
    b4_prob = lgb_tfidf.predict_proba(X_val_tfidf)[:, 1]
    results["4_lightgbm_tfidf_only"] = evaluate_predictions(y_val, b4_prob)
    print(f"    ROC-AUC: {results['4_lightgbm_tfidf_only']['roc_auc']:.4f}, PR-AUC: {results['4_lightgbm_tfidf_only']['pr_auc']:.4f}", flush=True)

    # Baseline 5: Combined LightGBM (All 534 features)
    print("[*] Baseline 5: Combined LightGBM (Full 534 features)...", flush=True)
    lgb_combined = lgb.LGBMClassifier(**lgb_params)
    lgb_combined.fit(
        X_train,
        y_train,
        sample_weight=train_weight,
        eval_set=[(X_val, y_val)],
        eval_sample_weight=[val_weight],
        callbacks=[lgb.early_stopping(50, verbose=False)],
    )
    b5_prob = lgb_combined.predict_proba(X_val)[:, 1]
    results["5_lightgbm_combined_full"] = evaluate_predictions(y_val, b5_prob)
    print(f"    ROC-AUC: {results['5_lightgbm_combined_full']['roc_auc']:.4f}, PR-AUC: {results['5_lightgbm_combined_full']['pr_auc']:.4f}", flush=True)

    return results, lgb_combined


def train_combined_only(
    X_train: Any,
    y_train: np.ndarray,
    X_val: Any,
    y_val: np.ndarray,
    train_weight: np.ndarray,
    val_weight: np.ndarray,
    lgb_params: Dict[str, Any],
) -> lgb.LGBMClassifier:
    print("\n--- Training Combined LightGBM Candidate ---", flush=True)
    model = lgb.LGBMClassifier(**lgb_params)
    model.fit(
        X_train,
        y_train,
        sample_weight=train_weight,
        eval_set=[(X_val, y_val)],
        eval_sample_weight=[val_weight],
        callbacks=[lgb.early_stopping(50, verbose=False)],
    )
    probability = model.predict_proba(X_val)[:, 1]
    metrics = evaluate_predictions(y_val, probability)
    print(
        f"    ROC-AUC: {metrics['roc_auc']:.4f}, PR-AUC: {metrics['pr_auc']:.4f}",
        flush=True,
    )
    return model


def run_training(config_path: str):
    t0 = time.time()
    print(f"[*] Loading training configuration from {config_path}...", flush=True)
    with open(config_path, "r", encoding="utf-8") as f:
        cfg = json.load(f)

    matrices_dir = os.path.join(BASE_DIR, cfg.get("matrices_dir", "data/derived/matrices"))
    partitions_dir = os.path.join(BASE_DIR, cfg.get("partitions_dir", "data/derived/partitions"))
    derived_dir = os.path.join(BASE_DIR, cfg.get("derived_dir", "data/derived"))
    models_dir = os.path.join(BASE_DIR, cfg.get("models_dir", "data/derived/models"))
    os.makedirs(models_dir, exist_ok=True)

    training_cfg = cfg.get("training", {})

    print("[*] Loading Train partition (X_train.npz)...", flush=True)
    X_train, y_train, train_weight, df_train = load_data_split(matrices_dir, partitions_dir, "train")
    print(f"    X_train shape: {X_train.shape}, Labels: safe={np.sum(y_train==0):,}, malicious={np.sum(y_train==1):,}", flush=True)

    print("[*] Loading Validation partition (X_val.npz)...", flush=True)
    X_val, y_val, val_weight, df_val = load_data_split(matrices_dir, partitions_dir, "validation")
    print(f"    X_val shape: {X_val.shape}, Labels: safe={np.sum(y_val==0):,}, malicious={np.sum(y_val==1):,}", flush=True)

    feature_manifest_path = os.path.join(derived_dir, "feature_manifest.json")
    with open(feature_manifest_path, "r", encoding="utf-8") as handle:
        feature_manifest = json.load(handle)
    feature_names = feature_manifest.get("feature_names", [])
    if len(feature_names) != X_train.shape[1]:
        raise ValueError(
            "feature manifest order does not match training matrix width"
        )
    lgb_params, monotone_report = apply_monotone_feature_policy(
        cfg.get("lightgbm_params", {}), training_cfg, feature_names
    )
    train_weight, weighting_report = apply_training_weight_policy(
        df_train, train_weight, training_cfg
    )
    evaluate_baselines = bool(training_cfg.get("evaluate_baselines", True))
    if evaluate_baselines:
        results, final_model = train_and_eval_baselines(
            X_train,
            y_train,
            X_val,
            y_val,
            train_weight,
            val_weight,
            df_val,
            lgb_params,
        )
    else:
        existing_report_path = os.path.join(models_dir, "baseline_report.json")
        results = {}
        if os.path.exists(existing_report_path):
            with open(existing_report_path, "r", encoding="utf-8") as handle:
                results = json.load(handle).get("baselines", {})
        final_model = train_combined_only(
            X_train,
            y_train,
            X_val,
            y_val,
            train_weight,
            val_weight,
            lgb_params,
        )

    # Save raw LightGBM text model using booster save_model
    booster = final_model.booster_
    raw_model_path = os.path.join(models_dir, "domain_threat_lgbm_raw.txt")
    booster.save_model(raw_model_path)
    print(f"\n[+] Saved raw LightGBM model text to {raw_model_path}", flush=True)

    # Feature Importance Top 25
    importances = booster.feature_importance(importance_type="gain")
    top_indices = np.argsort(importances)[::-1][:25]
    top_features = []
    for idx in top_indices:
        fname = feature_names[idx] if feature_names and idx < len(feature_names) else f"feature_{idx}"
        top_features.append({"index": int(idx), "name": fname, "gain": float(importances[idx])})

    report = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "wall_time_seconds": round(time.time() - t0, 2),
        "best_iteration": booster.best_iteration,
        "n_features": booster.num_feature(),
        "sample_weighting": {"enabled": bool(np.any(train_weight != 1.0)), **weighting_report},
        "monotone_feature_policy": monotone_report,
        "baselines": results,
        "top_25_features_by_gain": top_features,
    }

    report_path = os.path.join(models_dir, "baseline_report.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"[+] Saved baseline evaluation report to {report_path}", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train LightGBM & Evaluate Baselines")
    parser.add_argument("--config", type=str, default=os.path.join(BASE_DIR, "configs/v1.json"), help="Config path")
    args = parser.parse_args()
    run_training(args.config)
