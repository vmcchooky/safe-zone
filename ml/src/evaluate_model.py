"""
Phase 2 Model Evaluation & False Positive Audit Pipeline
Evaluates calibrated LightGBM model on frozen Test partition (X_test.npz) and hard cases.
Audits False Positive Rate (FPR) across SAFE VN, gov.vn/edu.vn, trusted brands, and shared hosting.
Selects block_threshold meeting false-positive budget and exports model_report.json.
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
from sklearn.metrics import (
    roc_auc_score,
    average_precision_score,
    brier_score_loss,
    confusion_matrix,
    f1_score,
    accuracy_score,
    precision_score,
    recall_score,
)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from src.calibrate_model import compute_expected_calibration_error
from src.build_features import build_feature_matrix_from_manifest
from src.canonicalize import canonicalize_domain


def run_evaluation(config_path: str):
    t0 = time.time()
    print(f"[*] Loading configuration from {config_path}...", flush=True)
    with open(config_path, "r", encoding="utf-8") as f:
        cfg = json.load(f)

    matrices_dir = os.path.join(BASE_DIR, cfg.get("matrices_dir", "data/derived/matrices"))
    partitions_dir = os.path.join(BASE_DIR, cfg.get("partitions_dir", "data/derived/partitions"))
    models_dir = os.path.join(BASE_DIR, cfg.get("models_dir", "data/derived/models"))
    derived_dir = os.path.join(BASE_DIR, cfg.get("derived_dir", "data/derived"))

    raw_model_path = os.path.join(models_dir, "domain_threat_lgbm_raw.txt")
    cal_json_path = os.path.join(models_dir, "calibration.json")

    if not os.path.exists(raw_model_path):
        raise FileNotFoundError(f"Raw LightGBM model missing: {raw_model_path}")
    if not os.path.exists(cal_json_path):
        raise FileNotFoundError(f"Calibration JSON missing: {cal_json_path}")

    with open(cal_json_path, "r", encoding="utf-8") as f:
        cal_meta = json.load(f)
    A = cal_meta["parameters"]["A"]
    B = cal_meta["parameters"]["B"]

    print(f"[*] Loading Test partition (X_test.npz)...", flush=True)
    test_matrix_path = os.path.join(matrices_dir, "X_test.npz")
    test_partition_path = os.path.join(partitions_dir, "test.parquet")

    X_test = load_npz(test_matrix_path)
    df_test = pd.read_parquet(test_partition_path)
    y_test = df_test["label"].to_numpy().astype(int)

    print(f"[*] Loading raw LightGBM booster from {raw_model_path}...", flush=True)
    booster = lgb.Booster(model_file=raw_model_path)

    # Predict raw margins & calibrated probabilities
    raw_margins_test = booster.predict(X_test, raw_score=True)
    calibrated_probs_test = 1.0 / (1.0 + np.exp(A * raw_margins_test + B))

    print("\n--- 1. Full Test Partition Evaluation ---", flush=True)
    roc_auc = float(roc_auc_score(y_test, calibrated_probs_test))
    pr_auc = float(average_precision_score(y_test, calibrated_probs_test))
    brier = float(brier_score_loss(y_test, calibrated_probs_test))
    ece = compute_expected_calibration_error(y_test, calibrated_probs_test)

    print(f"    ROC-AUC: {roc_auc:.4f}, PR-AUC: {pr_auc:.4f}, Brier: {brier:.6f}, ECE: {ece:.6f}", flush=True)

    # Candidate cohort evaluation (where is_ml_candidate == True)
    cand_mask = df_test["is_ml_candidate"].to_numpy() == True
    print(f"\n--- 2. Candidate Cohort Evaluation (N = {np.sum(cand_mask):,}) ---", flush=True)
    cand_y = y_test[cand_mask]
    cand_p = calibrated_probs_test[cand_mask]
    cand_roc_auc = float(roc_auc_score(cand_y, cand_p)) if len(np.unique(cand_y)) > 1 else 0.0
    cand_pr_auc = float(average_precision_score(cand_y, cand_p)) if len(np.unique(cand_y)) > 1 else 0.0
    print(f"    Candidate Cohort ROC-AUC: {cand_roc_auc:.4f}, PR-AUC: {cand_pr_auc:.4f}", flush=True)
    benign_candidate_mask = cand_mask & (y_test == 0)
    malicious_candidate_mask = cand_mask & (y_test == 1)
    benign_candidate_count = int(np.sum(benign_candidate_mask))
    malicious_candidate_count = int(np.sum(malicious_candidate_mask))
    evaluation_cfg = cfg.get("evaluation", {})
    recommended_threshold = float(
        evaluation_cfg.get("recommended_block_threshold", 0.85)
    )
    # Threshold sweeps
    thresholds = evaluation_cfg.get(
        "thresholds", [0.50, 0.70, 0.80, 0.85, 0.90, 0.95]
    )
    candidate_false_positives = int(
        np.sum(calibrated_probs_test[benign_candidate_mask] >= recommended_threshold)
    )
    candidate_true_positives = int(
        np.sum(calibrated_probs_test[malicious_candidate_mask] >= recommended_threshold)
    )
    threshold_reports = {}

    print("\n--- 3. Operating Threshold Sweeps ---", flush=True)
    for th in thresholds:
        preds = (calibrated_probs_test >= th).astype(int)
        tn, fp, fn, tp = confusion_matrix(y_test, preds).ravel()
        prec = float(precision_score(y_test, preds, zero_division=0))
        rec = float(recall_score(y_test, preds, zero_division=0))
        f1 = float(f1_score(y_test, preds, zero_division=0))
        fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0

        threshold_reports[str(th)] = {
            "threshold": th,
            "precision": prec,
            "recall": rec,
            "f1": f1,
            "fpr": fpr,
            "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        }
        print(f"    Th={th:.2f} -> Prec: {prec:.4f}, Rec: {rec:.4f}, F1: {f1:.4f}, FPR: {fpr:.6f} (FP={fp:,})", flush=True)

    # Hard Cases Audit
    hard_cases_value = evaluation_cfg.get("hard_cases_path")
    hard_cases_path = (
        hard_cases_value
        if hard_cases_value and os.path.isabs(hard_cases_value)
        else os.path.join(
            BASE_DIR,
            hard_cases_value
            if hard_cases_value
            else os.path.relpath(
                os.path.join(derived_dir, "hard_cases.parquet"), BASE_DIR
            ),
        )
    )
    print("\n--- 4. Benign Subsets FPR Audit ---", flush=True)
    hard_cases_count = (
        len(pd.read_parquet(hard_cases_path))
        if os.path.exists(hard_cases_path)
        else 0
    )
    gov_edu_mask = df_test["domain"].str.contains(r"\.(?:gov|edu)\.vn$", regex=True) & (df_test["label"] == 0)
    gov_edu_total = int(np.sum(gov_edu_mask))
    gov_edu_fp = int(np.sum(calibrated_probs_test[gov_edu_mask] >= recommended_threshold)) if gov_edu_total > 0 else 0

    safe_vn_mask = df_test["domain"].str.contains(r"\.vn$", regex=True) & (df_test["label"] == 0)
    safe_vn_total = int(np.sum(safe_vn_mask))
    safe_vn_fp = int(np.sum(calibrated_probs_test[safe_vn_mask] >= recommended_threshold)) if safe_vn_total > 0 else 0
    safe_vn_candidate_mask = safe_vn_mask.to_numpy() & cand_mask
    safe_vn_candidate_total = int(np.sum(safe_vn_candidate_mask))
    safe_vn_candidate_fp = int(
        np.sum(
            calibrated_probs_test[safe_vn_candidate_mask]
            >= recommended_threshold
        )
    ) if safe_vn_candidate_total > 0 else 0

    hard_cases_audit = {
        "hard_cases_total": hard_cases_count,
        "threshold": recommended_threshold,
        "safe_vn_benign_count": safe_vn_total,
        "safe_vn_false_positives": safe_vn_fp,
        "safe_vn_fpr": float(safe_vn_fp / safe_vn_total) if safe_vn_total > 0 else 0.0,
        "safe_vn_runtime_candidate_count": safe_vn_candidate_total,
        "safe_vn_runtime_candidate_false_positives": safe_vn_candidate_fp,
        "safe_vn_runtime_candidate_fpr": float(safe_vn_candidate_fp / safe_vn_candidate_total) if safe_vn_candidate_total > 0 else 0.0,
        "gov_edu_vn_benign_count": gov_edu_total,
        "gov_edu_vn_false_positives": gov_edu_fp,
        "gov_edu_vn_fpr": float(gov_edu_fp / gov_edu_total) if gov_edu_total > 0 else 0.0,
    }
    print(f"    SAFE VN Benign FPR: {hard_cases_audit['safe_vn_fpr']:.6f} ({safe_vn_fp}/{safe_vn_total})", flush=True)
    print(f"    gov.vn/edu.vn Benign FPR: {hard_cases_audit['gov_edu_vn_fpr']:.6f} ({gov_edu_fp}/{gov_edu_total})", flush=True)

    # Human-reviewed false positives are a frozen challenge set.  Their
    # registrable groups must be absent from every train/val/cal/test partition.
    frozen_challenge_audit = {}
    challenge_value = evaluation_cfg.get("frozen_challenge_labels")
    if challenge_value:
        challenge_path = (
            challenge_value
            if os.path.isabs(challenge_value)
            else os.path.join(BASE_DIR, challenge_value)
        )
        challenge = pd.read_csv(challenge_path)
        if not (challenge["human_label"].str.lower() == "benign").all():
            raise ValueError("frozen challenge must contain only human-labelled benign rows")
        challenge_domains = challenge["domain"].astype(str).tolist()
        challenge_groups = {
            canonicalize_domain(domain).registrable_domain
            for domain in challenge_domains
        }
        partition_groups = set()
        for split in ("train", "val", "cal", "test"):
            frame = pd.read_parquet(
                os.path.join(partitions_dir, f"{split}.parquet"),
                columns=["registrable_domain"],
            )
            partition_groups.update(frame["registrable_domain"].astype(str))
        leaked_groups = sorted(challenge_groups & partition_groups)
        if leaked_groups:
            raise ValueError(
                f"frozen challenge leakage detected in model partitions: {leaked_groups}"
            )
        challenge_matrix = build_feature_matrix_from_manifest(
            challenge_domains, os.path.join(derived_dir, "feature_manifest.json")
        )
        challenge_margins = booster.predict(challenge_matrix, raw_score=True)
        challenge_probs = 1.0 / (1.0 + np.exp(A * challenge_margins + B))
        false_positives = int(np.sum(challenge_probs >= recommended_threshold))
        frozen_challenge_audit = {
            "labels_path": challenge_path,
            "cases": len(challenge),
            "partition_group_overlap": 0,
            "threshold": recommended_threshold,
            "false_positives": false_positives,
            "fpr": float(false_positives / len(challenge)),
            "predictions": [
                {
                    "domain": domain,
                    "probability": float(probability),
                    "would_block": bool(probability >= recommended_threshold),
                }
                for domain, probability in zip(challenge_domains, challenge_probs)
            ],
        }
        print(
            f"    Frozen challenge FPR: {frozen_challenge_audit['fpr']:.6f} "
            f"({false_positives}/{len(challenge)})",
            flush=True,
        )

    training_summary = {}
    baseline_report_path = os.path.join(models_dir, "baseline_report.json")
    feature_manifest_path = os.path.join(derived_dir, "feature_manifest.json")
    if os.path.exists(baseline_report_path):
        with open(baseline_report_path, "r", encoding="utf-8") as handle:
            baseline_report = json.load(handle)
        training_summary["sample_weighting"] = baseline_report.get(
            "sample_weighting", {}
        )
        training_summary["best_iteration"] = baseline_report.get("best_iteration")
    if os.path.exists(feature_manifest_path):
        with open(feature_manifest_path, "r", encoding="utf-8") as handle:
            feature_manifest = json.load(handle)
        data_policy = feature_manifest.get("training_data_policy", {})
        frozen_policy = data_policy.get("frozen_challenge", {})
        hard_policy = data_policy.get("hard_negative", {})
        training_summary["feature_contract"] = {
            "contract_version": feature_manifest.get("contract_version"),
            "tfidf_input_view": feature_manifest.get("tfidf_config", {}).get(
                "input_view"
            ),
        }
        training_summary["training_data_provenance"] = {
            "manifest_sha256": data_policy.get("manifest_sha256"),
            "frozen_labels_sha256": frozen_policy.get("labels_sha256"),
            "frozen_domain_count": frozen_policy.get("domain_count"),
            "hard_negative_csv_sha256": hard_policy.get("csv_sha256"),
            "hard_negative_selected_rows": hard_policy.get("counts", {}).get(
                "selected_rows"
            ),
            "hard_negative_source_sha256": hard_policy.get("source", {}).get(
                "sha256"
            ),
        }

    report = {
        "model_name": "safe-zone-domain-threat-lgbm",
        "model_version": cfg.get("version", "1.0.0"),
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "test_evaluation": {
            "total_test_samples": len(y_test),
            "roc_auc": roc_auc,
            "pr_auc": pr_auc,
            "brier_score": brier,
            "ece": ece,
        },
        "candidate_cohort_evaluation": {
            "candidate_samples": int(np.sum(cand_mask)),
            "candidate_roc_auc": cand_roc_auc,
            "candidate_pr_auc": cand_pr_auc,
            "threshold": recommended_threshold,
            "benign_candidate_samples": benign_candidate_count,
            "malicious_candidate_samples": malicious_candidate_count,
            "false_positives": candidate_false_positives,
            "true_positives": candidate_true_positives,
            "runtime_candidate_fpr": float(candidate_false_positives / benign_candidate_count) if benign_candidate_count else 0.0,
            "runtime_candidate_recall": float(candidate_true_positives / malicious_candidate_count) if malicious_candidate_count else 0.0,
        },
        "threshold_sweeps": threshold_reports,
        "recommended_block_threshold": recommended_threshold,
        "threshold_selection": {
            "partition": "validation",
            "basis": evaluation_cfg.get("selection_basis", ""),
        },
        "hard_cases_audit": hard_cases_audit,
        "frozen_challenge_audit": frozen_challenge_audit,
        "training": training_summary,
        "calibration": cal_meta,
    }

    report_path = os.path.join(models_dir, "model_report.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"\n[+] Saved full evaluation model report to {report_path}", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Evaluate LightGBM Model & Audit False Positives")
    parser.add_argument("--config", type=str, default=os.path.join(BASE_DIR, "configs/v1.json"), help="Config path")
    args = parser.parse_args()
    run_evaluation(args.config)
