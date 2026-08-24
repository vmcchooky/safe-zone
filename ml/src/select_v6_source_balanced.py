"""Train and select the single pre-registered v6 source-balanced candidate."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict

import lightgbm as lgb
import numpy as np
import pandas as pd
from scipy.sparse import load_npz
from sklearn.linear_model import LogisticRegression

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from src.build_features import build_feature_matrix_from_manifest
from src.select_v5_char_linear import (
    _candidate_metrics,
    _control_domain_probabilities,
    _control_probabilities,
    _development_metrics,
)
from src.train_lightgbm import (
    apply_monotone_feature_policy,
    apply_source_balance_policy,
    apply_training_weight_policy,
)
from src.training_data import compute_file_sha256, resolve_ml_path


def _load_json(path: Path) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _require_hash(path: Path, expected: str, label: str) -> None:
    actual = compute_file_sha256(path)
    if actual != expected.lower():
        raise ValueError(f"{label} SHA-256 mismatch: expected {expected}, got {actual}")


def _calibrated_probabilities(
    booster: lgb.Booster, calibration: Dict[str, float], matrix: Any
) -> np.ndarray:
    margins = booster.predict(matrix, raw_score=True)
    exponent = float(calibration["A"]) * margins + float(calibration["B"])
    return 1.0 / (1.0 + np.exp(np.clip(exponent, -40.0, 40.0)))


def malicious_source_metrics(
    frame: pd.DataFrame,
    probabilities: np.ndarray,
    threshold: float,
    minimum_source_rows: int,
) -> Dict[str, Any]:
    candidate_mask = (frame["label"].to_numpy().astype(int) == 1) & (
        frame["is_ml_candidate"].to_numpy() == True  # noqa: E712
    )
    candidate = frame.loc[candidate_mask].copy()
    candidate["predicted"] = probabilities[candidate_mask] >= threshold
    per_source = []
    for source, group in candidate.groupby("source", sort=True):
        rows = len(group)
        true_positives = int(group["predicted"].sum())
        per_source.append(
            {
                "source": str(source),
                "rows": rows,
                "true_positives": true_positives,
                "recall": float(true_positives / rows),
            }
        )
    eligible = [row for row in per_source if row["rows"] >= minimum_source_rows]
    if not eligible:
        raise ValueError("no malicious source meets the pre-registered minimum row count")
    recalls = np.asarray([row["recall"] for row in eligible], dtype=float)
    return {
        "minimum_source_rows": minimum_source_rows,
        "eligible_source_count": len(eligible),
        "macro_recall": float(np.mean(recalls)),
        "worst_source_recall": float(np.min(recalls)),
        "per_source": per_source,
    }


def select(protocol_path: str | os.PathLike[str]) -> Dict[str, Any]:
    started = time.time()
    protocol_file = Path(protocol_path).resolve()
    protocol = _load_json(protocol_file)
    candidate_config = _load_json(resolve_ml_path(protocol["candidate_data"]["config"]))
    control_config = _load_json(resolve_ml_path(protocol["control"]["config"]))

    for split in ("train", "validation", "calibration"):
        partition = protocol["candidate_data"]["partitions"][split]
        matrix = protocol["candidate_data"]["matrices"][split]
        _require_hash(resolve_ml_path(partition["path"]), partition["sha256"], f"{split} partition")
        _require_hash(resolve_ml_path(matrix["path"]), matrix["sha256"], f"{split} matrix")
    manifest_meta = protocol["candidate_data"]["feature_manifest"]
    manifest_path = resolve_ml_path(manifest_meta["path"])
    _require_hash(manifest_path, manifest_meta["sha256"], "feature manifest")
    development_meta = protocol["development"]
    development_path = resolve_ml_path(development_meta["path"])
    _require_hash(development_path, development_meta["sha256"], "development cohort")

    partitions = protocol["candidate_data"]["partitions"]
    matrices = protocol["candidate_data"]["matrices"]
    train = pd.read_parquet(resolve_ml_path(partitions["train"]["path"]))
    validation = pd.read_parquet(resolve_ml_path(partitions["validation"]["path"]))
    calibration_frame = pd.read_parquet(resolve_ml_path(partitions["calibration"]["path"]))
    development = pd.read_parquet(development_path)
    if len(development) != int(development_meta["rows"]):
        raise ValueError("development row count mismatch")
    if not development["ordinary_looking"].astype(bool).all():
        raise ValueError("development cohort must be ordinary-looking")

    x_train = load_npz(resolve_ml_path(matrices["train"]["path"]))
    x_validation = load_npz(resolve_ml_path(matrices["validation"]["path"]))
    x_calibration = load_npz(resolve_ml_path(matrices["calibration"]["path"]))
    if x_train.shape[0] != len(train) or x_validation.shape[0] != len(validation):
        raise ValueError("candidate matrices and partitions are not aligned")
    if x_calibration.shape[0] != len(calibration_frame):
        raise ValueError("calibration matrix and partition are not aligned")

    control_partitions = resolve_ml_path(control_config["partitions_dir"])
    control_validation = pd.read_parquet(
        control_partitions / "val.parquet", columns=["domain_ascii"]
    )
    if not control_validation["domain_ascii"].astype(str).equals(
        validation["domain_ascii"].astype(str)
    ):
        raise ValueError("control and candidate validation domains are not aligned")
    control_matrix = load_npz(resolve_ml_path(control_config["matrices_dir"]) / "X_val.npz")
    control_validation_probability = _control_probabilities(control_config, control_matrix)
    control_development_probability = _control_domain_probabilities(
        control_config, development["domain_ascii"].astype(str).tolist()
    )

    base_weight = train.get("sample_weight", pd.Series(1.0, index=train.index)).to_numpy(float)
    baseline_weight, baseline_weight_report = apply_training_weight_policy(
        train, base_weight, candidate_config["training"]
    )
    balance_protocol = protocol["source_balance"]
    balanced_weight, balance_report = apply_source_balance_policy(
        train,
        baseline_weight,
        {
            "exponent": 0.5,
            "raw_factor_clip": balance_protocol["raw_factor_clip"],
            "maximum_effective_weight": balance_protocol["maximum_effective_weight"],
        },
    )

    feature_manifest = _load_json(manifest_path)
    feature_names = feature_manifest["feature_names"]
    if len(feature_names) != x_train.shape[1]:
        raise ValueError("feature manifest does not match candidate matrix width")
    parameters, monotone_report = apply_monotone_feature_policy(
        candidate_config["lightgbm_params"], candidate_config["training"], feature_names
    )
    validation_weight = validation.get(
        "sample_weight", pd.Series(1.0, index=validation.index)
    ).to_numpy(float)
    model = lgb.LGBMClassifier(**parameters)
    print("[*] Training the fixed v6 source-balanced candidate...", flush=True)
    model.fit(
        x_train,
        train["label"].to_numpy(int),
        sample_weight=balanced_weight,
        eval_set=[(x_validation, validation["label"].to_numpy(int))],
        eval_sample_weight=[validation_weight],
        callbacks=[lgb.early_stopping(50, verbose=False)],
    )
    booster = model.booster_

    print("[*] Fitting Platt calibration on the unchanged calibration partition...", flush=True)
    calibration_margin = booster.predict(x_calibration, raw_score=True)
    calibration_weight = calibration_frame.get(
        "sample_weight", pd.Series(1.0, index=calibration_frame.index)
    ).to_numpy(float)
    calibrator = LogisticRegression(
        solver="lbfgs", max_iter=200, C=1.0, random_state=int(protocol["seed"])
    )
    calibrator.fit(
        calibration_margin.reshape(-1, 1),
        calibration_frame["label"].to_numpy(int),
        sample_weight=calibration_weight,
    )
    slope = float(calibrator.coef_[0][0])
    intercept = float(calibrator.intercept_[0])
    calibration_parameters = {
        "A": -slope,
        "B": -intercept,
        "slope_w": slope,
        "intercept_c": intercept,
    }

    candidate_validation_probability = _calibrated_probabilities(
        booster, calibration_parameters, x_validation
    )
    development_matrix = build_feature_matrix_from_manifest(
        development["domain_ascii"].astype(str).tolist(), str(manifest_path)
    )
    candidate_development_probability = _calibrated_probabilities(
        booster, calibration_parameters, development_matrix
    )
    threshold = float(protocol["model"]["operating_threshold"])
    minimum_source_rows = int(
        protocol["selection"]["eligibility_gates"][
            "validation_malicious_source_macro_recall_not_below_control"
        ]["minimum_source_rows"]
    )
    control_metrics = _candidate_metrics(
        validation, control_validation_probability, threshold
    )
    candidate_metrics = _candidate_metrics(
        validation, candidate_validation_probability, threshold
    )
    control_development = _development_metrics(
        control_development_probability, threshold
    )
    candidate_development = _development_metrics(
        candidate_development_probability, threshold
    )
    control_sources = malicious_source_metrics(
        validation, control_validation_probability, threshold, minimum_source_rows
    )
    candidate_sources = malicious_source_metrics(
        validation, candidate_validation_probability, threshold, minimum_source_rows
    )
    gates = {
        "validation_runtime_candidate_false_positives_not_above_control": (
            candidate_metrics["runtime_candidate_false_positives"]
            <= control_metrics["runtime_candidate_false_positives"]
        ),
        "validation_runtime_candidate_true_positives_not_below_control": (
            candidate_metrics["runtime_candidate_true_positives"]
            >= control_metrics["runtime_candidate_true_positives"]
        ),
        "validation_malicious_source_macro_recall_not_below_control": (
            candidate_sources["macro_recall"] >= control_sources["macro_recall"]
        ),
        "validation_malicious_source_worst_recall_not_below_control": (
            candidate_sources["worst_source_recall"]
            >= control_sources["worst_source_recall"]
        ),
        "development_true_positives_above_control": (
            candidate_development["true_positives"]
            > control_development["true_positives"]
        ),
    }
    eligible = all(gates.values())

    derived_dir = resolve_ml_path(protocol["outputs"]["derived_dir"])
    models_dir = derived_dir / "models"
    models_dir.mkdir(parents=True, exist_ok=True)
    model_path = models_dir / "domain_threat_lgbm_raw.txt"
    calibration_path = models_dir / "calibration.json"
    booster.save_model(str(model_path))
    calibration_artifact = {
        "calibration_version": "1.0.0",
        "method": "platt_sigmoid",
        "fitted_on_partition": "calibration",
        "num_samples": len(calibration_frame),
        "parameters": {
            **calibration_parameters,
            "formula": "P(malicious|raw_margin) = 1.0 / (1.0 + exp(A * raw_margin + B))",
            "clip_eps": 1e-15,
        },
    }
    with open(calibration_path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(calibration_artifact, handle, indent=2)
        handle.write("\n")

    report = {
        "schema_version": 1,
        "protocol_sha256": compute_file_sha256(protocol_file),
        "selection_inputs": ["train", "calibration", "validation", "v5_development"],
        "forbidden_inputs_read": [],
        "wall_time_seconds": round(time.time() - started, 2),
        "model": {
            "family": "LightGBM GBDT",
            "best_iteration": int(booster.best_iteration),
            "features": int(booster.num_feature()),
            "monotone_feature_policy": monotone_report,
        },
        "baseline_weighting": baseline_weight_report,
        "source_balance": balance_report,
        "control": {
            "validation": control_metrics,
            "development": control_development,
            "malicious_sources": control_sources,
        },
        "candidate": {
            "validation": candidate_metrics,
            "development": candidate_development,
            "malicious_sources": candidate_sources,
        },
        "gates": gates,
        "eligible": eligible,
        "artifacts": {
            "model": {
                "path": str(model_path.relative_to(BASE_DIR)).replace("\\", "/"),
                "sha256": compute_file_sha256(model_path),
                "bytes": model_path.stat().st_size,
            },
            "calibration": {
                "path": str(calibration_path.relative_to(BASE_DIR)).replace("\\", "/"),
                "sha256": compute_file_sha256(calibration_path),
                "bytes": calibration_path.stat().st_size,
            },
        },
        "decision": "ELIGIBLE_FOR_FINAL_EVALUATION" if eligible else "NO_GO_SELECTION",
    }
    report_path = resolve_ml_path(protocol["outputs"]["selection_report"])
    with open(report_path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(report, handle, indent=2)
        handle.write("\n")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Select the v6 source-balanced candidate")
    parser.add_argument(
        "--protocol",
        default=str(BASE_DIR / "configs" / "v6-source-balanced-robustness-protocol.json"),
    )
    args = parser.parse_args()
    result = select(args.protocol)
    print(
        json.dumps(
            {"eligible": result["eligible"], "decision": result["decision"]}, indent=2
        )
    )
