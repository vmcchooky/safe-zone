"""Select a time-forward candidate without opening final/frozen holdouts."""

from __future__ import annotations

import argparse
import copy
import json
import os
import shutil
import sys
from pathlib import Path
from typing import Any, Dict

import lightgbm as lgb
import numpy as np
import pandas as pd
from scipy.sparse import load_npz
from sklearn.metrics import log_loss

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from src.build_features import build_feature_matrix_from_manifest
from src.calibrate_model import run_calibration
from src.train_lightgbm import run_training
from src.training_data import compute_file_sha256


def _load_json(path: Path) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _resolve(value: str) -> Path:
    path = Path(value)
    return path.resolve() if path.is_absolute() else (BASE_DIR / path).resolve()


def _predict(models_dir: Path, matrix: Any) -> np.ndarray:
    booster = lgb.Booster(model_file=str(models_dir / "domain_threat_lgbm_raw.txt"))
    calibration = _load_json(models_dir / "calibration.json")
    raw_margin = booster.predict(matrix, raw_score=True)
    parameters = calibration["parameters"]
    return 1.0 / (
        1.0
        + np.exp(
            float(parameters["A"]) * raw_margin + float(parameters["B"])
        )
    )


def _validation_metrics(config: Dict[str, Any], models_dir: Path, threshold: float) -> Dict[str, Any]:
    matrices_dir = _resolve(str(config["matrices_dir"]))
    partitions_dir = _resolve(str(config["partitions_dir"]))
    matrix = load_npz(matrices_dir / "X_val.npz")
    frame = pd.read_parquet(partitions_dir / "val.parquet")
    labels = frame["label"].to_numpy().astype(int)
    probabilities = _predict(models_dir, matrix)
    candidate = frame["is_ml_candidate"].to_numpy() == True  # noqa: E712
    benign_candidate = candidate & (labels == 0)
    malicious_candidate = candidate & (labels == 1)
    false_positives = int(np.sum(probabilities[benign_candidate] >= threshold))
    true_positives = int(np.sum(probabilities[malicious_candidate] >= threshold))
    return {
        "rows": len(frame),
        "binary_logloss": float(log_loss(labels, probabilities)),
        "runtime_candidate_benign_rows": int(np.sum(benign_candidate)),
        "runtime_candidate_malicious_rows": int(np.sum(malicious_candidate)),
        "runtime_candidate_false_positives": false_positives,
        "runtime_candidate_true_positives": true_positives,
        "runtime_candidate_fpr": (
            float(false_positives / np.sum(benign_candidate))
            if np.any(benign_candidate)
            else 0.0
        ),
        "runtime_candidate_recall": (
            float(true_positives / np.sum(malicious_candidate))
            if np.any(malicious_candidate)
            else 0.0
        ),
    }


def _development_metrics(
    config: Dict[str, Any], models_dir: Path, development: pd.DataFrame, threshold: float
) -> Dict[str, Any]:
    manifest_path = _resolve(str(config["derived_dir"])) / "feature_manifest.json"
    matrix = build_feature_matrix_from_manifest(
        development["domain_ascii"].astype(str).tolist(), str(manifest_path)
    )
    probabilities = _predict(models_dir, matrix)
    true_positives = int(np.sum(probabilities >= threshold))
    ordinary_mask = development["ordinary_looking"].to_numpy() == True  # noqa: E712
    ordinary_true_positives = int(
        np.sum(probabilities[ordinary_mask] >= threshold)
    )
    return {
        "rows": len(development),
        "true_positives": true_positives,
        "recall": float(true_positives / len(development)),
        "ordinary_rows": int(np.sum(ordinary_mask)),
        "ordinary_true_positives": ordinary_true_positives,
        "ordinary_recall": (
            float(ordinary_true_positives / np.sum(ordinary_mask))
            if np.any(ordinary_mask)
            else 0.0
        ),
        "mean_probability": float(np.mean(probabilities)),
        "median_probability": float(np.median(probabilities)),
    }


def select_candidate(protocol_path: str | os.PathLike[str]) -> Dict[str, Any]:
    protocol_file = Path(protocol_path).resolve()
    protocol = _load_json(protocol_file)
    selection = protocol["candidate_selection"]
    threshold = float(selection["operating_threshold"])
    weights = [float(value) for value in selection["hard_positive_weights"]]
    if weights != sorted(set(weights)):
        raise ValueError("candidate weights must be unique and sorted")

    public_manifest = _load_json(_resolve(protocol["outputs"]["public_manifest"]))
    development_meta = public_manifest["outputs"]["development"]
    development_path = _resolve(str(development_meta["path"]))
    if compute_file_sha256(development_path) != str(development_meta["sha256"]):
        raise ValueError("development cohort checksum does not match frozen manifest")
    development = pd.read_parquet(development_path)
    if len(development) != int(development_meta["rows"]):
        raise ValueError("development row count does not match frozen manifest")

    control_config_path = BASE_DIR / "configs" / "v3-leakage-free-context.json"
    control_config = _load_json(control_config_path)
    control_models_dir = _resolve(str(control_config["models_dir"]))
    control_validation = _validation_metrics(
        control_config, control_models_dir, threshold
    )

    families = {
        "v3_time_forward_data": BASE_DIR / "configs" / "v3-time-forward-data.json",
        "v4_ternary_tld_time_forward_data": BASE_DIR
        / "configs"
        / "v4-time-forward-ternary-tld.json",
    }
    requested_families = [str(value) for value in selection["candidate_families"]]
    if set(requested_families) != set(families):
        raise ValueError("protocol candidate family set is unsupported")

    ablation_root = _resolve("data/derived/v4-time-forward-weight-ablation")
    candidates = []
    for family_name in requested_families:
        base_config_path = families[family_name]
        base_config = _load_json(base_config_path)
        for weight in weights:
            weight_name = str(weight).replace(".", "p")
            models_dir = ablation_root / family_name / f"weight-{weight_name}" / "models"
            models_dir.mkdir(parents=True, exist_ok=True)
            run_config = copy.deepcopy(base_config)
            run_config["models_dir"] = str(models_dir)
            run_config["training"]["time_forward_hard_positive"]["weight"] = weight
            temp_config = models_dir.parent / "run-config.json"
            with open(temp_config, "w", encoding="utf-8", newline="\n") as handle:
                json.dump(run_config, handle, indent=2)
                handle.write("\n")
            run_training(str(temp_config))
            run_calibration(str(temp_config))
            validation = _validation_metrics(run_config, models_dir, threshold)
            development_metrics = _development_metrics(
                run_config, models_dir, development, threshold
            )
            eligible = (
                validation["runtime_candidate_false_positives"]
                <= control_validation["runtime_candidate_false_positives"]
            )
            candidates.append(
                {
                    "family": family_name,
                    "config_path": str(base_config_path.relative_to(BASE_DIR)).replace("\\", "/"),
                    "hard_positive_weight": weight,
                    "models_dir": str(models_dir.relative_to(BASE_DIR)).replace("\\", "/"),
                    "eligible": eligible,
                    "validation": validation,
                    "development": development_metrics,
                }
            )

    eligible_candidates = [candidate for candidate in candidates if candidate["eligible"]]
    selected = None
    if eligible_candidates:
        selected = sorted(
            eligible_candidates,
            key=lambda candidate: (
                -candidate["development"]["recall"],
                candidate["validation"]["binary_logloss"],
                candidate["hard_positive_weight"],
                candidate["family"],
            ),
        )[0]
        selected_config = _load_json(_resolve(selected["config_path"]))
        final_models_dir = _resolve(str(selected_config["models_dir"]))
        final_models_dir.mkdir(parents=True, exist_ok=True)
        source_models_dir = _resolve(selected["models_dir"])
        for name in (
            "domain_threat_lgbm_raw.txt",
            "baseline_report.json",
            "calibration.json",
        ):
            shutil.copy2(source_models_dir / name, final_models_dir / name)

    report = {
        "schema_version": 1,
        "protocol_path": str(protocol_file.relative_to(BASE_DIR)).replace("\\", "/"),
        "selection_inputs": ["validation", "phishtank_time_forward_development"],
        "forbidden_inputs_read": [],
        "operating_threshold": threshold,
        "control_validation": control_validation,
        "candidates": candidates,
        "selected": selected,
    }
    report_path = BASE_DIR / "experiments" / "v4-weight-ablation-selection.json"
    with open(report_path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(report, handle, indent=2)
        handle.write("\n")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Select a time-forward candidate without final holdout leakage"
    )
    parser.add_argument(
        "--protocol",
        default=str(BASE_DIR / "configs" / "v4-time-forward-protocol.json"),
    )
    args = parser.parse_args()
    result = select_candidate(args.protocol)
    print(json.dumps(result["selected"], indent=2))
