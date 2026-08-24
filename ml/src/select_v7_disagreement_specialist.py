"""Train and select the pre-registered v7 disagreement precision specialist."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict

import joblib
import lightgbm as lgb
import numpy as np
import pandas as pd
from scipy.sparse import load_npz
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from src.build_features import build_feature_matrix_from_manifest
from src.training_data import (
    _evaluation_group,
    compute_file_sha256,
    load_evaluation_group_policy,
    resolve_ml_path,
)


def _load_json(path: Path) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _require_hash(path: Path, expected: str, label: str) -> None:
    actual = compute_file_sha256(path)
    if actual != expected.lower():
        raise ValueError(f"{label} SHA-256 mismatch: expected {expected}, got {actual}")


def _load_booster_and_calibration(
    model_meta: Dict[str, Any], calibration_meta: Dict[str, Any]
) -> tuple[lgb.Booster, Dict[str, float]]:
    model_path = resolve_ml_path(model_meta["path"])
    calibration_path = resolve_ml_path(calibration_meta["path"])
    _require_hash(model_path, model_meta["sha256"], "base model")
    _require_hash(calibration_path, calibration_meta["sha256"], "base calibration")
    calibration = _load_json(calibration_path)["parameters"]
    return lgb.Booster(model_file=str(model_path)), calibration


def _predict(
    booster: lgb.Booster, calibration: Dict[str, float], matrix: Any
) -> tuple[np.ndarray, np.ndarray]:
    margin = booster.predict(matrix, raw_score=True)
    exponent = float(calibration["A"]) * margin + float(calibration["B"])
    probability = 1.0 / (1.0 + np.exp(np.clip(exponent, -40.0, 40.0)))
    return np.asarray(margin), np.asarray(probability)


def _logit(probability: np.ndarray) -> np.ndarray:
    clipped = np.clip(probability, 1e-9, 1.0 - 1e-9)
    return np.log(clipped / (1.0 - clipped))


def build_specialist_features(
    matrix: Any,
    control_probability: np.ndarray,
    recall_probability: np.ndarray,
) -> np.ndarray:
    if matrix.shape[0] != len(control_probability) or matrix.shape[0] != len(recall_probability):
        raise ValueError("specialist score features and matrix rows are not aligned")
    score_features = np.column_stack(
        [
            control_probability,
            recall_probability,
            recall_probability - control_probability,
            _logit(control_probability),
            _logit(recall_probability),
        ]
    )
    handcrafted = matrix[:, :22].toarray()
    return np.column_stack([score_features, handcrafted]).astype(np.float64, copy=False)


def stable_bucket(seed: int, evaluation_group: str, modulo: int = 10) -> int:
    digest = hashlib.sha256(f"{seed}|{evaluation_group}".encode("utf-8")).digest()
    return int.from_bytes(digest, "big", signed=False) % modulo


def select_zero_benign_threshold(
    probabilities: np.ndarray, labels: np.ndarray
) -> tuple[float, Dict[str, Any]]:
    probability = np.asarray(probabilities, dtype=float)
    label = np.asarray(labels, dtype=int)
    benign = probability[label == 0]
    malicious = probability[label == 1]
    if len(benign) == 0:
        raise ValueError("threshold-calibration disagreement requires benign rows")
    if len(malicious) == 0:
        raise ValueError("threshold-calibration disagreement requires malicious rows")
    threshold = float(np.nextafter(np.max(benign), 1.0))
    accepted_benign = int(np.sum(benign >= threshold))
    accepted_malicious = int(np.sum(malicious >= threshold))
    return threshold, {
        "rows": len(label),
        "benign_rows": len(benign),
        "malicious_rows": len(malicious),
        "accepted_benign": accepted_benign,
        "accepted_malicious": accepted_malicious,
        "threshold": threshold,
    }


def combined_decisions(
    frame: pd.DataFrame,
    control_probability: np.ndarray,
    recall_probability: np.ndarray,
    specialist_probability: np.ndarray,
    operating_threshold: float,
    specialist_threshold: float,
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    candidate = frame["is_ml_candidate"].to_numpy() == True  # noqa: E712
    primary = candidate & (control_probability >= operating_threshold)
    disagreement = (
        candidate
        & (control_probability < operating_threshold)
        & (recall_probability >= operating_threshold)
    )
    accepted = disagreement & (specialist_probability >= specialist_threshold)
    return primary | accepted, disagreement, accepted


def _runtime_metrics(frame: pd.DataFrame, decisions: np.ndarray) -> Dict[str, Any]:
    label = frame["label"].to_numpy().astype(int)
    candidate = frame["is_ml_candidate"].to_numpy() == True  # noqa: E712
    benign = candidate & (label == 0)
    malicious = candidate & (label == 1)
    false_positives = int(np.sum(decisions[benign]))
    true_positives = int(np.sum(decisions[malicious]))
    return {
        "rows": len(frame),
        "runtime_candidate_benign_rows": int(np.sum(benign)),
        "runtime_candidate_malicious_rows": int(np.sum(malicious)),
        "runtime_candidate_false_positives": false_positives,
        "runtime_candidate_true_positives": true_positives,
        "runtime_candidate_fpr": float(false_positives / np.sum(benign)),
        "runtime_candidate_recall": float(true_positives / np.sum(malicious)),
    }


def _evaluation_groups(frame: pd.DataFrame, policy: Dict[str, Any]) -> np.ndarray:
    roots = set(policy["roots"])
    groups = []
    for domain, registrable in zip(frame["domain_ascii"], frame["registrable_domain"]):
        group, _ = _evaluation_group(str(domain), str(registrable), roots)
        groups.append(group)
    return np.asarray(groups, dtype=object)


def select(protocol_path: str | os.PathLike[str]) -> Dict[str, Any]:
    started = time.time()
    protocol_file = Path(protocol_path).resolve()
    protocol = _load_json(protocol_file)

    for name in (
        "v3_model",
        "v3_calibration",
        "v6_model",
        "v6_calibration",
        "v6_selection_report",
        "v3_feature_manifest",
        "feature_manifest",
    ):
        meta = protocol["artifacts"][name]
        _require_hash(resolve_ml_path(meta["path"]), meta["sha256"], name)
    for name in (
        "calibration_partition",
        "v3_calibration_matrix",
        "calibration_matrix",
        "validation_partition",
        "v3_validation_matrix",
        "validation_matrix",
        "development",
    ):
        meta = protocol["inputs"][name]
        _require_hash(resolve_ml_path(meta["path"]), meta["sha256"], name)

    artifacts = protocol["artifacts"]
    control_booster, control_calibration = _load_booster_and_calibration(
        artifacts["v3_model"], artifacts["v3_calibration"]
    )
    recall_booster, recall_calibration = _load_booster_and_calibration(
        artifacts["v6_model"], artifacts["v6_calibration"]
    )
    calibration_frame = pd.read_parquet(
        resolve_ml_path(protocol["inputs"]["calibration_partition"]["path"])
    ).reset_index(drop=True)
    validation_frame = pd.read_parquet(
        resolve_ml_path(protocol["inputs"]["validation_partition"]["path"])
    ).reset_index(drop=True)
    development = pd.read_parquet(
        resolve_ml_path(protocol["inputs"]["development"]["path"])
    ).reset_index(drop=True)
    development["is_ml_candidate"] = True
    control_calibration_matrix = load_npz(
        resolve_ml_path(protocol["inputs"]["v3_calibration_matrix"]["path"])
    )
    recall_calibration_matrix = load_npz(
        resolve_ml_path(protocol["inputs"]["calibration_matrix"]["path"])
    )
    control_validation_matrix = load_npz(
        resolve_ml_path(protocol["inputs"]["v3_validation_matrix"]["path"])
    )
    recall_validation_matrix = load_npz(
        resolve_ml_path(protocol["inputs"]["validation_matrix"]["path"])
    )
    if (
        control_calibration_matrix.shape[0] != len(calibration_frame)
        or recall_calibration_matrix.shape[0] != len(calibration_frame)
    ):
        raise ValueError("calibration matrices and partition are not aligned")
    if (
        control_validation_matrix.shape[0] != len(validation_frame)
        or recall_validation_matrix.shape[0] != len(validation_frame)
    ):
        raise ValueError("validation matrices and partition are not aligned")
    if len(development) != int(protocol["inputs"]["development"]["rows"]):
        raise ValueError("development row count mismatch")

    _, control_calibration_probability = _predict(
        control_booster, control_calibration, control_calibration_matrix
    )
    _, recall_calibration_probability = _predict(
        recall_booster, recall_calibration, recall_calibration_matrix
    )
    operating_threshold = float(protocol["disagreement"]["operating_threshold"])
    calibration_candidate = calibration_frame["is_ml_candidate"].to_numpy() == True  # noqa: E712
    calibration_disagreement = (
        calibration_candidate
        & (control_calibration_probability < operating_threshold)
        & (recall_calibration_probability >= operating_threshold)
    )

    group_policy = load_evaluation_group_policy(
        protocol["specialist_split"]["evaluation_group_policy"]
    )
    groups = _evaluation_groups(calibration_frame, group_policy)
    buckets = np.asarray(
        [stable_bucket(int(protocol["seed"]), str(group)) for group in groups], dtype=int
    )
    train_buckets = set(int(value) for value in protocol["specialist_split"]["train_buckets"])
    threshold_buckets = set(
        int(value)
        for value in protocol["specialist_split"]["threshold_calibration_buckets"]
    )
    specialist_train = calibration_disagreement & np.isin(buckets, list(train_buckets))
    threshold_calibration = calibration_disagreement & np.isin(
        buckets, list(threshold_buckets)
    )
    train_groups = set(groups[specialist_train])
    threshold_groups = set(groups[threshold_calibration])
    if train_groups & threshold_groups:
        raise ValueError("specialist train and threshold-calibration groups overlap")

    calibration_features = build_specialist_features(
        recall_calibration_matrix,
        control_calibration_probability,
        recall_calibration_probability,
    )
    model_config = protocol["specialist_model"]
    specialist = Pipeline(
        [
            ("scale", StandardScaler()),
            (
                "logistic",
                LogisticRegression(
                    penalty=str(model_config["penalty"]),
                    C=float(model_config["C"]),
                    solver=str(model_config["solver"]),
                    max_iter=int(model_config["max_iter"]),
                    class_weight=str(model_config["class_weight"]),
                    random_state=int(model_config["random_state"]),
                ),
            ),
        ]
    )
    specialist.fit(
        calibration_features[specialist_train],
        calibration_frame["label"].to_numpy(int)[specialist_train],
    )
    threshold_probability = specialist.predict_proba(
        calibration_features[threshold_calibration]
    )[:, 1]
    specialist_threshold, threshold_metrics = select_zero_benign_threshold(
        threshold_probability,
        calibration_frame["label"].to_numpy(int)[threshold_calibration],
    )

    _, control_validation_probability = _predict(
        control_booster, control_calibration, control_validation_matrix
    )
    _, recall_validation_probability = _predict(
        recall_booster, recall_calibration, recall_validation_matrix
    )
    validation_features = build_specialist_features(
        recall_validation_matrix,
        control_validation_probability,
        recall_validation_probability,
    )
    validation_specialist_probability = specialist.predict_proba(validation_features)[:, 1]
    combined_validation, validation_disagreement, validation_accepted = combined_decisions(
        validation_frame,
        control_validation_probability,
        recall_validation_probability,
        validation_specialist_probability,
        operating_threshold,
        specialist_threshold,
    )
    control_validation_decision = (
        validation_frame["is_ml_candidate"].to_numpy() == True  # noqa: E712
    ) & (control_validation_probability >= operating_threshold)
    control_validation_metrics = _runtime_metrics(
        validation_frame, control_validation_decision
    )
    combined_validation_metrics = _runtime_metrics(validation_frame, combined_validation)

    control_feature_manifest_path = resolve_ml_path(
        artifacts["v3_feature_manifest"]["path"]
    )
    recall_feature_manifest_path = resolve_ml_path(artifacts["feature_manifest"]["path"])
    development_domains = development["domain_ascii"].astype(str).tolist()
    control_development_matrix = build_feature_matrix_from_manifest(
        development_domains, str(control_feature_manifest_path)
    )
    recall_development_matrix = build_feature_matrix_from_manifest(
        development_domains, str(recall_feature_manifest_path)
    )
    _, control_development_probability = _predict(
        control_booster, control_calibration, control_development_matrix
    )
    _, recall_development_probability = _predict(
        recall_booster, recall_calibration, recall_development_matrix
    )
    development_features = build_specialist_features(
        recall_development_matrix,
        control_development_probability,
        recall_development_probability,
    )
    development_specialist_probability = specialist.predict_proba(development_features)[:, 1]
    combined_development, development_disagreement, development_accepted = combined_decisions(
        development,
        control_development_probability,
        recall_development_probability,
        development_specialist_probability,
        operating_threshold,
        specialist_threshold,
    )
    development_candidate = development["is_ml_candidate"].to_numpy() == True  # noqa: E712
    control_development = development_candidate & (
        control_development_probability >= operating_threshold
    )
    control_development_tp = int(np.sum(control_development))
    combined_development_tp = int(np.sum(combined_development))

    gates = {
        "threshold_calibration_accepted_benign_max": (
            threshold_metrics["accepted_benign"]
            <= int(protocol["selection"]["eligibility_gates"]["threshold_calibration_accepted_benign_max"])
        ),
        "threshold_calibration_accepted_malicious_min": (
            threshold_metrics["accepted_malicious"]
            >= int(protocol["selection"]["eligibility_gates"]["threshold_calibration_accepted_malicious_min"])
        ),
        "validation_runtime_candidate_false_positives_not_above_v3": (
            combined_validation_metrics["runtime_candidate_false_positives"]
            <= control_validation_metrics["runtime_candidate_false_positives"]
        ),
        "validation_runtime_candidate_true_positives_above_v3": (
            combined_validation_metrics["runtime_candidate_true_positives"]
            > control_validation_metrics["runtime_candidate_true_positives"]
        ),
        "development_true_positives_above_v3": (
            combined_development_tp > control_development_tp
        ),
    }
    eligible = all(gates.values())

    derived_dir = resolve_ml_path(protocol["outputs"]["derived_dir"])
    models_dir = derived_dir / "models"
    models_dir.mkdir(parents=True, exist_ok=True)
    specialist_path = models_dir / "precision_specialist.joblib"
    joblib.dump(specialist, specialist_path)
    report = {
        "schema_version": 1,
        "protocol_sha256": compute_file_sha256(protocol_file),
        "selection_inputs": ["calibration", "validation", "v5_development"],
        "forbidden_inputs_read": [],
        "wall_time_seconds": round(time.time() - started, 2),
        "specialist": {
            "features": 27,
            "model": model_config,
            "threshold": specialist_threshold,
            "calibration_disagreement_rows": int(np.sum(calibration_disagreement)),
            "train_rows": int(np.sum(specialist_train)),
            "train_benign": int(
                np.sum(calibration_frame["label"].to_numpy(int)[specialist_train] == 0)
            ),
            "train_malicious": int(
                np.sum(calibration_frame["label"].to_numpy(int)[specialist_train] == 1)
            ),
            "threshold_calibration": threshold_metrics,
            "group_overlap": len(train_groups & threshold_groups),
        },
        "validation": {
            "control": control_validation_metrics,
            "combined": combined_validation_metrics,
            "disagreement_rows": int(np.sum(validation_disagreement)),
            "accepted_rows": int(np.sum(validation_accepted)),
            "accepted_benign": int(
                np.sum(validation_accepted & (validation_frame["label"].to_numpy(int) == 0))
            ),
            "accepted_malicious": int(
                np.sum(validation_accepted & (validation_frame["label"].to_numpy(int) == 1))
            ),
        },
        "development": {
            "rows": len(development),
            "control_true_positives": control_development_tp,
            "combined_true_positives": combined_development_tp,
            "disagreement_rows": int(np.sum(development_disagreement)),
            "accepted_rows": int(np.sum(development_accepted)),
        },
        "gates": gates,
        "eligible": eligible,
        "artifacts": {
            "specialist": {
                "path": str(specialist_path.relative_to(BASE_DIR)).replace("\\", "/"),
                "sha256": compute_file_sha256(specialist_path),
                "bytes": specialist_path.stat().st_size,
            }
        },
        "decision": "ELIGIBLE_FOR_FINAL_EVALUATION" if eligible else "NO_GO_SELECTION",
    }
    report_path = resolve_ml_path(protocol["outputs"]["selection_report"])
    with open(report_path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(report, handle, indent=2)
        handle.write("\n")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Select the v7 disagreement specialist")
    parser.add_argument(
        "--protocol",
        default=str(BASE_DIR / "configs" / "v7-disagreement-specialist-protocol.json"),
    )
    args = parser.parse_args()
    result = select(args.protocol)
    print(json.dumps({"eligible": result["eligible"], "decision": result["decision"]}, indent=2))
