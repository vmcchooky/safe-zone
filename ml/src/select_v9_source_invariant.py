"""Train and select the pre-registered v9 source-invariant architecture."""

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
from src.select_v7_disagreement_specialist import (
    _load_booster_and_calibration,
    _predict,
    build_specialist_features,
    combined_decisions,
    select_zero_benign_threshold,
    stable_bucket,
)
from src.source_invariant import select_source_invariant_features
from src.train_lightgbm import apply_monotone_feature_policy, apply_training_weight_policy
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


def _calibrate(
    booster: lgb.Booster,
    matrix: Any,
    frame: pd.DataFrame,
    seed: int,
) -> Dict[str, float]:
    margin = booster.predict(matrix, raw_score=True)
    weights = frame.get("sample_weight", pd.Series(1.0, index=frame.index)).to_numpy(float)
    model = LogisticRegression(solver="lbfgs", max_iter=200, C=1.0, random_state=seed)
    model.fit(margin.reshape(-1, 1), frame["label"].to_numpy(int), sample_weight=weights)
    slope = float(model.coef_[0][0])
    intercept = float(model.intercept_[0])
    return {"A": -slope, "B": -intercept, "slope_w": slope, "intercept_c": intercept}


def _metrics(frame: pd.DataFrame, decisions: np.ndarray) -> Dict[str, Any]:
    labels = frame["label"].to_numpy(int)
    candidate = (
        frame["is_ml_candidate"].to_numpy() == True  # noqa: E712
        if "is_ml_candidate" in frame.columns
        else np.ones(len(frame), dtype=bool)
    )
    benign = candidate & (labels == 0)
    malicious = candidate & (labels == 1)
    return {
        "rows": int(len(frame)),
        "candidate_benign_rows": int(np.sum(benign)),
        "candidate_malicious_rows": int(np.sum(malicious)),
        "benign_false_positives": int(np.sum(decisions[benign])),
        "malicious_true_positives": int(np.sum(decisions[malicious])),
    }


def _comparison(
    frame: pd.DataFrame, primary: np.ndarray, combined: np.ndarray
) -> Dict[str, Any]:
    control = _metrics(frame, primary)
    candidate = _metrics(frame, combined)
    return {
        "control": control,
        "combined": candidate,
        "incremental_benign_false_positives": candidate["benign_false_positives"]
        - control["benign_false_positives"],
        "incremental_malicious_true_positives": candidate["malicious_true_positives"]
        - control["malicious_true_positives"],
    }


def _evaluation_groups(frame: pd.DataFrame, policy: Dict[str, Any]) -> np.ndarray:
    roots = set(policy["roots"])
    return np.asarray(
        [
            _evaluation_group(str(domain), str(registrable), roots)[0]
            for domain, registrable in zip(
                frame["domain_ascii"], frame["registrable_domain"]
            )
        ],
        dtype=object,
    )


def _write_json(path: Path, value: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(value, handle, indent=2)
        handle.write("\n")


def select(protocol_path: str | os.PathLike[str]) -> Dict[str, Any]:
    started = time.time()
    protocol_file = Path(protocol_path).resolve()
    protocol = _load_json(protocol_file)
    protocol_hash = compute_file_sha256(protocol_file)
    seed = int(protocol["seed"])
    threshold = float(protocol["control"]["operating_threshold"])

    snapshot_path = resolve_ml_path(protocol["development_snapshot"]["manifest"])
    snapshot = _load_json(snapshot_path)
    if snapshot["protocol_sha256"] != protocol_hash:
        raise ValueError("development snapshot does not match active protocol")
    development_meta = snapshot["output"]
    development_path = resolve_ml_path(development_meta["path"])
    _require_hash(development_path, development_meta["sha256"], "fresh development")

    candidate_data = protocol["candidate_data"]
    for section in ("partitions", "matrices"):
        for name in ("train", "validation", "calibration"):
            meta = candidate_data[section][name]
            _require_hash(resolve_ml_path(meta["path"]), meta["sha256"], f"candidate {name} {section}")
    candidate_manifest_path = resolve_ml_path(candidate_data["feature_manifest"]["path"])
    _require_hash(
        candidate_manifest_path,
        candidate_data["feature_manifest"]["sha256"],
        "candidate feature manifest",
    )
    for name in ("model", "calibration", "feature_manifest"):
        meta = protocol["control"][name]
        _require_hash(resolve_ml_path(meta["path"]), meta["sha256"], f"control {name}")
    for name in ("calibration", "validation"):
        meta = protocol["control"]["matrices"][name]
        _require_hash(resolve_ml_path(meta["path"]), meta["sha256"], f"control {name} matrix")

    partitions = {
        name: pd.read_parquet(resolve_ml_path(candidate_data["partitions"][name]["path"]))
        for name in ("train", "validation", "calibration")
    }
    matrices = {
        name: load_npz(resolve_ml_path(candidate_data["matrices"][name]["path"])).tocsr()
        for name in ("train", "validation", "calibration")
    }
    for name in partitions:
        if len(partitions[name]) != matrices[name].shape[0]:
            raise ValueError(f"candidate {name} matrix is not aligned")
    development = pd.read_parquet(development_path)
    if len(development) != int(development_meta["rows"]):
        raise ValueError("fresh development row count mismatch")

    candidate_manifest = _load_json(candidate_manifest_path)
    feature_names = list(candidate_manifest["feature_names"])
    selected_indices, feature_report = select_source_invariant_features(
        partitions["train"],
        matrices["train"],
        feature_names,
        protocol["source_invariant_feature_policy"],
    )
    selected_names = [feature_names[index] for index in selected_indices]
    config = _load_json(resolve_ml_path(candidate_data["config"]))
    parameters, monotone_report = apply_monotone_feature_policy(
        config["lightgbm_params"], config["training"], selected_names
    )
    base_weight = partitions["train"].get(
        "sample_weight", pd.Series(1.0, index=partitions["train"].index)
    ).to_numpy(float)
    train_weight, weight_report = apply_training_weight_policy(
        partitions["train"], base_weight, config["training"]
    )
    validation_weight = partitions["validation"].get(
        "sample_weight", pd.Series(1.0, index=partitions["validation"].index)
    ).to_numpy(float)
    recall_model = lgb.LGBMClassifier(**parameters)
    print(f"[*] Training v9 recall model with {len(selected_indices)} source-invariant features...", flush=True)
    recall_model.fit(
        matrices["train"][:, selected_indices],
        partitions["train"]["label"].to_numpy(int),
        sample_weight=train_weight,
        eval_set=[
            (
                matrices["validation"][:, selected_indices],
                partitions["validation"]["label"].to_numpy(int),
            )
        ],
        eval_sample_weight=[validation_weight],
        callbacks=[lgb.early_stopping(50, verbose=False)],
    )
    recall_booster = recall_model.booster_
    recall_calibration = _calibrate(
        recall_booster,
        matrices["calibration"][:, selected_indices],
        partitions["calibration"],
        seed,
    )

    control_booster, control_calibration = _load_booster_and_calibration(
        protocol["control"]["model"], protocol["control"]["calibration"]
    )
    control_calibration_matrix = load_npz(
        resolve_ml_path(protocol["control"]["matrices"]["calibration"]["path"])
    )
    control_validation_matrix = load_npz(
        resolve_ml_path(protocol["control"]["matrices"]["validation"]["path"])
    )
    _, control_calibration_probability = _predict(
        control_booster, control_calibration, control_calibration_matrix
    )
    _, recall_calibration_probability = _predict(
        recall_booster,
        recall_calibration,
        matrices["calibration"][:, selected_indices],
    )
    calibration_candidate = partitions["calibration"]["is_ml_candidate"].to_numpy() == True  # noqa: E712
    disagreement = (
        calibration_candidate
        & (control_calibration_probability < threshold)
        & (recall_calibration_probability >= threshold)
    )
    group_policy = load_evaluation_group_policy(
        protocol["development_snapshot"]["group_policy"]
    )
    groups = _evaluation_groups(partitions["calibration"], group_policy)
    buckets = np.asarray([stable_bucket(seed, str(group)) for group in groups])
    specialist_cfg = protocol["precision_specialist"]
    specialist_train = disagreement & np.isin(buckets, specialist_cfg["train_buckets"])
    specialist_threshold_rows = disagreement & np.isin(
        buckets, specialist_cfg["threshold_buckets"]
    )
    if set(groups[specialist_train]) & set(groups[specialist_threshold_rows]):
        raise ValueError("specialist train and threshold groups overlap")
    specialist_features = build_specialist_features(
        matrices["calibration"],
        control_calibration_probability,
        recall_calibration_probability,
    )
    specialist = Pipeline(
        [
            ("scale", StandardScaler()),
            (
                "model",
                LogisticRegression(
                    penalty=specialist_cfg["penalty"],
                    C=float(specialist_cfg["C"]),
                    solver=specialist_cfg["solver"],
                    max_iter=int(specialist_cfg["max_iter"]),
                    class_weight=specialist_cfg["class_weight"],
                    random_state=int(specialist_cfg["random_state"]),
                ),
            ),
        ]
    )
    specialist.fit(
        specialist_features[specialist_train],
        partitions["calibration"]["label"].to_numpy(int)[specialist_train],
    )
    threshold_probability = specialist.predict_proba(
        specialist_features[specialist_threshold_rows]
    )[:, 1]
    specialist_threshold, threshold_metrics = select_zero_benign_threshold(
        threshold_probability,
        partitions["calibration"]["label"].to_numpy(int)[specialist_threshold_rows],
    )

    _, control_validation_probability = _predict(
        control_booster, control_calibration, control_validation_matrix
    )
    _, recall_validation_probability = _predict(
        recall_booster,
        recall_calibration,
        matrices["validation"][:, selected_indices],
    )
    validation_specialist_probability = specialist.predict_proba(
        build_specialist_features(
            matrices["validation"],
            control_validation_probability,
            recall_validation_probability,
        )
    )[:, 1]
    validation_combined, validation_disagreement, validation_accepted = combined_decisions(
        partitions["validation"],
        control_validation_probability,
        recall_validation_probability,
        validation_specialist_probability,
        threshold,
        specialist_threshold,
    )
    validation_primary = (
        (partitions["validation"]["is_ml_candidate"].to_numpy() == True)  # noqa: E712
        & (control_validation_probability >= threshold)
    )
    validation_comparison = _comparison(
        partitions["validation"], validation_primary, validation_combined
    )

    domains = development["domain_ascii"].astype(str).tolist()
    control_development_matrix = build_feature_matrix_from_manifest(
        domains, str(resolve_ml_path(protocol["control"]["feature_manifest"]["path"]))
    )
    candidate_development_matrix = build_feature_matrix_from_manifest(
        domains, str(candidate_manifest_path)
    )
    _, control_development_probability = _predict(
        control_booster, control_calibration, control_development_matrix
    )
    _, recall_development_probability = _predict(
        recall_booster,
        recall_calibration,
        candidate_development_matrix[:, selected_indices],
    )
    development_specialist_probability = specialist.predict_proba(
        build_specialist_features(
            candidate_development_matrix,
            control_development_probability,
            recall_development_probability,
        )
    )[:, 1]
    development_runtime = development.copy()
    development_runtime["is_ml_candidate"] = True
    development_combined, development_disagreement, development_accepted = combined_decisions(
        development_runtime,
        control_development_probability,
        recall_development_probability,
        development_specialist_probability,
        threshold,
        specialist_threshold,
    )
    development_primary = control_development_probability >= threshold
    development_comparison = _comparison(
        development_runtime, development_primary, development_combined
    )

    gates_cfg = protocol["selection"]["eligibility_gates"]
    gates = {
        "threshold_accepted_benign_max": threshold_metrics["accepted_benign"]
        <= int(gates_cfg["threshold_accepted_benign_max"]),
        "threshold_accepted_malicious_min": threshold_metrics["accepted_malicious"]
        >= int(gates_cfg["threshold_accepted_malicious_min"]),
        "validation_incremental_benign_false_positives_max": validation_comparison[
            "incremental_benign_false_positives"
        ]
        <= int(gates_cfg["validation_incremental_benign_false_positives_max"]),
        "validation_incremental_malicious_true_positives_min": validation_comparison[
            "incremental_malicious_true_positives"
        ]
        >= int(gates_cfg["validation_incremental_malicious_true_positives_min"]),
        "development_incremental_benign_false_positives_max": development_comparison[
            "incremental_benign_false_positives"
        ]
        <= int(gates_cfg["development_incremental_benign_false_positives_max"]),
        "development_incremental_malicious_true_positives_min": development_comparison[
            "incremental_malicious_true_positives"
        ]
        >= int(gates_cfg["development_incremental_malicious_true_positives_min"]),
    }
    eligible = all(gates.values())

    derived_dir = resolve_ml_path(protocol["outputs"]["derived_dir"])
    models_dir = derived_dir / "models"
    models_dir.mkdir(parents=True, exist_ok=True)
    model_path = models_dir / "source_invariant_lgbm.txt"
    calibration_path = models_dir / "calibration.json"
    specialist_path = models_dir / "precision_specialist.joblib"
    feature_path = derived_dir / "selected_features.json"
    recall_booster.save_model(str(model_path))
    _write_json(
        calibration_path,
        {"method": "platt_sigmoid", "parameters": recall_calibration},
    )
    joblib.dump(specialist, specialist_path)
    _write_json(
        feature_path,
        {
            "protocol_sha256": protocol_hash,
            "source_feature_manifest_sha256": compute_file_sha256(candidate_manifest_path),
            **feature_report,
        },
    )
    report = {
        "schema_version": 1,
        "protocol_sha256": protocol_hash,
        "snapshot_manifest_sha256": compute_file_sha256(snapshot_path),
        "selection_inputs": ["train", "calibration", "validation", "fresh_development"],
        "forbidden_inputs_read": [],
        "feature_selection": feature_report,
        "training": {
            "best_iteration": int(recall_booster.best_iteration),
            "sample_weighting": weight_report,
            "monotone_policy": monotone_report,
        },
        "specialist": {
            "calibration_disagreement_rows": int(np.sum(disagreement)),
            "train_rows": int(np.sum(specialist_train)),
            "threshold_rows": int(np.sum(specialist_threshold_rows)),
            "threshold": threshold_metrics,
        },
        "validation": {
            **validation_comparison,
            "disagreement_rows": int(np.sum(validation_disagreement)),
            "accepted_rows": int(np.sum(validation_accepted)),
        },
        "development": {
            **development_comparison,
            "disagreement_rows": int(np.sum(development_disagreement)),
            "accepted_rows": int(np.sum(development_accepted)),
        },
        "gates": gates,
        "eligible_for_final": eligible,
        "decision": "ELIGIBLE_FOR_FINAL" if eligible else "NO_ELIGIBLE_CANDIDATE",
        "artifacts": {
            "model": {"path": str(model_path.relative_to(BASE_DIR)).replace("\\", "/"), "sha256": compute_file_sha256(model_path)},
            "calibration": {"path": str(calibration_path.relative_to(BASE_DIR)).replace("\\", "/"), "sha256": compute_file_sha256(calibration_path)},
            "specialist": {"path": str(specialist_path.relative_to(BASE_DIR)).replace("\\", "/"), "sha256": compute_file_sha256(specialist_path)},
            "selected_features": {"path": str(feature_path.relative_to(BASE_DIR)).replace("\\", "/"), "sha256": compute_file_sha256(feature_path)},
        },
        "wall_time_seconds": round(time.time() - started, 2),
    }
    _write_json(resolve_ml_path(protocol["outputs"]["selection_report"]), report)
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Select v9 source-invariant candidate")
    parser.add_argument(
        "--protocol",
        default=str(BASE_DIR / "configs" / "v9-source-invariant-round1-protocol.json"),
    )
    args = parser.parse_args()
    result = select(args.protocol)
    print(json.dumps({"decision": result["decision"], "gates": result["gates"]}, indent=2))
