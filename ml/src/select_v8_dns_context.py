"""Collect, train, and select the pre-registered v8 DNS context candidate."""

from __future__ import annotations

import argparse
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
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from src.build_features import build_feature_matrix_from_manifest
from src.dns_context import (
    collect_dns_features,
    combined_decisions,
    coverage_metrics,
    select_zero_benign_threshold,
    stable_bucket,
)
from src.training_data import compute_file_sha256, resolve_ml_path


def _load_json(path: Path) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _require_hash(path: Path, expected: str, label: str) -> None:
    actual = compute_file_sha256(path)
    if actual != expected.lower():
        raise ValueError(f"{label} SHA-256 mismatch: expected {expected}, got {actual}")


def _load_primary(protocol: Dict[str, Any]) -> tuple[lgb.Booster, Dict[str, float], Path]:
    primary = protocol["primary_model"]
    model_path = resolve_ml_path(primary["model"]["path"])
    calibration_path = resolve_ml_path(primary["calibration"]["path"])
    manifest_path = resolve_ml_path(primary["feature_manifest"]["path"])
    _require_hash(model_path, primary["model"]["sha256"], "primary model")
    _require_hash(calibration_path, primary["calibration"]["sha256"], "primary calibration")
    _require_hash(manifest_path, primary["feature_manifest"]["sha256"], "primary feature manifest")
    calibration = _load_json(calibration_path)["parameters"]
    return lgb.Booster(model_file=str(model_path)), calibration, manifest_path


def _primary_probability(
    booster: lgb.Booster,
    calibration: Dict[str, float],
    manifest_path: Path,
    domains: list[str],
) -> np.ndarray:
    matrix = build_feature_matrix_from_manifest(domains, str(manifest_path))
    margin = booster.predict(matrix, raw_score=True)
    exponent = float(calibration["A"]) * margin + float(calibration["B"])
    return 1.0 / (1.0 + np.exp(np.clip(exponent, -40.0, 40.0)))


def _decision_metrics(labels: np.ndarray, decisions: np.ndarray) -> Dict[str, Any]:
    benign = labels == 0
    malicious = labels == 1
    return {
        "rows": int(len(labels)),
        "benign_rows": int(np.sum(benign)),
        "malicious_rows": int(np.sum(malicious)),
        "benign_false_positives": int(np.sum(decisions[benign])),
        "malicious_true_positives": int(np.sum(decisions[malicious])),
    }


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
    manifest_path = resolve_ml_path(protocol["outputs"]["snapshot_manifest"])
    snapshot = _load_json(manifest_path)
    if snapshot["protocol_sha256"] != protocol_hash:
        raise ValueError("snapshot was not built from the active v8 protocol")

    # Selection intentionally resolves and reads only train/development cohorts.
    cohort_frames: Dict[str, pd.DataFrame] = {}
    derived_dir = resolve_ml_path(protocol["outputs"]["derived_dir"])
    for name in ("train", "development"):
        meta = snapshot["outputs"][name]
        path = resolve_ml_path(meta["path"])
        _require_hash(path, meta["sha256"], f"{name} cohort")
        frame = pd.read_parquet(path)
        if len(frame) != int(meta["rows"]):
            raise ValueError(f"{name} cohort row count mismatch")
        cohort_frames[name] = collect_dns_features(
            frame,
            protocol["dns_collection"],
            protocol["dns_features"],
            derived_dir / "dns" / f"{name}.jsonl",
        )
        cohort_frames[name].to_parquet(
            derived_dir / "dns" / f"{name}-features.parquet", index=False
        )

    train = cohort_frames["train"]
    development = cohort_frames["development"]
    seed = int(protocol["seed"])
    split = protocol["context_model"]["train_threshold_split"]
    buckets = np.asarray(
        [stable_bucket(seed, str(group)) for group in train["evaluation_group"]]
    )
    model_mask = np.isin(buckets, [int(value) for value in split["model_train_buckets"]])
    threshold_mask = np.isin(buckets, [int(value) for value in split["threshold_buckets"]])
    if set(train.loc[model_mask, "evaluation_group"]) & set(
        train.loc[threshold_mask, "evaluation_group"]
    ):
        raise ValueError("model and threshold groups overlap")
    feature_names = list(protocol["dns_features"])
    model_config = protocol["context_model"]
    specialist = Pipeline(
        [
            ("scale", StandardScaler()),
            (
                "model",
                LogisticRegression(
                    penalty=model_config["penalty"],
                    C=float(model_config["C"]),
                    solver=model_config["solver"],
                    max_iter=int(model_config["max_iter"]),
                    class_weight=model_config["class_weight"],
                    random_state=int(model_config["random_state"]),
                ),
            ),
        ]
    )
    specialist.fit(
        train.loc[model_mask, feature_names].to_numpy(float),
        train.loc[model_mask, "label"].to_numpy(int),
    )
    threshold_probability = specialist.predict_proba(
        train.loc[threshold_mask, feature_names].to_numpy(float)
    )[:, 1]
    context_threshold, threshold_metrics = select_zero_benign_threshold(
        threshold_probability,
        train.loc[threshold_mask, "label"].to_numpy(int),
    )

    booster, calibration, primary_manifest = _load_primary(protocol)
    primary_probability = _primary_probability(
        booster,
        calibration,
        primary_manifest,
        development["domain_ascii"].astype(str).tolist(),
    )
    context_probability = specialist.predict_proba(
        development[feature_names].to_numpy(float)
    )[:, 1]
    primary_threshold = float(protocol["primary_model"]["operating_threshold"])
    primary_decision = primary_probability >= primary_threshold
    combined = combined_decisions(
        primary_probability,
        context_probability,
        primary_threshold,
        context_threshold,
    )
    labels = development["label"].to_numpy(int)
    primary_metrics = _decision_metrics(labels, primary_decision)
    combined_metrics = _decision_metrics(labels, combined)
    development_metrics = {
        "primary_v3": primary_metrics,
        "combined": combined_metrics,
        "incremental_benign_false_positives": combined_metrics["benign_false_positives"]
        - primary_metrics["benign_false_positives"],
        "incremental_malicious_true_positives": combined_metrics["malicious_true_positives"]
        - primary_metrics["malicious_true_positives"],
    }

    coverage = {
        "train": coverage_metrics(train),
        "development": coverage_metrics(development),
        "combined": coverage_metrics(pd.concat([train, development], ignore_index=True)),
    }
    coverage_gate = protocol["selection"]["coverage_gates"]
    eligibility_gate = protocol["selection"]["eligibility_gates"]
    gates = {
        "minimum_dns_coverage": all(
            value["minimum_label_coverage"]
            >= float(coverage_gate["domain_with_at_least_one_parsed_response_min_fraction"])
            for value in coverage.values()
        ),
        "maximum_label_coverage_gap": all(
            value["label_coverage_gap"] <= float(coverage_gate["maximum_label_coverage_gap"])
            for value in coverage.values()
        ),
        "threshold_accepted_benign_max": threshold_metrics["accepted_benign"]
        <= int(eligibility_gate["threshold_accepted_benign_max"]),
        "threshold_accepted_malicious_min": threshold_metrics["accepted_malicious"]
        >= int(eligibility_gate["threshold_accepted_malicious_min"]),
        "development_incremental_benign_false_positives_max": development_metrics[
            "incremental_benign_false_positives"
        ]
        <= int(eligibility_gate["development_incremental_benign_false_positives_max"]),
        "development_combined_malicious_true_positives_above_v3": development_metrics[
            "incremental_malicious_true_positives"
        ]
        > 0,
    }
    eligible = all(gates.values())
    model_path = derived_dir / "models" / "dns_context.joblib"
    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(
        {
            "pipeline": specialist,
            "feature_names": feature_names,
            "context_threshold": context_threshold,
            "protocol_sha256": protocol_hash,
        },
        model_path,
    )
    report = {
        "schema_version": 1,
        "protocol_sha256": protocol_hash,
        "snapshot_manifest_sha256": compute_file_sha256(manifest_path),
        "selection_inputs": ["dns_train", "dns_threshold", "dns_development"],
        "forbidden_inputs_read": [],
        "candidate_count": int(model_config["candidate_count"]),
        "coverage": coverage,
        "split": {
            "model_train_rows": int(np.sum(model_mask)),
            "threshold_rows": int(np.sum(threshold_mask)),
            "group_overlap": 0,
        },
        "threshold": threshold_metrics,
        "development": development_metrics,
        "gates": gates,
        "eligible_for_final": eligible,
        "decision": "ELIGIBLE_FOR_FINAL" if eligible else "NO_ELIGIBLE_CANDIDATE",
        "model": {
            "path": str(model_path.relative_to(BASE_DIR)).replace("\\", "/"),
            "sha256": compute_file_sha256(model_path),
        },
        "elapsed_seconds": time.time() - started,
    }
    _write_json(resolve_ml_path(protocol["outputs"]["selection_report"]), report)
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Select v8 DNS context candidate")
    parser.add_argument(
        "--protocol",
        default=str(BASE_DIR / "configs" / "v8-dns-context-feasibility-protocol.json"),
    )
    args = parser.parse_args()
    result = select(args.protocol)
    print(json.dumps({"decision": result["decision"], "gates": result["gates"]}, indent=2))
