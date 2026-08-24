"""Run the one-time final evaluation after candidate selection is frozen."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict

import lightgbm as lgb
import numpy as np
import pandas as pd

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from src.build_features import build_feature_matrix_from_manifest


def compute_file_sha256(path: str | os.PathLike[str]) -> str:
    hasher = hashlib.sha256()
    with open(path, "rb") as handle:
        while chunk := handle.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def _load_json(path: Path) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _resolve(value: str) -> Path:
    path = Path(value)
    return path.resolve() if path.is_absolute() else (BASE_DIR / path).resolve()


def _predict(config: Dict[str, Any], domains: list[str]) -> tuple[np.ndarray, Dict[str, str]]:
    derived_dir = _resolve(str(config["derived_dir"]))
    models_dir = _resolve(str(config["models_dir"]))
    manifest_path = derived_dir / "feature_manifest.json"
    model_path = models_dir / "domain_threat_lgbm_raw.txt"
    calibration_path = models_dir / "calibration.json"
    matrix = build_feature_matrix_from_manifest(domains, str(manifest_path))
    booster = lgb.Booster(model_file=str(model_path))
    calibration = _load_json(calibration_path)
    parameters = calibration["parameters"]
    margins = booster.predict(matrix, raw_score=True)
    probabilities = 1.0 / (
        1.0
        + np.exp(
            float(parameters["A"]) * margins + float(parameters["B"])
        )
    )
    return probabilities, {
        "feature_manifest_sha256": compute_file_sha256(manifest_path),
        "model_sha256": compute_file_sha256(model_path),
        "calibration_sha256": compute_file_sha256(calibration_path),
    }


def _malicious_metrics(probabilities: np.ndarray, threshold: float) -> Dict[str, Any]:
    true_positives = int(np.sum(probabilities >= threshold))
    return {
        "rows": len(probabilities),
        "true_positives": true_positives,
        "false_negatives": len(probabilities) - true_positives,
        "recall": float(true_positives / len(probabilities)) if len(probabilities) else 0.0,
        "mean_probability": float(np.mean(probabilities)) if len(probabilities) else 0.0,
        "median_probability": float(np.median(probabilities)) if len(probabilities) else 0.0,
    }


def run_final_evaluation(
    candidate_config_path: str | os.PathLike[str],
    protocol_path: str | os.PathLike[str],
) -> Dict[str, Any]:
    candidate_config_file = Path(candidate_config_path).resolve()
    protocol_file = Path(protocol_path).resolve()
    candidate_config = _load_json(candidate_config_file)
    protocol = _load_json(protocol_file)
    selection_report_path = BASE_DIR / "experiments" / "v4-weight-ablation-selection.json"
    selection_report = _load_json(selection_report_path)
    selected = selection_report.get("selected")
    if not selected or selected.get("config_path") != str(
        candidate_config_file.relative_to(BASE_DIR)
    ).replace("\\", "/"):
        raise ValueError("candidate config does not match the frozen selection report")
    configured_weight = float(
        candidate_config["training"]["time_forward_hard_positive"]["weight"]
    )
    if not np.isclose(configured_weight, float(selected["hard_positive_weight"])):
        raise ValueError("candidate hard-positive weight does not match selection")
    threshold = float(protocol["candidate_selection"]["operating_threshold"])

    public_manifest_path = _resolve(protocol["outputs"]["public_manifest"])
    public_manifest = _load_json(public_manifest_path)
    holdout_meta = public_manifest["outputs"]["openphish_holdout"]
    holdout_path = _resolve(str(holdout_meta["path"]))
    if compute_file_sha256(holdout_path) != str(holdout_meta["sha256"]):
        raise ValueError("OpenPhish holdout checksum mismatch")
    holdout = pd.read_parquet(holdout_path)
    if len(holdout) != int(holdout_meta["rows"]):
        raise ValueError("OpenPhish holdout row count mismatch")

    representative_path = _resolve(
        protocol["baseline"]["frozen_evaluation_labels"]
    )
    representative = pd.read_csv(representative_path, keep_default_na=False)
    binary = representative[
        representative["human_label"].astype(str).isin(["benign", "malicious"])
    ].copy()
    if binary["reviewer_id"].astype(str).str.strip().eq("").any():
        raise ValueError("representative binary labels must be owner reviewed")

    control_config_path = BASE_DIR / "configs" / "v3-leakage-free-context.json"
    control_config = _load_json(control_config_path)
    models = {
        "v3_control": control_config,
        "v4_selected": candidate_config,
    }
    model_artifacts: Dict[str, Any] = {}
    holdout_results: Dict[str, Any] = {}
    representative_results: Dict[str, Any] = {}
    holdout_domains = holdout["domain_ascii"].astype(str).tolist()
    binary_domains = binary["domain"].astype(str).tolist()
    ordinary_mask = holdout["ordinary_looking"].to_numpy() == True  # noqa: E712
    malicious_mask = binary["human_label"].astype(str).eq("malicious").to_numpy()
    benign_mask = binary["human_label"].astype(str).eq("benign").to_numpy()
    if int(np.sum(malicious_mask)) != 34 or int(np.sum(benign_mask)) != 25:
        raise ValueError("representative binary packet must contain 34 malicious and 25 benign rows")
    for name, config in models.items():
        holdout_probability, holdout_artifacts = _predict(config, holdout_domains)
        representative_probability, representative_artifacts = _predict(
            config, binary_domains
        )
        if holdout_artifacts != representative_artifacts:
            raise ValueError("model artifacts changed during final evaluation")
        model_artifacts[name] = holdout_artifacts
        holdout_results[name] = {
            "all": _malicious_metrics(holdout_probability, threshold),
            "ordinary_looking": _malicious_metrics(
                holdout_probability[ordinary_mask], threshold
            ),
        }
        malicious_probability = representative_probability[malicious_mask]
        benign_probability = representative_probability[benign_mask]
        benign_false_positives = int(np.sum(benign_probability >= threshold))
        representative_results[name] = {
            "malicious": _malicious_metrics(malicious_probability, threshold),
            "benign": {
                "rows": len(benign_probability),
                "false_positives": benign_false_positives,
                "fpr": float(benign_false_positives / len(benign_probability)),
            },
        }

    candidate_report_path = _resolve(candidate_config["models_dir"]) / "model_report.json"
    candidate_report = _load_json(candidate_report_path)
    safe_vn = candidate_report["hard_cases_audit"]
    targeted = candidate_report["frozen_challenge_audit"]
    selected_representative = representative_results["v4_selected"]
    gates = {
        "representative_malicious_at_least_26_of_34": (
            selected_representative["malicious"]["rows"] == 34
            and selected_representative["malicious"]["true_positives"] >= 26
        ),
        "representative_benign_zero_of_25": (
            selected_representative["benign"]["rows"] == 25
            and selected_representative["benign"]["false_positives"] == 0
        ),
        "targeted_benign_zero_of_3": (
            targeted["cases"] == 3 and targeted["false_positives"] == 0
        ),
        "safe_vn_candidate_zero_of_1400": (
            safe_vn["safe_vn_runtime_candidate_count"] == 1400
            and safe_vn["safe_vn_runtime_candidate_false_positives"] == 0
        ),
        "openphish_recall_not_below_v3_control": (
            holdout_results["v4_selected"]["all"]["recall"]
            >= holdout_results["v3_control"]["all"]["recall"]
        ),
    }
    result = {
        "schema_version": 1,
        "candidate_config": str(candidate_config_file.relative_to(BASE_DIR)).replace("\\", "/"),
        "candidate_config_sha256": compute_file_sha256(candidate_config_file),
        "protocol_sha256": compute_file_sha256(protocol_file),
        "selection_report_sha256": compute_file_sha256(selection_report_path),
        "final_inputs_opened_after_selection": [
            "final_test_partition",
            "targeted_benign_challenge",
            "openphish_source_disjoint_holdout",
            "representative_binary_packet",
        ],
        "operating_threshold": threshold,
        "input_integrity": {
            "public_manifest_sha256": compute_file_sha256(public_manifest_path),
            "openphish_holdout_sha256": compute_file_sha256(holdout_path),
            "representative_labels_sha256": compute_file_sha256(representative_path),
            "openphish_rows": len(holdout),
            "representative_binary_rows": len(binary),
        },
        "model_artifacts": model_artifacts,
        "openphish_holdout": holdout_results,
        "representative": representative_results,
        "final_test": {
            "test_evaluation": candidate_report["test_evaluation"],
            "candidate_cohort_evaluation": candidate_report[
                "candidate_cohort_evaluation"
            ],
            "threshold_0_92": candidate_report["threshold_sweeps"]["0.92"],
            "safe_vn_candidate": {
                "rows": safe_vn["safe_vn_runtime_candidate_count"],
                "false_positives": safe_vn[
                    "safe_vn_runtime_candidate_false_positives"
                ],
            },
            "targeted_benign": {
                "rows": targeted["cases"],
                "false_positives": targeted["false_positives"],
            },
        },
        "gates": gates,
        "decision": "GO" if all(gates.values()) else "NO-GO",
    }
    output_path = BASE_DIR / "experiments" / "v4-final-evaluation.json"
    with open(output_path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(result, handle, indent=2)
        handle.write("\n")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run one-time v4 final evaluation")
    parser.add_argument(
        "--config",
        default=str(BASE_DIR / "configs" / "v4-time-forward-ternary-tld.json"),
    )
    parser.add_argument(
        "--protocol",
        default=str(BASE_DIR / "configs" / "v4-time-forward-protocol.json"),
    )
    args = parser.parse_args()
    result = run_final_evaluation(args.config, args.protocol)
    print(json.dumps({"decision": result["decision"], "gates": result["gates"]}, indent=2))
