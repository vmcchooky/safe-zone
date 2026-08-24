"""Run the one-time v7 final evaluation after selection eligibility is frozen."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict

import joblib
import numpy as np
import pandas as pd
from scipy.sparse import load_npz

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from src.build_features import build_feature_matrix_from_manifest
from src.evaluate_model import (
    build_benign_subset_audit,
    load_reviewed_unclassifiable_domains,
)
from src.select_v7_disagreement_specialist import (
    _load_booster_and_calibration,
    _predict,
    _require_hash,
    _runtime_metrics,
    build_specialist_features,
    combined_decisions,
)
from src.training_data import compute_file_sha256, resolve_ml_path


def _load_json(path: Path) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _malicious_metrics(decisions: np.ndarray) -> Dict[str, Any]:
    true_positives = int(np.sum(decisions))
    return {
        "rows": len(decisions),
        "true_positives": true_positives,
        "false_negatives": len(decisions) - true_positives,
        "recall": float(true_positives / len(decisions)) if len(decisions) else 0.0,
    }


def evaluate(protocol_path: str | os.PathLike[str]) -> Dict[str, Any]:
    started = time.time()
    protocol_file = Path(protocol_path).resolve()
    protocol = _load_json(protocol_file)
    selection_path = resolve_ml_path(protocol["outputs"]["selection_report"])
    selection = _load_json(selection_path)
    protocol_sha = compute_file_sha256(protocol_file)
    if selection.get("protocol_sha256") != protocol_sha:
        raise ValueError("selection report does not match the final v7 protocol")
    if selection.get("decision") != "ELIGIBLE_FOR_FINAL_EVALUATION":
        raise ValueError("v7 candidate is not eligible for final evaluation")

    specialist_meta = selection["artifacts"]["specialist"]
    specialist_path = resolve_ml_path(specialist_meta["path"])
    _require_hash(specialist_path, specialist_meta["sha256"], "precision specialist")
    specialist = joblib.load(specialist_path)
    specialist_threshold = float(selection["specialist"]["threshold"])
    operating_threshold = float(protocol["disagreement"]["operating_threshold"])

    artifacts = protocol["artifacts"]
    control_booster, control_calibration = _load_booster_and_calibration(
        artifacts["v3_model"], artifacts["v3_calibration"]
    )
    recall_booster, recall_calibration = _load_booster_and_calibration(
        artifacts["v6_model"], artifacts["v6_calibration"]
    )
    control_manifest = resolve_ml_path(artifacts["v3_feature_manifest"]["path"])
    recall_manifest = resolve_ml_path(artifacts["feature_manifest"]["path"])

    for name in (
        "final_test_partition",
        "v3_final_test_matrix",
        "final_test_matrix",
        "phishdestroy_final_holdout",
    ):
        meta = protocol["inputs"][name]
        _require_hash(resolve_ml_path(meta["path"]), meta["sha256"], name)
    for name, meta in protocol["final_evidence"].items():
        _require_hash(resolve_ml_path(meta["path"]), meta["sha256"], name)

    final_test = pd.read_parquet(
        resolve_ml_path(protocol["inputs"]["final_test_partition"]["path"])
    ).reset_index(drop=True)
    control_test_matrix = load_npz(
        resolve_ml_path(protocol["inputs"]["v3_final_test_matrix"]["path"])
    )
    recall_test_matrix = load_npz(
        resolve_ml_path(protocol["inputs"]["final_test_matrix"]["path"])
    )
    if control_test_matrix.shape[0] != len(final_test):
        raise ValueError("v3 final-test matrix and partition are not aligned")
    if recall_test_matrix.shape[0] != len(final_test):
        raise ValueError("v6 final-test matrix and partition are not aligned")
    _, control_test_probability = _predict(
        control_booster, control_calibration, control_test_matrix
    )
    _, recall_test_probability = _predict(
        recall_booster, recall_calibration, recall_test_matrix
    )
    test_specialist_probability = specialist.predict_proba(
        build_specialist_features(
            recall_test_matrix, control_test_probability, recall_test_probability
        )
    )[:, 1]
    combined_test, test_disagreement, test_accepted = combined_decisions(
        final_test,
        control_test_probability,
        recall_test_probability,
        test_specialist_probability,
        operating_threshold,
        specialist_threshold,
    )
    control_test = (
        final_test["is_ml_candidate"].to_numpy() == True  # noqa: E712
    ) & (control_test_probability >= operating_threshold)
    final_test_metrics = {
        "control": _runtime_metrics(final_test, control_test),
        "combined": _runtime_metrics(final_test, combined_test),
        "disagreement_rows": int(np.sum(test_disagreement)),
        "accepted_rows": int(np.sum(test_accepted)),
        "accepted_benign": int(
            np.sum(test_accepted & (final_test["label"].to_numpy(int) == 0))
        ),
        "accepted_malicious": int(
            np.sum(test_accepted & (final_test["label"].to_numpy(int) == 1))
        ),
    }

    reviewed_meta = protocol["final_evidence"]["reviewed_unclassifiable_labels"]
    reviewed_domains, reviewed_info = load_reviewed_unclassifiable_domains(
        str(resolve_ml_path(reviewed_meta["path"]))
    )
    candidate_mask = final_test["is_ml_candidate"].to_numpy() == True  # noqa: E712
    safe_vn = {
        "control": build_benign_subset_audit(
            final_test,
            control_test_probability,
            candidate_mask,
            operating_threshold,
            reviewed_domains,
            reviewed_info,
        ),
        "combined": build_benign_subset_audit(
            final_test,
            combined_test.astype(float),
            candidate_mask,
            0.5,
            reviewed_domains,
            reviewed_info,
        ),
    }

    def domain_decisions(domains: list[str]) -> tuple[np.ndarray, np.ndarray]:
        control_matrix = build_feature_matrix_from_manifest(domains, str(control_manifest))
        recall_matrix = build_feature_matrix_from_manifest(domains, str(recall_manifest))
        _, control_probability = _predict(
            control_booster, control_calibration, control_matrix
        )
        _, recall_probability = _predict(recall_booster, recall_calibration, recall_matrix)
        specialist_probability = specialist.predict_proba(
            build_specialist_features(
                recall_matrix, control_probability, recall_probability
            )
        )[:, 1]
        frame = pd.DataFrame({"is_ml_candidate": np.ones(len(domains), dtype=bool)})
        combined, _, _ = combined_decisions(
            frame,
            control_probability,
            recall_probability,
            specialist_probability,
            operating_threshold,
            specialist_threshold,
        )
        return control_probability >= operating_threshold, combined

    holdout_meta = protocol["inputs"]["phishdestroy_final_holdout"]
    holdout = pd.read_parquet(resolve_ml_path(holdout_meta["path"]))
    if len(holdout) != int(holdout_meta["rows"]):
        raise ValueError("PhishDestroy holdout row count mismatch")
    ordinary = holdout["ordinary_looking"].to_numpy() == True  # noqa: E712
    if int(np.sum(ordinary)) != int(holdout_meta["ordinary_rows"]):
        raise ValueError("PhishDestroy ordinary-looking row count mismatch")
    holdout_control, holdout_combined = domain_decisions(
        holdout["domain_ascii"].astype(str).tolist()
    )
    phishdestroy = {
        "control": {
            "all": _malicious_metrics(holdout_control),
            "ordinary_looking": _malicious_metrics(holdout_control[ordinary]),
        },
        "combined": {
            "all": _malicious_metrics(holdout_combined),
            "ordinary_looking": _malicious_metrics(holdout_combined[ordinary]),
        },
    }

    representative_meta = protocol["final_evidence"]["representative_labels"]
    representative = pd.read_csv(
        resolve_ml_path(representative_meta["path"]), keep_default_na=False
    )
    binary = representative[
        representative["human_label"].astype(str).isin(["benign", "malicious"])
    ].copy()
    if binary["reviewer_id"].astype(str).str.strip().eq("").any():
        raise ValueError("representative binary labels must be owner reviewed")
    malicious = binary["human_label"].astype(str).eq("malicious").to_numpy()
    benign = binary["human_label"].astype(str).eq("benign").to_numpy()
    if int(np.sum(malicious)) != 34 or int(np.sum(benign)) != 25:
        raise ValueError("representative packet must contain 34 malicious and 25 benign")
    representative_control, representative_combined = domain_decisions(
        binary["domain"].astype(str).tolist()
    )
    representative_metrics = {
        "control": {
            "malicious": _malicious_metrics(representative_control[malicious]),
            "benign_rows": int(np.sum(benign)),
            "benign_false_positives": int(np.sum(representative_control[benign])),
        },
        "combined": {
            "malicious": _malicious_metrics(representative_combined[malicious]),
            "benign_rows": int(np.sum(benign)),
            "benign_false_positives": int(np.sum(representative_combined[benign])),
        },
    }

    targeted_meta = protocol["final_evidence"]["targeted_benign_labels"]
    targeted = pd.read_csv(
        resolve_ml_path(targeted_meta["path"]), keep_default_na=False
    )
    if not targeted["human_label"].astype(str).str.lower().eq("benign").all():
        raise ValueError("targeted packet must contain only benign labels")
    targeted_control, targeted_combined = domain_decisions(
        targeted["domain"].astype(str).tolist()
    )
    targeted_metrics = {
        "rows": len(targeted),
        "control_false_positives": int(np.sum(targeted_control)),
        "combined_false_positives": int(np.sum(targeted_combined)),
    }

    gates = {
        "representative_malicious_at_least_26_of_34": (
            representative_metrics["combined"]["malicious"]["true_positives"]
            >= int(protocol["final_gates"]["representative_malicious_true_positives_min"])
        ),
        "representative_benign_zero_of_25": (
            representative_metrics["combined"]["benign_false_positives"]
            <= int(protocol["final_gates"]["representative_benign_false_positives_max"])
        ),
        "targeted_benign_zero": (
            targeted_metrics["combined_false_positives"]
            <= int(protocol["final_gates"]["targeted_benign_false_positives_max"])
        ),
        "safe_vn_candidate_zero": (
            safe_vn["combined"]["safe_vn_runtime_candidate_false_positives"]
            <= int(protocol["final_gates"]["safe_vn_candidate_false_positives_max"])
        ),
        "phishdestroy_overall_recall_not_below_v3": (
            phishdestroy["combined"]["all"]["true_positives"]
            >= phishdestroy["control"]["all"]["true_positives"]
        ),
        "phishdestroy_ordinary_recall_not_below_v3": (
            phishdestroy["combined"]["ordinary_looking"]["true_positives"]
            >= phishdestroy["control"]["ordinary_looking"]["true_positives"]
        ),
        "final_test_candidate_false_positives_not_above_v3": (
            final_test_metrics["combined"]["runtime_candidate_false_positives"]
            <= final_test_metrics["control"]["runtime_candidate_false_positives"]
        ),
        "final_test_candidate_true_positives_above_v3": (
            final_test_metrics["combined"]["runtime_candidate_true_positives"]
            > final_test_metrics["control"]["runtime_candidate_true_positives"]
        ),
    }
    decision = "GO_FOR_SHADOW_PACKAGING" if all(gates.values()) else "NO_GO_FINAL"
    report = {
        "schema_version": 1,
        "protocol_sha256": protocol_sha,
        "selection_report_sha256": compute_file_sha256(selection_path),
        "final_inputs_opened_after_selection": [
            "final_test_partition",
            "phishdestroy_final_holdout",
            "representative_binary_packet",
            "targeted_benign_packet",
            "reviewed_unclassifiable_packet",
        ],
        "wall_time_seconds": round(time.time() - started, 2),
        "operating_threshold": operating_threshold,
        "specialist_threshold": specialist_threshold,
        "final_test": final_test_metrics,
        "safe_vn": safe_vn,
        "phishdestroy": phishdestroy,
        "representative": representative_metrics,
        "targeted_benign": targeted_metrics,
        "gates": gates,
        "decision": decision,
    }
    report_path = resolve_ml_path(protocol["outputs"]["final_report"])
    with open(report_path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(report, handle, indent=2)
        handle.write("\n")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Evaluate v7 disagreement specialist")
    parser.add_argument(
        "--protocol",
        default=str(BASE_DIR / "configs" / "v7-disagreement-specialist-protocol.json"),
    )
    args = parser.parse_args()
    result = evaluate(args.protocol)
    print(json.dumps({"decision": result["decision"], "gates": result["gates"]}, indent=2))
