"""Fit and select the single pre-registered v10 URL-aware candidate."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, Mapping, Sequence

import joblib
import lightgbm as lgb
import numpy as np
import pandas as pd
from scipy.sparse import csr_matrix, hstack
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression, SGDClassifier
from sklearn.preprocessing import StandardScaler

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from src.build_features import build_feature_matrix_from_manifest
from src.training_data import compute_file_sha256, resolve_ml_path
from src.url_context import HANDCRAFTED_FEATURES, build_url_features


def _load_json(path: Path) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(value, handle, indent=2)
        handle.write("\n")


def _require_hash(path: Path, expected: str, label: str) -> None:
    actual = compute_file_sha256(path)
    if actual != expected.lower():
        raise ValueError(f"{label} SHA-256 mismatch: expected {expected}, got {actual}")


def _load_token_contract(protocol: Mapping[str, Any]) -> tuple[list[str], list[str]]:
    feature_contract = protocol["url_feature_contract"]
    suspicious_meta = feature_contract["suspicious_tokens"]
    suspicious_path = resolve_ml_path(suspicious_meta["path"])
    _require_hash(suspicious_path, suspicious_meta["sha256"], "suspicious tokens")
    suspicious = _load_json(suspicious_path)
    brand_meta = feature_contract["brand_tokens"]
    brand_path = resolve_ml_path(brand_meta["path"])
    _require_hash(brand_path, brand_meta["sha256"], "brand tokens")
    brand_rows = _load_json(brand_path)
    brands = [str(row["name"]).lower() for row in brand_rows]
    return [str(value).lower() for value in suspicious], brands


def _url_matrices(
    frame: pd.DataFrame,
    protocol: Mapping[str, Any],
    suspicious_tokens: Sequence[str],
    brand_tokens: Sequence[str],
) -> tuple[list[str], np.ndarray]:
    contract = {
        **protocol["product_contract"],
        "executable_extensions": protocol["url_feature_contract"][
            "executable_extensions"
        ],
    }
    texts: list[str] = []
    handcrafted: list[np.ndarray] = []
    for row in frame.itertuples(index=False):
        text, values, parsed = build_url_features(
            str(row.requested_url),
            expected_host=str(row.domain_ascii),
            contract=contract,
            suspicious_tokens=suspicious_tokens,
            brand_tokens=brand_tokens,
        )
        if parsed.url_sha256 != str(row.url_sha256):
            raise ValueError("cohort URL hash does not match normalized URL")
        texts.append(text)
        handcrafted.append(values)
    return texts, np.vstack(handcrafted)


def _load_primary(
    protocol: Mapping[str, Any],
) -> tuple[lgb.Booster, Dict[str, float], Path]:
    control = protocol["control"]
    model_path = resolve_ml_path(control["model"]["path"])
    calibration_path = resolve_ml_path(control["calibration"]["path"])
    manifest_path = resolve_ml_path(control["feature_manifest"]["path"])
    _require_hash(model_path, control["model"]["sha256"], "v3 model")
    _require_hash(
        calibration_path, control["calibration"]["sha256"], "v3 calibration"
    )
    _require_hash(
        manifest_path, control["feature_manifest"]["sha256"], "v3 feature manifest"
    )
    calibration = _load_json(calibration_path)["parameters"]
    return lgb.Booster(model_file=str(model_path)), calibration, manifest_path


def _primary_probability(
    booster: lgb.Booster,
    calibration: Mapping[str, float],
    manifest_path: Path,
    domains: Sequence[str],
) -> np.ndarray:
    matrix = build_feature_matrix_from_manifest(list(domains), str(manifest_path))
    margin = booster.predict(matrix, raw_score=True)
    exponent = float(calibration["A"]) * margin + float(calibration["B"])
    return 1.0 / (1.0 + np.exp(np.clip(exponent, -40.0, 40.0)))


def select_zero_benign_threshold(
    probabilities: np.ndarray, labels: np.ndarray
) -> tuple[float, Dict[str, int]]:
    benign = probabilities[labels == 0]
    if len(benign) == 0:
        raise ValueError("threshold cohort contains no benign rows")
    threshold = float(np.nextafter(float(np.max(benign)), np.inf))
    accepted = probabilities >= threshold
    return threshold, {
        "accepted_benign": int(np.sum(accepted & (labels == 0))),
        "accepted_malicious": int(np.sum(accepted & (labels == 1))),
    }


def _decision_metrics(labels: np.ndarray, decisions: np.ndarray) -> Dict[str, int]:
    return {
        "rows": int(len(labels)),
        "benign_rows": int(np.sum(labels == 0)),
        "malicious_rows": int(np.sum(labels == 1)),
        "benign_false_positives": int(np.sum(decisions & (labels == 0))),
        "malicious_true_positives": int(np.sum(decisions & (labels == 1))),
    }


def _combined_metrics(
    frame: pd.DataFrame,
    url_probability: np.ndarray,
    url_threshold: float,
    booster: lgb.Booster,
    primary_calibration: Mapping[str, float],
    primary_manifest: Path,
    primary_threshold: float,
) -> tuple[Dict[str, Any], np.ndarray]:
    labels = frame["label"].to_numpy(int)
    primary_probability = _primary_probability(
        booster,
        primary_calibration,
        primary_manifest,
        frame["domain_ascii"].astype(str).tolist(),
    )
    primary_decision = primary_probability >= primary_threshold
    url_decision = url_probability >= url_threshold
    combined = primary_decision | (~primary_decision & url_decision)
    primary_metrics = _decision_metrics(labels, primary_decision)
    combined_metrics = _decision_metrics(labels, combined)
    return {
        "primary_v3": primary_metrics,
        "combined": combined_metrics,
        "incremental_benign_false_positives": combined_metrics[
            "benign_false_positives"
        ]
        - primary_metrics["benign_false_positives"],
        "incremental_malicious_true_positives": combined_metrics[
            "malicious_true_positives"
        ]
        - primary_metrics["malicious_true_positives"],
    }, primary_decision


def select(protocol_path: str | os.PathLike[str]) -> Dict[str, Any]:
    started = time.time()
    protocol_file = Path(protocol_path).resolve()
    protocol = _load_json(protocol_file)
    protocol_hash = compute_file_sha256(protocol_file)
    snapshot_path = resolve_ml_path(protocol["outputs"]["snapshot_manifest"])
    snapshot = _load_json(snapshot_path)
    if snapshot["protocol_sha256"] != protocol_hash:
        raise ValueError("snapshot was not built from the active v10 protocol")

    frames: Dict[str, pd.DataFrame] = {}
    for name in ("adaptation_train", "calibration", "threshold", "development"):
        meta = snapshot["outputs"][name]
        path = resolve_ml_path(meta["path"])
        _require_hash(path, meta["sha256"], f"{name} cohort")
        frame = pd.read_parquet(path)
        if len(frame) != int(meta["rows"]):
            raise ValueError(f"{name} row count mismatch")
        frames[name] = frame

    suspicious_tokens, brand_tokens = _load_token_contract(protocol)
    texts: Dict[str, list[str]] = {}
    handcrafted: Dict[str, np.ndarray] = {}
    for name, frame in frames.items():
        texts[name], handcrafted[name] = _url_matrices(
            frame, protocol, suspicious_tokens, brand_tokens
        )

    vector_config = protocol["url_feature_contract"]["text_vectorizer"]
    vectorizer = TfidfVectorizer(
        analyzer=vector_config["analyzer"],
        ngram_range=tuple(int(value) for value in vector_config["ngram_range"]),
        max_features=int(vector_config["max_features"]),
        min_df=int(vector_config["min_df"]),
        sublinear_tf=bool(vector_config["sublinear_tf"]),
        dtype=np.float64,
    )
    scaler = StandardScaler()
    train_name = "adaptation_train"
    train_text = vectorizer.fit_transform(texts[train_name])
    train_hand = scaler.fit_transform(handcrafted[train_name])
    train_matrix = hstack([csr_matrix(train_hand), train_text], format="csr")
    model_config = protocol["model"]
    model = SGDClassifier(
        loss="log_loss",
        alpha=float(model_config["alpha"]),
        penalty=model_config["penalty"],
        max_iter=int(model_config["max_iter"]),
        class_weight=model_config["class_weight"],
        average=bool(model_config["average"]),
        random_state=int(model_config["random_state"]),
        tol=1e-4,
    )
    model.fit(train_matrix, frames[train_name]["label"].to_numpy(int))

    def raw_scores(name: str) -> np.ndarray:
        text_matrix = vectorizer.transform(texts[name])
        hand_matrix = scaler.transform(handcrafted[name])
        matrix = hstack([csr_matrix(hand_matrix), text_matrix], format="csr")
        return np.asarray(model.decision_function(matrix), dtype=np.float64)

    calibration_raw = raw_scores("calibration")
    platt = LogisticRegression(
        C=1_000_000.0,
        solver="lbfgs",
        max_iter=500,
        random_state=int(model_config["random_state"]),
    )
    platt.fit(
        calibration_raw.reshape(-1, 1),
        frames["calibration"]["label"].to_numpy(int),
    )

    def calibrated_probability(name: str) -> np.ndarray:
        return platt.predict_proba(raw_scores(name).reshape(-1, 1))[:, 1]

    threshold_probability = calibrated_probability("threshold")
    threshold_labels = frames["threshold"]["label"].to_numpy(int)
    url_threshold, threshold_url_metrics = select_zero_benign_threshold(
        threshold_probability, threshold_labels
    )
    booster, primary_calibration, primary_manifest = _load_primary(protocol)
    primary_threshold = float(protocol["control"]["operating_threshold"])
    threshold_metrics, threshold_primary_decision = _combined_metrics(
        frames["threshold"],
        threshold_probability,
        url_threshold,
        booster,
        primary_calibration,
        primary_manifest,
        primary_threshold,
    )
    threshold_incremental_accepted = (
        (threshold_probability >= url_threshold)
        & ~threshold_primary_decision
        & (threshold_labels == 1)
    )
    threshold_metrics["url_threshold_only"] = threshold_url_metrics
    threshold_metrics["incremental_accepted_malicious"] = int(
        np.sum(threshold_incremental_accepted)
    )

    development_probability = calibrated_probability("development")
    development_metrics, _ = _combined_metrics(
        frames["development"],
        development_probability,
        url_threshold,
        booster,
        primary_calibration,
        primary_manifest,
        primary_threshold,
    )
    gates_config = protocol["selection"]["eligibility_gates"]
    gates = {
        "threshold_accepted_benign_max": threshold_url_metrics["accepted_benign"]
        <= int(gates_config["threshold_accepted_benign_max"]),
        "threshold_accepted_malicious_min": threshold_metrics[
            "incremental_accepted_malicious"
        ]
        >= int(gates_config["threshold_accepted_malicious_min"]),
        "development_incremental_benign_false_positives_max": development_metrics[
            "incremental_benign_false_positives"
        ]
        <= int(gates_config["development_incremental_benign_false_positives_max"]),
        "development_incremental_malicious_true_positives_min": development_metrics[
            "incremental_malicious_true_positives"
        ]
        >= int(gates_config["development_incremental_malicious_true_positives_min"]),
    }
    eligible = all(gates.values())

    model_path = resolve_ml_path(protocol["outputs"]["derived_dir"]) / "models" / "url_specialist.joblib"
    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(
        {
            "schema_version": 1,
            "vectorizer": vectorizer,
            "scaler": scaler,
            "model": model,
            "platt": platt,
            "url_threshold": url_threshold,
            "handcrafted_features": list(HANDCRAFTED_FEATURES),
            "product_contract": protocol["product_contract"],
            "url_feature_contract": protocol["url_feature_contract"],
        },
        model_path,
    )
    report = {
        "schema_version": 1,
        "protocol_sha256": protocol_hash,
        "snapshot_manifest_sha256": compute_file_sha256(snapshot_path),
        "selection_inputs": {
            name: {"path": snapshot["outputs"][name]["path"], "sha256": snapshot["outputs"][name]["sha256"]}
            for name in frames
        },
        "forbidden_inputs_read": [],
        "feature_contract": {
            "handcrafted_feature_count": len(HANDCRAFTED_FEATURES),
            "tfidf_vocabulary_size": len(vectorizer.vocabulary_),
            "hostname_features_excluded": True,
            "query_values_redacted": True,
        },
        "url_threshold": url_threshold,
        "threshold": threshold_metrics,
        "development": development_metrics,
        "gates": gates,
        "eligible_for_final": eligible,
        "candidate_count": 1,
        "artifacts": {
            "model": {
                "path": str(model_path.relative_to(BASE_DIR)).replace("\\", "/"),
                "sha256": compute_file_sha256(model_path),
            }
        },
        "duration_seconds": round(time.time() - started, 3),
    }
    report_path = resolve_ml_path(protocol["outputs"]["selection_report"])
    _write_json(report_path, report)
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Select v10 URL-aware candidate")
    parser.add_argument(
        "--protocol",
        default=str(BASE_DIR / "configs" / "v10-url-aware-signal-protocol.json"),
    )
    args = parser.parse_args()
    result = select(args.protocol)
    print(
        json.dumps(
            {
                "eligible_for_final": result["eligible_for_final"],
                "url_threshold": result["url_threshold"],
                "threshold": result["threshold"],
                "development": result["development"],
                "gates": result["gates"],
            },
            indent=2,
        )
    )
