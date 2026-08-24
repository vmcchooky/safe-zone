"""Train and select the pre-registered v5 char-linear log-odds ensemble."""

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
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression, SGDClassifier
from sklearn.metrics import log_loss

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from src.build_features import build_feature_matrix_from_manifest, build_tfidf_inputs
from src.train_lightgbm import apply_training_weight_policy
from src.training_data import compute_file_sha256, resolve_ml_path


def _load_json(path: Path) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _require_hash(path: Path, expected: str, label: str) -> None:
    actual = compute_file_sha256(path)
    if actual != expected.lower():
        raise ValueError(f"{label} SHA-256 mismatch: expected {expected}, got {actual}")


def _sigmoid(value: np.ndarray) -> np.ndarray:
    clipped = np.clip(value, -40.0, 40.0)
    return 1.0 / (1.0 + np.exp(-clipped))


def _logit(probability: np.ndarray) -> np.ndarray:
    clipped = np.clip(probability, 1e-9, 1.0 - 1e-9)
    return np.log(clipped / (1.0 - clipped))


def blend_log_odds(control: np.ndarray, linear: np.ndarray, linear_weight: float) -> np.ndarray:
    if not 0.0 <= linear_weight <= 1.0:
        raise ValueError("linear ensemble weight must be in [0, 1]")
    return _sigmoid((1.0 - linear_weight) * _logit(control) + linear_weight * _logit(linear))


def _control_probabilities(config: Dict[str, Any], matrix: Any) -> np.ndarray:
    models_dir = resolve_ml_path(str(config["models_dir"]))
    booster = lgb.Booster(model_file=str(models_dir / "domain_threat_lgbm_raw.txt"))
    calibration = _load_json(models_dir / "calibration.json")["parameters"]
    margins = booster.predict(matrix, raw_score=True)
    return 1.0 / (
        1.0
        + np.exp(float(calibration["A"]) * margins + float(calibration["B"]))
    )


def _control_domain_probabilities(config: Dict[str, Any], domains: list[str]) -> np.ndarray:
    manifest = resolve_ml_path(str(config["derived_dir"])) / "feature_manifest.json"
    matrix = build_feature_matrix_from_manifest(domains, str(manifest))
    return _control_probabilities(config, matrix)


def _candidate_metrics(
    frame: pd.DataFrame, probabilities: np.ndarray, threshold: float
) -> Dict[str, Any]:
    labels = frame["label"].to_numpy().astype(int)
    candidate = frame["is_ml_candidate"].to_numpy() == True  # noqa: E712
    benign = candidate & (labels == 0)
    malicious = candidate & (labels == 1)
    fp = int(np.sum(probabilities[benign] >= threshold))
    tp = int(np.sum(probabilities[malicious] >= threshold))
    return {
        "rows": len(frame),
        "binary_logloss": float(log_loss(labels, probabilities)),
        "runtime_candidate_benign_rows": int(np.sum(benign)),
        "runtime_candidate_malicious_rows": int(np.sum(malicious)),
        "runtime_candidate_false_positives": fp,
        "runtime_candidate_true_positives": tp,
        "runtime_candidate_fpr": float(fp / np.sum(benign)) if np.any(benign) else 0.0,
        "runtime_candidate_recall": float(tp / np.sum(malicious)) if np.any(malicious) else 0.0,
    }


def _development_metrics(probabilities: np.ndarray, threshold: float) -> Dict[str, Any]:
    tp = int(np.sum(probabilities >= threshold))
    return {
        "rows": len(probabilities),
        "true_positives": tp,
        "recall": float(tp / len(probabilities)) if len(probabilities) else 0.0,
        "mean_probability": float(np.mean(probabilities)),
        "median_probability": float(np.median(probabilities)),
    }


def select(protocol_path: str | os.PathLike[str]) -> Dict[str, Any]:
    started = time.time()
    protocol_file = Path(protocol_path).resolve()
    protocol = _load_json(protocol_file)
    manifest_path = resolve_ml_path(protocol["outputs"]["snapshot_manifest"])
    manifest = _load_json(manifest_path)
    if manifest["protocol_sha256"] != compute_file_sha256(protocol_file):
        raise ValueError("snapshot manifest does not match v5 protocol")

    for split in ("train", "val", "cal"):
        meta = protocol["baseline"]["partitions"][split]
        _require_hash(resolve_ml_path(meta["path"]), meta["sha256"], f"{split} partition")
    development_meta = manifest["outputs"]["development"]
    development_path = resolve_ml_path(development_meta["path"])
    _require_hash(development_path, development_meta["sha256"], "v5 development")

    training_config = _load_json(resolve_ml_path(protocol["baseline"]["training_config"]))
    control_config = _load_json(resolve_ml_path(protocol["baseline"]["control_config"]))
    partitions_dir = resolve_ml_path(str(training_config["partitions_dir"]))
    train = pd.read_parquet(partitions_dir / "train.parquet")
    val = pd.read_parquet(partitions_dir / "val.parquet")
    cal = pd.read_parquet(partitions_dir / "cal.parquet")
    development = pd.read_parquet(development_path)
    if len(development) != int(development_meta["rows"]):
        raise ValueError("v5 development row count mismatch")
    if not development["ordinary_looking"].astype(bool).all():
        raise ValueError("v5 development must contain only ordinary-looking rows")

    control_partitions_dir = resolve_ml_path(str(control_config["partitions_dir"]))
    control_val = pd.read_parquet(control_partitions_dir / "val.parquet", columns=["domain_ascii"])
    if not control_val["domain_ascii"].astype(str).equals(val["domain_ascii"].astype(str)):
        raise ValueError("control and v5 validation rows are not aligned")
    control_val_matrix = load_npz(resolve_ml_path(str(control_config["matrices_dir"])) / "X_val.npz")
    control_val_probability = _control_probabilities(control_config, control_val_matrix)
    control_development_probability = _control_domain_probabilities(
        control_config, development["domain_ascii"].astype(str).tolist()
    )

    representation = protocol["representation"]
    tfidf = representation["tfidf"]
    input_view = str(tfidf["input_view"])
    print("[*] Building train-only TF-IDF inputs...", flush=True)
    train_inputs = build_tfidf_inputs(
        train["domain_ascii"].astype(str).tolist(), input_view, min(4, os.cpu_count() or 1)
    )
    vectorizer = TfidfVectorizer(
        analyzer=str(tfidf["analyzer"]),
        ngram_range=tuple(int(value) for value in tfidf["ngram_range"]),
        max_features=int(tfidf["max_features"]),
        min_df=int(tfidf["min_df"]),
        lowercase=bool(tfidf["lowercase"]),
        sublinear_tf=bool(tfidf["sublinear_tf"]),
        norm=str(tfidf["norm"]),
        dtype=np.float32,
    )
    print("[*] Fitting 4096-feature char TF-IDF...", flush=True)
    train_matrix = vectorizer.fit_transform(train_inputs)
    base_weight = train.get("sample_weight", pd.Series(1.0, index=train.index)).to_numpy(float)
    train_weight, weighting_report = apply_training_weight_policy(
        train, base_weight, training_config["training"]
    )
    classifier = SGDClassifier(
        loss=str(representation["loss"]),
        penalty=str(representation["penalty"]),
        alpha=float(representation["alpha"]),
        max_iter=int(representation["max_iter"]),
        tol=float(representation["tol"]),
        average=bool(representation["average"]),
        random_state=int(protocol["seed"]),
        n_jobs=-1,
    )
    print("[*] Training char-linear classifier...", flush=True)
    classifier.fit(train_matrix, train["label"].to_numpy(int), sample_weight=train_weight)
    del train_matrix, train_inputs, train

    def linear_margins(frame: pd.DataFrame) -> np.ndarray:
        inputs = build_tfidf_inputs(
            frame["domain_ascii"].astype(str).tolist(), input_view, min(4, os.cpu_count() or 1)
        )
        return classifier.decision_function(vectorizer.transform(inputs))

    print("[*] Fitting Platt calibration on the calibration partition...", flush=True)
    cal_margin = linear_margins(cal)
    cal_weight = cal.get("sample_weight", pd.Series(1.0, index=cal.index)).to_numpy(float)
    calibrator = LogisticRegression(
        solver="lbfgs", max_iter=200, C=1.0, random_state=int(protocol["seed"])
    )
    calibrator.fit(cal_margin.reshape(-1, 1), cal["label"].to_numpy(int), sample_weight=cal_weight)

    val_linear_probability = calibrator.predict_proba(
        linear_margins(val).reshape(-1, 1)
    )[:, 1]
    development_linear_probability = calibrator.predict_proba(
        linear_margins(development).reshape(-1, 1)
    )[:, 1]
    threshold = float(protocol["candidate_selection"]["operating_threshold"])
    control_validation = _candidate_metrics(val, control_val_probability, threshold)
    control_development = _development_metrics(control_development_probability, threshold)
    linear_validation = _candidate_metrics(val, val_linear_probability, threshold)
    linear_development = _development_metrics(development_linear_probability, threshold)

    candidates = []
    for weight in [float(value) for value in representation["linear_weights"]]:
        val_probability = blend_log_odds(control_val_probability, val_linear_probability, weight)
        development_probability = blend_log_odds(
            control_development_probability, development_linear_probability, weight
        )
        validation_metrics = _candidate_metrics(val, val_probability, threshold)
        development_metrics = _development_metrics(development_probability, threshold)
        eligible = (
            validation_metrics["runtime_candidate_false_positives"]
            <= control_validation["runtime_candidate_false_positives"]
            and validation_metrics["runtime_candidate_true_positives"]
            >= control_validation["runtime_candidate_true_positives"]
        )
        candidates.append(
            {
                "linear_weight": weight,
                "eligible": eligible,
                "validation": validation_metrics,
                "development": development_metrics,
            }
        )

    eligible = [candidate for candidate in candidates if candidate["eligible"]]
    selected = None
    if eligible:
        selected = sorted(
            eligible,
            key=lambda candidate: (
                -candidate["development"]["true_positives"],
                candidate["validation"]["binary_logloss"],
                candidate["linear_weight"],
            ),
        )[0]

    derived_dir = resolve_ml_path(protocol["outputs"]["derived_dir"])
    models_dir = derived_dir / "models"
    models_dir.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "vectorizer": models_dir / "char_tfidf.joblib",
        "classifier": models_dir / "char_sgd.joblib",
        "calibrator": models_dir / "char_platt.joblib",
    }
    joblib.dump(vectorizer, artifacts["vectorizer"])
    joblib.dump(classifier, artifacts["classifier"])
    joblib.dump(calibrator, artifacts["calibrator"])
    artifact_report = {
        name: {
            "path": str(path.relative_to(BASE_DIR)).replace("\\", "/"),
            "sha256": compute_file_sha256(path),
            "bytes": path.stat().st_size,
        }
        for name, path in artifacts.items()
    }
    vocabulary_hash = hashlib.sha256(
        "\n".join(vectorizer.get_feature_names_out()).encode("utf-8")
    ).hexdigest()
    report = {
        "schema_version": 1,
        "protocol_sha256": compute_file_sha256(protocol_file),
        "snapshot_manifest_sha256": compute_file_sha256(manifest_path),
        "selection_inputs": ["train", "calibration", "validation", "v5_development"],
        "forbidden_inputs_read": [],
        "wall_time_seconds": round(time.time() - started, 2),
        "representation": {
            **representation,
            "vocabulary_size": len(vectorizer.vocabulary_),
            "vocabulary_sha256": vocabulary_hash,
        },
        "sample_weighting": weighting_report,
        "control_validation": control_validation,
        "control_development": control_development,
        "linear_validation": linear_validation,
        "linear_development": linear_development,
        "candidates": candidates,
        "selected": selected,
        "artifacts": artifact_report,
        "decision": "ELIGIBLE_FOR_FINAL_EVALUATION" if selected else "NO_ELIGIBLE_CANDIDATE",
    }
    report_path = resolve_ml_path(protocol["outputs"]["selection_report"])
    with open(report_path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(report, handle, indent=2)
        handle.write("\n")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Select v5 char-linear ensemble")
    parser.add_argument(
        "--protocol",
        default=str(BASE_DIR / "configs" / "v5-char-linear-ensemble-protocol.json"),
    )
    args = parser.parse_args()
    result = select(args.protocol)
    print(json.dumps({"selected": result["selected"], "decision": result["decision"]}, indent=2))
