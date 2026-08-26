"""Export the selected sklearn URL specialist to a deterministic Go bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Dict, Mapping, Sequence

import joblib
import numpy as np
import pandas as pd
from scipy.sparse import csr_matrix, hstack

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from src.select_v10_url_aware import (
    _load_json,
    _load_token_contract,
    _require_hash,
    _url_matrices,
)
from src.training_data import compute_file_sha256, resolve_ml_path
from src.url_context import URLContextError, build_url_features


MODEL_VERSION = "safe-zone-url-sgd-v10-20260825"
PROBABILITY_BUCKETS = [
    "lt_0_10",
    "0_10_0_19",
    "0_20_0_29",
    "0_30_0_39",
    "0_40_0_49",
    "0_50_0_59",
    "0_60_0_69",
    "0_70_0_79",
    "0_80_0_89",
    "gte_0_90",
]


def _canonical_json(path: Path, value: Mapping[str, Any] | Sequence[Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(value, handle, indent=2, ensure_ascii=False, sort_keys=True)
        handle.write("\n")


def _sha256_lf(path: Path) -> str:
    data = path.read_bytes().replace(b"\r\n", b"\n")
    return hashlib.sha256(data).hexdigest()


def _probability(
    text: str, handcrafted: np.ndarray, bundle: Mapping[str, Any]
) -> tuple[float, float]:
    text_matrix = bundle["vectorizer"].transform([text])
    hand_matrix = bundle["scaler"].transform([handcrafted])
    matrix = hstack([csr_matrix(hand_matrix), text_matrix], format="csr")
    raw = float(bundle["model"].decision_function(matrix)[0])
    probability = float(
        bundle["platt"].predict_proba(np.asarray([[raw]], dtype=np.float64))[0, 1]
    )
    return raw, probability


def _monitoring_reference(
    selection: Mapping[str, Any],
    selected: Mapping[str, Any],
    protocol: Mapping[str, Any],
) -> Dict[str, Any]:
    development_meta = selection["selection_inputs"]["development"]
    development_path = resolve_ml_path(development_meta["path"])
    _require_hash(
        development_path,
        development_meta["sha256"],
        "v10 monitoring development cohort",
    )
    frame = pd.read_parquet(development_path)
    suspicious_tokens, brand_tokens = _load_token_contract(protocol)
    texts, handcrafted = _url_matrices(
        frame, protocol, suspicious_tokens, brand_tokens
    )
    text_matrix = selected["vectorizer"].transform(texts)
    hand_matrix = selected["scaler"].transform(handcrafted)
    matrix = hstack([csr_matrix(hand_matrix), text_matrix], format="csr")
    raw = selected["model"].decision_function(matrix)
    probability = selected["platt"].predict_proba(
        np.asarray(raw).reshape(-1, 1)
    )[:, 1]
    indexes = np.minimum((probability * 10).astype(int), 9)
    counts = np.bincount(indexes, minlength=10).astype(int)
    # Jeffreys smoothing avoids zero-probability PSI divisions at runtime.
    distribution = (counts.astype(float) + 0.5) / (len(frame) + 5.0)
    labels = frame["label"].to_numpy(int)
    return {
        "reference_kind": "balanced_group_disjoint_development_proxy",
        "reference_operational": False,
        "reference_rows": int(len(frame)),
        "reference_labels": {
            "benign": int(np.sum(labels == 0)),
            "malicious": int(np.sum(labels == 1)),
        },
        "probability_buckets": PROBABILITY_BUCKETS,
        "probability_counts": counts.tolist(),
        "probability_distribution_smoothed": distribution.tolist(),
        "psi": {
            "minimum_live_samples": 100,
            "watch_threshold": 0.10,
            "alert_threshold": 0.25,
            "interpretation": "population shift against a balanced development proxy; not a live-label calibration score",
        },
    }


def export(
    protocol_path: str | Path,
    output_dir: str | Path,
) -> Dict[str, Any]:
    protocol_file = Path(protocol_path).resolve()
    protocol = _load_json(protocol_file)
    final_path = resolve_ml_path(protocol["outputs"]["final_report"])
    final_report = _load_json(final_path)
    if not final_report.get("passed"):
        raise ValueError("v10 final gates have not passed")
    selection_path = resolve_ml_path(protocol["outputs"]["selection_report"])
    selection = _load_json(selection_path)
    model_meta = selection["artifacts"]["model"]
    selected_path = resolve_ml_path(model_meta["path"])
    _require_hash(selected_path, model_meta["sha256"], "selected v10 URL model")
    selected = joblib.load(selected_path)
    suspicious_tokens, brand_tokens = _load_token_contract(protocol)

    vectorizer = selected["vectorizer"]
    scaler = selected["scaler"]
    linear = selected["model"]
    platt = selected["platt"]
    vocabulary = [""] * len(vectorizer.vocabulary_)
    for token, index in vectorizer.vocabulary_.items():
        vocabulary[int(index)] = token
    if any(not token for token in vocabulary):
        raise ValueError("TF-IDF vocabulary contains an empty slot")

    bundle_output = {
        "schema_version": 1,
        "model_version": MODEL_VERSION,
        "source": {
            "protocol_sha256": compute_file_sha256(protocol_file),
            "selection_report_sha256": compute_file_sha256(selection_path),
            "final_report_sha256": compute_file_sha256(final_path),
            "selected_model_sha256": model_meta["sha256"],
        },
        "product_contract": protocol["product_contract"],
        "feature_contract": {
            "handcrafted_features": selected["handcrafted_features"],
            "suspicious_tokens": suspicious_tokens,
            "brand_tokens": brand_tokens,
            "executable_extensions": protocol["url_feature_contract"][
                "executable_extensions"
            ],
            "query_value_shape": protocol["url_feature_contract"][
                "query_value_shape"
            ],
        },
        "vectorizer": {
            "analyzer": "char",
            "lowercase": True,
            "ngram_min": int(vectorizer.ngram_range[0]),
            "ngram_max": int(vectorizer.ngram_range[1]),
            "sublinear_tf": bool(vectorizer.sublinear_tf),
            "norm": str(vectorizer.norm),
            "vocabulary": vocabulary,
            "idf": vectorizer.idf_.astype(float).tolist(),
        },
        "scaler": {
            "mean": scaler.mean_.astype(float).tolist(),
            "scale": scaler.scale_.astype(float).tolist(),
        },
        "linear_model": {
            "loss": "log_loss",
            "coefficients": linear.coef_[0].astype(float).tolist(),
            "intercept": float(linear.intercept_[0]),
        },
        "calibration": {
            "method": "sklearn_logistic_sigmoid",
            "coefficient": float(platt.coef_[0, 0]),
            "intercept": float(platt.intercept_[0]),
        },
        "policy": {
            "mode_default": "disabled",
            "supported_runtime_modes": ["disabled", "shadow"],
            "url_threshold": float(selected["url_threshold"]),
            "failure_policy": "fail_open_to_domain_only",
        },
        "monitoring": _monitoring_reference(selection, selected, protocol),
    }

    output = Path(output_dir).resolve()
    model_output = output / "url_model.v1.json"
    _canonical_json(model_output, bundle_output)

    valid_cases = [
        ("home", "https://example.test/", "example.test", []),
        ("safe_search", "https://shop.example/search?q=summer+sale&page=12", "shop.example", []),
        ("account_verify", "https://secure.example/account/verify?token=AbC123456", "secure.example", []),
        ("encoded_path", "https://example.test/a%2Fb/%E2%9C%93?q=%2Fadmin", "example.test", []),
        ("download", "http://files.example/update/setup.exe?id=99122", "files.example", []),
        ("ip_in_path", "https://example.test/redirect/192.168.10.1/login", "example.test", []),
        ("double_slash", "https://example.test/paypal//secure/login", "example.test", []),
        ("unicode", "https://xn--bcher-kva.example/t%C3%A0i-kho%E1%BA%A3n?m%C3%A3=123", "xn--bcher-kva.example", []),
        (
            "cross_host_redirect",
            "https://safe.example/start",
            "safe.example",
            ["http://other.example/login"],
        ),
    ]
    product_contract = {
        **protocol["product_contract"],
        "executable_extensions": protocol["url_feature_contract"][
            "executable_extensions"
        ],
    }
    vectors: list[Dict[str, Any]] = []
    for case_id, requested_url, expected_host, redirects in valid_cases:
        text, handcrafted, _ = build_url_features(
            requested_url,
            expected_host=expected_host,
            redirect_chain=redirects,
            contract=product_contract,
            suspicious_tokens=suspicious_tokens,
            brand_tokens=brand_tokens,
        )
        raw, probability = _probability(text, handcrafted, selected)
        vectors.append(
            {
                "case_id": case_id,
                "requested_url": requested_url,
                "expected_host": expected_host,
                "redirect_chain": redirects,
                "feature_text": text,
                "handcrafted": handcrafted.astype(float).tolist(),
                "raw_margin": raw,
                "probability": probability,
                "action": (
                    "promote_malicious"
                    if probability >= float(selected["url_threshold"])
                    else "abstain"
                ),
            }
        )
    invalid_cases = [
        ("invalid_scheme", "ftp://example.test/file", "example.test"),
        ("credentials", "https://user:secret@example.test/login", "example.test"),
        ("host_mismatch", "https://evil.example/login", "safe.example"),
    ]
    for case_id, requested_url, expected_host in invalid_cases:
        error_class = ""
        try:
            build_url_features(
                requested_url,
                expected_host=expected_host,
                contract=product_contract,
                suspicious_tokens=suspicious_tokens,
                brand_tokens=brand_tokens,
            )
        except URLContextError:
            error_class = "invalid_url_context"
        if not error_class:
            raise AssertionError(f"invalid golden case was accepted: {case_id}")
        vectors.append(
            {
                "case_id": case_id,
                "requested_url": requested_url,
                "expected_host": expected_host,
                "redirect_chain": [],
                "error_class": error_class,
            }
        )
    golden_output = output / "golden_vectors.v1.json"
    _canonical_json(
        golden_output,
        {
            "schema_version": 1,
            "model_version": MODEL_VERSION,
            "probability_absolute_tolerance": 1e-9,
            "feature_absolute_tolerance": 1e-12,
            "vectors": vectors,
        },
    )
    sums = {
        "url_model.v1.json": _sha256_lf(model_output),
        "golden_vectors.v1.json": _sha256_lf(golden_output),
    }
    sums_output = output / "SHA256SUMS"
    with open(sums_output, "w", encoding="utf-8", newline="\n") as handle:
        for name in sorted(sums):
            handle.write(f"{sums[name]}  {name}\n")
    return {
        "output_dir": str(output),
        "files": {
            name: {"sha256": digest}
            for name, digest in {**sums, "SHA256SUMS": _sha256_lf(sums_output)}.items()
        },
        "golden_vectors": len(vectors),
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Export v10 URL runtime bundle")
    parser.add_argument(
        "--protocol",
        default=str(BASE_DIR / "configs" / "v10-url-aware-signal-protocol.json"),
    )
    parser.add_argument(
        "--output-dir", default=str(BASE_DIR / "models" / "url-v1")
    )
    args = parser.parse_args()
    print(json.dumps(export(args.protocol, args.output_dir), indent=2))
