"""Open and evaluate the frozen v10 final cohort exactly once after selection."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, Mapping

import joblib
import numpy as np
import pandas as pd
from scipy.sparse import csr_matrix, hstack

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

try:
    from select_v10_url_aware import (  # noqa: E402
        _decision_metrics,
        _load_json,
        _load_primary,
        _load_token_contract,
        _primary_probability,
        _require_hash,
        _url_matrices,
        _write_json,
    )
    from training_data import compute_file_sha256, resolve_ml_path  # noqa: E402
    from url_context import URLContextError, build_url_features  # noqa: E402
except ModuleNotFoundError:
    from src.select_v10_url_aware import (  # type: ignore  # noqa: E402
        _decision_metrics,
        _load_json,
        _load_primary,
        _load_token_contract,
        _primary_probability,
        _require_hash,
        _url_matrices,
        _write_json,
    )
    from src.training_data import compute_file_sha256, resolve_ml_path  # type: ignore  # noqa: E402
    from src.url_context import URLContextError, build_url_features  # type: ignore  # noqa: E402


def combine_optional_url(
    primary_probability: np.ndarray,
    primary_threshold: float,
    url_probability: np.ndarray | None = None,
    url_threshold: float | None = None,
) -> tuple[np.ndarray, np.ndarray]:
    primary_output = np.asarray(primary_probability, dtype=np.float64).copy()
    primary_decision = primary_output >= primary_threshold
    if url_probability is None:
        return primary_output, primary_decision
    if url_threshold is None:
        raise ValueError("URL threshold is required when URL probability is supplied")
    url_decision = np.asarray(url_probability) >= url_threshold
    return primary_output, primary_decision | (~primary_decision & url_decision)


def _url_probability(
    frame: pd.DataFrame,
    bundle: Mapping[str, Any],
    protocol: Mapping[str, Any],
) -> np.ndarray:
    suspicious_tokens, brand_tokens = _load_token_contract(protocol)
    texts, handcrafted = _url_matrices(
        frame, protocol, suspicious_tokens, brand_tokens
    )
    text_matrix = bundle["vectorizer"].transform(texts)
    hand_matrix = bundle["scaler"].transform(handcrafted)
    matrix = hstack([csr_matrix(hand_matrix), text_matrix], format="csr")
    raw = bundle["model"].decision_function(matrix)
    return bundle["platt"].predict_proba(np.asarray(raw).reshape(-1, 1))[:, 1]


def _parse_failure_preserves_domain_decision(
    bundle: Mapping[str, Any], protocol: Mapping[str, Any]
) -> bool:
    suspicious_tokens, brand_tokens = _load_token_contract(protocol)
    contract = {
        **protocol["product_contract"],
        "executable_extensions": protocol["url_feature_contract"][
            "executable_extensions"
        ],
    }
    invalid_cases = [
        ("ftp://example.com/file", "example.com"),
        ("https://user:secret@example.com/login", "example.com"),
        ("https://evil.example/login", "safe.example"),
        ("https://example.com/" + "a" * 4096, "example.com"),
    ]
    for primary_decision in (False, True):
        for requested_url, expected_host in invalid_cases:
            combined_decision = primary_decision
            try:
                text, handcrafted, _ = build_url_features(
                    requested_url,
                    expected_host=expected_host,
                    contract=contract,
                    suspicious_tokens=suspicious_tokens,
                    brand_tokens=brand_tokens,
                )
                text_matrix = bundle["vectorizer"].transform([text])
                hand_matrix = bundle["scaler"].transform([handcrafted])
                matrix = hstack(
                    [csr_matrix(hand_matrix), text_matrix], format="csr"
                )
                raw = bundle["model"].decision_function(matrix)
                probability = bundle["platt"].predict_proba(
                    np.asarray(raw).reshape(-1, 1)
                )[0, 1]
                combined_decision = primary_decision or (
                    not primary_decision
                    and probability >= float(bundle["url_threshold"])
                )
            except URLContextError:
                combined_decision = primary_decision
            if combined_decision != primary_decision:
                return False
    return True


def evaluate(protocol_path: str | os.PathLike[str]) -> Dict[str, Any]:
    started = time.time()
    protocol_file = Path(protocol_path).resolve()
    protocol = _load_json(protocol_file)
    protocol_hash = compute_file_sha256(protocol_file)
    selection_path = resolve_ml_path(protocol["outputs"]["selection_report"])
    selection = _load_json(selection_path)
    if selection["protocol_sha256"] != protocol_hash:
        raise ValueError("selection report does not match active v10 protocol")
    if not selection["eligible_for_final"]:
        raise ValueError("v10 candidate is not eligible for final evaluation")

    snapshot_path = resolve_ml_path(protocol["outputs"]["snapshot_manifest"])
    snapshot = _load_json(snapshot_path)
    final_meta = snapshot["outputs"]["final"]
    final_path = resolve_ml_path(final_meta["path"])
    _require_hash(final_path, final_meta["sha256"], "frozen final cohort")
    final_frame = pd.read_parquet(final_path)
    if len(final_frame) != int(final_meta["rows"]):
        raise ValueError("frozen final row count mismatch")

    model_meta = selection["artifacts"]["model"]
    model_path = resolve_ml_path(model_meta["path"])
    _require_hash(model_path, model_meta["sha256"], "selected URL model")
    bundle = joblib.load(model_path)
    url_probability = _url_probability(final_frame, bundle, protocol)

    booster, primary_calibration, primary_manifest = _load_primary(protocol)
    primary_probability = _primary_probability(
        booster,
        primary_calibration,
        primary_manifest,
        final_frame["domain_ascii"].astype(str).tolist(),
    )
    primary_threshold = float(protocol["control"]["operating_threshold"])
    primary_decision = primary_probability >= primary_threshold
    url_decision = url_probability >= float(bundle["url_threshold"])
    _, combined = combine_optional_url(
        primary_probability,
        primary_threshold,
        url_probability,
        float(bundle["url_threshold"]),
    )
    labels = final_frame["label"].to_numpy(int)
    primary_metrics = _decision_metrics(labels, primary_decision)
    combined_metrics = _decision_metrics(labels, combined)
    metrics = {
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
        "url_only_accepted_benign": int(np.sum(url_decision & (labels == 0))),
        "url_only_accepted_malicious": int(np.sum(url_decision & (labels == 1))),
    }
    domain_probability, domain_decision = combine_optional_url(
        primary_probability, primary_threshold
    )
    domain_only_probability_parity = np.array_equal(
        primary_probability, domain_probability
    )
    domain_only_decision_parity = np.array_equal(primary_decision, domain_decision)
    parse_failure_parity = _parse_failure_preserves_domain_decision(bundle, protocol)
    gate_config = protocol["final_gates"]
    gates = {
        "source_disjoint_final_incremental_benign_false_positives_max": metrics[
            "incremental_benign_false_positives"
        ]
        <= int(
            gate_config[
                "source_disjoint_final_incremental_benign_false_positives_max"
            ]
        ),
        "source_disjoint_final_incremental_malicious_true_positives_min": metrics[
            "incremental_malicious_true_positives"
        ]
        >= int(
            gate_config[
                "source_disjoint_final_incremental_malicious_true_positives_min"
            ]
        ),
        "domain_only_probability_and_decision_parity": domain_only_probability_parity
        and domain_only_decision_parity,
        "url_parse_failure_preserves_domain_only_decision": parse_failure_parity,
    }
    passed = all(gates.values())
    report = {
        "schema_version": 1,
        "protocol_sha256": protocol_hash,
        "snapshot_manifest_sha256": compute_file_sha256(snapshot_path),
        "selection_report_sha256": compute_file_sha256(selection_path),
        "final_input": {
            "path": final_meta["path"],
            "sha256": final_meta["sha256"],
            "rows": final_meta["rows"],
            "labels": final_meta["labels"],
        },
        "selected_model": model_meta,
        "metrics": metrics,
        "invariants": {
            "domain_only_probability_parity": domain_only_probability_parity,
            "domain_only_decision_parity": domain_only_decision_parity,
            "parse_failure_preserves_domain_only_decision": parse_failure_parity,
        },
        "gates": gates,
        "passed": passed,
        "status": (
            "OFFLINE_ELIGIBLE_URL_SHADOW_CANDIDATE"
            if passed
            else "FINAL_GATE_FAILED"
        ),
        "representative_packet_evaluated": False,
        "representative_packet_note": "frozen representative evidence contains domains, not caller-observed URL/path context, and remains a forbidden tuning input",
        "duration_seconds": round(time.time() - started, 3),
    }
    report_path = resolve_ml_path(protocol["outputs"]["final_report"])
    _write_json(report_path, report)
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Evaluate frozen v10 URL final")
    parser.add_argument(
        "--protocol",
        default=str(BASE_DIR / "configs" / "v10-url-aware-signal-protocol.json"),
    )
    args = parser.parse_args()
    result = evaluate(args.protocol)
    print(
        json.dumps(
            {
                "status": result["status"],
                "metrics": result["metrics"],
                "invariants": result["invariants"],
                "gates": result["gates"],
            },
            indent=2,
        )
    )
