"""
Phase 2 Model Pipeline & Calibration Unit Tests
Verifies Expected Calibration Error (ECE) math, Platt sigmoid formula,
and metric calculation bounds.
"""

import json
import math
import os
import sys
import numpy as np
import pandas as pd
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.calibrate_model import compute_expected_calibration_error
from src.build_features import FeatureExtractor, SnapshotStore
from src.evaluate_model import (
    build_benign_subset_audit,
    load_reviewed_unclassifiable_domains,
)
from src.export_artifacts import compute_file_sha256
from src.train_lightgbm import (
    apply_monotone_feature_policy,
    apply_training_weight_policy,
    evaluate_predictions,
)


def test_expected_calibration_error_calculation():
    # Perfectly calibrated predictions: 100 samples at 0.8 conf, exactly 80 are 1
    y_true = np.array([1] * 80 + [0] * 20)
    y_prob = np.array([0.8] * 100)

    ece = compute_expected_calibration_error(y_true, y_prob, n_bins=10)
    assert abs(ece) < 1e-6, f"Expected ECE ~ 0 for perfect calibration, got {ece}"

    # Perfectly miscalibrated predictions: 100 samples at 1.0 conf, all 0
    y_true_bad = np.array([0] * 100)
    y_prob_bad = np.array([1.0] * 100)
    ece_bad = compute_expected_calibration_error(y_true_bad, y_prob_bad, n_bins=10)
    assert abs(ece_bad - 1.0) < 1e-6, f"Expected ECE ~ 1.0 for completely miscalibrated, got {ece_bad}"


def test_platt_sigmoid_formula_parity():
    # Test formula P = 1 / (1 + exp(A*z + B))
    A = 0.5
    B = -0.1
    z = 1.2

    prob_manual = 1.0 / (1.0 + math.exp(A * z + B))
    prob_np = 1.0 / (1.0 + np.exp(A * z + B))

    assert abs(prob_manual - prob_np) < 1e-12
    assert 0.0 <= prob_manual <= 1.0


def test_evaluation_metrics_bounds():
    y_true = np.array([1, 1, 0, 0, 1, 0, 1, 0])
    y_prob = np.array([0.9, 0.8, 0.1, 0.2, 0.7, 0.3, 0.95, 0.05])

    res = evaluate_predictions(y_true, y_prob, threshold=0.5)

    assert 0.0 <= res["roc_auc"] <= 1.0
    assert 0.0 <= res["pr_auc"] <= 1.0
    assert 0.0 <= res["accuracy"] <= 1.0
    assert 0.0 <= res["f1"] <= 1.0
    assert res["log_loss"] >= 0.0


def test_tiered_training_weights_preserve_stronger_evidence_weight():
    frame = pd.DataFrame(
        [
            {"label": 0, "is_ml_candidate": True, "source": "vietnam_whitelist", "training_role": "standard"},
            {"label": 0, "is_ml_candidate": True, "source": "vietnam_whitelist", "training_role": "weighted_hard_negative"},
            {"label": 1, "is_ml_candidate": True, "source": "vietnam_whitelist", "training_role": "standard"},
            {"label": 0, "is_ml_candidate": False, "source": "vietnam_whitelist", "training_role": "standard"},
        ]
    )
    weights, report = apply_training_weight_policy(
        frame,
        np.array([1.0, 3.0, 1.0, 1.0]),
        {
            "source_proxy": {
                "enabled": True,
                "source": "vietnam_whitelist",
                "label": 0,
                "weight": 1.5,
            }
        },
    )
    assert weights.tolist() == [1.5, 3.0, 1.0, 1.0]
    assert report["source_proxy_rows"] == 2
    assert report["evidence_hard_negative_rows"] == 1


def test_named_monotone_feature_policy_uses_frozen_order():
    params, report = apply_monotone_feature_policy(
        {"objective": "binary"},
        {"monotone_increasing_features": ["tld_risk_score"]},
        ["fqdn_length", "tld_risk_score", "phishing_keyword_count"],
    )
    assert params["monotone_constraints"] == [0, 1, 0]
    assert params["monotone_constraints_method"] == "intermediate"
    assert report["increasing_features"] == ["tld_risk_score"]

    with pytest.raises(ValueError, match="unknown monotone features"):
        apply_monotone_feature_policy(
            {}, {"monotone_increasing_features": ["missing"]}, ["known"]
        )


def test_v3_snapshot_extensions_are_explicit_and_bounded():
    contract_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "contracts",
        "domain_feature_contract.v3.json",
    )
    with open(contract_path, encoding="utf-8") as handle:
        contract = json.load(handle)
    extractor = FeatureExtractor(
        snapshot_store=SnapshotStore(snapshot_policy=contract["snapshot_policy"])
    )

    assert extractor.extract_features("pl.spotify-original.com")[
        "has_brand_in_main_label"
    ] == 1
    assert extractor.extract_features("1xbet-xoso.com")[
        "phishing_keyword_count"
    ] >= 1
    assert extractor.extract_features("open.spotify.com")[
        "has_brand_in_main_label"
    ] == 0
    assert extractor.extract_features("tenant.weebly.com")[
        "is_shared_hosting"
    ] == 1


def test_bundle_hash_is_canonical_across_windows_and_unix_newlines(tmp_path):
    crlf = tmp_path / "crlf.json"
    lf = tmp_path / "lf.json"
    crlf.write_bytes(b'{\r\n  "ok": true\r\n}\r\n')
    lf.write_bytes(b'{\n  "ok": true\n}\n')
    assert compute_file_sha256(crlf) == compute_file_sha256(lf)


def test_reviewed_unclassifiable_labels_require_unknown_unresolved(tmp_path):
    labels_path = tmp_path / "labels.csv"
    frame = pd.DataFrame(
        [
            {
                "case_id": "stale-0001",
                "domain": "Expired.Example.VN",
                "human_label": "unknown",
                "review_outcome": "unresolved",
                "reviewer_id": "reviewer.test",
                "reviewed_at": "2026-08-24T10:18:33+07:00",
                "evidence_refs": "evidence/expired.example.vn.md",
                "review_notes": "Registry reports unallocated and DNS returns NXDOMAIN.",
            }
        ]
    )
    frame.to_csv(labels_path, index=False)

    domains, metadata = load_reviewed_unclassifiable_domains(str(labels_path))

    assert domains == {"expired.example.vn"}
    assert metadata["reviewed_cases"] == 1
    assert len(metadata["labels_sha256"]) == 64

    frame.loc[0, "human_label"] = "benign"
    frame.to_csv(labels_path, index=False)
    with pytest.raises(ValueError, match="human_label=unknown"):
        load_reviewed_unclassifiable_domains(str(labels_path))


def test_reviewed_unclassifiable_rows_are_separated_from_safe_vn_fpr():
    frame = pd.DataFrame(
        [
            {"domain": "stale.vn", "domain_ascii": "stale.vn", "label": 0},
            {"domain": "active.vn", "domain_ascii": "active.vn", "label": 0},
            {"domain": "pass.vn", "domain_ascii": "pass.vn", "label": 0},
            {
                "domain": "agency.gov.vn",
                "domain_ascii": "agency.gov.vn",
                "label": 0,
            },
            {"domain": "malicious.vn", "domain_ascii": "malicious.vn", "label": 1},
        ]
    )
    probabilities = np.array([0.95, 0.94, 0.10, 0.05, 0.99])
    candidate_mask = np.array([True, True, True, True, True])

    audit = build_benign_subset_audit(
        frame,
        probabilities,
        candidate_mask,
        0.92,
        {"stale.vn"},
        {"reviewed_cases": 1},
    )

    assert audit["safe_vn_raw_benign_count"] == 4
    assert audit["safe_vn_benign_count"] == 3
    assert audit["safe_vn_false_positives"] == 1
    assert audit["safe_vn_runtime_candidate_raw_count"] == 4
    assert audit["safe_vn_runtime_candidate_count"] == 3
    assert audit["safe_vn_runtime_candidate_false_positives"] == 1
    assert audit["reviewed_unclassifiable"]["matched_test_cases"] == 1
    assert audit["reviewed_unclassifiable"]["would_block"] == 1
