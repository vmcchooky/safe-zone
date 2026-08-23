"""
Phase 2 Model Pipeline & Calibration Unit Tests
Verifies Expected Calibration Error (ECE) math, Platt sigmoid formula,
and metric calculation bounds.
"""

import math
import os
import sys
import numpy as np
import pandas as pd
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.calibrate_model import compute_expected_calibration_error
from src.export_artifacts import compute_file_sha256
from src.train_lightgbm import apply_training_weight_policy, evaluate_predictions


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


def test_bundle_hash_is_canonical_across_windows_and_unix_newlines(tmp_path):
    crlf = tmp_path / "crlf.json"
    lf = tmp_path / "lf.json"
    crlf.write_bytes(b'{\r\n  "ok": true\r\n}\r\n')
    lf.write_bytes(b'{\n  "ok": true\n}\n')
    assert compute_file_sha256(crlf) == compute_file_sha256(lf)
