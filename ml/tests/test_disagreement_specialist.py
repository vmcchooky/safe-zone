from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pandas as pd

ML_DIR = Path(__file__).resolve().parents[1]
if str(ML_DIR) not in sys.path:
    sys.path.insert(0, str(ML_DIR))

from src.select_v7_disagreement_specialist import (
    combined_decisions,
    select_zero_benign_threshold,
    stable_bucket,
)


def test_stable_bucket_is_deterministic_and_bounded() -> None:
    first = stable_bucket(42, "example.com")
    second = stable_bucket(42, "example.com")
    assert first == second
    assert 0 <= first < 10


def test_zero_benign_threshold_accepts_no_benign() -> None:
    threshold, metrics = select_zero_benign_threshold(
        np.array([0.20, 0.80, 0.81, 0.95]),
        np.array([0, 0, 1, 1]),
    )
    assert threshold > 0.80
    assert metrics["accepted_benign"] == 0
    assert metrics["accepted_malicious"] == 2


def test_combined_decision_preserves_primary_and_filters_disagreement() -> None:
    frame = pd.DataFrame({"is_ml_candidate": [True, True, True, False]})
    combined, disagreement, accepted = combined_decisions(
        frame,
        control_probability=np.array([0.95, 0.80, 0.80, 0.80]),
        recall_probability=np.array([0.70, 0.95, 0.95, 0.99]),
        specialist_probability=np.array([0.10, 0.90, 0.40, 0.99]),
        operating_threshold=0.92,
        specialist_threshold=0.80,
    )
    np.testing.assert_array_equal(disagreement, [False, True, True, False])
    np.testing.assert_array_equal(accepted, [False, True, False, False])
    np.testing.assert_array_equal(combined, [True, True, False, False])
