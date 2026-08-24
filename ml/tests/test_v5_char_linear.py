from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pandas as pd

ML_DIR = Path(__file__).resolve().parents[1]
if str(ML_DIR) not in sys.path:
    sys.path.insert(0, str(ML_DIR))

from src.select_v5_char_linear import _candidate_metrics, blend_log_odds


def test_blend_log_odds_preserves_endpoints() -> None:
    control = np.array([0.1, 0.5, 0.9])
    linear = np.array([0.8, 0.4, 0.2])
    np.testing.assert_allclose(blend_log_odds(control, linear, 0.0), control)
    np.testing.assert_allclose(blend_log_odds(control, linear, 1.0), linear)


def test_candidate_metrics_counts_only_runtime_candidates() -> None:
    frame = pd.DataFrame(
        {
            "label": [0, 0, 1, 1],
            "is_ml_candidate": [True, False, True, False],
        }
    )
    metrics = _candidate_metrics(frame, np.array([0.95, 0.99, 0.93, 0.01]), 0.92)
    assert metrics["runtime_candidate_benign_rows"] == 1
    assert metrics["runtime_candidate_malicious_rows"] == 1
    assert metrics["runtime_candidate_false_positives"] == 1
    assert metrics["runtime_candidate_true_positives"] == 1
