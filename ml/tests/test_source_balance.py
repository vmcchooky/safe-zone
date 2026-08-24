from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pandas as pd

ML_DIR = Path(__file__).resolve().parents[1]
if str(ML_DIR) not in sys.path:
    sys.path.insert(0, str(ML_DIR))

from src.train_lightgbm import apply_source_balance_policy
from src.select_v6_source_balanced import malicious_source_metrics


def test_source_balance_preserves_each_class_mass() -> None:
    frame = pd.DataFrame(
        {
            "label": [0, 0, 0, 1, 1, 1, 1],
            "source": [
                "large-safe",
                "large-safe",
                "small-safe",
                "large-bad",
                "large-bad",
                "large-bad",
                "small-bad",
            ],
        }
    )
    baseline = np.array([1.0, 1.0, 3.0, 1.0, 1.0, 1.0, 1.5])
    balanced, report = apply_source_balance_policy(
        frame,
        baseline,
        {
            "exponent": 0.5,
            "raw_factor_clip": [1.0, 3.0],
            "maximum_effective_weight": 10.0,
        },
    )

    for label in (0, 1):
        mask = frame["label"].to_numpy() == label
        assert np.isclose(baseline[mask].sum(), balanced[mask].sum())
    assert np.isclose(report["effective_train_weight"], np.sum(baseline))


def test_source_balance_increases_small_source_relative_weight() -> None:
    frame = pd.DataFrame(
        {
            "label": [1, 1, 1, 1],
            "source": ["large", "large", "large", "small"],
        }
    )
    balanced, _ = apply_source_balance_policy(
        frame,
        np.ones(4),
        {
            "exponent": 0.5,
            "raw_factor_clip": [1.0, 3.0],
            "maximum_effective_weight": 10.0,
        },
    )

    assert balanced[3] > balanced[0]
    assert np.isclose(balanced.sum(), 4.0)


def test_malicious_source_metrics_filters_non_candidates_and_small_sources() -> None:
    frame = pd.DataFrame(
        {
            "label": [1, 1, 1, 1, 0],
            "source": ["large", "large", "small", "small", "safe"],
            "is_ml_candidate": [True, True, True, False, True],
        },
        index=[10, 20, 30, 40, 50],
    )
    metrics = malicious_source_metrics(
        frame,
        np.array([0.95, 0.20, 0.93, 0.99, 0.99]),
        threshold=0.92,
        minimum_source_rows=2,
    )

    assert metrics["eligible_source_count"] == 1
    assert metrics["macro_recall"] == 0.5
    assert metrics["worst_source_recall"] == 0.5
