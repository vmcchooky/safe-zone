from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pandas as pd
from scipy.sparse import csr_matrix

ML_DIR = Path(__file__).resolve().parents[1]
if str(ML_DIR) not in sys.path:
    sys.path.insert(0, str(ML_DIR))

from src.source_invariant import select_source_invariant_features


def test_source_consensus_keeps_only_cross_source_malicious_feature() -> None:
    frame = pd.DataFrame(
        {
            "label": [0, 0, 1, 1, 1],
            "source": ["b1", "b2", "m1", "m2", "m3"],
        }
    )
    matrix = csr_matrix(
        [
            [1.0, 0.10, 0.90],
            [2.0, 0.20, 0.80],
            [3.0, 0.70, 0.95],
            [4.0, 0.80, 0.10],
            [5.0, 0.90, 0.10],
        ]
    )
    indices, report = select_source_invariant_features(
        frame,
        matrix,
        ["handcrafted", "stable", "source_specific"],
        {
            "handcrafted_feature_count": 1,
            "tfidf_source_minimum_rows": 1,
            "required_malicious_source_count": 3,
            "required_benign_source_count": 2,
            "malicious_source_support_minimum": 2,
            "median_log_ratio_minimum_exclusive": 0.0,
            "log_ratio_epsilon": 0.000001,
        },
    )
    np.testing.assert_array_equal(indices, [0, 1])
    assert report["tfidf_features_selected"] == 1
    assert report["selected_feature_names"] == ["handcrafted", "stable"]
