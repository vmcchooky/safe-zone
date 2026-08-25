from __future__ import annotations

import math
import sys
from pathlib import Path

import numpy as np

ML_DIR = Path(__file__).resolve().parents[1]
if str(ML_DIR) not in sys.path:
    sys.path.insert(0, str(ML_DIR))

from src.dns_context import (
    combined_decisions,
    extract_dns_features,
    has_parsed_response,
    select_zero_benign_threshold,
    stable_bucket,
)


def test_extract_dns_features_uses_fixed_record_semantics() -> None:
    responses = {
        "A": {
            "Status": 0,
            "Answer": [
                {"type": 5, "TTL": 300, "data": "target.example"},
                {"type": 1, "TTL": 60, "data": "192.0.2.1"},
            ],
        },
        "AAAA": {"Status": 0, "Answer": []},
        "NS": {"Status": 0, "Answer": [{"type": 2, "TTL": 600}]},
        "MX": {"Status": 3},
    }
    features = extract_dns_features(responses)
    assert len(features) == 18
    assert features["a_noerror"] == 1.0
    assert features["a_answer_count"] == 2.0
    assert features["a_address_count"] == 1.0
    assert features["a_cname_count"] == 1.0
    assert features["log1p_a_min_ttl"] == math.log1p(60)
    assert features["mx_noerror"] == 0.0
    assert features["resolved_any"] == 1.0
    assert features["dns_error_count"] == 0.0
    assert has_parsed_response(responses)


def test_collection_failures_are_counted_without_becoming_dns_statuses() -> None:
    features = extract_dns_features(
        {
            "A": {"error": "ReadTimeout"},
            "AAAA": {"error": "ReadTimeout"},
            "NS": {"Status": 2},
            "MX": {"error": "HTTPStatusError"},
        }
    )
    assert features["dns_error_count"] == 3.0
    assert features["a_nxdomain"] == 0.0
    assert features["resolved_any"] == 0.0


def test_zero_benign_threshold_accepts_no_benign() -> None:
    threshold, metrics = select_zero_benign_threshold(
        np.array([0.2, 0.8, 0.81, 0.95]), np.array([0, 0, 1, 1])
    )
    assert threshold > 0.8
    assert metrics["accepted_benign"] == 0
    assert metrics["accepted_malicious"] == 2


def test_combined_decision_preserves_every_primary_positive() -> None:
    combined = combined_decisions(
        primary_probability=np.array([0.95, 0.8, 0.8]),
        context_probability=np.array([0.1, 0.9, 0.4]),
        primary_threshold=0.92,
        context_threshold=0.8,
    )
    np.testing.assert_array_equal(combined, [True, True, False])


def test_stable_bucket_is_deterministic_and_bounded() -> None:
    assert stable_bucket(42, "example.com") == stable_bucket(42, "example.com")
    assert 0 <= stable_bucket(42, "example.com") < 10
