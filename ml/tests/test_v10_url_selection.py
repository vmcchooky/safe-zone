from __future__ import annotations

import json
from pathlib import Path

import numpy as np

from src.evaluate_v10_url_aware_final import combine_optional_url
from src.replay_v10_url_shadow import _percentile
from src.select_v10_url_aware import select_zero_benign_threshold


def test_zero_benign_threshold_is_strictly_above_maximum_benign():
    probabilities = np.asarray([0.1, 0.4, 0.4, 0.8, 0.9])
    labels = np.asarray([0, 0, 1, 1, 1])

    threshold, metrics = select_zero_benign_threshold(probabilities, labels)

    assert threshold > 0.4
    assert metrics == {"accepted_benign": 0, "accepted_malicious": 2}


def test_optional_url_combiner_preserves_domain_only_probability_and_decision():
    primary = np.asarray([0.1, 0.92, 0.99])

    probability, decision = combine_optional_url(primary, 0.92)

    assert np.array_equal(probability, primary)
    assert np.array_equal(decision, np.asarray([False, True, True]))


def test_runtime_bundle_contains_normalized_shadow_monitoring_reference():
    model_path = Path(__file__).resolve().parents[1] / "models" / "url-v1" / "url_model.v1.json"
    bundle = json.loads(model_path.read_text(encoding="utf-8"))
    monitoring = bundle["monitoring"]

    assert monitoring["reference_rows"] == 2000
    assert monitoring["reference_operational"] is False
    assert monitoring["reference_labels"] == {"benign": 1000, "malicious": 1000}
    assert len(monitoring["probability_buckets"]) == 10
    assert len(monitoring["probability_distribution_smoothed"]) == 10
    assert abs(sum(monitoring["probability_distribution_smoothed"]) - 1.0) < 1e-12


def test_shadow_replay_percentile_uses_nearest_rank():
    assert _percentile([1.0, 2.0, 3.0, 4.0], 0.95) == 4.0
