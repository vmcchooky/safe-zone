from __future__ import annotations

import numpy as np

from src.evaluate_v10_url_aware_final import combine_optional_url
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
