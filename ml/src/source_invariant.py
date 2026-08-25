"""Train-only cross-source feature selection for the v9 recall model."""

from __future__ import annotations

from typing import Any, Dict, Sequence

import numpy as np
import pandas as pd


def select_source_invariant_features(
    frame: pd.DataFrame,
    matrix: Any,
    feature_names: Sequence[str],
    policy: Dict[str, Any],
) -> tuple[np.ndarray, Dict[str, Any]]:
    handcrafted_count = int(policy["handcrafted_feature_count"])
    if matrix.shape != (len(frame), len(feature_names)):
        raise ValueError("training matrix, frame, and feature names are not aligned")
    minimum_rows = int(policy["tfidf_source_minimum_rows"])
    aliases = {str(key): str(value) for key, value in policy.get("source_family_aliases", {}).items()}
    source_family = frame["source"].astype(str).map(lambda value: aliases.get(value, value))
    malicious_sources = sorted(
        str(source)
        for source, group in frame[frame["label"].to_numpy(int) == 1]
        .assign(source_family=source_family[frame["label"].to_numpy(int) == 1])
        .groupby("source_family")
        if len(group) >= minimum_rows
    )
    benign_sources = sorted(
        str(source)
        for source, group in frame[frame["label"].to_numpy(int) == 0]
        .assign(source_family=source_family[frame["label"].to_numpy(int) == 0])
        .groupby("source_family")
        if len(group) >= minimum_rows
    )
    if len(malicious_sources) != int(policy["required_malicious_source_count"]):
        raise ValueError(f"unexpected malicious source count: {malicious_sources}")
    if len(benign_sources) != int(policy["required_benign_source_count"]):
        raise ValueError(f"unexpected benign source count: {benign_sources}")

    tfidf = matrix[:, handcrafted_count:]
    malicious_means = np.vstack(
        [
            np.asarray(tfidf[source_family.eq(source).to_numpy()].mean(axis=0)).ravel()
            for source in malicious_sources
        ]
    )
    benign_means = np.vstack(
        [
            np.asarray(tfidf[source_family.eq(source).to_numpy()].mean(axis=0)).ravel()
            for source in benign_sources
        ]
    )
    benign_reference = np.max(benign_means, axis=0)
    support = np.sum(malicious_means > benign_reference, axis=0)
    epsilon = float(policy["log_ratio_epsilon"])
    median_log_ratio = np.median(
        np.log((malicious_means + epsilon) / (benign_reference + epsilon)), axis=0
    )
    keep_tfidf = (support >= int(policy["malicious_source_support_minimum"])) & (
        median_log_ratio > float(policy["median_log_ratio_minimum_exclusive"])
    )
    tfidf_indices = np.flatnonzero(keep_tfidf) + handcrafted_count
    selected = np.concatenate(
        [np.arange(handcrafted_count, dtype=int), tfidf_indices.astype(int)]
    )
    selected_names = [str(feature_names[index]) for index in selected]
    return selected, {
        "malicious_sources": malicious_sources,
        "benign_sources": benign_sources,
        "handcrafted_features": handcrafted_count,
        "tfidf_features_before": int(matrix.shape[1] - handcrafted_count),
        "tfidf_features_selected": int(len(tfidf_indices)),
        "total_features_selected": int(len(selected)),
        "selected_feature_indices": selected.tolist(),
        "selected_feature_names": selected_names,
        "selected_tfidf_support_minimum": int(
            np.min(support[keep_tfidf]) if np.any(keep_tfidf) else 0
        ),
        "selected_tfidf_median_log_ratio_minimum": float(
            np.min(median_log_ratio[keep_tfidf]) if np.any(keep_tfidf) else 0.0
        ),
    }
