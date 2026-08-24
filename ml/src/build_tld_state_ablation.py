"""Build a one-feature TLD-state ablation from a validated reference matrix."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import time
from pathlib import Path
from typing import Any, Dict

import numpy as np
import pandas as pd
from scipy.sparse import csr_matrix, hstack, load_npz, save_npz

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from src.build_features import FeatureExtractor, SnapshotStore
from src.canonicalize import get_psl


def compute_file_sha256(path: str | os.PathLike[str]) -> str:
    hasher = hashlib.sha256()
    with open(path, "rb") as handle:
        while chunk := handle.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def _known_top_level_labels() -> set[str]:
    psl = get_psl()
    rules = psl.exact_rules | psl.wildcard_rules | psl.exception_rules
    return {rule.rsplit(".", 1)[-1] for rule in rules if rule}


def ternary_tld_values(domains: pd.Series, snapshot_policy: Dict[str, Any]) -> np.ndarray:
    store = SnapshotStore(snapshot_policy=snapshot_policy)
    if store.tld_state_encoding is None:
        raise ValueError("target contract must define ternary TLD state encoding")
    top_labels = domains.astype(str).str.rsplit(".", n=1).str[-1].str.lower()
    risky = top_labels.isin(set(store.tld_risk))
    known = top_labels.isin(_known_top_level_labels())
    values = np.zeros(len(domains), dtype=np.float64)
    values[known.to_numpy()] = store.tld_state_encoding["known_neutral"]
    values[risky.to_numpy()] = store.tld_state_encoding["risky"]
    return values


def build_ablation(
    source_derived_dir: str | os.PathLike[str],
    target_config_path: str | os.PathLike[str],
) -> Dict[str, Any]:
    started = time.time()
    source_dir = Path(source_derived_dir).resolve()
    config_path = Path(target_config_path).resolve()
    with open(config_path, "r", encoding="utf-8") as handle:
        config = json.load(handle)
    target_dir = (BASE_DIR / config["derived_dir"]).resolve()
    target_matrices = (BASE_DIR / config["matrices_dir"]).resolve()
    target_partitions = (BASE_DIR / config["partitions_dir"]).resolve()
    contract_path = (BASE_DIR / config["contract_path"]).resolve()
    with open(contract_path, "r", encoding="utf-8") as handle:
        contract = json.load(handle)
    if contract.get("contract_version") != "4.0.0":
        raise ValueError("TLD-state ablation requires feature contract 4.0.0")
    snapshot_policy = contract["snapshot_policy"]

    source_feature_manifest_path = source_dir / "feature_manifest.json"
    source_training_manifest_path = source_dir / "training_data_manifest.json"
    with open(source_feature_manifest_path, "r", encoding="utf-8") as handle:
        source_feature_manifest = json.load(handle)
    with open(source_training_manifest_path, "r", encoding="utf-8") as handle:
        training_manifest = json.load(handle)
    if source_feature_manifest.get("contract_version") != "3.0.0":
        raise ValueError("reference feature manifest must use contract 3.0.0")
    if source_feature_manifest.get("total_feature_count") != 534:
        raise ValueError("reference feature manifest must contain 534 features")

    target_matrices.mkdir(parents=True, exist_ok=True)
    target_partitions.mkdir(parents=True, exist_ok=True)
    checksums: Dict[str, str] = {}
    matrix_info: Dict[str, Any] = {}
    parity_samples = []
    extractor = FeatureExtractor(snapshot_store=SnapshotStore(snapshot_policy=snapshot_policy))
    for split in ("train", "val", "cal", "test"):
        source_partition = source_dir / "partitions" / f"{split}.parquet"
        source_matrix = source_dir / "matrices" / f"X_{split}.npz"
        target_partition = target_partitions / f"{split}.parquet"
        target_matrix = target_matrices / f"X_{split}.npz"
        shutil.copy2(source_partition, target_partition)
        frame = pd.read_parquet(target_partition, columns=["domain_ascii"])
        matrix = load_npz(source_matrix).tocsr()
        if matrix.shape != (len(frame), 534):
            raise ValueError(f"reference {split} matrix/partition shape mismatch")
        tld_values = ternary_tld_values(frame["domain_ascii"], snapshot_policy)
        transformed = hstack(
            [matrix[:, :14], csr_matrix(tld_values.reshape(-1, 1)), matrix[:, 15:]],
            format="csr",
        )
        transformed.sort_indices()
        save_npz(target_matrix, transformed)

        sample_indices = np.linspace(
            0, len(frame) - 1, num=min(25, len(frame)), dtype=int
        )
        for index in sample_indices:
            domain = str(frame.iloc[index]["domain_ascii"])
            expected = extractor.extract_features(domain)["tld_risk_score"]
            actual = float(tld_values[index])
            if actual != expected:
                raise ValueError(
                    f"v4 TLD parity mismatch for {domain}: {actual} != {expected}"
                )
            parity_samples.append(domain)

        matrix_rel = str(target_matrix.relative_to(BASE_DIR)).replace("\\", "/")
        partition_rel = str(target_partition.relative_to(BASE_DIR)).replace("\\", "/")
        matrix_sha = compute_file_sha256(target_matrix)
        partition_sha = compute_file_sha256(target_partition)
        checksums[matrix_rel] = matrix_sha
        checksums[partition_rel] = partition_sha
        matrix_info[split] = {
            "file": matrix_rel,
            "shape": list(transformed.shape),
            "nnz": int(transformed.nnz),
            "density": round(
                float(transformed.nnz / (transformed.shape[0] * transformed.shape[1])),
                6,
            ),
            "sha256": matrix_sha,
        }
        training_manifest["partition_files"][split] = {
            "path": str(target_partition),
            "rows": len(frame),
            "sha256": partition_sha,
        }

    source_hard_negative = Path(training_manifest["hard_negative"]["csv_path"])
    target_hard_negative = target_dir / "hard_negatives.csv"
    target_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source_hard_negative, target_hard_negative)
    training_manifest["hard_negative"]["csv_path"] = str(target_hard_negative)
    training_manifest["hard_negative"]["csv_sha256"] = compute_file_sha256(
        target_hard_negative
    )
    training_manifest_path = target_dir / "training_data_manifest.json"
    with open(training_manifest_path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(training_manifest, handle, indent=2, ensure_ascii=False)
        handle.write("\n")

    feature_manifest = dict(source_feature_manifest)
    feature_manifest["contract_version"] = "4.0.0"
    feature_manifest["generated_at"] = time.strftime(
        "%Y-%m-%dT%H:%M:%SZ", time.gmtime()
    )
    feature_manifest["snapshot_policy"] = snapshot_policy
    feature_manifest["matrices"] = matrix_info
    feature_manifest["checksums"] = checksums
    feature_manifest["ablation_provenance"] = {
        "source_feature_manifest": str(
            source_feature_manifest_path.relative_to(BASE_DIR)
        ).replace("\\", "/"),
        "source_feature_manifest_sha256": compute_file_sha256(
            source_feature_manifest_path
        ),
        "changed_feature_index": 14,
        "changed_feature_name": "tld_risk_score",
        "unchanged_feature_indices": "0-13,15-533",
        "python_feature_parity_samples": len(parity_samples),
    }
    feature_manifest["training_data_policy"]["manifest_path"] = str(
        training_manifest_path
    )
    feature_manifest["training_data_policy"]["manifest_sha256"] = (
        compute_file_sha256(training_manifest_path)
    )
    feature_manifest_path = target_dir / "feature_manifest.json"
    with open(feature_manifest_path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(feature_manifest, handle, indent=2)
        handle.write("\n")

    capacity_report = {
        "generated_at": feature_manifest["generated_at"],
        "mode": "single_feature_ablation_from_validated_reference",
        "source_derived_dir": str(source_dir.relative_to(BASE_DIR)).replace("\\", "/"),
        "changed_feature_index": 14,
        "wall_time_seconds": round(time.time() - started, 2),
        "python_feature_parity_samples": len(parity_samples),
    }
    with open(target_dir / "capacity_report.json", "w", encoding="utf-8", newline="\n") as handle:
        json.dump(capacity_report, handle, indent=2)
        handle.write("\n")
    return capacity_report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Build the v4 ternary TLD ablation")
    parser.add_argument(
        "--source-derived-dir",
        default=str(BASE_DIR / "data" / "derived" / "v3-time-forward-data"),
    )
    parser.add_argument(
        "--config",
        default=str(BASE_DIR / "configs" / "v4-time-forward-ternary-tld.json"),
    )
    args = parser.parse_args()
    result = build_ablation(args.source_derived_dir, args.config)
    print(json.dumps(result, indent=2))
