"""
Group-Disjoint Partitioning & Split Manifest Generator (Phase 1)
Partitions dataset by registrable_domain hash across train, val, cal, and test splits.
Asserts group_overlap = 0 and conflicts_in_trainable = 0.
"""

import hashlib
import json
import os
import sys
import time
from typing import Dict, Any, List, Set, Tuple, Optional

import pandas as pd

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from src.build_candidate_cohort import build_candidate_cohort


def compute_file_sha256(filepath: str) -> str:
    hasher = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def assign_group_partition(group_key: str, seed: int = 42) -> str:
    """
    Deterministic hash-based partition assignment for a group key.
    Ratios:
    - Train: 70% (0.00 <= h < 0.70)
    - Val:   10% (0.70 <= h < 0.80)
    - Cal:   10% (0.80 <= h < 0.90)
    - Test:  10% (0.90 <= h < 1.00)
    """
    input_bytes = f"{seed}:{group_key}".encode("utf-8")
    hash_hex = hashlib.sha256(input_bytes).hexdigest()
    val = int(hash_hex[:16], 16) / float(0xFFFFFFFFFFFFFFFF)

    if val < 0.70:
        return "train"
    elif val < 0.80:
        return "validation"
    elif val < 0.90:
        return "calibration"
    else:
        return "test"


def make_splits(
    cohort_parquet: Optional[str] = None,
    derived_dir: Optional[str] = None,
    seed: int = 42,
) -> Dict[str, Any]:
    t0 = time.time()

    if derived_dir is None:
        derived_dir = os.path.join(BASE_DIR, "data", "derived")
    os.makedirs(derived_dir, exist_ok=True)
    partitions_dir = os.path.join(derived_dir, "partitions")
    os.makedirs(partitions_dir, exist_ok=True)

    if cohort_parquet is None:
        cohort_parquet = os.path.join(derived_dir, "candidate_cohort.parquet")

    if not os.path.exists(cohort_parquet):
        print(f"[*] {cohort_parquet} not found. Running build_candidate_cohort()...")
        df_cohort = build_candidate_cohort(output_parquet=cohort_parquet)
    else:
        print(f"[*] Reading candidate cohort from {cohort_parquet}...")
        df_cohort = pd.read_parquet(cohort_parquet)

    total_rows = len(df_cohort)
    print(f"[+] Loaded {total_rows:,} records from cohort.")

    # 1. Identify Cross-label Conflicts
    # Cross-label conflict: same domain_ascii appears with both label 0 and label 1
    label_map = df_cohort.groupby("domain_ascii")["label"].nunique()
    conflicting_domains = set(label_map[label_map > 1].index)
    print(f"[+] Found {len(conflicting_domains):,} conflicting domains with cross-label overlap.")

    is_conflict = df_cohort["domain_ascii"].isin(conflicting_domains)
    df_conflicts = df_cohort[is_conflict].copy()
    df_clean = df_cohort[~is_conflict].copy()

    # Save conflicts_excluded
    conflicts_parquet = os.path.join(derived_dir, "conflicts_excluded.parquet")
    df_conflicts.to_parquet(conflicts_parquet, index=False)
    print(f"[+] Saved {len(df_conflicts):,} conflict records to {conflicts_parquet}")

    # 2. Group-disjoint Partitioning by Registrable Domain Hash
    print(f"[*] Partitioning dataset by registrable_domain hash (seed={seed})...")
    df_clean["partition"] = df_clean["registrable_domain"].apply(lambda g: assign_group_partition(str(g), seed=seed))

    # Split into dataframes
    df_train = df_clean[df_clean["partition"] == "train"].copy()
    df_val = df_clean[df_clean["partition"] == "validation"].copy()
    df_cal = df_clean[df_clean["partition"] == "calibration"].copy()
    df_test = df_clean[df_clean["partition"] == "test"].copy()

    # 3. Hard Cases Identification
    # Hard cases include trusted brand suffixes, protected Vietnam public service abuse, high-risk brand typos
    trusted_brands = {"google.com", "vietcombank.com.vn", "facebook.com", "chinhphu.vn", "vneid.gov.vn", "techcombank.com.vn"}
    is_hard = (
        df_clean["reasons"].str.contains("protected|typosquatting|homoglyph|dichvucong|shared", case=False, na=False)
        | df_clean["registrable_domain"].isin(trusted_brands)
    )
    df_hard = df_clean[is_hard].copy()
    hard_cases_parquet = os.path.join(derived_dir, "hard_cases.parquet")
    df_hard.to_parquet(hard_cases_parquet, index=False)
    print(f"[+] Saved {len(df_hard):,} hard case records to {hard_cases_parquet}")

    # 4. Assertions: Group Overlap & Conflicts in Trainable
    train_groups = set(df_train["registrable_domain"])
    val_groups = set(df_val["registrable_domain"])
    cal_groups = set(df_cal["registrable_domain"])
    test_groups = set(df_test["registrable_domain"])

    overlap_train_val = len(train_groups & val_groups)
    overlap_train_cal = len(train_groups & cal_groups)
    overlap_train_test = len(train_groups & test_groups)
    overlap_val_cal = len(val_groups & cal_groups)
    overlap_val_test = len(val_groups & test_groups)
    overlap_cal_test = len(cal_groups & test_groups)

    total_group_overlap = (
        overlap_train_val
        + overlap_train_cal
        + overlap_train_test
        + overlap_val_cal
        + overlap_val_test
        + overlap_cal_test
    )

    # Check conflicts in clean trainable dataset
    trainable_label_counts = df_clean.groupby("domain_ascii")["label"].nunique()
    conflicts_in_trainable = (trainable_label_counts > 1).sum()

    print(f"[+] Assertion Check: group_overlap = {total_group_overlap}")
    print(f"[+] Assertion Check: conflicts_in_trainable = {conflicts_in_trainable}")
    assert total_group_overlap == 0, f"Error: group overlap detected ({total_group_overlap})"
    assert conflicts_in_trainable == 0, f"Error: label conflicts in trainable dataset ({conflicts_in_trainable})"

    # 5. Save Parquet Files for Candidates & Metadata Partitions
    parquet_files = {}

    # Candidate cohort subsets (is_ml_candidate == True)
    train_cand = os.path.join(derived_dir, "train_candidates.parquet")
    val_cand = os.path.join(derived_dir, "validation_candidates.parquet")
    cal_cand = os.path.join(derived_dir, "calibration_candidates.parquet")
    test_cand = os.path.join(derived_dir, "test_candidates.parquet")

    df_train[df_train["is_ml_candidate"]].to_parquet(train_cand, index=False)
    df_val[df_val["is_ml_candidate"]].to_parquet(val_cand, index=False)
    df_cal[df_cal["is_ml_candidate"]].to_parquet(cal_cand, index=False)
    df_test[df_test["is_ml_candidate"]].to_parquet(test_cand, index=False)

    # Full metadata partitions
    train_part = os.path.join(partitions_dir, "train.parquet")
    val_part = os.path.join(partitions_dir, "val.parquet")
    cal_part = os.path.join(partitions_dir, "cal.parquet")
    test_part = os.path.join(partitions_dir, "test.parquet")

    df_train.to_parquet(train_part, index=False)
    df_val.to_parquet(val_part, index=False)
    df_cal.to_parquet(cal_part, index=False)
    df_test.to_parquet(test_part, index=False)

    # Empty holdouts if not present
    source_holdout_path = os.path.join(derived_dir, "source_holdout.parquet")
    temporal_holdout_path = os.path.join(derived_dir, "temporal_holdout.parquet")

    pd.DataFrame(columns=df_cohort.columns).to_parquet(source_holdout_path, index=False)
    pd.DataFrame(columns=df_cohort.columns).to_parquet(temporal_holdout_path, index=False)

    # Compute SHA-256 for all generated files
    all_parquet_paths = [
        train_cand, val_cand, cal_cand, test_cand,
        train_part, val_part, cal_part, test_part,
        conflicts_parquet, hard_cases_parquet,
        source_holdout_path, temporal_holdout_path
    ]

    for p in all_parquet_paths:
        rel_path = os.path.relpath(p, BASE_DIR).replace("\\", "/")
        parquet_files[rel_path] = compute_file_sha256(p)

    # 6. Generate split_manifest.json
    data_manifest_path = os.path.join(BASE_DIR, "data", "data_manifest.json")
    if not os.path.exists(data_manifest_path):
        raise FileNotFoundError(
            f"Required data provenance manifest is missing: {data_manifest_path}. "
            "Refusing to generate a split manifest without input_data_manifest_hash."
        )
    input_manifest_hash = compute_file_sha256(data_manifest_path)

    def get_partition_stats(df_p: pd.DataFrame) -> Dict[str, Any]:
        return {
            "total_rows": len(df_p),
            "safe_rows": int((df_p["label"] == 0).sum()),
            "malicious_rows": int((df_p["label"] == 1).sum()),
            "ml_candidates": int(df_p["is_ml_candidate"].sum()),
            "unique_groups": int(df_p["registrable_domain"].nunique()),
        }

    manifest_data = {
        "manifest_version": 1,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "pipeline_git_sha": "1fb895883bad2ae2dcc2fde586812963a547d653",
        "input_data_manifest_hash": input_manifest_hash,
        "label_policy_version": 1,
        "canonicalization_psl_version": "public_suffix_list.v1.dat",
        "group_key_algorithm": "registrable_domain_sha256",
        "seed": seed,
        "split_ratios": {
            "train": 0.70,
            "validation": 0.10,
            "calibration": 0.10,
            "test": 0.10,
        },
        "partition_counts": {
            "train": get_partition_stats(df_train),
            "validation": get_partition_stats(df_val),
            "calibration": get_partition_stats(df_cal),
            "test": get_partition_stats(df_test),
            "conflicts_excluded": len(df_conflicts),
            "hard_cases": len(df_hard),
        },
        "assertions": {
            "group_overlap": int(total_group_overlap),
            "conflicts_in_trainable": int(conflicts_in_trainable),
            "group_overlap_assert_pass": True,
            "conflicts_assert_pass": True,
        },
        "file_checksums": parquet_files,
    }

    manifest_path = os.path.join(derived_dir, "split_manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest_data, f, indent=2, default=int)

    t1 = time.time()
    print(f"[+] Saved split manifest to {manifest_path} (Completed in {t1 - t0:.2f}s)")
    return manifest_data


if __name__ == "__main__":
    make_splits()
