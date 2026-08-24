"""
Artifact Validation Suite (Phase 2)
Validates generated NPZ matrices, Parquet partitions, and JSON manifests.
Checks group-disjoint assertions (group_overlap=0, conflicts=0), matrix dimensions,
non-empty data rows, NaN/Inf sanity, and SHA-256 manifest hashes.
"""

import hashlib
import argparse
import json
import os
import sys
import time
from typing import Dict, Any, List, Tuple, Set, Optional

import numpy as np
import pandas as pd
from scipy.sparse import load_npz

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)


def compute_file_sha256(filepath: str) -> str:
    hasher = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


class ArtifactValidator:
    def __init__(self, derived_dir: Optional[str] = None):
        if derived_dir is None:
            derived_dir = os.path.join(BASE_DIR, "data", "derived")
        self.derived_dir = derived_dir
        self.matrices_dir = os.path.join(derived_dir, "matrices")
        self.partitions_dir = os.path.join(derived_dir, "partitions")
        self.results: List[Dict[str, Any]] = []

    def log_check(self, category: str, name: str, passed: bool, message: str):
        status_str = "PASS" if passed else "FAIL"
        self.results.append(
            {
                "category": category,
                "name": name,
                "passed": passed,
                "message": message,
            }
        )
        print(f"[{status_str}] [{category}] {name}: {message}")

    def validate_manifests(self) -> bool:
        print("\n--- 1. Validating JSON Manifests & Checksums ---")
        training_manifest_path = os.path.join(
            self.derived_dir, "training_data_manifest.json"
        )
        candidate_mode = os.path.exists(training_manifest_path)
        manifests = [
            ("data_manifest", os.path.join(BASE_DIR, "data", "data_manifest.json")),
            ("feature_manifest", os.path.join(self.derived_dir, "feature_manifest.json")),
            ("capacity_report", os.path.join(self.derived_dir, "capacity_report.json")),
        ]
        manifests.append(
            (
                "training_data_manifest" if candidate_mode else "split_manifest",
                training_manifest_path
                if candidate_mode
                else os.path.join(self.derived_dir, "split_manifest.json"),
            )
        )

        all_ok = True
        for name, mpath in manifests:
            if not os.path.exists(mpath):
                self.log_check("Manifest", name, False, f"Manifest file missing: {mpath}")
                all_ok = False
                continue

            try:
                with open(mpath, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self.log_check("Manifest", name, True, f"Valid JSON (version {data.get('manifest_version', data.get('contract_version', '1'))})")
            except Exception as e:
                self.log_check("Manifest", name, False, f"Invalid JSON syntax: {e}")
                all_ok = False

        # Validate file checksums against split_manifest.json & feature_manifest.json
        split_mpath = os.path.join(self.derived_dir, "split_manifest.json")
        if os.path.exists(split_mpath):
            with open(split_mpath, "r", encoding="utf-8") as f:
                sdata = json.load(f)

            data_manifest_path = os.path.join(BASE_DIR, "data", "data_manifest.json")
            expected_manifest_sha = sdata.get("input_data_manifest_hash", "")
            if os.path.exists(data_manifest_path):
                actual_manifest_sha = compute_file_sha256(data_manifest_path)
                link_pass = bool(expected_manifest_sha) and actual_manifest_sha.lower() == expected_manifest_sha.lower()
                link_message = "input_data_manifest_hash matches data_manifest.json" if link_pass else (
                    f"Manifest hash mismatch: expected {expected_manifest_sha or '<empty>'}, got {actual_manifest_sha}"
                )
                self.log_check("Manifest", "split_manifest_data_manifest_link", link_pass, link_message)
                if not link_pass:
                    all_ok = False
            else:
                self.log_check("Manifest", "split_manifest_data_manifest_link", False, "Cannot verify link: data_manifest.json is missing")
                all_ok = False

            checksums = sdata.get("file_checksums", {})
            for rel_path, expected_sha in checksums.items():
                full_path = os.path.join(BASE_DIR, rel_path)
                if not os.path.exists(full_path):
                    self.log_check("Checksum", rel_path, False, "File missing from disk")
                    all_ok = False
                    continue
                actual_sha = compute_file_sha256(full_path)
                match = actual_sha.lower() == expected_sha.lower()
                msg = "SHA-256 match" if match else f"Mismatch! expected {expected_sha[:8]}.. got {actual_sha[:8]}.."
                self.log_check("Checksum", rel_path, match, msg)
                if not match:
                    all_ok = False

        feature_manifest_path = os.path.join(
            self.derived_dir, "feature_manifest.json"
        )
        if os.path.exists(feature_manifest_path):
            with open(feature_manifest_path, "r", encoding="utf-8") as f:
                feature_data = json.load(f)
            for rel_path, expected_sha in feature_data.get("checksums", {}).items():
                full_path = os.path.join(BASE_DIR, rel_path)
                exists = os.path.exists(full_path)
                actual_sha = compute_file_sha256(full_path) if exists else ""
                match = exists and actual_sha.lower() == expected_sha.lower()
                self.log_check(
                    "Checksum",
                    f"feature:{rel_path}",
                    match,
                    "SHA-256 match"
                    if match
                    else f"Missing or mismatched artifact: {full_path}",
                )
                if not match:
                    all_ok = False

        if candidate_mode:
            with open(training_manifest_path, "r", encoding="utf-8") as f:
                training_data = json.load(f)
            challenge = training_data.get("frozen_challenge", {})
            challenge_ok = (
                challenge.get("domain_count", 0) > 0
                and challenge.get("overlap_after_exclusion") == 0
            )
            self.log_check(
                "Leakage",
                "frozen_challenge_excluded",
                challenge_ok,
                f"domains={challenge.get('domain_count', 0)}, overlap={challenge.get('overlap_after_exclusion')}",
            )
            all_ok = all_ok and challenge_ok
            frozen_evaluation = training_data.get("frozen_evaluation")
            if frozen_evaluation is not None:
                evaluation_ok = (
                    frozen_evaluation.get("case_count", 0) > 0
                    and frozen_evaluation.get("registrable_group_count", 0) > 0
                    and frozen_evaluation.get("overlap_after_exclusion") == 0
                )
                self.log_check(
                    "Leakage",
                    "frozen_evaluation_excluded",
                    evaluation_ok,
                    "cases="
                    f"{frozen_evaluation.get('case_count', 0)}, groups="
                    f"{frozen_evaluation.get('registrable_group_count', 0)}, overlap="
                    f"{frozen_evaluation.get('overlap_after_exclusion')}",
                )
                all_ok = all_ok and evaluation_ok
            combined = training_data.get("combined_exclusions")
            if combined is not None:
                combined_ok = (
                    combined.get("registrable_group_count", 0) > 0
                    and combined.get("overlap_after_exclusion") == 0
                )
                self.log_check(
                    "Leakage",
                    "combined_evaluation_exclusions",
                    combined_ok,
                    "groups="
                    f"{combined.get('registrable_group_count', 0)}, overlap="
                    f"{combined.get('overlap_after_exclusion')}",
                )
                all_ok = all_ok and combined_ok
            hard_negative = training_data.get("hard_negative", {})
            hard_csv = hard_negative.get("csv_path", "")
            hard_sha = hard_negative.get("csv_sha256", "")
            hard_ok = (
                bool(hard_csv)
                and os.path.exists(hard_csv)
                and compute_file_sha256(hard_csv).lower() == str(hard_sha).lower()
                and hard_negative.get("counts", {}).get("selected_rows", 0) > 0
            )
            self.log_check(
                "Provenance",
                "hard_negative_manifest",
                hard_ok,
                f"selected_rows={hard_negative.get('counts', {}).get('selected_rows', 0)}",
            )
            all_ok = all_ok and hard_ok
            hard_positive = training_data.get("hard_positive")
            if hard_positive is not None:
                positive_path = hard_positive.get("source_path", "")
                positive_sha = hard_positive.get("source_sha256", "")
                positive_ok = (
                    bool(positive_path)
                    and os.path.exists(positive_path)
                    and compute_file_sha256(positive_path).lower()
                    == str(positive_sha).lower()
                    and hard_positive.get("selected_rows", 0) > 0
                    and hard_positive.get("overlap_with_existing_partitions") == 0
                    and hard_positive.get("overlap_with_frozen_groups") == 0
                )
                self.log_check(
                    "Provenance",
                    "time_forward_hard_positive_manifest",
                    positive_ok,
                    f"selected_rows={hard_positive.get('selected_rows', 0)}",
                )
                all_ok = all_ok and positive_ok

        return all_ok

    def validate_parquet_partitions(self) -> bool:
        print("\n--- 2. Validating Parquet Partitions & Group-Disjoint Assertions ---")
        partition_names = ["train", "val", "cal", "test"]
        partition_dfs = {}
        all_ok = True

        for p_name in partition_names:
            ppath = os.path.join(self.partitions_dir, f"{p_name}.parquet")
            if not os.path.exists(ppath):
                self.log_check("Parquet", f"partition_{p_name}", False, f"Missing partition file: {ppath}")
                all_ok = False
                continue
            try:
                df = pd.read_parquet(ppath)
                partition_dfs[p_name] = df
                non_empty = len(df) > 0
                self.log_check("Parquet", f"partition_{p_name}", non_empty, f"Loaded {len(df):,} rows, {len(df.columns)} columns")
                if not non_empty:
                    all_ok = False
            except Exception as e:
                self.log_check("Parquet", f"partition_{p_name}", False, f"Failed to read Parquet: {e}")
                all_ok = False

        # Candidate Parquet Files
        candidate_mode = os.path.exists(
            os.path.join(self.derived_dir, "training_data_manifest.json")
        )
        cand_names = [] if candidate_mode else ["train_candidates", "validation_candidates", "calibration_candidates", "test_candidates", "conflicts_excluded", "hard_cases"]
        for c_name in cand_names:
            cpath = os.path.join(self.derived_dir, f"{c_name}.parquet")
            if not os.path.exists(cpath):
                self.log_check("Parquet", c_name, False, f"Missing candidate file: {cpath}")
                all_ok = False
                continue
            try:
                df_c = pd.read_parquet(cpath)
                self.log_check("Parquet", c_name, True, f"Loaded {len(df_c):,} rows")
            except Exception as e:
                self.log_check("Parquet", c_name, False, f"Failed to read Parquet: {e}")
                all_ok = False

        if len(partition_dfs) == 4:
            # Group Overlap Assertion
            groups = {p: set(partition_dfs[p]["registrable_domain"]) for p in partition_names}
            overlap_pairs = [
                ("train", "val"), ("train", "cal"), ("train", "test"),
                ("val", "cal"), ("val", "test"), ("cal", "test")
            ]
            total_overlap = 0
            for p1, p2 in overlap_pairs:
                overlap = len(groups[p1] & groups[p2])
                total_overlap += overlap

            overlap_pass = (total_overlap == 0)
            self.log_check("Assertion", "group_overlap_zero", overlap_pass, f"Total group overlap across all partition pairs: {total_overlap}")
            if not overlap_pass:
                all_ok = False

            # Conflicts Assertion across Trainable Partitions
            df_all_trainable = pd.concat(list(partition_dfs.values()), ignore_index=True)
            label_counts = df_all_trainable.groupby("domain_ascii")["label"].nunique()
            conflicts = (label_counts > 1).sum()
            conflicts_pass = (conflicts == 0)
            self.log_check("Assertion", "conflicts_in_trainable_zero", conflicts_pass, f"Total cross-label conflicts in trainable partitions: {conflicts}")
            if not conflicts_pass:
                all_ok = False

            if candidate_mode:
                train_weights = partition_dfs["train"].get("sample_weight")
                weight_pass = (
                    train_weights is not None
                    and train_weights.notna().all()
                    and (train_weights > 0).all()
                    and (train_weights <= 10).all()
                    and int((train_weights > 1).sum()) > 0
                )
                self.log_check(
                    "Training",
                    "bounded_sample_weights",
                    weight_pass,
                    f"weighted_rows={int((train_weights > 1).sum()) if train_weights is not None else 0}",
                )
                if not weight_pass:
                    all_ok = False

        return all_ok

    def validate_matrices(self) -> bool:
        print("\n--- 3. Validating Sparse CSR NPZ Matrices ---")
        partition_names = ["train", "val", "cal", "test"]
        all_ok = True

        for p_name in partition_names:
            mpath = os.path.join(self.matrices_dir, f"X_{p_name}.npz")
            ppath = os.path.join(self.partitions_dir, f"{p_name}.parquet")

            if not os.path.exists(mpath):
                self.log_check("Matrix", f"X_{p_name}", False, f"Missing matrix file: {mpath}")
                all_ok = False
                continue

            try:
                matrix = load_npz(mpath)
                # Check dimensions
                num_rows, num_cols = matrix.shape
                cols_pass = (num_cols == 534)
                self.log_check("Matrix", f"X_{p_name}_cols", cols_pass, f"Columns: {num_cols} (expected 534)")
                if not cols_pass:
                    all_ok = False

                if os.path.exists(ppath):
                    df_p = pd.read_parquet(ppath)
                    rows_pass = (num_rows == len(df_p))
                    self.log_check("Matrix", f"X_{p_name}_rows_match", rows_pass, f"Matrix rows ({num_rows:,}) match Parquet rows ({len(df_p):,})")
                    if not rows_pass:
                        all_ok = False

                # Check NaN / Inf
                has_nan = np.isnan(matrix.data).any()
                has_inf = np.isinf(matrix.data).any()
                sanity_pass = (not has_nan) and (not has_inf)
                self.log_check("Matrix", f"X_{p_name}_sanity", sanity_pass, f"NaNs: {has_nan}, Infs: {has_inf}, nnz: {matrix.nnz:,}")
                if not sanity_pass:
                    all_ok = False

            except Exception as e:
                self.log_check("Matrix", f"X_{p_name}", False, f"Failed to load NPZ matrix: {e}")
                all_ok = False

        return all_ok

    def run_all_validations(self) -> bool:
        t0 = time.time()
        print("===============================================================")
        print("          SAFE ZONE ML ARTIFACT VALIDATION SUITE              ")
        print("===============================================================")

        v1 = self.validate_manifests()
        v2 = self.validate_parquet_partitions()
        v3 = self.validate_matrices()

        t1 = time.time()
        total_checks = len(self.results)
        passed_checks = sum(1 for r in self.results if r["passed"])
        failed_checks = total_checks - passed_checks

        print("\n===============================================================")
        print(f"VALIDATION SUMMARY: {passed_checks}/{total_checks} checks passed in {t1 - t0:.2f}s")
        print("===============================================================")

        if failed_checks == 0:
            print(">>> ALL ARTIFACT VALIDATIONS PASSED CLEANLY (SUCCESS) <<<")
            return True
        else:
            print(f">>> VALIDATION FAILED: {failed_checks} check(s) failed <<<")
            return False


def validate_artifacts(derived_dir: Optional[str] = None) -> bool:
    validator = ArtifactValidator(derived_dir=derived_dir)
    success = validator.run_all_validations()
    if not success:
        sys.exit(1)
    return success


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Validate ML derived artifacts")
    parser.add_argument("--derived-dir", default=None)
    args = parser.parse_args()
    validate_artifacts(args.derived_dir)
