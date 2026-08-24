"""Freeze v5 development and source-disjoint final holdout cohorts."""

from __future__ import annotations

import argparse
from concurrent.futures import ProcessPoolExecutor
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

import pandas as pd

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from src.build_time_forward_snapshot import (
    _canonical_rows,
    _dedupe_groups,
    _ordinary_looking_mask,
    _partition_groups,
    _write_parquet,
    compute_file_sha256,
)
from src.training_data import (
    load_evaluation_group_policy,
    load_frozen_challenge,
    load_frozen_evaluation,
    resolve_ml_path,
)


def _load_json(path: Path) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _ordinary_chunk(domains: list[str], contract_path: str) -> list[bool]:
    frame = pd.DataFrame({"domain_ascii": domains})
    return _ordinary_looking_mask(frame, Path(contract_path)).tolist()


def _ordinary_mask_parallel(frame: pd.DataFrame, contract_path: Path) -> pd.Series:
    domains = frame["domain_ascii"].astype(str).tolist()
    if len(domains) < 2000:
        return _ordinary_looking_mask(frame, contract_path)
    chunk_size = 5000
    chunks = [domains[index : index + chunk_size] for index in range(0, len(domains), chunk_size)]
    values: list[bool] = []
    with ProcessPoolExecutor(max_workers=min(4, os.cpu_count() or 1)) as executor:
        for result in executor.map(
            _ordinary_chunk,
            chunks,
            [str(contract_path)] * len(chunks),
        ):
            values.extend(result)
    return pd.Series(values, index=frame.index, dtype=bool)


def _require_hash(path: Path, expected: str, label: str) -> None:
    actual = compute_file_sha256(path)
    if actual != expected.lower():
        raise ValueError(f"{label} SHA-256 mismatch: expected {expected}, got {actual}")


def _load_prior_development_groups() -> tuple[set[str], Dict[str, Any]]:
    manifest_path = BASE_DIR / "experiments" / "v4-time-forward-snapshot.json"
    manifest = _load_json(manifest_path)
    meta = manifest["outputs"]["development"]
    path = resolve_ml_path(str(meta["path"]))
    _require_hash(path, str(meta["sha256"]), "prior development cohort")
    frame = pd.read_parquet(path, columns=["evaluation_group"])
    if len(frame) != int(meta["rows"]):
        raise ValueError("prior development row count mismatch")
    return set(frame["evaluation_group"].astype(str)), {
        "manifest_sha256": compute_file_sha256(manifest_path),
        "path": str(meta["path"]),
        "sha256": str(meta["sha256"]),
        "rows": len(frame),
    }


def build_snapshot(protocol_path: str | os.PathLike[str]) -> Dict[str, Any]:
    protocol_file = Path(protocol_path).resolve()
    protocol = _load_json(protocol_file)
    baseline = protocol["baseline"]
    sources = protocol["cohort_sources"]
    policy = protocol["cohort_policy"]

    group_policy = load_evaluation_group_policy(baseline["evaluation_group_policy"])
    roots = set(group_policy["roots"])
    frozen_challenge = load_frozen_challenge(
        resolve_ml_path(baseline["frozen_challenge_labels"])
    )
    frozen_evaluation = load_frozen_evaluation(
        resolve_ml_path(baseline["frozen_evaluation_labels"]), roots
    )
    frozen_groups = set(frozen_challenge["groups"]) | set(frozen_evaluation["groups"])

    partition_paths = {
        name: resolve_ml_path(str(meta["path"]))
        for name, meta in baseline["partitions"].items()
    }
    for name, path in partition_paths.items():
        _require_hash(path, baseline["partitions"][name]["sha256"], f"{name} partition")
    partition_groups = _partition_groups(partition_paths["train"].parent, roots)
    prior_development_groups, prior_meta = _load_prior_development_groups()
    excluded_groups = partition_groups | frozen_groups | prior_development_groups

    development_source = sources["development"]
    phishtank_path = resolve_ml_path(development_source["path"])
    _require_hash(phishtank_path, development_source["sha256"], "PhishTank source")
    phishtank_raw = pd.read_csv(phishtank_path, keep_default_na=False)
    required = {"phish_id", "url", "verification_time", "verified", "online", "target"}
    missing = sorted(required - set(phishtank_raw.columns))
    if missing:
        raise ValueError(f"PhishTank snapshot missing columns: {missing}")
    eligible = phishtank_raw[
        phishtank_raw["verified"].astype(str).str.lower().eq("yes")
        & phishtank_raw["online"].astype(str).str.lower().eq("yes")
    ].copy()
    eligible["source_record_id"] = eligible["phish_id"].astype(str)
    phishtank = pd.DataFrame(_canonical_rows(eligible.to_dict(orient="records"), roots))
    phishtank["verification_time"] = pd.to_datetime(
        phishtank["verification_time"], utc=True, errors="raise"
    )
    after = pd.Timestamp(development_source["required_verification_time_gte"])
    before = pd.Timestamp(development_source["required_verification_time_lt"])
    development_window = phishtank[
        (phishtank["verification_time"] >= after)
        & (phishtank["verification_time"] < before)
        & ~phishtank["evaluation_group"].isin(excluded_groups)
    ].copy()
    ordinary_contract = resolve_ml_path(policy["ordinary_looking_contract"])
    development_window["ordinary_looking"] = _ordinary_mask_parallel(
        development_window,
        ordinary_contract,
    )
    development = _dedupe_groups(
        development_window[development_window["ordinary_looking"]],
        ["verification_time", "domain_ascii"],
    )
    development_output = development[
        [
            "domain_ascii",
            "registrable_domain",
            "evaluation_group",
            "source_record_id",
            "verification_time",
            "ordinary_looking",
        ]
    ].copy()
    development_output["label"] = 1
    development_output["source"] = "phishtank_v5_development"

    holdout_source = sources["final_holdout"]
    holdout_path = resolve_ml_path(holdout_source["path"])
    with open(holdout_path, "r", encoding="utf-8", errors="strict") as handle:
        holdout_values = [
            {"url": line.strip(), "source_record_id": str(index + 1)}
            for index, line in enumerate(handle)
            if line.strip() and not line.lstrip().startswith("#")
        ]
    holdout_raw_hash = compute_file_sha256(holdout_path)
    holdout = pd.DataFrame(_canonical_rows(holdout_values, roots))
    if holdout.empty:
        raise ValueError("PhishDestroy source produced no canonical domains")
    all_phishtank_groups = set(phishtank["evaluation_group"].astype(str))
    holdout = _dedupe_groups(
        holdout[
            ~holdout["evaluation_group"].isin(excluded_groups | all_phishtank_groups)
        ],
        ["domain_ascii"],
    )
    holdout["ordinary_looking"] = _ordinary_mask_parallel(
        holdout,
        ordinary_contract,
    )
    holdout_output = holdout[
        [
            "domain_ascii",
            "registrable_domain",
            "evaluation_group",
            "source_record_id",
            "ordinary_looking",
        ]
    ].copy()
    holdout_output["label"] = 1
    holdout_output["source"] = "phishdestroy_v5_source_disjoint_holdout"

    if set(development_output["evaluation_group"]) & set(holdout_output["evaluation_group"]):
        raise ValueError("v5 development and holdout groups overlap")
    if set(development_output["evaluation_group"]) & excluded_groups:
        raise ValueError("v5 development overlaps excluded groups")
    if set(holdout_output["evaluation_group"]) & (excluded_groups | all_phishtank_groups):
        raise ValueError("v5 holdout overlaps excluded groups")

    derived_dir = resolve_ml_path(protocol["outputs"]["derived_dir"])
    outputs = {
        "development": _write_parquet(development_output, derived_dir / "development.parquet"),
        "phishdestroy_holdout": _write_parquet(
            holdout_output, derived_dir / "phishdestroy-holdout.parquet"
        ),
    }
    manifest = {
        "schema_version": 1,
        "protocol_path": str(protocol_file.relative_to(BASE_DIR)).replace("\\", "/"),
        "protocol_sha256": compute_file_sha256(protocol_file),
        "collected_at": datetime.fromtimestamp(
            holdout_path.stat().st_mtime, tz=timezone.utc
        ).isoformat().replace("+00:00", "Z"),
        "inputs": {
            "phishtank": {
                "path": str(development_source["path"]),
                "sha256": compute_file_sha256(phishtank_path),
                "raw_rows": len(phishtank_raw),
                "canonical_rows": len(phishtank),
            },
            "phishdestroy": {
                "path": str(holdout_source["path"]),
                "source_url": str(holdout_source["source_url"]),
                "sha256": holdout_raw_hash,
                "bytes": holdout_path.stat().st_size,
                "raw_rows": len(holdout_values),
                "source_disjoint_rows": len(holdout_output),
            },
            "prior_development": prior_meta,
        },
        "exclusions": {
            "baseline_partition_groups": len(partition_groups),
            "frozen_groups": len(frozen_groups),
            "prior_development_groups": len(prior_development_groups),
            "current_phishtank_groups": len(all_phishtank_groups),
            "cross_cohort_group_overlap": 0,
        },
        "cohort_policy": policy,
        "outputs": outputs,
        "counts": {
            "development_window_rows_before_ordinary_filter": len(development_window),
            "development_rows": len(development_output),
            "holdout_rows": len(holdout_output),
            "holdout_ordinary_rows": int(holdout_output["ordinary_looking"].sum()),
        },
    }
    manifest_path = resolve_ml_path(protocol["outputs"]["snapshot_manifest"])
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    with open(manifest_path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(manifest, handle, indent=2)
        handle.write("\n")
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Freeze v5 char-linear cohorts")
    parser.add_argument(
        "--protocol",
        default=str(BASE_DIR / "configs" / "v5-char-linear-ensemble-protocol.json"),
    )
    args = parser.parse_args()
    result = build_snapshot(args.protocol)
    print(json.dumps(result["counts"], indent=2))
