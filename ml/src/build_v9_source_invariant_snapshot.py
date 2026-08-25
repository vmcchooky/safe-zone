"""Freeze the fresh development cohort for the v9 source-invariant study."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict

import pandas as pd

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from src.build_time_forward_snapshot import _partition_groups, compute_file_sha256
from src.build_v8_dns_context_snapshot import (
    _canonical_rows,
    _stable_select,
    _write_parquet,
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


def _require_hash(path: Path, expected: str, label: str) -> None:
    actual = compute_file_sha256(path)
    if actual != expected.lower():
        raise ValueError(f"{label} SHA-256 mismatch: expected {expected}, got {actual}")


def build(protocol_path: str | os.PathLike[str]) -> Dict[str, Any]:
    protocol_file = Path(protocol_path).resolve()
    protocol = _load_json(protocol_file)
    snapshot = protocol["development_snapshot"]
    seed = int(protocol["seed"])

    group_policy = load_evaluation_group_policy(snapshot["group_policy"])
    if group_policy["snapshot_sha256"] != snapshot["group_policy"][
        "shared_hosting_snapshot_sha256"
    ]:
        raise ValueError("shared-hosting group policy mismatch")
    roots = set(group_policy["roots"])

    partition_paths = {}
    for name, meta in protocol["candidate_data"]["partitions"].items():
        path = resolve_ml_path(meta["path"])
        _require_hash(path, meta["sha256"], f"{name} partition")
        partition_paths[name] = path
    baseline_groups = _partition_groups(partition_paths["train"].parent, roots)

    representative = protocol["final_evidence"]["representative_labels"]
    targeted = protocol["final_evidence"]["targeted_benign_labels"]
    _require_hash(resolve_ml_path(representative["path"]), representative["sha256"], "representative labels")
    _require_hash(resolve_ml_path(targeted["path"]), targeted["sha256"], "targeted labels")
    frozen_groups = set(
        load_frozen_evaluation(resolve_ml_path(representative["path"]), roots)["groups"]
    ) | set(load_frozen_challenge(resolve_ml_path(targeted["path"]))["groups"])

    opened_groups: set[str] = set()
    opened_meta: Dict[str, Any] = {}
    for section in ("exclude_prior_opened_groups", "exclude_v8_cohorts"):
        for name, meta in snapshot[section].items():
            path = resolve_ml_path(meta["path"])
            _require_hash(path, meta["sha256"], name)
            frame = pd.read_parquet(path, columns=["evaluation_group"])
            groups = set(frame["evaluation_group"].astype(str))
            opened_groups.update(groups)
            opened_meta[name] = {"rows": len(frame), "groups": len(groups)}
    excluded_groups = baseline_groups | frozen_groups | opened_groups

    malicious_meta = snapshot["malicious_source"]
    malicious_path = resolve_ml_path(malicious_meta["path"])
    _require_hash(malicious_path, malicious_meta["sha256"], "development malicious source")
    with open(malicious_path, "r", encoding="utf-8", errors="strict") as handle:
        malicious_raw = handle.readlines()
    malicious_pool = _canonical_rows(
        malicious_raw, roots, "phishing_database_active_v9_development", 1
    )
    malicious_pool = malicious_pool[
        ~malicious_pool["evaluation_group"].isin(excluded_groups)
    ].reset_index(drop=True)
    malicious = _stable_select(
        malicious_pool, int(malicious_meta["required_rows"]), seed
    )

    benign_meta = snapshot["benign_source"]
    benign_path = resolve_ml_path(benign_meta["path"])
    _require_hash(benign_path, benign_meta["sha256"], "development benign source")
    benign_raw = pd.read_csv(
        benign_path,
        usecols=[benign_meta["required_column"]],
        keep_default_na=False,
    )
    benign_pool = _canonical_rows(
        benign_raw[benign_meta["required_column"]].astype(str),
        roots,
        "vietnam_official_trust_v9_development",
        0,
    )
    benign_pool = benign_pool[
        ~benign_pool["evaluation_group"].isin(excluded_groups)
    ].reset_index(drop=True)
    benign = _stable_select(benign_pool, int(benign_meta["required_rows"]), seed)

    development = pd.concat([benign, malicious], ignore_index=True)
    if development["evaluation_group"].duplicated().any():
        raise ValueError("v9 development contains duplicate evaluation groups")
    final_meta = protocol["fresh_final"]
    final_path = resolve_ml_path(final_meta["path"])
    _require_hash(final_path, final_meta["sha256"], "fresh final cohort")
    final_groups = set(
        pd.read_parquet(final_path, columns=["evaluation_group"])[
            "evaluation_group"
        ].astype(str)
    )
    overlap = len(set(development["evaluation_group"].astype(str)) & final_groups)
    if overlap:
        raise ValueError(f"v9 development overlaps fresh final by {overlap} groups")

    output_path = resolve_ml_path(snapshot["output"])
    output = _write_parquet(development, output_path)
    manifest = {
        "schema_version": 1,
        "protocol_sha256": compute_file_sha256(protocol_file),
        "raw_sources": {
            "malicious": {
                "path": malicious_meta["path"],
                "sha256": compute_file_sha256(malicious_path),
                "raw_lines": len(malicious_raw),
                "eligible_groups": len(malicious_pool),
            },
            "benign": {
                "path": benign_meta["path"],
                "sha256": compute_file_sha256(benign_path),
                "raw_rows": len(benign_raw),
                "eligible_groups": len(benign_pool),
            },
        },
        "exclusions": {
            "baseline_groups": len(baseline_groups),
            "frozen_groups": len(frozen_groups),
            "prior_opened_groups": len(opened_groups),
            "inputs": opened_meta,
        },
        "fresh_final_group_overlap": overlap,
        "output": output,
    }
    manifest_path = resolve_ml_path(snapshot["manifest"])
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    with open(manifest_path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(manifest, handle, indent=2)
        handle.write("\n")
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Build v9 source-invariant development snapshot")
    parser.add_argument(
        "--protocol",
        default=str(BASE_DIR / "configs" / "v9-source-invariant-round1-protocol.json"),
    )
    args = parser.parse_args()
    result = build(args.protocol)
    print(json.dumps(result["output"], indent=2))
