"""Freeze leakage-safe, time-forward hard-positive and evaluation cohorts.

The policy is deliberately fixed in a tracked JSON file before model training.
Raw threat-feed snapshots and row-level outputs remain under ``data/derived``;
the tracked public manifest contains only provenance, checksums, and counts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping

import pandas as pd

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from src.build_features import FeatureExtractor, SnapshotStore
from src.canonicalize import canonicalize_domain
from src.training_data import (
    _evaluation_group,
    load_evaluation_group_policy,
    load_frozen_challenge,
    load_frozen_evaluation,
    resolve_ml_path,
)


def compute_file_sha256(path: str | os.PathLike[str]) -> str:
    hasher = hashlib.sha256()
    with open(path, "rb") as handle:
        while chunk := handle.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def _require_sha256(path: Path, expected: str, label: str) -> None:
    actual = compute_file_sha256(path)
    if actual != expected.lower():
        raise ValueError(
            f"{label} SHA-256 mismatch: expected {expected.lower()}, got {actual}"
        )


def _load_baseline_source_metadata(config: Mapping[str, Any]) -> Dict[str, Any]:
    manifest_path = resolve_ml_path(str(config["data_manifest"]))
    with open(manifest_path, "r", encoding="utf-8") as handle:
        manifest = json.load(handle)
    logical_name = str(config["phishtank_logical_name"])
    matches = [
        entry
        for entry in manifest.get("raw_sources", [])
        if entry.get("logical_name") == logical_name
    ]
    if len(matches) != 1:
        raise ValueError(
            f"data manifest must contain exactly one source named {logical_name!r}"
        )
    return {
        "manifest_path": str(manifest_path.relative_to(BASE_DIR)).replace("\\", "/"),
        "manifest_sha256": compute_file_sha256(manifest_path),
        "logical_name": logical_name,
        "source_sha256": str(matches[0]["sha256"]),
        "retrieved_at": str(matches[0]["retrieved_at"]),
    }


def _partition_groups(partitions_dir: Path, roots: set[str]) -> set[str]:
    groups: set[str] = set()
    root_values = tuple(sorted(roots, key=lambda value: (-len(value), value)))
    root_suffixes = tuple(f".{root}" for root in root_values)
    for split in ("train", "val", "cal", "test"):
        path = partitions_dir / f"{split}.parquet"
        if not path.exists():
            raise FileNotFoundError(f"source partition missing: {path}")
        frame = pd.read_parquet(
            path, columns=["domain_ascii", "registrable_domain"]
        )
        domains = frame["domain_ascii"].astype(str)
        shared_mask = domains.isin(root_values) | domains.str.endswith(root_suffixes)
        groups.update(
            frame.loc[~shared_mask, "registrable_domain"].astype(str).tolist()
        )
        # Tenant-aware grouping is needed only for the small shared-hosting
        # subset. Ordinary registrable groups can be collected vectorially.
        for row in frame.loc[
            shared_mask, ["domain_ascii", "registrable_domain"]
        ].itertuples(index=False):
            group, _ = _evaluation_group(
                str(row.domain_ascii), str(row.registrable_domain), roots
            )
            if group:
                groups.add(group)
    return groups


def _canonical_rows(
    values: Iterable[Mapping[str, Any]], roots: set[str]
) -> list[Dict[str, Any]]:
    rows: list[Dict[str, Any]] = []
    for value in values:
        canonical = canonicalize_domain(str(value["url"]))
        if not canonical.is_valid or not canonical.registrable_domain:
            continue
        group, shared_root = _evaluation_group(
            canonical.domain_ascii, canonical.registrable_domain, roots
        )
        if not group:
            continue
        rows.append(
            {
                **dict(value),
                "domain": canonical.domain_ascii,
                "domain_ascii": canonical.domain_ascii,
                "registrable_domain": canonical.registrable_domain,
                "evaluation_group": group,
                "shared_hosting_root": shared_root or "",
            }
        )
    return rows


def _ordinary_looking_mask(
    frame: pd.DataFrame,
    feature_contract_path: Path,
) -> pd.Series:
    with open(feature_contract_path, "r", encoding="utf-8") as handle:
        contract = json.load(handle)
    store = SnapshotStore(snapshot_policy=contract.get("snapshot_policy", {}))
    extractor = FeatureExtractor(snapshot_store=store)
    selected: list[bool] = []
    for domain in frame["domain_ascii"].astype(str):
        features = extractor.extract_features(domain)
        selected.append(
            features["tld_risk_score"] == 0.0
            and features["phishing_keyword_count"] == 0
            and features["is_shared_hosting"] == 0
            and features["is_punycode"] == 0
            and features["has_mixed_script"] == 0
            and features["is_ip_like"] == 0
            and features["has_brand_homoglyph"] == 0
            and features["has_brand_in_main_label"] == 0
            and features["has_brand_in_subdomain"] == 0
        )
    return pd.Series(selected, index=frame.index, dtype=bool)


def _dedupe_groups(frame: pd.DataFrame, order: list[str]) -> pd.DataFrame:
    if frame.empty:
        return frame.copy()
    return (
        frame.sort_values(order)
        .drop_duplicates(subset=["evaluation_group"], keep="first")
        .reset_index(drop=True)
    )


def _training_rows(frame: pd.DataFrame) -> pd.DataFrame:
    result = pd.DataFrame(
        {
            "domain": frame["domain_ascii"],
            "label": 1,
            "domain_ascii": frame["domain_ascii"],
            "registrable_domain": frame["registrable_domain"],
            "lexical_verdict": "",
            "lexical_score": 0,
            "is_ml_candidate": False,
            "reasons": "",
            "source": "phishtank_time_forward",
            "impersonated_org": frame["target"].fillna("").astype(str),
            "impersonated_org_category": "",
            "detected_date": frame["verification_time"].astype(str),
            "partition": "train",
            "evaluation_group": frame["evaluation_group"],
            "source_record_id": frame["source_record_id"].astype(str),
            "verification_time": frame["verification_time"].astype(str),
        }
    )
    return result


def _write_parquet(frame: pd.DataFrame, path: Path) -> Dict[str, Any]:
    path.parent.mkdir(parents=True, exist_ok=True)
    frame.to_parquet(path, index=False)
    return {
        "path": str(path.relative_to(BASE_DIR)).replace("\\", "/"),
        "rows": len(frame),
        "sha256": compute_file_sha256(path),
    }


def build_snapshot(config_path: str | os.PathLike[str]) -> Dict[str, Any]:
    config_file = Path(config_path).resolve()
    with open(config_file, "r", encoding="utf-8") as handle:
        config = json.load(handle)

    collection = config["collection"]
    baseline_cfg = config["baseline"]
    output_cfg = config["outputs"]
    phishtank_path = resolve_ml_path(collection["phishtank_current"]["path"])
    openphish_path = resolve_ml_path(collection["openphish_current"]["path"])
    _require_sha256(
        phishtank_path,
        str(collection["phishtank_current"]["sha256"]),
        "PhishTank snapshot",
    )
    _require_sha256(
        openphish_path,
        str(collection["openphish_current"]["sha256"]),
        "OpenPhish snapshot",
    )

    group_policy = load_evaluation_group_policy(
        baseline_cfg["evaluation_group_policy"]
    )
    roots = set(group_policy["roots"])
    frozen_challenge = load_frozen_challenge(
        resolve_ml_path(baseline_cfg["frozen_challenge_labels"])
    )
    frozen_evaluation = load_frozen_evaluation(
        resolve_ml_path(baseline_cfg["frozen_evaluation_labels"]), roots
    )
    frozen_groups = set(frozen_challenge["groups"]) | set(
        frozen_evaluation["groups"]
    )
    baseline_groups = _partition_groups(
        resolve_ml_path(baseline_cfg["source_partitions_dir"]), roots
    )
    excluded_groups = baseline_groups | frozen_groups

    phishtank_raw = pd.read_csv(phishtank_path, keep_default_na=False)
    required_phishtank = {
        "phish_id",
        "url",
        "verification_time",
        "verified",
        "online",
        "target",
    }
    missing = sorted(required_phishtank - set(phishtank_raw.columns))
    if missing:
        raise ValueError(f"PhishTank snapshot missing columns: {missing}")
    eligible_raw = phishtank_raw[
        phishtank_raw["verified"].astype(str).str.lower().eq("yes")
        & phishtank_raw["online"].astype(str).str.lower().eq("yes")
    ].copy()
    eligible_raw["source_record_id"] = eligible_raw["phish_id"].astype(str)
    phishtank_rows = pd.DataFrame(
        _canonical_rows(eligible_raw.to_dict(orient="records"), roots)
    )
    if phishtank_rows.empty:
        raise ValueError("PhishTank snapshot produced no valid domains")
    phishtank_rows["verification_time"] = pd.to_datetime(
        phishtank_rows["verification_time"], utc=True, errors="raise"
    )
    windows = config["windows"]
    verified_after = pd.Timestamp(windows["baseline_verified_through"])
    adaptation_before = pd.Timestamp(windows["adaptation_before"])
    development_before = pd.Timestamp(windows["development_before"])
    if not verified_after < adaptation_before < development_before:
        raise ValueError("time-forward windows must be strictly increasing")
    # Only the post-baseline adaptation/development window needs expensive
    # feature filtering. All current PhishTank groups are still retained for
    # source-disjoint OpenPhish exclusion below.
    phishtank_rows["ordinary_looking"] = False
    forward_window_mask = (
        (phishtank_rows["verification_time"] > verified_after)
        & (phishtank_rows["verification_time"] < development_before)
    )
    phishtank_rows.loc[forward_window_mask, "ordinary_looking"] = (
        _ordinary_looking_mask(
            phishtank_rows.loc[forward_window_mask],
            resolve_ml_path(config["hard_positive_policy"]["feature_contract"]),
        )
    )

    common_mask = (
        phishtank_rows["ordinary_looking"]
        & ~phishtank_rows["evaluation_group"].isin(excluded_groups)
    )
    adaptation = _dedupe_groups(
        phishtank_rows[
            common_mask
            & (phishtank_rows["verification_time"] > verified_after)
            & (phishtank_rows["verification_time"] < adaptation_before)
        ],
        ["verification_time", "domain_ascii"],
    )
    development = _dedupe_groups(
        phishtank_rows[
            common_mask
            & (phishtank_rows["verification_time"] >= adaptation_before)
            & (phishtank_rows["verification_time"] < development_before)
            & ~phishtank_rows["evaluation_group"].isin(
                set(adaptation["evaluation_group"])
            )
        ],
        ["verification_time", "domain_ascii"],
    )

    with open(openphish_path, "r", encoding="utf-8", errors="strict") as handle:
        openphish_values = [
            {"url": line.strip(), "source_record_id": str(index + 1)}
            for index, line in enumerate(handle)
            if line.strip()
        ]
    openphish_rows = pd.DataFrame(_canonical_rows(openphish_values, roots))
    if openphish_rows.empty:
        raise ValueError("OpenPhish snapshot produced no valid domains")
    all_phishtank_groups = set(phishtank_rows["evaluation_group"])
    holdout = _dedupe_groups(
        openphish_rows[
            ~openphish_rows["evaluation_group"].isin(
                excluded_groups | all_phishtank_groups
            )
        ],
        ["domain_ascii"],
    )
    holdout["ordinary_looking"] = _ordinary_looking_mask(
        holdout,
        resolve_ml_path(config["hard_positive_policy"]["feature_contract"]),
    )
    holdout["label"] = 1
    holdout["source"] = "openphish_time_forward_source_disjoint"

    adaptation_training = _training_rows(adaptation)
    development_eval = development[
        [
            "domain_ascii",
            "registrable_domain",
            "evaluation_group",
            "source_record_id",
            "verification_time",
            "ordinary_looking",
        ]
    ].copy()
    development_eval["label"] = 1
    development_eval["source"] = "phishtank_time_forward_development"
    holdout_eval = holdout[
        [
            "domain_ascii",
            "registrable_domain",
            "evaluation_group",
            "source_record_id",
            "ordinary_looking",
            "label",
            "source",
        ]
    ].copy()

    derived_dir = resolve_ml_path(output_cfg["derived_dir"])
    outputs = {
        "adaptation": _write_parquet(
            adaptation_training, derived_dir / "adaptation.parquet"
        ),
        "development": _write_parquet(
            development_eval, derived_dir / "development.parquet"
        ),
        "openphish_holdout": _write_parquet(
            holdout_eval, derived_dir / "openphish-holdout.parquet"
        ),
    }
    if (
        set(adaptation_training["evaluation_group"])
        & set(development_eval["evaluation_group"])
        or set(adaptation_training["evaluation_group"])
        & set(holdout_eval["evaluation_group"])
        or set(development_eval["evaluation_group"])
        & set(holdout_eval["evaluation_group"])
    ):
        raise ValueError("time-forward cohorts are not group-disjoint")

    baseline_meta = _load_baseline_source_metadata(baseline_cfg)
    manifest = {
        "schema_version": 1,
        "protocol_path": str(config_file.relative_to(BASE_DIR)).replace("\\", "/"),
        "protocol_sha256": compute_file_sha256(config_file),
        "collected_at": collection["collected_at"],
        "inputs": {
            "baseline": baseline_meta,
            "phishtank_current": {
                "source_url": collection["phishtank_current"]["source_url"],
                "sha256": compute_file_sha256(phishtank_path),
                "bytes": phishtank_path.stat().st_size,
                "raw_rows": len(phishtank_raw),
                "valid_online_verified_rows": len(eligible_raw),
                "canonical_rows": len(phishtank_rows),
                "unique_evaluation_groups": int(
                    phishtank_rows["evaluation_group"].nunique()
                ),
            },
            "openphish_current": {
                "source_url": collection["openphish_current"]["source_url"],
                "sha256": compute_file_sha256(openphish_path),
                "bytes": openphish_path.stat().st_size,
                "raw_rows": len(openphish_values),
                "canonical_rows": len(openphish_rows),
                "unique_evaluation_groups": int(
                    openphish_rows["evaluation_group"].nunique()
                ),
            },
        },
        "exclusions": {
            "baseline_partition_groups": len(baseline_groups),
            "frozen_groups": len(frozen_groups),
            "post_exclusion_overlap": 0,
        },
        "windows": windows,
        "hard_positive_policy": config["hard_positive_policy"],
        "holdout_policy": config["holdout_policy"],
        "candidate_selection": config["candidate_selection"],
        "outputs": outputs,
        "counts": {
            "adaptation_rows": len(adaptation_training),
            "development_rows": len(development_eval),
            "openphish_holdout_rows": len(holdout_eval),
            "openphish_holdout_ordinary_rows": int(
                holdout_eval["ordinary_looking"].sum()
            ),
            "cross_cohort_group_overlap": 0,
        },
    }
    public_manifest = resolve_ml_path(output_cfg["public_manifest"])
    public_manifest.parent.mkdir(parents=True, exist_ok=True)
    with open(public_manifest, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(manifest, handle, indent=2, ensure_ascii=False)
        handle.write("\n")
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Freeze time-forward hard-positive and holdout cohorts"
    )
    parser.add_argument(
        "--config",
        default=str(BASE_DIR / "configs" / "v4-time-forward-protocol.json"),
    )
    args = parser.parse_args()
    result = build_snapshot(args.config)
    print(json.dumps(result["counts"], indent=2))
