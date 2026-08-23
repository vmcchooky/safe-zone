"""Build leakage-safe training partitions and a weighted hard-negative cohort.

The hard-negative cohort is a benign proxy selected from checksum-pinned local
evidence.  It is intentionally distinct from the human-reviewed frozen
challenge set, which is excluded by registrable-domain group from every model
partition.
"""

from __future__ import annotations

import csv
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping
from urllib.parse import urlsplit

import pandas as pd

BASE_DIR = Path(__file__).resolve().parent.parent

from src.canonicalize import canonicalize_domain


def compute_file_sha256(path: str | os.PathLike[str]) -> str:
    hasher = hashlib.sha256()
    with open(path, "rb") as handle:
        while chunk := handle.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def resolve_ml_path(value: str | os.PathLike[str]) -> Path:
    path = Path(value)
    if not path.is_absolute():
        path = BASE_DIR / path
    return path.resolve()


def _load_pinned_source(
    data_manifest_path: Path, logical_name: str, source_path: Path
) -> Dict[str, Any]:
    with open(data_manifest_path, "r", encoding="utf-8") as handle:
        manifest = json.load(handle)
    matches = [
        entry
        for entry in manifest.get("raw_sources", [])
        if entry.get("logical_name") == logical_name
    ]
    if len(matches) != 1:
        raise ValueError(
            f"data manifest must contain exactly one raw source named {logical_name!r}"
        )
    source = matches[0]
    actual_size = source_path.stat().st_size
    actual_sha = compute_file_sha256(source_path)
    if actual_size != int(source.get("bytes", -1)):
        raise ValueError(
            f"source byte-size mismatch for {logical_name}: "
            f"expected {source.get('bytes')}, got {actual_size}"
        )
    if actual_sha.lower() != str(source.get("sha256", "")).lower():
        raise ValueError(f"source SHA-256 mismatch for {logical_name}")
    return {
        "logical_name": logical_name,
        "path": str(source_path),
        "sha256": actual_sha,
        "bytes": actual_size,
        "retrieved_at": source.get("retrieved_at", ""),
        "trust_tier": source.get("trust_tier", ""),
        "terms_review_id": source.get("terms_review_id", ""),
        "data_manifest_sha256": compute_file_sha256(data_manifest_path),
    }


def _approved_evidence_host(url_value: str, allowed_hosts: set[str]) -> str | None:
    try:
        parsed = urlsplit(url_value.strip())
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return None
        if parsed.username or parsed.password or parsed.port is not None:
            return None
    except ValueError:
        return None
    host = parsed.hostname.rstrip(".").lower()
    return host if host in allowed_hosts else None


def load_frozen_challenge(labels_path: Path) -> Dict[str, Any]:
    domains: set[str] = set()
    groups: set[str] = set()
    with open(labels_path, "r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        required = {"domain", "human_label", "review_outcome"}
        if not required.issubset(reader.fieldnames or []):
            raise ValueError(
                f"frozen challenge labels are missing columns: "
                f"{sorted(required - set(reader.fieldnames or []))}"
            )
        for row in reader:
            if row["human_label"].strip().lower() != "benign":
                raise ValueError("frozen challenge contains a non-benign human label")
            if row["review_outcome"].strip().lower() != "false_positive":
                raise ValueError("frozen challenge contains a non-false-positive outcome")
            canonical = canonicalize_domain(row["domain"])
            if not canonical.is_valid or not canonical.registrable_domain:
                raise ValueError(f"invalid frozen challenge domain: {row['domain']!r}")
            domains.add(canonical.domain_ascii)
            groups.add(canonical.registrable_domain)
    if not domains:
        raise ValueError("frozen challenge is empty")
    return {
        "labels_path": str(labels_path),
        "labels_sha256": compute_file_sha256(labels_path),
        "domains": domains,
        "groups": groups,
    }


def _iter_evidence_rows(
    source_path: Path,
    allowed_hosts: set[str],
) -> Iterable[Dict[str, str]]:
    with open(source_path, "r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        required = {"domain", "detail_url"}
        if not required.issubset(reader.fieldnames or []):
            raise ValueError(
                f"hard-negative source is missing columns: "
                f"{sorted(required - set(reader.fieldnames or []))}"
            )
        for row in reader:
            host = _approved_evidence_host(row.get("detail_url", ""), allowed_hosts)
            if host is None:
                continue
            canonical = canonicalize_domain(row.get("domain", ""))
            if not canonical.is_valid or not canonical.registrable_domain:
                continue
            yield {
                "domain_ascii": canonical.domain_ascii,
                "registrable_domain": canonical.registrable_domain,
                "evidence_host": host,
                "evidence_reference": row.get("detail_url", "").strip(),
            }


def select_hard_negatives(
    train_df: pd.DataFrame,
    policy: Mapping[str, Any],
    frozen: Mapping[str, Any],
) -> tuple[pd.DataFrame, Dict[str, Any]]:
    source_path = resolve_ml_path(str(policy["source_csv"]))
    data_manifest_path = resolve_ml_path(str(policy["data_manifest"]))
    logical_name = str(policy["logical_name"])
    source_meta = _load_pinned_source(data_manifest_path, logical_name, source_path)

    weight = float(policy.get("weight", 3.0))
    if not 1.0 < weight <= 10.0:
        raise ValueError("hard-negative weight must be in (1, 10]")
    max_samples = int(policy.get("max_samples", 300))
    if max_samples <= 0:
        raise ValueError("hard-negative max_samples must be positive")
    allowed_hosts = {
        str(host).strip().rstrip(".").lower()
        for host in policy.get("allowed_evidence_hosts", [])
        if str(host).strip()
    }
    if not allowed_hosts:
        raise ValueError("hard-negative allowed_evidence_hosts cannot be empty")

    eligible = train_df[
        (train_df["label"] == 0)
        & (train_df["is_ml_candidate"] == True)  # noqa: E712
        & (train_df["source"] == "vietnam_whitelist")
    ].copy()
    eligible = eligible[
        ~eligible["registrable_domain"].isin(set(frozen["groups"]))
    ]
    eligible_by_domain = {
        row.domain_ascii: row
        for row in eligible[
            ["domain_ascii", "registrable_domain", "lexical_score", "reasons"]
        ].itertuples(index=False)
    }

    selected_by_domain: Dict[str, Dict[str, Any]] = {}
    evidence_rows = 0
    for evidence in _iter_evidence_rows(source_path, allowed_hosts):
        evidence_rows += 1
        domain = evidence["domain_ascii"]
        training_row = eligible_by_domain.get(domain)
        if training_row is None or domain in selected_by_domain:
            continue
        selected_by_domain[domain] = {
            **evidence,
            "label": 0,
            "label_kind": "benign_proxy",
            "training_weight": weight,
            "lexical_score": int(training_row.lexical_score),
            "lexical_reasons": str(training_row.reasons),
        }

    ranked = sorted(
        selected_by_domain.values(),
        key=lambda row: (
            -int(row["lexical_score"]),
            -len(str(row["domain_ascii"])),
            str(row["domain_ascii"]),
        ),
    )[:max_samples]
    selected = pd.DataFrame(
        ranked,
        columns=[
            "domain_ascii",
            "registrable_domain",
            "label",
            "label_kind",
            "training_weight",
            "lexical_score",
            "lexical_reasons",
            "evidence_host",
            "evidence_reference",
        ],
    )
    if selected.empty:
        raise ValueError("hard-negative selection produced no eligible training rows")
    if set(selected["registrable_domain"]) & set(frozen["groups"]):
        raise ValueError("frozen challenge leaked into the hard-negative cohort")

    metadata = {
        "source": source_meta,
        "selection_policy": {
            "label_kind": "benign_proxy",
            "required_train_label": 0,
            "required_train_source": "vietnam_whitelist",
            "required_ml_candidate": True,
            "allowed_evidence_hosts": sorted(allowed_hosts),
            "weight": weight,
            "max_samples": max_samples,
            "ranking": "lexical_score_desc,domain_length_desc,domain_ascii_asc",
        },
        "counts": {
            "approved_evidence_rows": evidence_rows,
            "eligible_train_rows": len(eligible),
            "matched_unique_rows": len(selected_by_domain),
            "selected_rows": len(selected),
        },
    }
    return selected, metadata


def prepare_training_partitions(
    source_partitions_dir: str | os.PathLike[str],
    output_partitions_dir: str | os.PathLike[str],
    policy: Mapping[str, Any],
    output_dir: str | os.PathLike[str],
) -> Dict[str, Any]:
    source_dir = resolve_ml_path(source_partitions_dir)
    target_dir = Path(output_partitions_dir).resolve()
    artifacts_dir = Path(output_dir).resolve()
    target_dir.mkdir(parents=True, exist_ok=True)
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    frozen = load_frozen_challenge(
        resolve_ml_path(str(policy["frozen_challenge_labels"]))
    )
    frames: Dict[str, pd.DataFrame] = {}
    exclusion_counts: Dict[str, int] = {}
    for split in ("train", "val", "cal", "test"):
        source_path = source_dir / f"{split}.parquet"
        if not source_path.exists():
            raise FileNotFoundError(f"source partition missing: {source_path}")
        frame = pd.read_parquet(source_path)
        excluded = frame["registrable_domain"].isin(set(frozen["groups"]))
        exclusion_counts[split] = int(excluded.sum())
        frame = frame.loc[~excluded].copy()
        frame["sample_weight"] = 1.0
        frame["label_provenance"] = "original_partition"
        frame["training_role"] = "standard"
        frames[split] = frame

    hard_negative_df, hard_negative_meta = select_hard_negatives(
        frames["train"], policy["hard_negative"], frozen
    )
    weights = hard_negative_df.set_index("domain_ascii")["training_weight"]
    hard_mask = frames["train"]["domain_ascii"].isin(weights.index)
    frames["train"].loc[hard_mask, "sample_weight"] = frames["train"].loc[
        hard_mask, "domain_ascii"
    ].map(weights)
    frames["train"].loc[hard_mask, "label_provenance"] = "benign_proxy"
    frames["train"].loc[hard_mask, "training_role"] = "weighted_hard_negative"
    if int(hard_mask.sum()) != len(hard_negative_df):
        raise ValueError("hard-negative weights did not map one-to-one to training rows")

    groups = {
        split: set(frame["registrable_domain"])
        for split, frame in frames.items()
    }
    overlap = 0
    split_names = list(groups)
    for index, left in enumerate(split_names):
        for right in split_names[index + 1 :]:
            overlap += len(groups[left] & groups[right])
    if overlap != 0:
        raise ValueError(f"group leakage detected after challenge exclusion: {overlap}")
    for split, frame in frames.items():
        if set(frame["registrable_domain"]) & set(frozen["groups"]):
            raise ValueError(f"frozen challenge group leaked into {split}")
        frame.to_parquet(target_dir / f"{split}.parquet", index=False)

    hard_negative_path = artifacts_dir / "hard_negatives.csv"
    hard_negative_df.to_csv(hard_negative_path, index=False, lineterminator="\n")
    partition_files = {
        split: {
            "path": str(target_dir / f"{split}.parquet"),
            "rows": len(frame),
            "sha256": compute_file_sha256(target_dir / f"{split}.parquet"),
        }
        for split, frame in frames.items()
    }
    manifest = {
        "schema_version": 1,
        "frozen_challenge": {
            "labels_path": frozen["labels_path"],
            "labels_sha256": frozen["labels_sha256"],
            "domain_count": len(frozen["domains"]),
            "registrable_group_count": len(frozen["groups"]),
            "excluded_rows_by_partition": exclusion_counts,
            "overlap_after_exclusion": 0,
        },
        "hard_negative": {
            **hard_negative_meta,
            "csv_path": str(hard_negative_path),
            "csv_sha256": compute_file_sha256(hard_negative_path),
        },
        "partition_files": partition_files,
    }
    manifest_path = artifacts_dir / "training_data_manifest.json"
    with open(manifest_path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(manifest, handle, indent=2, ensure_ascii=False)
        handle.write("\n")
    manifest["manifest_path"] = str(manifest_path)
    manifest["manifest_sha256"] = compute_file_sha256(manifest_path)
    return manifest
