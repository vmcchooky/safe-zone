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


def _evaluation_group(
    domain_ascii: str, registrable_domain: str, shared_hosting_roots: set[str]
) -> tuple[str, str | None]:
    for root in sorted(shared_hosting_roots, key=lambda value: (-len(value), value)):
        suffix = "." + root
        if domain_ascii == root:
            return root, root
        if domain_ascii.endswith(suffix):
            prefix = domain_ascii[: -len(suffix)]
            tenant = prefix.rsplit(".", 1)[-1]
            if tenant:
                return tenant + suffix, root
    return registrable_domain, None


def load_frozen_evaluation(
    labels_path: Path, shared_hosting_roots: set[str]
) -> Dict[str, Any]:
    """Load every registrable group from an immutable evaluation packet.

    Evaluation rows may be benign, malicious, or unresolved.  Their labels are
    intentionally not interpreted here; every group is excluded so that later
    human adjudication cannot leak into train, validation, calibration, or test.
    """

    domains: set[str] = set()
    groups: set[str] = set()
    case_ids: set[str] = set()
    shared_groups_by_root: Dict[str, set[str]] = {}
    with open(labels_path, "r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        required = {"case_id", "domain", "human_label", "reviewer_id"}
        if not required.issubset(reader.fieldnames or []):
            raise ValueError(
                "frozen evaluation labels are missing columns: "
                f"{sorted(required - set(reader.fieldnames or []))}"
            )
        for row in reader:
            case_id = row["case_id"].strip()
            if not case_id:
                raise ValueError("frozen evaluation contains an empty case_id")
            if case_id in case_ids:
                raise ValueError(
                    f"frozen evaluation contains duplicate case_id: {case_id}"
                )
            case_ids.add(case_id)
            if not row["human_label"].strip() or not row["reviewer_id"].strip():
                raise ValueError(
                    f"frozen evaluation case {case_id} is not owner reviewed"
                )
            canonical = canonicalize_domain(row["domain"])
            if not canonical.is_valid or not canonical.registrable_domain:
                raise ValueError(
                    f"invalid frozen evaluation domain: {row['domain']!r}"
                )
            domains.add(canonical.domain_ascii)
            group, shared_root = _evaluation_group(
                canonical.domain_ascii,
                canonical.registrable_domain,
                shared_hosting_roots,
            )
            groups.add(group)
            if shared_root is not None and group != shared_root:
                shared_groups_by_root.setdefault(shared_root, set()).add(group)
    if not domains:
        raise ValueError("frozen evaluation is empty")
    return {
        "labels_path": str(labels_path),
        "labels_sha256": compute_file_sha256(labels_path),
        "case_count": len(case_ids),
        "domains": domains,
        "groups": groups,
        "shared_groups_by_root": shared_groups_by_root,
    }


def load_evaluation_group_policy(policy: Mapping[str, Any]) -> Dict[str, Any]:
    snapshot_path = resolve_ml_path(str(policy["shared_hosting_snapshot"]))
    with open(snapshot_path, "r", encoding="utf-8") as handle:
        roots = json.load(handle)
    if not isinstance(roots, list):
        raise ValueError("shared-hosting snapshot must be a list")
    extensions = [
        str(value).strip().rstrip(".").lower()
        for value in policy.get("shared_hosting_extensions", [])
        if str(value).strip()
    ]
    values = [str(value).strip().rstrip(".").lower() for value in roots]
    values.extend(extensions)
    if any(not value or "." not in value for value in values):
        raise ValueError("invalid shared-hosting root in evaluation group policy")
    roots_set = set(values)
    return {
        "roots": roots_set,
        "snapshot_path": str(snapshot_path),
        "snapshot_sha256": compute_file_sha256(snapshot_path),
        "extensions": sorted(set(extensions)),
    }


def _frozen_evaluation_mask(
    frame: pd.DataFrame, frozen_evaluation: Mapping[str, Any]
) -> pd.Series:
    shared_groups_by_root = frozen_evaluation.get("shared_groups_by_root", {})
    shared_groups = {
        group for groups in shared_groups_by_root.values() for group in groups
    }
    ordinary_groups = set(frozen_evaluation["groups"]) - shared_groups
    excluded = frame["registrable_domain"].isin(ordinary_groups)
    domains = frame["domain_ascii"].astype(str)
    for root, groups in shared_groups_by_root.items():
        suffix = "." + root
        related = domains.str.endswith(suffix)
        if not related.any():
            continue
        prefixes = domains.loc[related].str.slice(stop=-len(suffix))
        tenant_groups = prefixes.str.rsplit(".", n=1).str[-1] + suffix
        excluded.loc[related] = excluded.loc[related] | tenant_groups.isin(groups)
    return excluded


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


def load_time_forward_hard_positives(
    policy: Mapping[str, Any],
    existing_groups: set[str],
    excluded_groups: set[str],
) -> tuple[pd.DataFrame, Dict[str, Any]]:
    """Load a checksum-pinned malicious adaptation cohort.

    The row-level Parquet remains Git-ignored. Its path, row count, and digest
    must match the tracked public snapshot manifest produced before training.
    """

    source_path = resolve_ml_path(str(policy["source_parquet"]))
    manifest_path = resolve_ml_path(str(policy["public_manifest"]))
    with open(manifest_path, "r", encoding="utf-8") as handle:
        public_manifest = json.load(handle)
    output_name = str(policy.get("manifest_output", "adaptation"))
    source_meta = public_manifest.get("outputs", {}).get(output_name)
    if not isinstance(source_meta, dict):
        raise ValueError(
            f"time-forward manifest has no output named {output_name!r}"
        )
    expected_path = resolve_ml_path(str(source_meta.get("path", "")))
    if expected_path != source_path:
        raise ValueError("time-forward hard-positive path does not match manifest")
    actual_sha = compute_file_sha256(source_path)
    if actual_sha != str(source_meta.get("sha256", "")).lower():
        raise ValueError("time-forward hard-positive SHA-256 does not match manifest")

    frame = pd.read_parquet(source_path)
    required = {
        "domain",
        "label",
        "domain_ascii",
        "registrable_domain",
        "source",
        "evaluation_group",
    }
    missing = sorted(required - set(frame.columns))
    if missing:
        raise ValueError(f"time-forward hard-positive rows missing columns: {missing}")
    if len(frame) != int(source_meta.get("rows", -1)):
        raise ValueError("time-forward hard-positive row count does not match manifest")
    if frame.empty or not frame["label"].astype(int).eq(1).all():
        raise ValueError("time-forward hard positives must be non-empty and malicious")
    expected_source = str(policy.get("required_source", "phishtank_time_forward"))
    if not frame["source"].astype(str).eq(expected_source).all():
        raise ValueError("time-forward hard-positive source provenance mismatch")
    if frame["evaluation_group"].astype(str).duplicated().any():
        raise ValueError("time-forward hard-positive groups must be unique")

    groups = set(frame["evaluation_group"].astype(str))
    registrable_groups = set(frame["registrable_domain"].astype(str))
    if (groups | registrable_groups) & existing_groups:
        raise ValueError("time-forward hard-positive group overlaps model partitions")
    if groups & excluded_groups:
        raise ValueError("frozen group leaked into time-forward hard positives")

    metadata = {
        "source_path": str(source_path),
        "source_sha256": actual_sha,
        "public_manifest_path": str(manifest_path),
        "public_manifest_sha256": compute_file_sha256(manifest_path),
        "manifest_output": output_name,
        "selected_rows": len(frame),
        "evaluation_group_count": len(groups),
        "required_label": 1,
        "required_source": expected_source,
        "overlap_with_existing_partitions": 0,
        "overlap_with_frozen_groups": 0,
    }
    return frame, metadata


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
    frozen_evaluation = None
    evaluation_group_policy = None
    if policy.get("frozen_evaluation_labels"):
        evaluation_group_policy = load_evaluation_group_policy(
            policy.get("evaluation_group_policy", {})
        )
        frozen_evaluation = load_frozen_evaluation(
            resolve_ml_path(str(policy["frozen_evaluation_labels"])),
            set(evaluation_group_policy["roots"]),
        )
    excluded_groups = set(frozen["groups"])
    if frozen_evaluation is not None:
        excluded_groups.update(frozen_evaluation["groups"])
    all_exclusions = {"groups": excluded_groups}
    frames: Dict[str, pd.DataFrame] = {}
    exclusion_counts: Dict[str, int] = {}
    evaluation_exclusion_counts: Dict[str, int] = {}
    total_exclusion_counts: Dict[str, int] = {}
    for split in ("train", "val", "cal", "test"):
        source_path = source_dir / f"{split}.parquet"
        if not source_path.exists():
            raise FileNotFoundError(f"source partition missing: {source_path}")
        frame = pd.read_parquet(source_path)
        challenge_excluded = frame["registrable_domain"].isin(
            set(frozen["groups"])
        )
        evaluation_excluded = (
            _frozen_evaluation_mask(frame, frozen_evaluation)
            if frozen_evaluation is not None
            else pd.Series(False, index=frame.index)
        )
        excluded = challenge_excluded | evaluation_excluded
        exclusion_counts[split] = int(challenge_excluded.sum())
        evaluation_exclusion_counts[split] = int(evaluation_excluded.sum())
        total_exclusion_counts[split] = int(excluded.sum())
        frame = frame.loc[~excluded].copy()
        frame["sample_weight"] = 1.0
        frame["label_provenance"] = "original_partition"
        frame["training_role"] = "standard"
        frames[split] = frame

    hard_negative_df, hard_negative_meta = select_hard_negatives(
        frames["train"], policy["hard_negative"], all_exclusions
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

    hard_positive_meta = None
    if policy.get("hard_positive"):
        existing_groups = set().union(
            *(set(frame["registrable_domain"].astype(str)) for frame in frames.values())
        )
        hard_positive_df, hard_positive_meta = load_time_forward_hard_positives(
            policy["hard_positive"], existing_groups, excluded_groups
        )
        metadata_columns = {"sample_weight", "label_provenance", "training_role"}
        base_columns = [
            column
            for column in frames["train"].columns
            if column not in metadata_columns
        ]
        missing_base = sorted(set(base_columns) - set(hard_positive_df.columns))
        if missing_base:
            raise ValueError(
                f"time-forward hard positives cannot populate train schema: {missing_base}"
            )
        appended = hard_positive_df[base_columns].copy()
        appended["sample_weight"] = 1.0
        appended["label_provenance"] = "verified_online_time_forward"
        appended["training_role"] = "time_forward_hard_positive"
        appended = appended[list(frames["train"].columns)]
        frames["train"] = pd.concat(
            [frames["train"], appended], ignore_index=True
        )

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
        if frozen_evaluation is not None and _frozen_evaluation_mask(
            frame, frozen_evaluation
        ).any():
            raise ValueError(f"frozen evaluation group leaked into {split}")
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
        "frozen_evaluation": (
            {
                "labels_path": frozen_evaluation["labels_path"],
                "labels_sha256": frozen_evaluation["labels_sha256"],
                "case_count": frozen_evaluation["case_count"],
                "domain_count": len(frozen_evaluation["domains"]),
                "registrable_group_count": len(frozen_evaluation["groups"]),
                "shared_tenant_group_count": sum(
                    len(groups)
                    for groups in frozen_evaluation["shared_groups_by_root"].values()
                ),
                "evaluation_group_policy": {
                    "shared_hosting_snapshot": evaluation_group_policy["snapshot_path"],
                    "shared_hosting_snapshot_sha256": evaluation_group_policy["snapshot_sha256"],
                    "shared_hosting_extensions": evaluation_group_policy["extensions"],
                },
                "excluded_rows_by_partition": evaluation_exclusion_counts,
                "overlap_after_exclusion": 0,
            }
            if frozen_evaluation is not None
            else None
        ),
        "combined_exclusions": {
            "registrable_group_count": len(excluded_groups),
            "excluded_rows_by_partition": total_exclusion_counts,
            "overlap_after_exclusion": 0,
        },
        "hard_negative": {
            **hard_negative_meta,
            "csv_path": str(hard_negative_path),
            "csv_sha256": compute_file_sha256(hard_negative_path),
        },
        "hard_positive": hard_positive_meta,
        "partition_files": partition_files,
    }
    manifest_path = artifacts_dir / "training_data_manifest.json"
    with open(manifest_path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(manifest, handle, indent=2, ensure_ascii=False)
        handle.write("\n")
    manifest["manifest_path"] = str(manifest_path)
    manifest["manifest_sha256"] = compute_file_sha256(manifest_path)
    return manifest
