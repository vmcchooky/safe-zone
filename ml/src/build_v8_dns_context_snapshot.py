"""Freeze source- and group-disjoint cohorts for the v8 DNS context study."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, Iterable

import pandas as pd

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from src.build_time_forward_snapshot import _partition_groups, compute_file_sha256
from src.canonicalize import canonicalize_domain
from src.training_data import (
    _evaluation_group,
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


def _canonical_rows(
    values: Iterable[str], roots: set[str], source: str, label: int
) -> pd.DataFrame:
    rows = []
    for raw in values:
        value = str(raw).strip()
        if not value or value.startswith("#") or value.startswith("!"):
            continue
        canonical = canonicalize_domain(value)
        if not canonical.is_valid or not canonical.registrable_domain:
            continue
        group, _ = _evaluation_group(
            canonical.domain_ascii, canonical.registrable_domain, roots
        )
        if not group:
            continue
        rows.append(
            {
                "domain_ascii": canonical.domain_ascii,
                "registrable_domain": canonical.registrable_domain,
                "evaluation_group": group,
                "label": int(label),
                "source": source,
            }
        )
    if not rows:
        return pd.DataFrame(
            columns=[
                "domain_ascii",
                "registrable_domain",
                "evaluation_group",
                "label",
                "source",
            ]
        )
    return (
        pd.DataFrame(rows)
        .sort_values("domain_ascii")
        .drop_duplicates("evaluation_group", keep="first")
        .reset_index(drop=True)
    )


def _stable_select(frame: pd.DataFrame, rows: int, seed: int) -> pd.DataFrame:
    if len(frame) < rows:
        raise ValueError(f"cohort has only {len(frame)} eligible rows; requires {rows}")
    selected = frame.copy()
    selected["selection_hash"] = [
        hashlib.sha256(
            f"{seed}|{int(label)}|{group}".encode("utf-8")
        ).hexdigest()
        for label, group in zip(selected["label"], selected["evaluation_group"])
    ]
    return (
        selected.sort_values(["selection_hash", "domain_ascii"])
        .head(rows)
        .drop(columns="selection_hash")
        .reset_index(drop=True)
    )


def _write_parquet(frame: pd.DataFrame, path: Path) -> Dict[str, Any]:
    path.parent.mkdir(parents=True, exist_ok=True)
    frame.to_parquet(path, index=False)
    return {
        "path": str(path.relative_to(BASE_DIR)).replace("\\", "/"),
        "rows": len(frame),
        "sha256": compute_file_sha256(path),
    }


def build(protocol_path: str | os.PathLike[str]) -> Dict[str, Any]:
    protocol_file = Path(protocol_path).resolve()
    protocol = _load_json(protocol_file)
    seed = int(protocol["seed"])
    group_policy = load_evaluation_group_policy(protocol["group_policy"])
    roots = set(group_policy["roots"])
    if group_policy["snapshot_sha256"] != protocol["group_policy"][
        "shared_hosting_snapshot_sha256"
    ]:
        raise ValueError("shared-hosting snapshot does not match v8 protocol")

    partition_paths = {}
    for name, meta in protocol["baseline_partitions"].items():
        path = resolve_ml_path(meta["path"])
        _require_hash(path, meta["sha256"], f"{name} partition")
        partition_paths[name] = path
    baseline_groups = _partition_groups(partition_paths["train"].parent, roots)

    frozen_challenge = load_frozen_challenge(
        resolve_ml_path(protocol["final_evidence"]["targeted_benign_labels"]["path"])
    )
    frozen_evaluation = load_frozen_evaluation(
        resolve_ml_path(protocol["final_evidence"]["representative_labels"]["path"]),
        roots,
    )
    frozen_groups = set(frozen_challenge["groups"]) | set(frozen_evaluation["groups"])
    prior_groups: set[str] = set()
    prior_meta = {}
    for name, meta in protocol["prior_opened_groups"].items():
        path = resolve_ml_path(meta["path"])
        _require_hash(path, meta["sha256"], name)
        frame = pd.read_parquet(path, columns=["evaluation_group"])
        groups = set(frame["evaluation_group"].astype(str))
        prior_groups.update(groups)
        prior_meta[name] = {"rows": len(frame), "groups": len(groups)}
    external_exclusions = baseline_groups | frozen_groups | prior_groups

    sources = protocol["sources"]
    train_malicious_path = resolve_ml_path(sources["malicious_train_development"]["path"])
    final_malicious_path = resolve_ml_path(sources["malicious_final"]["path"])
    with open(train_malicious_path, "r", encoding="utf-8", errors="strict") as handle:
        train_malicious_raw = handle.readlines()
    with open(final_malicious_path, "r", encoding="utf-8", errors="strict") as handle:
        final_malicious_raw = handle.readlines()
    malicious_pool = _canonical_rows(
        train_malicious_raw,
        roots,
        sources["malicious_train_development"]["name"],
        1,
    )
    malicious_pool = malicious_pool[
        ~malicious_pool["evaluation_group"].isin(external_exclusions)
    ].reset_index(drop=True)
    train_malicious_count = int(protocol["cohorts"]["train"]["malicious_rows"])
    development_malicious_count = int(
        protocol["cohorts"]["development"]["malicious_rows"]
    )
    selected_malicious = _stable_select(
        malicious_pool, train_malicious_count + development_malicious_count, seed
    )
    train_malicious = selected_malicious.iloc[:train_malicious_count].copy()
    development_malicious = selected_malicious.iloc[train_malicious_count:].copy()

    train_partition = pd.read_parquet(partition_paths["train"])
    train_benign_pool = train_partition[
        (train_partition["label"].to_numpy(int) == 0)
        & train_partition["source"].astype(str).eq(
            sources["benign_train"]["required_source"]
        )
    ][["domain_ascii", "registrable_domain", "label", "source"]].copy()
    train_benign_pool["evaluation_group"] = [
        _evaluation_group(str(domain), str(registrable), roots)[0]
        for domain, registrable in zip(
            train_benign_pool["domain_ascii"], train_benign_pool["registrable_domain"]
        )
    ]
    train_benign = _stable_select(
        train_benign_pool,
        int(protocol["cohorts"]["train"]["benign_rows"]),
        seed,
    )

    validation_partition = pd.read_parquet(partition_paths["validation"])
    development_benign_pool = validation_partition[
        (validation_partition["label"].to_numpy(int) == 0)
        & validation_partition["source"].astype(str).eq(
            sources["benign_development"]["required_source"]
        )
    ][["domain_ascii", "registrable_domain", "label", "source"]].copy()
    development_benign_pool["evaluation_group"] = [
        _evaluation_group(str(domain), str(registrable), roots)[0]
        for domain, registrable in zip(
            development_benign_pool["domain_ascii"],
            development_benign_pool["registrable_domain"],
        )
    ]
    development_benign = _stable_select(
        development_benign_pool,
        int(protocol["cohorts"]["development"]["benign_rows"]),
        seed,
    )

    whitelist_meta = sources["benign_final"]
    whitelist_path = resolve_ml_path(whitelist_meta["path"])
    _require_hash(whitelist_path, whitelist_meta["sha256"], "final benign source")
    whitelist = pd.read_csv(
        whitelist_path,
        usecols=[whitelist_meta["required_column"]],
        keep_default_na=False,
    )
    final_benign_pool = _canonical_rows(
        whitelist[whitelist_meta["required_column"]].astype(str),
        roots,
        whitelist_meta["name"],
        0,
    )
    final_benign_pool = final_benign_pool[
        ~final_benign_pool["evaluation_group"].isin(external_exclusions)
    ].reset_index(drop=True)
    final_benign = _stable_select(
        final_benign_pool,
        int(protocol["cohorts"]["final"]["benign_rows"]),
        seed,
    )

    selected_groups = set(selected_malicious["evaluation_group"])
    final_malicious_pool = _canonical_rows(
        final_malicious_raw,
        roots,
        sources["malicious_final"]["name"],
        1,
    )
    final_malicious_pool = final_malicious_pool[
        ~final_malicious_pool["evaluation_group"].isin(
            external_exclusions | selected_groups
        )
    ].reset_index(drop=True)
    final_malicious = _stable_select(
        final_malicious_pool,
        int(protocol["cohorts"]["final"]["malicious_rows"]),
        seed,
    )

    train = pd.concat([train_benign, train_malicious], ignore_index=True)
    development = pd.concat(
        [development_benign, development_malicious], ignore_index=True
    )
    final = pd.concat([final_benign, final_malicious], ignore_index=True)
    cohort_groups = {
        "train": set(train["evaluation_group"].astype(str)),
        "development": set(development["evaluation_group"].astype(str)),
        "final": set(final["evaluation_group"].astype(str)),
    }
    overlaps = {
        "train_development": len(cohort_groups["train"] & cohort_groups["development"]),
        "train_final": len(cohort_groups["train"] & cohort_groups["final"]),
        "development_final": len(
            cohort_groups["development"] & cohort_groups["final"]
        ),
    }
    if any(overlaps.values()):
        raise ValueError(f"v8 cohorts overlap: {overlaps}")

    derived_dir = resolve_ml_path(protocol["outputs"]["derived_dir"])
    outputs = {
        "train": _write_parquet(train, derived_dir / "cohorts" / "train.parquet"),
        "development": _write_parquet(
            development, derived_dir / "cohorts" / "development.parquet"
        ),
        "final": _write_parquet(final, derived_dir / "cohorts" / "final.parquet"),
    }
    manifest = {
        "schema_version": 1,
        "protocol_sha256": compute_file_sha256(protocol_file),
        "raw_sources": {
            "malicious_train_development": {
                "path": sources["malicious_train_development"]["path"],
                "sha256": compute_file_sha256(train_malicious_path),
                "bytes": train_malicious_path.stat().st_size,
                "raw_lines": len(train_malicious_raw),
                "eligible_groups": len(malicious_pool),
            },
            "malicious_final": {
                "path": sources["malicious_final"]["path"],
                "sha256": compute_file_sha256(final_malicious_path),
                "bytes": final_malicious_path.stat().st_size,
                "raw_lines": len(final_malicious_raw),
                "eligible_groups": len(final_malicious_pool),
            },
            "benign_final": {
                "path": whitelist_meta["path"],
                "sha256": compute_file_sha256(whitelist_path),
                "raw_rows": len(whitelist),
                "eligible_groups": len(final_benign_pool),
            },
        },
        "exclusions": {
            "baseline_groups": len(baseline_groups),
            "frozen_groups": len(frozen_groups),
            "prior_opened_groups": len(prior_groups),
            "prior_inputs": prior_meta,
        },
        "cross_cohort_group_overlap": overlaps,
        "outputs": outputs,
    }
    manifest_path = resolve_ml_path(protocol["outputs"]["snapshot_manifest"])
    with open(manifest_path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(manifest, handle, indent=2)
        handle.write("\n")
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Build v8 DNS context cohorts")
    parser.add_argument(
        "--protocol",
        default=str(BASE_DIR / "configs" / "v8-dns-context-feasibility-protocol.json"),
    )
    args = parser.parse_args()
    result = build(args.protocol)
    print(json.dumps(result["outputs"], indent=2))
