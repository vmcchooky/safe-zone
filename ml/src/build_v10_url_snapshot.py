"""Freeze fresh, group-disjoint URL cohorts for the v10 signal study."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import sys
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from itertools import islice
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

import pandas as pd
import pyarrow.parquet as pq

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from src.canonicalize import canonicalize_domain
from src.training_data import (
    _evaluation_group,
    compute_file_sha256,
    load_evaluation_group_policy,
    resolve_ml_path,
)
from src.url_context import URLContextError, parse_url


def _load_json(path: Path) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(value, handle, indent=2)
        handle.write("\n")


def _require_hash(path: Path, expected: str, label: str) -> None:
    actual = compute_file_sha256(path)
    if actual != expected.lower():
        raise ValueError(f"{label} SHA-256 mismatch: expected {expected}, got {actual}")


def _stable_hash(*parts: object) -> str:
    return hashlib.sha256("|".join(str(part) for part in parts).encode("utf-8")).hexdigest()


def _stable_bucket(seed: int, group: str) -> int:
    return int.from_bytes(
        hashlib.sha256(f"{seed}|{group}".encode("utf-8")).digest()[:8], "big"
    ) % 10


def _generic_csv_groups(path: Path, roots: set[str]) -> set[str]:
    groups: set[str] = set()
    with open(path, "r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if "domain" not in (reader.fieldnames or []):
            raise ValueError(f"frozen CSV lacks domain column: {path}")
        for row in reader:
            canonical = canonicalize_domain(row["domain"])
            if not canonical.is_valid or not canonical.registrable_domain:
                raise ValueError(f"invalid frozen domain: {row['domain']!r}")
            group, _ = _evaluation_group(
                canonical.domain_ascii, canonical.registrable_domain, roots
            )
            groups.add(group)
    return groups


def _load_exclusions(
    protocol: Mapping[str, Any], roots: set[str]
) -> tuple[set[str], Dict[str, Any]]:
    cache_dir = resolve_ml_path(protocol["outputs"]["derived_dir"]) / "cache"
    cache_path = cache_dir / "excluded-groups.parquet"
    cache_manifest_path = cache_dir / "excluded-groups.json"
    cache_key = _stable_hash(
        protocol["group_policy"]["shared_hosting_snapshot_sha256"],
        *(
            f"{name}:{meta['sha256']}"
            for name, meta in sorted(protocol["exclusions"]["inputs"].items())
        ),
    )
    for name, meta in protocol["exclusions"]["inputs"].items():
        _require_hash(resolve_ml_path(meta["path"]), meta["sha256"], f"exclusion {name}")
    if cache_path.exists() and cache_manifest_path.exists():
        cache_manifest = _load_json(cache_manifest_path)
        if (
            cache_manifest.get("cache_key") == cache_key
            and cache_manifest.get("sha256") == compute_file_sha256(cache_path)
        ):
            cached = pd.read_parquet(cache_path, columns=["evaluation_group"])
            return set(cached["evaluation_group"].astype(str)), dict(
                cache_manifest["inputs"]
            )

    excluded: set[str] = set()
    details: Dict[str, Any] = {}
    for name, meta in protocol["exclusions"]["inputs"].items():
        path = resolve_ml_path(meta["path"])
        if path.suffix.lower() == ".parquet":
            schema_names = set(pq.read_schema(path).names)
            if "evaluation_group" in schema_names:
                frame = pd.read_parquet(path, columns=["evaluation_group"])
                groups = set(frame["evaluation_group"].astype(str))
            elif {"domain_ascii", "registrable_domain"}.issubset(schema_names):
                frame = pd.read_parquet(
                    path, columns=["domain_ascii", "registrable_domain"]
                )
                groups = {
                    _evaluation_group(str(domain), str(registrable), roots)[0]
                    for domain, registrable in zip(
                        frame["domain_ascii"], frame["registrable_domain"]
                    )
                }
            else:
                raise ValueError(f"exclusion parquet lacks group columns: {path}")
            rows = len(frame)
        else:
            groups = _generic_csv_groups(path, roots)
            with open(path, "r", encoding="utf-8-sig", newline="") as handle:
                rows = sum(1 for _ in csv.DictReader(handle))
        excluded.update(groups)
        details[name] = {"rows": rows, "groups": len(groups)}
    cache_dir.mkdir(parents=True, exist_ok=True)
    pd.DataFrame({"evaluation_group": sorted(excluded)}).to_parquet(
        cache_path, index=False
    )
    _write_json(
        cache_manifest_path,
        {
            "cache_key": cache_key,
            "sha256": compute_file_sha256(cache_path),
            "inputs": details,
        },
    )
    return excluded, details


def _url_row(
    raw_url: str,
    *,
    source: str,
    label: int,
    roots: set[str],
    product_contract: Mapping[str, Any],
) -> Dict[str, Any] | None:
    try:
        parsed = parse_url(
            raw_url,
            allowed_schemes=product_contract["allowed_schemes"],
            maximum_url_bytes=int(product_contract["maximum_url_bytes"]),
            reject_credentials=bool(product_contract["reject_credentials"]),
        )
    except URLContextError:
        return None
    canonical = canonicalize_domain(parsed.host)
    if not canonical.is_valid or not canonical.registrable_domain:
        return None
    group, _ = _evaluation_group(
        canonical.domain_ascii, canonical.registrable_domain, roots
    )
    return {
        "requested_url": parsed.normalized_url,
        "url_sha256": parsed.url_sha256,
        "domain_ascii": canonical.domain_ascii,
        "registrable_domain": canonical.registrable_domain,
        "evaluation_group": group,
        "label": int(label),
        "source": source,
    }


def _read_feed_rows(
    path: Path,
    *,
    source: str,
    label: int,
    roots: set[str],
    product_contract: Mapping[str, Any],
) -> Iterator[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8", errors="strict") as handle:
        for raw in handle:
            value = raw.strip()
            if not value or value.startswith(("#", "!")):
                continue
            row = _url_row(
                value,
                source=source,
                label=label,
                roots=roots,
                product_contract=product_contract,
            )
            if row is not None:
                yield row


def _stable_select(
    rows: Iterable[Dict[str, Any]], *, seed: int, maximum_rows: int
) -> list[Dict[str, Any]]:
    values = list(rows)
    values.sort(
        key=lambda row: (
            _stable_hash(seed, row["label"], row["requested_url"]),
            row["requested_url"],
        )
    )
    return values[:maximum_rows]


def _fetch_common_crawl_domain(
    domain: str, config: Mapping[str, Any]
) -> tuple[str, list[Dict[str, Any]], str | None]:
    params = urlencode(
        [
            ("url", f"{domain}/*"),
            ("output", "json"),
            ("filter", f"status:{config['required_status']}"),
            ("filter", f"mime:{config['required_mime_prefix']}"),
            ("collapse", "urlkey"),
        ]
    )
    url = f"{config['common_crawl_endpoint']}?{params}"
    attempts = int(config["maximum_attempts"])
    maximum = int(config["maximum_urls_per_domain"])
    last_error: str | None = None
    for attempt in range(attempts):
        try:
            request = Request(
                url,
                headers={"User-Agent": "Safe-Zone-Research/1.0 (+local offline evaluation)"},
            )
            records: list[Dict[str, Any]] = []
            with urlopen(request, timeout=float(config["timeout_seconds"])) as response:
                for raw in response:
                    if len(records) >= maximum:
                        break
                    try:
                        record = json.loads(raw.decode("utf-8"))
                    except (UnicodeDecodeError, json.JSONDecodeError):
                        continue
                    if isinstance(record, dict) and record.get("url"):
                        records.append(record)
            return domain, records, None
        except (HTTPError, URLError, TimeoutError, OSError) as exc:
            last_error = f"{type(exc).__name__}: {exc}"
            if attempt + 1 < attempts:
                time.sleep(0.5 * (attempt + 1))
    return domain, [], last_error


def _common_crawl_preflight(config: Mapping[str, Any]) -> None:
    if not bool(config.get("preflight_required", False)):
        return
    last_error: Exception | None = None
    for attempt in range(int(config["maximum_attempts"])):
        try:
            request = Request(
                str(config["common_crawl_endpoint"]),
                headers={"User-Agent": "Safe-Zone-Research/1.0 (+local offline evaluation)"},
            )
            with urlopen(request, timeout=float(config["timeout_seconds"])) as response:
                if int(response.status) != 200:
                    raise URLContextError(
                        f"Common Crawl preflight returned HTTP {response.status}"
                    )
                response.read(256)
            return
        except (HTTPError, URLError, TimeoutError, OSError, URLContextError) as exc:
            last_error = exc
            if attempt + 1 < int(config["maximum_attempts"]):
                time.sleep(0.5 * (attempt + 1))
    raise URLContextError(f"Common Crawl preflight failed: {last_error}")


def _collect_benign_rows(
    protocol: Mapping[str, Any],
    roots: set[str],
    excluded_groups: set[str],
    reserved_final_groups: set[str],
) -> tuple[list[Dict[str, Any]], Dict[str, Any]]:
    source = protocol["sources"]["benign_proxy"]
    trust_path = resolve_ml_path(source["trust_directory_path"])
    _require_hash(trust_path, source["trust_directory_sha256"], "benign trust directory")
    frame = pd.read_csv(
        trust_path,
        usecols=[source["required_domain_column"]],
        keep_default_na=False,
    )
    candidates: Dict[str, tuple[str, str]] = {}
    for value in frame[source["required_domain_column"]].astype(str):
        canonical = canonicalize_domain(value)
        if not canonical.is_valid or not canonical.registrable_domain:
            continue
        group, _ = _evaluation_group(
            canonical.domain_ascii, canonical.registrable_domain, roots
        )
        if group in excluded_groups or group in reserved_final_groups:
            continue
        candidates.setdefault(canonical.domain_ascii, (group, canonical.domain_ascii))
    seed = int(protocol["seed"])
    ordered = sorted(
        candidates.values(),
        key=lambda item: (_stable_hash(seed, "benign-source-domain", item[0]), item[1]),
    )
    selected_domains = [item[1] for item in ordered[: int(source["maximum_source_domains"])]]

    raw_path = resolve_ml_path(source["raw_output"])
    raw_path.parent.mkdir(parents=True, exist_ok=True)
    _common_crawl_preflight(source)
    results: Dict[str, tuple[list[Dict[str, Any]], str | None]] = {}
    consecutive_failures = 0
    maximum_failures = int(source["abort_after_consecutive_failed_queries"])
    selected_iterator = iter(selected_domains)
    concurrency = int(source["maximum_concurrency"])
    while batch := list(islice(selected_iterator, concurrency)):
        with ThreadPoolExecutor(max_workers=concurrency) as executor:
            futures = {
                executor.submit(_fetch_common_crawl_domain, domain, source): domain
                for domain in batch
            }
            for future in as_completed(futures):
                domain, records, error = future.result()
                results[domain] = (records, error)
        for domain in batch:
            records, error = results[domain]
            if error:
                consecutive_failures += 1
            else:
                consecutive_failures = 0
            if consecutive_failures >= maximum_failures:
                raise URLContextError(
                    "Common Crawl collection aborted after "
                    f"{consecutive_failures} consecutive failed queries"
                )

    rows: list[Dict[str, Any]] = []
    seen_hashes: set[str] = set()
    failed = 0
    with open(raw_path, "w", encoding="utf-8", newline="\n") as raw_handle:
        for domain in selected_domains:
            records, error = results.get(domain, ([], "missing result"))
            if error:
                failed += 1
            for record in records:
                raw_handle.write(
                    json.dumps(
                        {"source_domain": domain, "record": record},
                        ensure_ascii=False,
                    )
                    + "\n"
                )
                row = _url_row(
                    str(record["url"]),
                    source="common_crawl_vietnam_trust",
                    label=0,
                    roots=roots,
                    product_contract=protocol["product_contract"],
                )
                if row is None or row["domain_ascii"] != domain:
                    continue
                if row["evaluation_group"] in excluded_groups | reserved_final_groups:
                    continue
                if row["url_sha256"] in seen_hashes:
                    continue
                seen_hashes.add(row["url_sha256"])
                rows.append(row)
    return rows, {
        "trust_directory_rows": len(frame),
        "eligible_source_domains": len(candidates),
        "queried_source_domains": len(selected_domains),
        "failed_queries": failed,
        "raw_records": sum(len(value[0]) for value in results.values()),
        "eligible_urls": len(rows),
        "raw_output": source["raw_output"],
        "raw_output_sha256": compute_file_sha256(raw_path),
    }


def _collect_uci_benign_rows(
    protocol: Mapping[str, Any],
    roots: set[str],
    excluded_groups: set[str],
    reserved_final_groups: set[str],
) -> tuple[list[Dict[str, Any]], Dict[str, Any]]:
    source = protocol["sources"]["benign_proxy"]
    archive_path = resolve_ml_path(source["path"])
    with zipfile.ZipFile(archive_path) as archive:
        names = archive.namelist()
        matches = [
            name for name in names if Path(name).name == source["csv_member"]
        ]
        if len(matches) != 1:
            raise ValueError(
                f"UCI archive must contain one {source['csv_member']!r}; got {matches}"
            )
        with archive.open(matches[0]) as csv_handle:
            frame = pd.read_csv(
                csv_handle,
                usecols=[source["required_url_column"], source["required_label_column"]],
                keep_default_na=False,
            )
    benign = frame[
        frame[source["required_label_column"]].astype(int)
        == int(source["required_benign_label"])
    ]
    rows: list[Dict[str, Any]] = []
    seen_hashes: set[str] = set()
    for raw_url in benign[source["required_url_column"]].astype(str):
        row = _url_row(
            raw_url,
            source=source["name"],
            label=0,
            roots=roots,
            product_contract=protocol["product_contract"],
        )
        if row is None:
            continue
        if row["evaluation_group"] in excluded_groups | reserved_final_groups:
            continue
        if row["url_sha256"] in seen_hashes:
            continue
        seen_hashes.add(row["url_sha256"])
        rows.append(row)
    return rows, {
        "path": source["path"],
        "sha256": compute_file_sha256(archive_path),
        "bytes": archive_path.stat().st_size,
        "csv_member": matches[0],
        "raw_rows": len(frame),
        "raw_benign_rows": len(benign),
        "eligible_urls": len(rows),
        "license": source["license"],
    }


def _write_parquet(frame: pd.DataFrame, path: Path) -> Dict[str, Any]:
    path.parent.mkdir(parents=True, exist_ok=True)
    frame.to_parquet(path, index=False)
    return {
        "path": str(path.relative_to(BASE_DIR)).replace("\\", "/"),
        "rows": len(frame),
        "labels": {
            str(int(label)): int(count)
            for label, count in frame["label"].value_counts().sort_index().items()
        },
        "groups": int(frame["evaluation_group"].nunique()),
        "sha256": compute_file_sha256(path),
    }


def build(protocol_path: str | os.PathLike[str]) -> Dict[str, Any]:
    protocol_file = Path(protocol_path).resolve()
    protocol = _load_json(protocol_file)
    seed = int(protocol["seed"])
    product_contract = protocol["product_contract"]
    group_policy = load_evaluation_group_policy(protocol["group_policy"])
    if group_policy["snapshot_sha256"] != protocol["group_policy"][
        "shared_hosting_snapshot_sha256"
    ]:
        raise ValueError("shared-hosting snapshot mismatch")
    roots = set(group_policy["roots"])
    excluded_groups, exclusion_details = _load_exclusions(protocol, roots)

    adaptation_meta = protocol["sources"]["malicious_adaptation"]
    adaptation_path = resolve_ml_path(adaptation_meta["path"])
    final_meta = protocol["sources"]["malicious_final"]
    final_path = resolve_ml_path(final_meta["path"])

    final_rows_all = list(
        _read_feed_rows(
            final_path,
            source=final_meta["name"],
            label=1,
            roots=roots,
            product_contract=product_contract,
        )
    )
    final_rows_eligible = [
        row for row in final_rows_all if row["evaluation_group"] not in excluded_groups
    ]
    final_rows = _stable_select(
        final_rows_eligible,
        seed=seed,
        maximum_rows=int(protocol["partition_policy"]["maximum_rows"]["final_malicious"]),
    )
    final_groups = {row["evaluation_group"] for row in final_rows}
    final_hashes = {row["url_sha256"] for row in final_rows}

    if protocol["sources"]["benign_proxy"]["name"] == "uci_phiusiil_legitimate_urls":
        benign_rows, benign_meta = _collect_uci_benign_rows(
            protocol, roots, excluded_groups, final_groups
        )
    else:
        benign_rows, benign_meta = _collect_benign_rows(
            protocol, roots, excluded_groups, final_groups
        )
    benign_groups = {row["evaluation_group"] for row in benign_rows}
    benign_hashes = {row["url_sha256"] for row in benign_rows}

    adaptation_seen: set[str] = set()
    adaptation_rows: list[Dict[str, Any]] = []
    adaptation_raw_rows = 0
    adaptation_valid_rows = 0
    for row in _read_feed_rows(
        adaptation_path,
        source=adaptation_meta["name"],
        label=1,
        roots=roots,
        product_contract=product_contract,
    ):
        adaptation_raw_rows += 1
        if row["evaluation_group"] in excluded_groups | final_groups | benign_groups:
            continue
        if row["url_sha256"] in final_hashes | benign_hashes | adaptation_seen:
            continue
        adaptation_seen.add(row["url_sha256"])
        adaptation_rows.append(row)
        adaptation_valid_rows += 1

    partition_rows: Dict[str, list[Dict[str, Any]]] = {
        "adaptation_train": [],
        "calibration": [],
        "threshold": [],
        "development": [],
        "final": list(final_rows),
    }
    bucket_to_partition = {
        **{int(value): "adaptation_train" for value in protocol["partition_policy"]["adaptation_train_buckets"]},
        **{int(value): "calibration" for value in protocol["partition_policy"]["calibration_bucket"]},
        **{int(value): "threshold" for value in protocol["partition_policy"]["threshold_bucket"]},
        **{int(value): "development" for value in protocol["partition_policy"]["development_bucket"]},
        **{int(value): "final" for value in protocol["partition_policy"]["benign_final_bucket"]},
    }
    for row in [*benign_rows, *adaptation_rows]:
        partition_rows[bucket_to_partition[_stable_bucket(seed, row["evaluation_group"])]].append(row)

    maxima = protocol["partition_policy"]["maximum_rows"]
    max_by_partition = {
        "adaptation_train": int(maxima["adaptation_train_per_label"]),
        "calibration": int(maxima["calibration_per_label"]),
        "threshold": int(maxima["threshold_per_label"]),
        "development": int(maxima["development_per_label"]),
    }
    for name, maximum_per_label in max_by_partition.items():
        selected: list[Dict[str, Any]] = []
        for label in (0, 1):
            selected.extend(
                _stable_select(
                    (row for row in partition_rows[name] if row["label"] == label),
                    seed=seed,
                    maximum_rows=maximum_per_label,
                )
            )
        partition_rows[name] = selected
    benign_final = _stable_select(
        (row for row in partition_rows["final"] if row["label"] == 0),
        seed=seed,
        maximum_rows=int(maxima["final_benign"]),
    )
    partition_rows["final"] = [*benign_final, *final_rows]

    group_sets = {
        name: {row["evaluation_group"] for row in rows}
        for name, rows in partition_rows.items()
    }
    overlaps: Dict[str, int] = {}
    names = list(group_sets)
    for index, left in enumerate(names):
        for right in names[index + 1 :]:
            overlap = len(group_sets[left] & group_sets[right])
            overlaps[f"{left}__{right}"] = overlap
            if overlap > int(protocol["exclusions"]["cross_partition_group_overlap_max"]):
                raise ValueError(f"group overlap between {left} and {right}: {overlap}")

    derived_dir = resolve_ml_path(protocol["outputs"]["derived_dir"])
    outputs: Dict[str, Any] = {}
    columns = [
        "requested_url",
        "url_sha256",
        "domain_ascii",
        "registrable_domain",
        "evaluation_group",
        "label",
        "source",
    ]
    for name, rows in partition_rows.items():
        frame = pd.DataFrame(rows, columns=columns).sort_values(
            ["label", "url_sha256"]
        ).reset_index(drop=True)
        outputs[name] = _write_parquet(frame, derived_dir / "cohorts" / f"{name}.parquet")

    manifest = {
        "schema_version": 1,
        "protocol_sha256": compute_file_sha256(protocol_file),
        "raw_sources": {
            "malicious_adaptation": {
                "path": adaptation_meta["path"],
                "sha256": compute_file_sha256(adaptation_path),
                "bytes": adaptation_path.stat().st_size,
                "parsed_rows": adaptation_raw_rows,
                "eligible_rows": adaptation_valid_rows,
            },
            "malicious_final": {
                "path": final_meta["path"],
                "sha256": compute_file_sha256(final_path),
                "bytes": final_path.stat().st_size,
                "parsed_rows": len(final_rows_all),
                "eligible_rows": len(final_rows_eligible),
            },
            "benign": benign_meta,
        },
        "exclusions": {
            "unique_groups": len(excluded_groups),
            "inputs": exclusion_details,
            "malicious_final_reserved_groups": len(final_groups),
            "benign_proxy_groups": len(benign_groups),
        },
        "cross_partition_group_overlap": overlaps,
        "outputs": outputs,
    }
    manifest_path = resolve_ml_path(protocol["outputs"]["snapshot_manifest"])
    _write_json(manifest_path, manifest)
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Build v10 URL-aware cohorts")
    parser.add_argument(
        "--protocol",
        default=str(BASE_DIR / "configs" / "v10-url-aware-signal-protocol.json"),
    )
    args = parser.parse_args()
    result = build(args.protocol)
    print(json.dumps(result["outputs"], indent=2))
