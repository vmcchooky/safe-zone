"""
Handcrafted & TF-IDF Feature Extractor (Phase 0B & Phase 2)
Matches Go internal/analysis rules and extracts 534 features (22 handcrafted + 512 TF-IDF).
Fits TfidfVectorizer ONLY on the train partition.
Exports CSR sparse matrices (.npz), Parquet partitions, feature_manifest.json, and capacity_report.json.
"""

from dataclasses import dataclass
import hashlib
import json
import math
import os
import re
import sys
import time
import tracemalloc
from typing import Any, Dict, List, Optional, Tuple
from concurrent.futures import ProcessPoolExecutor, as_completed

import numpy as np
import pandas as pd

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from src.canonicalize import CanonicalResult, canonicalize_domain, get_psl

FEATURE_NAMES = [
    "fqdn_length",
    "num_dots",
    "num_hyphens",
    "num_digits",
    "digit_ratio",
    "entropy",
    "max_consecutive_consonants",
    "main_label_length",
    "registrable_domain_length",
    "subdomain_depth",
    "token_count",
    "is_punycode",
    "has_mixed_script",
    "is_ip_like",
    "tld_risk_score",
    "phishing_keyword_count",
    "is_shared_hosting",
    "min_brand_levenshtein",
    "min_brand_keyboard_distance",
    "has_brand_homoglyph",
    "has_brand_in_main_label",
    "has_brand_in_subdomain",
]


class SnapshotStore:
    def __init__(self, snapshots_dir: Optional[str] = None):
        if snapshots_dir is None:
            snapshots_dir = os.path.join(BASE_DIR, "contracts", "snapshots")
        self.snapshots_dir = snapshots_dir

        self.brands = self._load_json("brands.v1.json")
        self.keywords = self._load_json("keywords.v1.json")
        self.tld_risk = self._load_json("tld_risk.v1.json")
        self.shared_hosting = self._load_json("shared_hosting.v1.json")
        self.homoglyphs = self._load_json("homoglyphs.v1.json")
        self.keyboard_adjacency = self._load_json("keyboard_adjacency.v1.json")

    def _load_json(self, filename: str) -> Any:
        filepath = os.path.join(self.snapshots_dir, filename)
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Snapshot file not found at {filepath}")
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)


def to_skeleton(text: str, homoglyph_map: Dict[str, str]) -> str:
    res = []
    for char in text:
        res.append(homoglyph_map.get(char, char))
    return "".join(res)


def levenshtein_distance(s1: str, s2: str) -> int:
    r1, r2 = list(s1), list(s2)
    len1, len2 = len(r1), len(r2)
    if len1 == 0:
        return len2
    if len2 == 0:
        return len1

    column = list(range(len1 + 1))
    for x in range(1, len2 + 1):
        column[0] = x
        lastkey = x - 1
        for y in range(1, len1 + 1):
            oldkey = column[y]
            incr = 0 if r1[y - 1] == r2[x - 1] else 1
            column[y] = min(column[y] + 1, column[y - 1] + 1, lastkey + incr)
            lastkey = oldkey
    return column[len1]


def weighted_levenshtein_distance(
    s1: str, s2: str, keyboard_adj: Dict[str, str]
) -> float:
    r1, r2 = list(s1), list(s2)
    len1, len2 = len(r1), len(r2)
    if len1 == 0:
        return float(len2)
    if len2 == 0:
        return float(len1)

    dp = [float(y) for y in range(len1 + 1)]

    for x in range(1, len2 + 1):
        lastkey = dp[0]
        dp[0] = float(x)
        for y in range(1, len1 + 1):
            oldkey = dp[y]
            c1, c2 = r1[y - 1], r2[x - 1]
            if c1 == c2:
                incr = 0.0
            else:
                c1_low, c2_low = c1.lower(), c2.lower()
                adj1 = keyboard_adj.get(c1_low, "")
                adj2 = keyboard_adj.get(c2_low, "")
                if c2_low in adj1 or c1_low in adj2:
                    incr = 0.5
                else:
                    incr = 1.0
            dp[y] = min(dp[y] + 1.0, dp[y - 1] + 1.0, lastkey + incr)
            lastkey = oldkey

    return dp[len1]


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    frequencies = {}
    for char in s:
        frequencies[char] = frequencies.get(char, 0) + 1
    entropy = 0.0
    length = float(len(s))
    for count in frequencies.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def max_consecutive_consonants(s: str) -> int:
    consonants = set("bcdfghjklmnpqrstvwxyz")
    max_c = 0
    curr = 0
    for char in s.lower():
        if char in consonants:
            curr += 1
            if curr > max_c:
                max_c = curr
        else:
            curr = 0
    return max_c


def has_mixed_script(value: str) -> bool:
    has_latin = False
    has_non_latin = False
    for r in value:
        if r in ".-" or r.isdigit():
            continue
        if ord(r) <= 127:
            has_latin = True
        else:
            has_non_latin = True
    return has_latin and has_non_latin


def is_suspicious_label(label: str, brand_name: str) -> bool:
    label = label.lower()
    brand_name = brand_name.lower()
    if label == brand_name:
        return True
    parts = label.split("-")
    for p in parts:
        if p == brand_name:
            return True
    if len(brand_name) < 6:
        return False
    return brand_name in label


def is_trusted_brand_suffix(domain: str, brands: list) -> bool:
    domain = domain.lower().strip()
    if not domain:
        return False
    for brand in brands:
        official = brand.get("official_domain", "").lower().strip()
        if official and (domain == official or domain.endswith("." + official)):
            return True
        for alt in brand.get("alt_domains", []):
            alt = alt.lower().strip()
            if alt and (domain == alt or domain.endswith("." + alt)):
                return True
    return False


class FeatureExtractor:
    def __init__(self, snapshot_store: Optional[SnapshotStore] = None):
        if snapshot_store is None:
            snapshot_store = SnapshotStore()
        self.snapshots = snapshot_store

    def extract_features(
        self, domain_or_url: str, canonical_res: Optional[CanonicalResult] = None
    ) -> Dict[str, Any]:
        if canonical_res is None:
            canonical_res = canonicalize_domain(domain_or_url)

        if not canonical_res.is_valid:
            return {
                "fqdn_length": len(canonical_res.domain_ascii) if canonical_res.domain_ascii else 0,
                "num_dots": 0,
                "num_hyphens": 0,
                "num_digits": 0,
                "digit_ratio": 0.0,
                "entropy": 0.0,
                "max_consecutive_consonants": 0,
                "main_label_length": 0,
                "registrable_domain_length": 0,
                "subdomain_depth": 0,
                "token_count": 0,
                "is_punycode": 0,
                "has_mixed_script": 0,
                "is_ip_like": 1 if canonical_res.is_ip_like else 0,
                "tld_risk_score": 0.0,
                "phishing_keyword_count": 0,
                "is_shared_hosting": 0,
                "min_brand_levenshtein": 99.0,
                "min_brand_keyboard_distance": 99.0,
                "has_brand_homoglyph": 0,
                "has_brand_in_main_label": 0,
                "has_brand_in_subdomain": 0,
            }

        domain_ascii = canonical_res.domain_ascii
        domain_unicode = canonical_res.domain_unicode

        # Lexical
        fqdn_length = len(domain_ascii)
        num_dots = domain_ascii.count(".")
        num_hyphens = domain_ascii.count("-")
        num_digits = sum(1 for c in domain_ascii if c.isdigit())
        digit_ratio = num_digits / fqdn_length if fqdn_length > 0 else 0.0
        entropy = shannon_entropy(canonical_res.main_label)
        max_consonants = max_consecutive_consonants(domain_ascii)

        # PSL
        main_label_len = len(canonical_res.main_label)
        registrable_domain_len = len(canonical_res.registrable_domain)
        subdomain_depth = canonical_res.subdomain_depth

        # Token
        tokens = [t for t in re.split(r"[\.-]", domain_ascii) if t]
        token_count = len(tokens)

        # IDN
        is_punycode = 1 if (domain_ascii.startswith("xn--") or ".xn--" in domain_ascii) else 0
        mixed_script = 1 if has_mixed_script(domain_unicode) else 0

        # Pattern
        is_ip_like = 1 if canonical_res.is_ip_like else 0

        # Lookup
        suffix_parts = canonical_res.suffix.split(".")
        tld = suffix_parts[-1] if suffix_parts else ""
        tld_risk_score = 1.0 if self.snapshots.tld_risk.get(tld, False) else 0.0

        phishing_keyword_count = 0
        for kw in self.snapshots.keywords:
            if kw.lower() in domain_ascii:
                phishing_keyword_count += 1

        is_shared = 0
        reg_domain = canonical_res.registrable_domain.lower()
        for host in self.snapshots.shared_hosting:
            host_low = host.lower()
            if reg_domain == host_low or domain_ascii == host_low or domain_ascii.endswith("." + host_low):
                is_shared = 1
                break

        # Brand Features
        labels = domain_ascii.split(".")
        sk_domain = to_skeleton(domain_unicode, self.snapshots.homoglyphs)
        sk_labels = sk_domain.split(".")

        non_tld_count = len(labels)
        if len(labels) > 1:
            non_tld_count -= 1
            if len(labels) > 2 and labels[-2] in {"com", "co", "net", "org", "gov", "edu", "ac"} and len(labels[-1]) == 2:
                non_tld_count -= 1

        non_tld_labels = labels[:non_tld_count]
        non_tld_sk_labels = sk_labels[:non_tld_count]

        min_lev = 99.0
        min_kbd = 99.0
        has_homoglyph = 0
        has_brand_main = 0
        has_brand_sub = 0

        is_trusted = is_trusted_brand_suffix(domain_ascii, self.snapshots.brands)
        is_homoglyph_spoof = sk_domain != domain_unicode

        if not is_trusted:
            for brand_entry in self.snapshots.brands:
                brand_name = brand_entry.get("name", "").lower()
                official = brand_entry.get("official_domain", "").lower()
                alts = [a.lower() for a in brand_entry.get("alt_domains", [])]

                if not brand_name or not official:
                    continue

                root_dom = canonical_res.registrable_domain.lower()
                is_official = root_dom == official or root_dom in alts
                if is_official:
                    continue

                for idx, label in enumerate(non_tld_labels):
                    sk_label = non_tld_sk_labels[idx] if idx < len(non_tld_sk_labels) else label

                    min_len = min(len(brand_name), len(sk_label))
                    if min_len >= 4:
                        if abs(len(sk_label) - len(brand_name)) > 2:
                            continue

                        lev = levenshtein_distance(sk_label, brand_name)
                        if lev < min_lev:
                            min_lev = float(lev)

                        kbd = weighted_levenshtein_distance(sk_label, brand_name, self.snapshots.keyboard_adjacency)
                        if kbd < min_kbd:
                            min_kbd = kbd

                        if sk_label == brand_name and label != brand_name and is_homoglyph_spoof:
                            has_homoglyph = 1

                if is_suspicious_label(canonical_res.main_label, brand_name) or is_suspicious_label(to_skeleton(canonical_res.main_label, self.snapshots.homoglyphs), brand_name):
                    has_brand_main = 1

                for idx, sub_label in enumerate(canonical_res.subdomain_labels):
                    sk_sub = to_skeleton(sub_label, self.snapshots.homoglyphs)
                    if is_suspicious_label(sub_label, brand_name) or is_suspicious_label(sk_sub, brand_name):
                        has_brand_sub = 1
        else:
            min_lev = 0.0
            min_kbd = 0.0

        return {
            "fqdn_length": fqdn_length,
            "num_dots": num_dots,
            "num_hyphens": num_hyphens,
            "num_digits": num_digits,
            "digit_ratio": round(digit_ratio, 6),
            "entropy": round(entropy, 6),
            "max_consecutive_consonants": max_consonants,
            "main_label_length": main_label_len,
            "registrable_domain_length": registrable_domain_len,
            "subdomain_depth": subdomain_depth,
            "token_count": token_count,
            "is_punycode": is_punycode,
            "has_mixed_script": mixed_script,
            "is_ip_like": is_ip_like,
            "tld_risk_score": tld_risk_score,
            "phishing_keyword_count": phishing_keyword_count,
            "is_shared_hosting": is_shared,
            "min_brand_levenshtein": min_lev,
            "min_brand_keyboard_distance": min_kbd,
            "has_brand_homoglyph": has_homoglyph,
            "has_brand_in_main_label": has_brand_main,
            "has_brand_in_subdomain": has_brand_sub,
        }


def _extract_handcrafted_chunk(domains: List[str]) -> np.ndarray:
    psl = get_psl()
    store = SnapshotStore()
    extractor = FeatureExtractor(snapshot_store=store)

    rows = []
    for d in domains:
        c = canonicalize_domain(str(d), psl)
        feats = extractor.extract_features(str(d), c)
        rows.append([feats[col] for col in FEATURE_NAMES])
    return np.array(rows, dtype=np.float64)


def compute_file_sha256(filepath: str) -> str:
    hasher = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def build_full_features(
    derived_dir: Optional[str] = None,
    num_workers: Optional[int] = None,
) -> Dict[str, Any]:
    from scipy.sparse import hstack, csr_matrix, save_npz
    from sklearn.feature_extraction.text import TfidfVectorizer

    tracemalloc.start()
    t0 = time.time()

    if derived_dir is None:
        derived_dir = os.path.join(BASE_DIR, "data", "derived")

    matrices_dir = os.path.join(derived_dir, "matrices")
    partitions_dir = os.path.join(derived_dir, "partitions")
    os.makedirs(matrices_dir, exist_ok=True)
    os.makedirs(partitions_dir, exist_ok=True)

    # 1. Ensure Partitions Exist
    train_part = os.path.join(partitions_dir, "train.parquet")
    val_part = os.path.join(partitions_dir, "val.parquet")
    cal_part = os.path.join(partitions_dir, "cal.parquet")
    test_part = os.path.join(partitions_dir, "test.parquet")

    if not all(os.path.exists(p) for p in [train_part, val_part, cal_part, test_part]):
        print("[*] Partitions missing. Running make_splits()...", flush=True)
        from src.make_splits import make_splits
        make_splits(derived_dir=derived_dir)

    print("[*] Loading partition metadata Parquet files...", flush=True)
    df_train = pd.read_parquet(train_part)
    df_val = pd.read_parquet(val_part)
    df_cal = pd.read_parquet(cal_part)
    df_test = pd.read_parquet(test_part)

    partition_dfs = {
        "train": df_train,
        "val": df_val,
        "cal": df_cal,
        "test": df_test,
    }

    # 2. Fit TfidfVectorizer ONLY on the train split
    print("[*] Fitting TfidfVectorizer (range=(2,3), max_features=512) ONLY on train split...", flush=True)
    train_ascii = df_train["domain_ascii"].fillna("").astype(str).tolist()

    vectorizer = TfidfVectorizer(
        analyzer="char",
        ngram_range=(2, 3),
        max_features=512,
        sublinear_tf=True,
        norm="l2",
        lowercase=True,
    )
    vectorizer.fit(train_ascii)
    vocab = vectorizer.get_feature_names_out().tolist()
    print(f"[+] TfidfVectorizer fitted successfully. Vocab size: {len(vocab)}", flush=True)

    # 3. Extract Features and Transform for Each Partition
    if num_workers is None:
        num_workers = min(os.cpu_count() or 4, 8)

    matrix_info = {}
    checksums = {}

    for name, df in partition_dfs.items():
        print(f"[*] Processing partition '{name}' ({len(df):,} rows)...", flush=True)
        domains = df["domain_ascii"].fillna("").astype(str).tolist()

        # Handcrafted extraction via multiprocessing
        chunk_size = 50000
        domain_chunks = [domains[i : i + chunk_size] for i in range(0, len(domains), chunk_size)]
        handcrafted_chunks = []

        with ProcessPoolExecutor(max_workers=num_workers) as executor:
            futures = [executor.submit(_extract_handcrafted_chunk, chunk) for chunk in domain_chunks]
            for f in as_completed(futures):
                handcrafted_chunks.append(f.result())

        handcrafted_np = np.vstack(handcrafted_chunks) if handcrafted_chunks else np.empty((0, 22), dtype=np.float64)
        handcrafted_csr = csr_matrix(handcrafted_np)

        # TF-IDF transform
        tfidf_csr = vectorizer.transform(domains)

        # Combine into full 534 feature CSR matrix
        full_csr = hstack([handcrafted_csr, tfidf_csr]).tocsr()
        full_csr.sort_indices()

        out_npz = os.path.join(matrices_dir, f"X_{name}.npz")
        save_npz(out_npz, full_csr)

        rel_npz = os.path.relpath(out_npz, BASE_DIR).replace("\\", "/")
        sha256 = compute_file_sha256(out_npz)
        checksums[rel_npz] = sha256

        rel_parquet = os.path.relpath(os.path.join(partitions_dir, f"{name}.parquet"), BASE_DIR).replace("\\", "/")
        checksums[rel_parquet] = compute_file_sha256(os.path.join(partitions_dir, f"{name}.parquet"))

        density = float(full_csr.nnz / (full_csr.shape[0] * full_csr.shape[1])) if full_csr.shape[0] > 0 else 0.0
        matrix_info[name] = {
            "file": rel_npz,
            "shape": list(full_csr.shape),
            "nnz": int(full_csr.nnz),
            "density": round(density, 6),
            "sha256": sha256,
        }

        print(f"[+] Partition '{name}' matrix saved: shape={full_csr.shape}, nnz={full_csr.nnz:,}, density={density:.4f}", flush=True)

    # 4. Generate feature_manifest.json
    all_feature_names = FEATURE_NAMES + [f"char_2_3_{term}" for term in vocab]
    feature_manifest = {
        "contract_version": "1.0.0",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "handcrafted_feature_count": len(FEATURE_NAMES),
        "tfidf_feature_count": len(vocab),
        "total_feature_count": len(all_feature_names),
        "feature_names": all_feature_names,
        "tfidf_config": {
            "ngram_range": [2, 3],
            "max_features": 512,
            "analyzer": "char",
            "lowercase": True,
            "sublinear_tf": True,
            "norm": "l2",
            "fitted_on": "train_split_only",
        },
        # Runtime Go inference needs the learned smoothed IDF values; keeping
        # them adjacent to the vocabulary makes the feature contract
        # self-contained and prevents silent drift from the train matrix.
        "idf_by_index": [float(value) for value in vectorizer.idf_],
        "matrices": matrix_info,
        "checksums": checksums,
    }

    manifest_path = os.path.join(derived_dir, "feature_manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(feature_manifest, f, indent=2)
    print(f"[+] Saved feature manifest to {manifest_path}", flush=True)

    # 5. Measure Capacity & Performance Metrics
    current_mem, peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    t1 = time.time()

    peak_rss_mb = round(peak_mem / (1024 * 1024), 2)
    wall_time_sec = round(t1 - t0, 2)

    # Disk usage calculation
    disk_bytes = 0
    for root, _, files in os.walk(derived_dir):
        for fname in files:
            disk_bytes += os.path.getsize(os.path.join(root, fname))
    disk_mb = round(disk_bytes / (1024 * 1024), 2)

    capacity_report = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "performance": {
            "wall_time_seconds": wall_time_sec,
            "peak_rss_mb": peak_rss_mb,
            "cpu_workers": num_workers,
        },
        "storage": {
            "total_derived_mb": disk_mb,
            "matrices_directory": os.path.relpath(matrices_dir, BASE_DIR).replace("\\", "/"),
            "partitions_directory": os.path.relpath(partitions_dir, BASE_DIR).replace("\\", "/"),
        },
        "dataset_summary": {
            "train_rows": len(df_train),
            "val_rows": len(df_val),
            "cal_rows": len(df_cal),
            "test_rows": len(df_test),
            "total_rows": len(df_train) + len(df_val) + len(df_cal) + len(df_test),
            "matrix_features": 534,
        },
    }

    capacity_path = os.path.join(derived_dir, "capacity_report.json")
    with open(capacity_path, "w", encoding="utf-8") as f:
        json.dump(capacity_report, f, indent=2)
    print(f"[+] Saved capacity report to {capacity_path}", flush=True)

    return {
        "feature_manifest": feature_manifest,
        "capacity_report": capacity_report,
    }


if __name__ == "__main__":
    build_full_features()
