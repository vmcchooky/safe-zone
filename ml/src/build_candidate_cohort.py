"""
Candidate Cohort & Lexical Verdict Generator (Phase 1)
Matches Go internal/analysis rules and calculates lexical_verdict, is_ml_candidate, and reasons.
Ultra-fast pyarrow CSV loading (0.3s) and zero-IPC file-based chunk output.
"""

import os
os.environ["OPENBLAS_NUM_THREADS"] = "1"
os.environ["OMP_NUM_THREADS"] = "1"
os.environ["MKL_NUM_THREADS"] = "1"

from dataclasses import dataclass
import glob
import json
import math
import re
import sys
import time
from typing import Any, Dict, List, Optional, Set, Tuple
from concurrent.futures import ProcessPoolExecutor, as_completed

import idna
import pandas as pd
import pyarrow.csv as pcsv

# Add ml root to sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from src.canonicalize import CanonicalResult, canonicalize_domain, get_psl
from src.build_features import (
    SnapshotStore,
    shannon_entropy,
    to_skeleton,
    levenshtein_distance,
    weighted_levenshtein_distance,
    has_mixed_script,
    is_suspicious_label,
)


@dataclass
class LexicalResult:
    domain: str
    verdict: str  # "SAFE", "SUSPICIOUS", "MALICIOUS", "INVALID"
    score: int
    reasons: List[str]
    is_ml_candidate: bool


class LexicalAnalyzer:
    def __init__(self, snapshot_store: Optional[SnapshotStore] = None):
        if snapshot_store is None:
            snapshot_store = SnapshotStore()
        self.snapshots = snapshot_store

        # Load analysis config snapshot if available
        config_path = os.path.join(self.snapshots.snapshots_dir, "analysis_config.v1.json")
        if os.path.exists(config_path):
            with open(config_path, "r", encoding="utf-8") as f:
                self.config = json.load(f)
        else:
            self.config = {
                "punycode_score": 35,
                "long_domain_length": 24,
                "long_domain_score": 15,
                "hyphen_count_threshold": 3,
                "hyphen_score": 10,
                "digit_ratio_threshold": 0.25,
                "digit_ratio_score": 10,
                "mixed_script_score": 25,
                "keywords": self.snapshots.keywords,
                "keyword_base_score": 15,
                "keyword_match_score": 10,
                "keyword_multiple_bonus": 10,
                "brand_spoofing_score": 50,
                "entropy_threshold": 3.0,
                "entropy_score": 35,
            }

        # Pre-build fast brand lookups, trusted sets, and C-compiled regex
        self.brand_names: List[str] = []
        self.brand_candidates_by_len: Dict[int, List[Dict[str, Any]]] = {}
        self.trusted_domains: Set[str] = set()
        self.trusted_suffixes: List[str] = []

        for brand in self.snapshots.brands:
            official = brand.get("official_domain", "").lower().strip()
            if official:
                self.trusted_domains.add(official)
                self.trusted_suffixes.append("." + official)
            for alt in brand.get("alt_domains", []):
                alt_clean = alt.lower().strip()
                if alt_clean:
                    self.trusted_domains.add(alt_clean)
                    self.trusted_suffixes.append("." + alt_clean)

            bname = brand.get("name", "").lower()
            if not bname:
                continue
            self.brand_names.append(bname)
            L = len(bname)
            for l in range(max(1, L - 2), L + 3):
                if l not in self.brand_candidates_by_len:
                    self.brand_candidates_by_len[l] = []
                self.brand_candidates_by_len[l].append(brand)

        self.trusted_suffixes_tuple = tuple(self.trusted_suffixes)

        if self.brand_names:
            escaped = [re.escape(b) for b in sorted(self.brand_names, key=len, reverse=True)]
            self.brand_regex = re.compile(r"|".join(escaped), re.IGNORECASE)
        else:
            self.brand_regex = None

    def is_trusted_brand(self, domain: str) -> bool:
        domain = domain.lower().strip()
        if not domain:
            return False
        if domain in self.trusted_domains:
            return True
        return domain.endswith(self.trusted_suffixes_tuple)

    def analyze(self, input_str: str, canonical_res: Optional[CanonicalResult] = None) -> LexicalResult:
        if canonical_res is None:
            canonical_res = canonicalize_domain(input_str)

        domain = canonical_res.domain_ascii if canonical_res.is_valid else input_str.strip().lower()
        if not canonical_res.is_valid:
            return LexicalResult(
                domain=domain,
                verdict="INVALID",
                score=100,
                reasons=[canonical_res.error or "invalid domain"],
                is_ml_candidate=False,
            )

        score = 0
        reasons = []

        # 1. Punycode check
        if domain.startswith("xn--") or ".xn--" in domain:
            score += self.config.get("punycode_score", 35)
            reasons.append("punycode detected")

        # 2. Long domain check
        if len(domain) > self.config.get("long_domain_length", 24):
            score += self.config.get("long_domain_score", 15)
            reasons.append("domain is long")

        # 3. Hyphen count check
        if domain.count("-") >= self.config.get("hyphen_count_threshold", 3):
            score += self.config.get("hyphen_score", 10)
            reasons.append("many hyphens")

        # 4. Digit ratio check
        num_digits = sum(1 for c in domain if c.isdigit())
        digit_ratio = num_digits / len(domain) if len(domain) > 0 else 0.0
        if digit_ratio > self.config.get("digit_ratio_threshold", 0.25):
            score += self.config.get("digit_ratio_score", 10)
            reasons.append("high digit ratio")

        # 5. Mixed script check
        if has_mixed_script(canonical_res.domain_unicode):
            score += self.config.get("mixed_script_score", 25)
            reasons.append("mixed script characters")

        # 6. Phishing keywords check
        keywords = self.config.get("keywords", self.snapshots.keywords)
        matched_kw_count = 0
        for kw in keywords:
            if kw.lower() in domain:
                matched_kw_count += 1

        if matched_kw_count > 0:
            kw_score = self.config.get("keyword_base_score", 15) + matched_kw_count * self.config.get(
                "keyword_match_score", 10
            )
            if matched_kw_count >= 2:
                kw_score += self.config.get("keyword_multiple_bonus", 10)
            score += kw_score
            reasons.append("phishing keyword pattern")
            if matched_kw_count >= 2:
                reasons.append("multiple phishing keywords")

        # 7. Protected Vietnam public service abuse check
        if "dichvucong" in domain:
            reg = canonical_res.registrable_domain.lower()
            if reg != "dichvucong.gov.vn" and not reg.endswith(".gov.vn") and not domain.endswith(".gov.vn"):
                if score < 75:
                    score = 75
                reasons.append("protected Vietnamese public-service keyword abuse (dichvucong)")

        # 8. Advanced Brand Spoofing Detection
        is_spoof, spoof_reason, penalty = self._check_brand_spoofing(canonical_res)
        if is_spoof:
            score += penalty
            reasons.append(spoof_reason)

        # 9. Shannon entropy (DGA detection)
        main_label = canonical_res.main_label
        reg_domain = canonical_res.registrable_domain.lower()
        is_cdn = any(
            reg_domain == host.lower() or domain == host.lower() or domain.endswith("." + host.lower())
            for host in self.snapshots.shared_hosting
        )
        is_trusted = self.is_trusted_brand(domain)

        if (
            len(main_label) >= 10
            and "-" not in main_label
            and matched_kw_count == 0
            and not is_cdn
            and not is_trusted
        ):
            entropy = shannon_entropy(main_label)
            if entropy > self.config.get("entropy_threshold", 3.0):
                score += self.config.get("entropy_score", 35)
                reasons.append("high_entropy_dga_suspected")

        # Cap score at 100
        score = min(score, 100)

        # Verdict assignment
        if score >= 70:
            verdict = "MALICIOUS"
        elif score >= 40:
            verdict = "SUSPICIOUS"
        else:
            verdict = "SAFE"

        is_ml_candidate = (verdict == "SUSPICIOUS")

        return LexicalResult(
            domain=domain,
            verdict=verdict,
            score=score,
            reasons=reasons,
            is_ml_candidate=is_ml_candidate,
        )

    def _check_brand_spoofing(self, canonical_res: CanonicalResult) -> Tuple[bool, str, int]:
        domain = canonical_res.domain_ascii
        if not domain:
            return False, "", 0

        reg_domain = canonical_res.registrable_domain.lower()
        if reg_domain == "gov.vn" or reg_domain.endswith(".gov.vn") or domain.endswith(".gov.vn"):
            return False, "", 0

        if self.is_trusted_brand(domain):
            return False, "", 0

        labels = domain.split(".")
        unicode_domain = canonical_res.domain_unicode
        sk_domain = to_skeleton(unicode_domain, self.snapshots.homoglyphs)
        sk_labels = sk_domain.split(".")
        is_homoglyph_spoof = sk_domain != unicode_domain
        brand_spoofing_base = self.config.get("brand_spoofing_score", 50)

        suffix_parts = canonical_res.suffix.split(".")
        tld = suffix_parts[-1] if suffix_parts else ""
        is_susp_tld = self.snapshots.tld_risk.get(tld, False)

        has_regex_match = bool(self.brand_regex and (self.brand_regex.search(domain) or self.brand_regex.search(sk_domain)))

        candidate_brands = []
        seen_brands = set()
        for idx, label in enumerate(labels):
            if len(label) < 4:
                continue
            sk_label = sk_labels[idx] if idx < len(sk_labels) else label
            c1 = sk_label[0]
            for b in self.brand_candidates_by_len.get(len(sk_label), []):
                bname = b["name"]
                if bname in seen_brands:
                    continue
                c2 = bname[0]
                if c1 == c2 or c2 in self.snapshots.keyboard_adjacency.get(c1, "") or sk_label[1:] == bname[1:] or sk_label[:-1] == bname[1:]:
                    seen_brands.add(bname)
                    candidate_brands.append(b)

        if has_regex_match:
            for b in self.snapshots.brands:
                bname = b.get("name", "").lower()
                if bname and (bname in domain or bname in sk_domain) and bname not in seen_brands:
                    seen_brands.add(bname)
                    candidate_brands.append(b)

        if not candidate_brands:
            return False, "", 0

        for brand in candidate_brands:
            brand_name = brand.get("name", "").lower()
            official = brand.get("official_domain", "").lower()
            alts = [a.lower() for a in brand.get("alt_domains", [])]

            if not brand_name or not official:
                continue

            is_official = reg_domain == official or reg_domain in alts
            if is_official:
                continue

            # Typosquatting checks
            for idx, label in enumerate(labels):
                if len(labels) > 1 and idx == len(labels) - 1:
                    continue
                if (
                    len(labels) > 2
                    and idx == len(labels) - 2
                    and label in {"com", "co", "net", "org", "gov", "edu", "ac"}
                ):
                    continue

                sk_label = sk_labels[idx] if idx < len(sk_labels) else label
                min_len = min(len(brand_name), len(sk_label))
                len_diff = abs(len(sk_label) - len(brand_name))
                if min_len < 4 or len_diff > 2:
                    continue

                penalty = brand_spoofing_base + (20 if is_susp_tld else 0)

                # A. Homoglyph visual spoofing
                if sk_label == brand_name and label != brand_name and is_homoglyph_spoof:
                    return (
                        True,
                        f"homoglyph visual spoofing of {brand_name} brand ({label})",
                        penalty,
                    )

                # B. Keyboard weighted typosquatting (only when length diff <= 1)
                if len_diff <= 1:
                    w_dist = weighted_levenshtein_distance(
                        sk_label, brand_name, self.snapshots.keyboard_adjacency
                    )
                    if 0.0 < w_dist <= 1.5:
                        reason = f"keyboard typosquatting of {brand_name} brand ({label})"
                        if sk_label != label:
                            reason = f"homoglyph keyboard typosquatting of {brand_name} brand ({label})"
                        return True, reason, penalty

                # C. Classic Levenshtein
                dist = levenshtein_distance(sk_label, brand_name)
                if 0 < dist <= 2:
                    return True, f"typosquatting of {brand_name} brand ({label})", penalty

            # Brand keyword mention
            if is_suspicious_label(canonical_res.main_label, brand_name) or is_suspicious_label(
                to_skeleton(canonical_res.main_label, self.snapshots.homoglyphs), brand_name
            ):
                penalty = brand_spoofing_base + (20 if is_susp_tld else 0)
                return True, f"suspicious usage of trusted brand keyword ({brand_name})", penalty

            # Subdomain abuse
            for idx, sub_label in enumerate(canonical_res.subdomain_labels):
                sk_sub = to_skeleton(sub_label, self.snapshots.homoglyphs)
                if is_suspicious_label(sub_label, brand_name) or is_suspicious_label(sk_sub, brand_name):
                    penalty = brand_spoofing_base - 10 + (20 if is_susp_tld else 0)
                    return True, f"suspicious brand subdomain usage ({brand_name})", penalty

        return False, "", 0


def process_domain_chunk_to_file(worker_idx: int, domains: List[str], labels: List[int], out_part_path: str) -> str:
    psl = get_psl()
    store = SnapshotStore()
    analyzer = LexicalAnalyzer(snapshot_store=store)

    domain_raw_list = []
    label_list = []
    ascii_list = []
    reg_list = []
    verdict_list = []
    score_list = []
    candidate_list = []
    reasons_list = []

    for d, lbl in zip(domains, labels):
        domain_str = str(d)
        label_val = int(lbl)

        c = canonicalize_domain(domain_str, psl)
        lex = analyzer.analyze(domain_str, c)

        domain_raw_list.append(domain_str)
        label_list.append(label_val)
        ascii_list.append(c.domain_ascii if c.is_valid else domain_str.lower().strip())
        reg_list.append(c.registrable_domain if c.is_valid and c.registrable_domain else (c.domain_ascii if c.is_valid else domain_str.lower().strip()))
        verdict_list.append(lex.verdict)
        score_list.append(lex.score)
        candidate_list.append(lex.is_ml_candidate)
        reasons_list.append("|".join(lex.reasons))

    part_df = pd.DataFrame(
        {
            "domain": domain_raw_list,
            "label": label_list,
            "domain_ascii": ascii_list,
            "registrable_domain": reg_list,
            "lexical_verdict": verdict_list,
            "lexical_score": score_list,
            "is_ml_candidate": candidate_list,
            "reasons": reasons_list,
        }
    )

    part_df.to_parquet(out_part_path, index=False)
    return out_part_path


def build_candidate_cohort(
    dataset_csv: Optional[str] = None,
    provenance_csv: Optional[str] = None,
    output_parquet: Optional[str] = None,
    num_workers: Optional[int] = None,
) -> pd.DataFrame:
    if dataset_csv is None:
        dataset_csv = os.path.join(BASE_DIR, "data", "processed", "domain_dataset.csv")
    if provenance_csv is None:
        provenance_csv = os.path.join(BASE_DIR, "data", "processed", "domain_dataset_provenance.csv")
    if output_parquet is None:
        output_parquet = os.path.join(BASE_DIR, "data", "derived", "candidate_cohort.parquet")

    print(f"[*] Building candidate cohort from {dataset_csv}...", flush=True)
    t0 = time.time()

    table_base = pcsv.read_csv(dataset_csv, convert_options=pcsv.ConvertOptions(include_columns=["domain", "label"]))
    domains = table_base["domain"].to_pylist()
    labels = table_base["label"].to_pylist()
    total_rows = len(domains)
    print(f"[+] Total input rows loaded: {total_rows:,}", flush=True)

    if num_workers is None:
        num_workers = 4

    temp_dir = os.path.join(os.path.dirname(output_parquet), "_temp_cohort_parts")
    os.makedirs(temp_dir, exist_ok=True)

    chunk_size = (total_rows + num_workers - 1) // num_workers
    worker_args = []
    for w in range(num_workers):
        start_idx = w * chunk_size
        end_idx = min(start_idx + chunk_size, total_rows)
        if start_idx < end_idx:
            out_part = os.path.join(temp_dir, f"part_{w}.parquet")
            worker_args.append((w, domains[start_idx:end_idx], labels[start_idx:end_idx], out_part))

    part_files = []
    print(f"[*] Executing across {len(worker_args)} parallel worker processes...", flush=True)
    with ProcessPoolExecutor(max_workers=num_workers) as executor:
        futures = [executor.submit(process_domain_chunk_to_file, *args) for args in worker_args]
        completed = 0
        for f in as_completed(futures):
            part_path = f.result()
            part_files.append(part_path)
            completed += 1
            print(f"[+] Worker {completed}/{len(worker_args)} finished ({part_path}).", flush=True)

    print("[*] Merging chunk Parquet files...", flush=True)
    part_files.sort()
    part_dfs = [pd.read_parquet(pf) for pf in part_files]
    cohort_df = pd.concat(part_dfs, ignore_index=True)

    # Clean up temp directory
    for pf in part_files:
        if os.path.exists(pf):
            os.remove(pf)
    if os.path.exists(temp_dir):
        os.rmdir(temp_dir)

    if os.path.exists(provenance_csv):
        print(f"[*] Joining provenance metadata from {provenance_csv}...", flush=True)
        table_prov = pcsv.read_csv(
            provenance_csv,
            convert_options=pcsv.ConvertOptions(
                include_columns=["source", "impersonated_org", "impersonated_org_category", "detected_date"]
            ),
        )
        df_prov = table_prov.to_pandas()
        if len(cohort_df) == len(df_prov):
            for col in df_prov.columns:
                cohort_df[col] = df_prov[col].fillna("")

    t1 = time.time()
    print(f"[+] Candidate cohort built in {t1 - t0:.2f} seconds.", flush=True)

    verdict_counts = cohort_df["lexical_verdict"].value_counts().to_dict()
    candidate_count = int(cohort_df["is_ml_candidate"].sum())
    print(f"[+] Verdict Breakdown: {verdict_counts}", flush=True)
    print(f"[+] ML Candidate Cohort (SUSPICIOUS): {candidate_count:,} / {total_rows:,} ({candidate_count / total_rows * 100:.2f}%)", flush=True)

    os.makedirs(os.path.dirname(output_parquet), exist_ok=True)
    cohort_df.to_parquet(output_parquet, index=False)
    print(f"[+] Saved candidate cohort to {output_parquet}", flush=True)

    return cohort_df


if __name__ == "__main__":
    build_candidate_cohort()
