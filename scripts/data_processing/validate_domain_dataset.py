#!/usr/bin/env python3
"""Validate the generated domain dataset for preflight rules."""

import json
import csv
import sys
import re
from pathlib import Path
import hashlib

ROOT = Path(__file__).resolve().parents[2]
PROCESSED_DIR = ROOT / "ml" / "data" / "processed"
DERIVED_DIR = ROOT / "ml" / "data" / "derived"
MANIFEST_PATH = ROOT / "ml" / "data" / "data_manifest.json"

DOMAIN_RE = re.compile(r"^[a-z0-9]+([.\-][a-z0-9]+)*\.[a-z]{2,}$")
IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

def sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hasher.update(chunk)
    return hasher.hexdigest()

def main():
    if not MANIFEST_PATH.exists():
        print("ERROR: data_manifest.json missing!")
        sys.exit(1)
        
    with MANIFEST_PATH.open("r", encoding="utf-8") as f:
        manifest = json.load(f)

    # Check checksums
    for f in manifest.get("processed", []):
        path = ROOT / f["path"]
        if not path.exists():
            print(f"ERROR: Processed file {f['path']} missing!")
            sys.exit(1)
        if sha256_file(path) != f["sha256"]:
            print(f"ERROR: Checksum mismatch for {f['path']}!")
            sys.exit(1)

    # Read the final dataset
    dataset_csv = PROCESSED_DIR / "domain_dataset.csv"
    seen_domains = set()
    label_counts = {0: 0, 1: 0}
    
    with dataset_csv.open("r", encoding="utf-8") as f:
        reader = csv.reader(f)
        header = next(reader)
        if header != ["domain", "label"]:
            print("ERROR: domain_dataset.csv header invalid!")
            sys.exit(1)
            
        for row in reader:
            d, l = row
            # valid FQDN / IP check
            if IP_RE.fullmatch(d):
                print(f"ERROR: Bare IP found in dataset: {d}")
                sys.exit(1)
            if not DOMAIN_RE.fullmatch(d):
                print(f"ERROR: Invalid FQDN found in dataset: {d}")
                sys.exit(1)
            
            # duplicate check
            if d in seen_domains:
                print(f"ERROR: Duplicate domain found: {d}")
                sys.exit(1)
            seen_domains.add(d)
            label_counts[int(l)] += 1

    # Conflict exclusion check
    conflicts_csv = DERIVED_DIR / "conflicts_excluded.csv"
    if not conflicts_csv.exists():
        print("ERROR: conflicts_excluded.csv missing!")
        sys.exit(1)
        
    with conflicts_csv.open("r", encoding="utf-8") as f:
        reader = csv.reader(f)
        next(reader) # skip header
        for row in reader:
            if row[0] in seen_domains:
                print(f"ERROR: Conflict domain {row[0]} was NOT excluded from the trainable set!")
                sys.exit(1)

    # Check match with cleaning_report
    report_path = PROCESSED_DIR / "cleaning_report.json"
    with report_path.open("r", encoding="utf-8") as f:
        report = json.load(f)
        
    final_stats = report.get("final_dataset", {})
    if final_stats.get("label_0_safe") != label_counts[0]:
        print("ERROR: label_0_safe count mismatch!")
        sys.exit(1)
    if final_stats.get("label_1_malicious") != label_counts[1]:
        print("ERROR: label_1_malicious count mismatch!")
        sys.exit(1)
        
    print("SUCCESS: Data Preflight Validation Passed!")

if __name__ == "__main__":
    main()
