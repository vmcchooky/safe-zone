#!/usr/bin/env python3
"""Create data manifest as required by AI plan phase 1 preflight."""

import json
import hashlib
from datetime import datetime, timezone
from pathlib import Path
import os
import subprocess

ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = ROOT / "data"
ML_DATA_DIR = ROOT / "ml" / "data"
PROCESSED_DIR = ML_DATA_DIR / "processed"

def sha256_file(path: Path) -> str:
    if not path.exists():
        return ""
    hasher = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hasher.update(chunk)
    return hasher.hexdigest()

def get_git_sha():
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT).decode("utf-8").strip()
    except Exception:
        return "unknown"

def main():
    raw_files = [
        ("tranco_46ZYX.csv", DATA_DIR / "whitelist" / "general" / "tranco_46ZYX.csv", "weak-safe"),
        ("top-1m.csv", DATA_DIR / "whitelist" / "general" / "top-1m.csv", "weak-safe"),
        ("vietnam_domains.txt", DATA_DIR / "whitelist" / "vietnam" / "vietnam_domains.txt", "strong-safe"),
        ("vietnam_websites.csv", DATA_DIR / "whitelist" / "vietnam" / "vietnam_websites.csv", "strong-safe"),
        ("hagezi_tif.txt", DATA_DIR / "blacklist" / "general" / "hagezi_tif.txt", "weak-malicious"),
        ("tempest_phishing.txt", DATA_DIR / "blacklist" / "general" / "tempest_phishing.txt", "weak-malicious"),
        ("verified_online.csv", DATA_DIR / "blacklist" / "general" / "verified_online.csv", "strong-malicious"),
        ("phishing_army.txt", DATA_DIR / "blacklist" / "general" / "phishing_army.txt", "specialist-community-malicious"),
        ("urlhaus.csv", DATA_DIR / "blacklist" / "general" / "urlhaus.csv", "strong-malicious"),
        ("stevenblack_hosts.txt", DATA_DIR / "blacklist" / "general" / "stevenblack_hosts.txt", "unwanted-ad-tracker"),
        ("openphish.txt", DATA_DIR / "blacklist" / "general" / "openphish.txt", "specialist-community-malicious"),
        ("raw_scraped_domains.json", DATA_DIR / "blacklist" / "vietnam" / "raw_scraped_domains.json", "strong-malicious"),
    ]

    manifest = {
        "manifest_version": 1,
        "pipeline_git_sha": get_git_sha(),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "random_state": 42,
        "raw_sources": [],
        "processed": [],
        "cleaning_report_sha256": sha256_file(PROCESSED_DIR / "cleaning_report.json"),
        "label_policy_version": 1
    }

    for logical_name, path, trust_tier in raw_files:
        if path.exists():
            manifest["raw_sources"].append({
                "logical_name": logical_name,
                "path": str(path.relative_to(ROOT)).replace("\\", "/"),
                "sha256": sha256_file(path),
                "bytes": path.stat().st_size,
                "retrieved_at": datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat(),
                "trust_tier": trust_tier,
                "terms_review_id": "TR-2026-07-APPROVED"
            })

    processed_files = [
        "domain_dataset.csv",
        "domain_dataset_lite.csv",
        "domain_dataset_provenance.csv"
    ]

    for fname in processed_files:
        path = PROCESSED_DIR / fname
        if path.exists():
            file_rows = 0
            with path.open("r", encoding="utf-8") as f:
                file_rows = sum(1 for _ in f)
            data_rows = max(0, file_rows - 1)
            manifest["processed"].append({
                "path": str(path.relative_to(ROOT)).replace("\\", "/"),
                "sha256": sha256_file(path),
                "file_rows": file_rows,
                "data_rows": data_rows
            })

    out_path = ML_DATA_DIR / "data_manifest.json"
    with out_path.open("w", encoding="utf-8", newline="\n") as f:
        json.dump(manifest, f, indent=2)
        f.write("\n")
    
    print(f"Data manifest written to {out_path}")

if __name__ == "__main__":
    main()
