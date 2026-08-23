"""
Phase 2 & Phase 3 Artifact Bundle Exporter
Packages LightGBM text model, feature manifest, calibration mapping, policy, and model report
into an immutable bundle directory ml/models/v1/ with SHA256SUMS verification.
Ensures version=v3 header compatibility for pure Go leaves library.
"""

import argparse
import hashlib
import json
import os
import shutil
import sys
import time

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)


def compute_file_sha256(filepath: str) -> str:
    # Go canonicalizes text bundle files to LF before verification so the same
    # immutable revision works on Windows and Linux checkouts.
    with open(filepath, "rb") as f:
        canonical = f.read().replace(b"\r\n", b"\n")
    return hashlib.sha256(canonical).hexdigest()


def run_exporter(config_path: str):
    t0 = time.time()
    print(f"[*] Loading configuration from {config_path}...", flush=True)
    with open(config_path, "r", encoding="utf-8") as f:
        cfg = json.load(f)

    models_derived_dir = os.path.join(BASE_DIR, cfg.get("models_dir", "data/derived/models"))
    bundle_dir = os.path.join(BASE_DIR, cfg.get("bundle_dir", "models/v1"))
    os.makedirs(bundle_dir, exist_ok=True)

    raw_model_src = os.path.join(models_derived_dir, "domain_threat_lgbm_raw.txt")
    cal_src = os.path.join(models_derived_dir, "calibration.json")
    report_src = os.path.join(models_derived_dir, "model_report.json")
    derived_dir = os.path.join(BASE_DIR, cfg.get("derived_dir", "data/derived"))
    feature_manifest_src = os.path.join(derived_dir, "feature_manifest.json")

    for p, name in [
        (raw_model_src, "LightGBM model text"),
        (cal_src, "Calibration JSON"),
        (report_src, "Model Report JSON"),
        (feature_manifest_src, "Feature Manifest JSON"),
    ]:
        if not os.path.exists(p):
            raise FileNotFoundError(f"Source artifact missing for bundle: {name} at {p}")

    # Copy files into bundle
    print(f"[*] Exporting immutable model bundle to {bundle_dir}...", flush=True)
    model_dst = os.path.join(bundle_dir, "domain_threat_lgbm.txt")
    cal_dst = os.path.join(bundle_dir, "calibration.json")
    report_dst = os.path.join(bundle_dir, "model_report.json")
    feature_dst = os.path.join(bundle_dir, "feature_manifest.v1.json")

    # Ensure leaves Go compatibility by replacing version=v4 header with version=v3 at top of file
    with open(raw_model_src, "r", encoding="utf-8") as f_in:
        content = f_in.read()
    if content.startswith("tree\nversion=v4"):
        content = "tree\nversion=v3" + content[len("tree\nversion=v4"):]
    with open(model_dst, "w", encoding="utf-8") as f_out:
        f_out.write(content)

    shutil.copy2(cal_src, cal_dst)
    shutil.copy2(report_src, report_dst)
    shutil.copy2(feature_manifest_src, feature_dst)

    # Generate policy.json
    policy_cfg = cfg.get("policy", {})
    policy = {
        "policy_version": policy_cfg.get("policy_version", "1.0.0"),
        "operating_mode": policy_cfg.get("operating_mode", "enforce_v1"),
        "block_threshold": float(policy_cfg.get("block_threshold", 0.85)),
        "action_on_block": policy_cfg.get("action_on_block", "PROMOTE_SUSPICIOUS_TO_MALICIOUS"),
        "action_on_pass": policy_cfg.get("action_on_pass", "ABSTAIN_KEEP_SUSPICIOUS"),
        "allow_threshold_enabled": False,
        "created_at": policy_cfg.get(
            "created_at", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        ),
    }
    policy_dst = os.path.join(bundle_dir, "policy.json")
    with open(policy_dst, "w", encoding="utf-8") as f:
        json.dump(policy, f, indent=2)

    # Generate SHA256SUMS
    sums_path = os.path.join(bundle_dir, "SHA256SUMS")
    bundle_files = [
        "domain_threat_lgbm.txt",
        "feature_manifest.v1.json",
        "calibration.json",
        "policy.json",
        "model_report.json",
    ]

    sums_lines = []
    print("\n--- Model Bundle Checksums ---", flush=True)
    for fname in bundle_files:
        fpath = os.path.join(bundle_dir, fname)
        sha = compute_file_sha256(fpath)
        sums_lines.append(f"{sha}  {fname}\n")
        print(f"  {sha}  {fname}", flush=True)

    with open(sums_path, "w", encoding="utf-8") as f:
        f.writelines(sums_lines)

    print(f"\n[+] Bundle successfully exported to {bundle_dir} in {time.time() - t0:.2f}s", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Export Immutable Model Bundle")
    parser.add_argument("--config", type=str, default=os.path.join(BASE_DIR, "configs/v1.json"), help="Config path")
    args = parser.parse_args()
    run_exporter(args.config)
