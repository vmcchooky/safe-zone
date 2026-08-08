#!/usr/bin/env python3
"""
Phase 3 Golden Vectors Exporter for Safe-Zone AI Engine.
Generates comprehensive golden test vectors from the full immutable model bundle ml/models/v1/
and exports ml/tests/fixtures/golden_vectors.v1.json for Go parity and gate validation testing.
"""

import json
import hashlib
import os
import sys
import numpy as np
import lightgbm as lgb
from pathlib import Path
from typing import Any, Dict, List, Tuple
from sklearn.feature_extraction.text import TfidfVectorizer

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))
if str(BASE_DIR / "src") not in sys.path:
    sys.path.insert(0, str(BASE_DIR / "src"))

from src.canonicalize import canonicalize_domain
from src.build_features import FeatureExtractor, FEATURE_NAMES

MODELS_DIR = BASE_DIR / "models" / "v1"
DERIVED_DIR = BASE_DIR / "data" / "derived"
FIXTURES_DIR = BASE_DIR / "tests" / "fixtures"

def compute_sha256(file_path: Path) -> str:
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(8192):
            hasher.update(chunk)
    return hasher.hexdigest()

def load_bundle_metadata():
    model_path = MODELS_DIR / "domain_threat_lgbm.txt"
    raw_model_path = DERIVED_DIR / "models" / "domain_threat_lgbm_raw.txt"
    manifest_path = MODELS_DIR / "feature_manifest.v1.json"
    calib_path = MODELS_DIR / "calibration.json"
    policy_path = MODELS_DIR / "policy.json"
    report_path = MODELS_DIR / "model_report.json"

    for p in [model_path, raw_model_path, manifest_path, calib_path, policy_path, report_path]:
        if not p.exists():
            raise FileNotFoundError(f"Missing required bundle file: {p}")

    model_hash = compute_sha256(model_path)
    manifest_hash = compute_sha256(manifest_path)
    calib_hash = compute_sha256(calib_path)
    policy_hash = compute_sha256(policy_path)

    # Deterministic bundle revision hash (Section 6.4)
    revision_src = f"{model_hash}:{manifest_hash}:{calib_hash}:{policy_hash}"
    bundle_revision = hashlib.sha256(revision_src.encode("utf-8")).hexdigest()

    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest_data = json.load(f)
    with open(calib_path, "r", encoding="utf-8") as f:
        calib_data = json.load(f)
    with open(policy_path, "r", encoding="utf-8") as f:
        policy_data = json.load(f)

    return {
        "model_path": str(model_path),
        "raw_model_path": str(raw_model_path),
        "bundle_revision": bundle_revision,
        "manifest": manifest_data,
        "calib": calib_data,
        "policy": policy_data,
        "hashes": {
            "model": model_hash,
            "manifest": manifest_hash,
            "calibration": calib_hash,
            "policy": policy_hash,
        }
    }

def get_test_domains() -> List[str]:
    """Cover diverse domain types: standard, VN public service, deep subdomains, IDN/punycode, phishing, brand typos."""
    return [
        # Standard benign domains
        "example.com",
        "google.com",
        "facebook.com",
        "wikipedia.org",
        "github.com",

        # VN safe & public service domains
        "chinhphu.vn",
        "baohiemxahoi.gov.vn",
        "dichvucong.gov.vn",
        "hust.edu.vn",
        "vnu.edu.vn",
        "tuoitre.vn",
        "vnexpress.net",

        # Subdomains & deep subdomains
        "sub.portal.edu.vn",
        "a.b.c.d.evil-phishing-test.com",
        "login.account.security-update.net",
        "cdn.static.shared-hosting.cloud",

        # Phishing candidates & lexical suspicious
        "paypal-security-login-verify-account.com",
        "g00gle-login-security.net",
        "appleid-verify-checkpoint-alert.org",
        "account-update-bank.vn-alert.com",
        "safe-zone-security-update-test.xyz",

        # Brand typos & homoglyphs
        "baohiemxah0i.com",
        "chinhphu-portal-verify.info",
        "xn--d1acj3b.xn--p1ai",  # IDN Punycode
        "xn--googl-fxa.com",

        # Edge cases & short/long domains
        "a.co",
        "very-long-domain-name-testing-lexical-entropy-and-character-ngram-tfidf-features-for-safe-zone-ai-engine.tech",
        "1234567890.top",
        "free-crypto-airdrop-claim-now.bid"
    ]

def build_vectorizer_from_manifest(manifest_data: dict) -> Tuple[TfidfVectorizer, List[str]]:
    all_names = manifest_data["feature_names"]
    tfidf_names = all_names[22:] # first 22 are handcrafted

    # Extract terms: char_2_3_<term>
    vocab_dict = {}
    terms = []
    prefix = "char_2_3_"
    for idx, fn in enumerate(tfidf_names):
        term = fn[len(prefix):] if fn.startswith(prefix) else fn
        vocab_dict[term] = idx
        terms.append(term)

    vec = TfidfVectorizer(
        ngram_range=(2, 3),
        analyzer="char",
        lowercase=True,
        sublinear_tf=True,
        norm="l2",
        vocabulary=vocab_dict
    )
    # Fit a tiny dummy corpus to initialize the fixed vocabulary, then restore
    # the learned IDF values exported by the runtime feature contract.
    vec.fit([" ".join(terms)])
    idf_by_index = manifest_data.get("idf_by_index")
    if not isinstance(idf_by_index, list) or len(idf_by_index) != len(terms):
        raise ValueError("feature manifest must contain idf_by_index for golden export")
    vec._tfidf.idf_ = np.asarray(idf_by_index, dtype=np.float64)
    return vec, tfidf_names

def generate_golden_vectors():
    print("Loading LightGBM model bundle...")
    meta = load_bundle_metadata()
    model = lgb.Booster(model_file=meta["raw_model_path"])
    vectorizer, tfidf_names = build_vectorizer_from_manifest(meta["manifest"])
    extractor = FeatureExtractor()

    domains = get_test_domains()
    print(f"Generating golden vectors for {len(domains)} test domains...")

    A = float(meta["calib"]["parameters"]["A"])
    B = float(meta["calib"]["parameters"]["B"])
    block_threshold = float(meta["policy"]["block_threshold"])

    test_cases = []
    for idx, domain in enumerate(domains, 1):
        canon = canonicalize_domain(domain)
        feat_dict = extractor.extract_features(domain, canon)
        handcrafted = np.array([feat_dict[fn] for fn in FEATURE_NAMES], dtype=np.float64)

        # Compute TF-IDF n-grams (512 features)
        tfidf_vec = vectorizer.transform([canon.domain_ascii]).toarray()[0]

        # Combine handcrafted (22) + TF-IDF (512) = 534 features
        feature_vec = np.concatenate([handcrafted, tfidf_vec])

        # Predict raw margin score (raw LightGBM margin)
        raw_margin = float(model.predict([feature_vec], raw_score=True)[0])

        # Uncalibrated probability
        uncalibrated_prob = float(model.predict([feature_vec], raw_score=False)[0])

        # Calibrated probability via Platt Sigmoid: P = 1 / (1 + exp(A * z + B))
        calibrated_prob = float(1.0 / (1.0 + np.exp(A * raw_margin + B)))

        # Policy action
        action = "promote_malicious" if calibrated_prob >= block_threshold else "abstain"

        test_cases.append({
            "id": idx,
            "domain": domain,
            "canonical_ascii": canon.domain_ascii,
            "canonical_unicode": canon.domain_unicode,
            "is_valid": canon.is_valid,
            "raw_margin": raw_margin,
            "uncalibrated_prob": uncalibrated_prob,
            "calibrated_prob": calibrated_prob,
            "action": action,
            "features": feature_vec.tolist()
        })

    fixture_output = {
        "fixture_version": "1.0.0",
        "bundle_revision": meta["bundle_revision"],
        "total_feature_count": 534,
        "num_cases": len(test_cases),
        "calibration": {
            "method": "platt_sigmoid",
            "sigmoid_a": A,
            "sigmoid_b": B,
        },
        "policy": {
            "block_threshold": block_threshold,
            "action_on_block": meta["policy"]["action_on_block"],
            "action_on_pass": meta["policy"]["action_on_pass"]
        },
        "bundle_hashes": meta["hashes"],
        "test_cases": test_cases
    }

    FIXTURES_DIR.mkdir(parents=True, exist_ok=True)
    output_path = FIXTURES_DIR / "golden_vectors.v1.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(fixture_output, f, indent=2)

    print(f"Successfully generated {len(test_cases)} golden test vectors.")
    print(f"Saved to: {output_path}")
    print(f"Bundle Revision: {meta['bundle_revision']}")

if __name__ == "__main__":
    generate_golden_vectors()
