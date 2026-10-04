"""
ml/src/train_mini_model.py

Trains a mini-LightGBM model according to domain_feature_contract.v1.json
and exports fixtures for Phase 0D leaves Go spike testing:
- ml/tests/fixtures/mini_lightgbm_v1.txt
- ml/tests/fixtures/parity_test_cases.json
- ml/tests/fixtures/malformed_model.txt
"""

import json
import math
import os
import sys
import time
from typing import Dict, List, Any

import lightgbm as lgb
import numpy as np
import pandas as pd
from scipy.sparse import hstack, csr_matrix
from sklearn.feature_extraction.text import TfidfVectorizer

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from src.canonicalize import canonicalize_domain, get_psl
from src.build_features import FeatureExtractor, FEATURE_NAMES, SnapshotStore


def main():
    print("[*] Starting mini-LightGBM model training for contract v1...")

    contract_path = os.path.join(BASE_DIR, "contracts", "domain_feature_contract.v1.json")
    with open(contract_path, "r", encoding="utf-8") as f:
        contract = json.load(f)

    csv_path = os.path.join(BASE_DIR, "data", "processed", "domain_dataset_lite.csv")
    df = pd.read_csv(csv_path)
    total_rows = len(df)
    print(f"[+] Loaded {total_rows:,} rows from dataset.")

    # 1. Feature extraction on all rows
    psl = get_psl()
    store = SnapshotStore()
    extractor = FeatureExtractor(snapshot_store=store)

    handcrafted_rows = []
    ascii_domains = []
    for d in df['domain']:
        c = canonicalize_domain(str(d), psl)
        f_vec = extractor.extract_features(str(d), c)
        handcrafted_rows.append([f_vec[fn] for fn in FEATURE_NAMES])
        ascii_domains.append(c.domain_ascii if c.is_valid else str(d).lower().strip())

    X_hand = np.array(handcrafted_rows, dtype=np.float64)
    y = df['label'].values

    # Train/val split (80/20)
    split_idx = int(0.8 * total_rows)
    X_hand_tr, X_hand_va = X_hand[:split_idx], X_hand[split_idx:]
    ascii_tr, ascii_va = ascii_domains[:split_idx], ascii_domains[split_idx:]
    y_tr, y_va = y[:split_idx], y[split_idx:]

    # 2. Fit TF-IDF on train split ONLY
    tfidf_cfg = contract["tfidf_config"]
    vec = TfidfVectorizer(
        ngram_range=tuple(tfidf_cfg["ngram_range"]),
        max_features=tfidf_cfg["max_features"],
        analyzer=tfidf_cfg["analyzer"],
        lowercase=tfidf_cfg["lowercase"],
        sublinear_tf=tfidf_cfg["sublinear_tf"],
        norm=tfidf_cfg["norm"]
    )

    X_tf_tr = vec.fit_transform(ascii_tr)
    X_tf_va = vec.transform(ascii_va)

    # Combine handcrafted + TF-IDF
    X_comb_tr = hstack([csr_matrix(X_hand_tr), X_tf_tr]).tocsr()
    X_comb_va = hstack([csr_matrix(X_hand_va), X_tf_va]).tocsr()

    print(f"[+] Combined feature matrix shape: Train {X_comb_tr.shape}, Val {X_comb_va.shape}")
    assert X_comb_tr.shape[1] == contract["total_feature_count"], "Feature count mismatch with contract v1!"

    # 3. Train LightGBM Booster
    train_data = lgb.Dataset(X_comb_tr, label=y_tr)
    val_data = lgb.Dataset(X_comb_va, label=y_va, reference=train_data)

    params = {
        "objective": "binary",
        "metric": "binary_logloss",
        "boosting_type": "gbdt",
        "num_leaves": 31,
        "learning_rate": 0.05,
        "feature_fraction": 0.9,
        "verbose": -1,
        "seed": 42
    }

    print("[*] Fitting LightGBM model...")
    booster = lgb.train(
        params,
        train_data,
        num_boost_round=150,
        valid_sets=[val_data]
    )

    # 4. Save fixtures
    fixtures_dir = os.path.join(BASE_DIR, "tests", "fixtures")
    os.makedirs(fixtures_dir, exist_ok=True)

    model_txt_path = os.path.join(fixtures_dir, "mini_lightgbm_v1.txt")
    booster.save_model(model_txt_path)

    # Normalize version header for leaves parser compatibility (version=v4 -> version=v3)
    with open(model_txt_path, "r", encoding="utf-8") as f_in:
        txt_data = f_in.read()

    txt_data_v3 = txt_data.replace("version=v4\n", "version=v3\n", 1)
    with open(model_txt_path, "w", encoding="utf-8") as f_out:
        f_out.write(txt_data_v3)

    print(f"[+] Model text artifact saved to {model_txt_path} (normalized version=v3 for leaves parser)")

    # Malformed model fixture
    malformed_txt_path = os.path.join(fixtures_dir, "malformed_model.txt")
    corrupted_content = txt_data_v3[:len(txt_data_v3) // 2] + "\n[Corrupted End]\n"
    with open(malformed_txt_path, "w", encoding="utf-8") as f_out:
        f_out.write(corrupted_content)
    print(f"[+] Malformed model fixture saved to {malformed_txt_path}")

    # Save 1,000 prediction parity test cases
    parity_cases_path = os.path.join(fixtures_dir, "parity_test_cases.json")
    num_samples = min(1000, len(y_va))
    sample_indices = np.arange(num_samples)

    X_sample_dense = X_comb_va[sample_indices].toarray()
    raw_scores = booster.predict(X_sample_dense, raw_score=True)
    probabilities = booster.predict(X_sample_dense, raw_score=False)

    test_cases = []
    for idx in range(num_samples):
        domain_name = df['domain'].iloc[split_idx + idx]
        feats = X_sample_dense[idx].tolist()
        raw_m = float(raw_scores[idx])
        prob = float(probabilities[idx])

        test_cases.append({
            "id": idx,
            "domain": str(domain_name),
            "features": feats,
            "raw_margin": raw_m,
            "probability": prob
        })

    with open(parity_cases_path, "w", encoding="utf-8") as f:
        json.dump({
            "contract_version": contract["contract_version"],
            "total_feature_count": contract["total_feature_count"],
            "num_cases": len(test_cases),
            "test_cases": test_cases
        }, f, indent=2)

    print(f"[+] Parity test cases (1,000 samples) saved to {parity_cases_path}")
    print("[+] Mini-model training & fixture export completed successfully!")


if __name__ == "__main__":
    main()
