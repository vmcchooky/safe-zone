import pytest
import sys
import os
import json

# Add ml root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.canonicalize import canonicalize_domain
from src.build_features import (
    FeatureExtractor,
    FEATURE_NAMES,
    TFIDF_INPUT_DOMAIN_ASCII,
    TFIDF_INPUT_WITHOUT_PUBLIC_SUFFIX,
    shannon_entropy,
    tfidf_input_from_domain,
    weighted_levenshtein_distance,
    levenshtein_distance,
    SnapshotStore,
)


def test_feature_extractor_initialization():
    fe = FeatureExtractor()
    assert fe.snapshots is not None
    assert len(fe.snapshots.brands) >= 40
    assert len(fe.snapshots.keywords) >= 15
    assert len(fe.snapshots.shared_hosting) >= 36


def test_feature_names_list():
    assert len(FEATURE_NAMES) == 22
    assert "fqdn_length" in FEATURE_NAMES
    assert "min_brand_keyboard_distance" in FEATURE_NAMES
    assert "has_brand_homoglyph" in FEATURE_NAMES


def test_lexical_and_psl_features():
    fe = FeatureExtractor()
    features = fe.extract_features("https://www.google.com/path")

    assert features["fqdn_length"] == 10
    assert features["num_dots"] == 1
    assert features["num_hyphens"] == 0
    assert features["num_digits"] == 0
    assert features["digit_ratio"] == 0.0
    assert features["main_label_length"] == 6
    assert features["registrable_domain_length"] == 10
    assert features["subdomain_depth"] == 0
    assert features["token_count"] == 2
    assert features["is_punycode"] == 0
    assert features["has_mixed_script"] == 0


def test_dga_entropy_parity():
    # Matches Go TestAnalyzeHighEntropyDGASuspected: "xjfjwqeoas.com"
    fe = FeatureExtractor()
    features = fe.extract_features("xjfjwqeoas.com")

    main_label_entropy = shannon_entropy("xjfjwqeoas")
    assert main_label_entropy > 3.0
    assert features["entropy"] == round(main_label_entropy, 6)
    assert features["max_consecutive_consonants"] == 6


def test_lookup_features_risk_tld_and_keywords():
    fe = FeatureExtractor()
    # Domain with suspicious TLD .xyz and phishing keyword "verify"
    features = fe.extract_features("secure-verify-account.xyz")

    assert features["tld_risk_score"] == 1.0
    assert features["phishing_keyword_count"] >= 2  # matches 'secure', 'verify', 'account'
    assert features["num_hyphens"] == 2


def test_shared_hosting_feature():
    fe = FeatureExtractor()
    # Matches Go CDN test domain: "vietcombank-login.cloudfront.net"
    features = fe.extract_features("vietcombank-login.cloudfront.net")

    assert features["is_shared_hosting"] == 1
    assert features["has_brand_in_main_label"] == 1
    assert features["phishing_keyword_count"] >= 1  # matches 'login'

    # Subdomain brand spoofing
    sub_features = fe.extract_features("vietcombank.example.com")
    assert sub_features["has_brand_in_subdomain"] == 1


def test_brand_parity_official_vs_spoofed():
    fe = FeatureExtractor()

    # Official Vietcombank domain
    official_feats = fe.extract_features("vietcombank.com.vn")
    assert official_feats["min_brand_levenshtein"] == 0.0
    assert official_feats["min_brand_keyboard_distance"] == 0.0
    assert official_feats["has_brand_in_main_label"] == 0

    # Phishing / Spoofed Vietcombank domain
    spoof_feats = fe.extract_features("vietcombank-login.com")
    assert spoof_feats["has_brand_in_main_label"] == 1
    assert spoof_feats["phishing_keyword_count"] >= 1


def test_keyboard_distance_and_levenshtein():
    kbd_adj = {"g": "tyhbvf", "o": "iklp90", "l": "okp", "e": "wsdr34"}

    # Adjacent typo (e.g. 'gogole' vs 'google')
    dist = levenshtein_distance("gogole", "google")
    w_dist = weighted_levenshtein_distance("gogole", "google", kbd_adj)

    assert dist == 2
    assert w_dist <= 2.0


def test_invalid_domain_feature_output():
    fe = FeatureExtractor()
    features = fe.extract_features("192.168.1.1")

    assert features["is_ip_like"] == 1
    assert features["fqdn_length"] == 11
    assert features["main_label_length"] == 0
    assert features["min_brand_levenshtein"] == 99.0


@pytest.mark.parametrize(
    ("domain", "expected"),
    [
        ("example.com", "example"),
        ("login.example.gov.vn", "login.example"),
        ("a.b.example.co.uk", "a.b.example"),
        ("ec2-54-208-233-16.compute-1.amazonaws.com", ""),
    ],
)
def test_tfidf_input_removes_complete_public_suffix(domain, expected):
    assert (
        tfidf_input_from_domain(domain, TFIDF_INPUT_WITHOUT_PUBLIC_SUFFIX)
        == expected
    )
    assert tfidf_input_from_domain(domain, TFIDF_INPUT_DOMAIN_ASCII) == domain


def test_tfidf_suffix_stripping_is_suffix_invariant():
    assert tfidf_input_from_domain(
        "login.example.com", TFIDF_INPUT_WITHOUT_PUBLIC_SUFFIX
    ) == tfidf_input_from_domain(
        "login.example.net", TFIDF_INPUT_WITHOUT_PUBLIC_SUFFIX
    )


def test_v3_snapshot_extensions_are_explicit_and_bounded():
    contract_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "contracts",
        "domain_feature_contract.v3.json",
    )
    with open(contract_path, encoding="utf-8") as handle:
        contract = json.load(handle)
    store = SnapshotStore(snapshot_policy=contract["snapshot_policy"])
    extractor = FeatureExtractor(snapshot_store=store)

    spotify = extractor.extract_features("pl.spotify-original.com")
    xbet = extractor.extract_features("1xbet-xoso.com")
    official = extractor.extract_features("open.spotify.com")
    weebly = extractor.extract_features("tenant.weebly.com")

    assert spotify["has_brand_in_main_label"] == 1
    assert xbet["phishing_keyword_count"] >= 1
    assert official["has_brand_in_main_label"] == 0
    assert weebly["is_shared_hosting"] == 1
