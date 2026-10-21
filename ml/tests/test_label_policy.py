"""The label policy of the domain dataset.

The data manifest records the trust tier of every raw source. A source may
only supply a positive (malicious) label when its tier says the source is
about malware or phishing.

This file pins that rule. The canonical plan forbids using a broad
ad/tracker blocklist as malicious ground truth (§0.4, §2.3), and the build
script used to label with one anyway: stevenblack_hosts.txt is an
ad/tracker list, the manifest records it as "unwanted-ad-tracker", and it
was a positive source. That inflated the measured recall and understated the
real false-positive risk, because the negative side is full of ad-tech and
CDN domains that a model trained on "ads are malicious" learns to block.

The tests call the shipped policy functions, not just their constants: a
special case such as ``or label == "stevenblack"`` inside
``split_sources_by_tier`` must turn this file red.
"""

import ast
import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
MANIFEST = REPO_ROOT / "ml" / "data" / "data_manifest.json"
MAKE_SPLITS = REPO_ROOT / "ml" / "src" / "make_splits.py"
CREATE_MANIFEST = REPO_ROOT / "scripts" / "data_processing" / "create_data_manifest.py"

MALICIOUS_TIERS = {"strong-malicious", "specialist-community-malicious", "weak-malicious"}
SAFE_TIERS = {"strong-safe", "weak-safe"}
LABEL_POLICY_VERSION = 2

POSITIVE_SOURCES = {
    "hagezi",
    "tempest_phishing",
    "phishtank",
    "phishing_army",
    "urlhaus",
    "openphish",
    "vietnam_blacklist",
}
NEGATIVE_SOURCES = {"tranco", "top_1m", "vietnam_whitelist"}


def _manifest_tiers() -> dict[str, str]:
    with MANIFEST.open(encoding="utf-8") as handle:
        manifest = json.load(handle)
    return {
        entry["logical_name"]: entry["trust_tier"]
        for entry in manifest["raw_sources"]
        if entry.get("logical_name") and entry.get("trust_tier")
    }


def _build_module():
    """Import the build module so the tests read the shipped policy.

    The module is imported by path because it lives outside the ``src``
    package the other tests import.
    """

    sys.path.insert(0, str(REPO_ROOT / "scripts" / "data_processing"))
    try:
        import build_domain_dataset  # type: ignore[import-not-found]

        return build_domain_dataset
    finally:
        sys.path.pop(0)


def _build_script_policy() -> dict[str, object]:
    module = _build_module()
    return {
        "malicious_tiers": set(module.MALICIOUS_TIERS),
        "safe_tiers": set(module.SAFE_TIERS),
        "source_manifest_names": dict(module.SOURCE_MANIFEST_NAMES),
    }


def _module_constant(path: Path, name: str):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id == name:
                return ast.literal_eval(node.value)
    raise AssertionError(f"{path} does not define {name}")


def test_manifest_declares_a_trust_tier_for_every_source():
    tiers = _manifest_tiers()
    assert tiers, "the data manifest must record at least one source"
    for name, tier in tiers.items():
        assert tier, f"source {name} has no trust tier"


def test_ad_and_tracker_tiers_are_not_malicious_tiers():
    """The tier that caused the drift must stay out of the positive set."""
    tiers = _manifest_tiers()
    ad_tiers = {
        name: tier
        for name, tier in tiers.items()
        if "ad" in tier or "tracker" in tier
    }
    assert ad_tiers, "the manifest should still classify at least one ad/tracker source"
    for name, tier in ad_tiers.items():
        assert tier not in MALICIOUS_TIERS, (
            f"{name} has trust tier {tier!r}, which must not be a malicious tier"
        )
        assert tier not in SAFE_TIERS, (
            f"{name} has trust tier {tier!r}, which must not be a safe tier either"
        )


def test_build_policy_matches_the_manifest_taxonomy():
    policy = _build_script_policy()
    assert policy["malicious_tiers"] == MALICIOUS_TIERS
    assert policy["safe_tiers"] == SAFE_TIERS


def test_resolve_source_tiers_maps_every_build_label_to_the_manifest():
    module = _build_module()
    resolved = module.resolve_source_tiers(_manifest_tiers())

    assert set(resolved) == set(module.SOURCE_MANIFEST_NAMES)
    assert resolved["stevenblack"] == "unwanted-ad-tracker"
    assert resolved["vietnam_whitelist"] == "strong-safe"
    assert resolved["hagezi"] == "weak-malicious"


def test_split_sources_by_tier_excludes_the_ad_tracker_from_positive():
    """The real split output must match the manifest taxonomy.

    A special case that re-adds stevenblack to the positive list changes the
    output and fails here, even when the tier constants are untouched.
    """
    module = _build_module()
    source_tiers = module.resolve_source_tiers(_manifest_tiers())
    positive, negative, excluded = module.split_sources_by_tier(source_tiers)

    assert set(positive) == POSITIVE_SOURCES
    assert set(negative) == NEGATIVE_SOURCES
    assert excluded == {"stevenblack": "unwanted-ad-tracker"}
    assert "stevenblack" not in positive
    assert "stevenblack" not in negative


def test_split_sources_by_tier_uses_only_the_tier():
    """A source name must not override its tier, in either direction."""
    module = _build_module()
    positive, negative, excluded = module.split_sources_by_tier(
        {
            "stevenblack": "unwanted-ad-tracker",
            "hagezi": "weak-malicious",
            "tranco": "weak-safe",
        }
    )

    assert positive == ["hagezi"]
    assert negative == ["tranco"]
    assert excluded == {"stevenblack": "unwanted-ad-tracker"}


def test_resolve_source_tiers_rejects_a_missing_source():
    module = _build_module()
    tiers = _manifest_tiers()
    tiers.pop("stevenblack_hosts.txt")

    with pytest.raises(RuntimeError, match="stevenblack"):
        module.resolve_source_tiers(tiers)


def test_resolve_source_tiers_rejects_conflicting_tiers():
    module = _build_module()
    tiers = _manifest_tiers()
    tiers["vietnam_websites.csv"] = "weak-safe"

    with pytest.raises(RuntimeError, match="vietnam_whitelist"):
        module.resolve_source_tiers(tiers)


def test_no_ad_tracker_source_can_supply_a_positive_label():
    """The core invariant: the build may not label with a non-malicious source."""
    module = _build_module()
    tiers = _manifest_tiers()
    positive, _, _ = module.split_sources_by_tier(module.resolve_source_tiers(tiers))

    for label in positive:
        tier = tiers[module.SOURCE_MANIFEST_NAMES[label][0]]
        assert tier in module.MALICIOUS_TIERS, (
            f"source {label} has trust tier {tier!r} and must not supply a positive label"
        )


def test_every_source_in_the_manifest_is_accounted_for():
    """A source that the build does not know about is a source it cannot label."""
    policy = _build_script_policy()
    tiers = _manifest_tiers()
    known = {
        manifest_name
        for manifest_names in policy["source_manifest_names"].values()
        for manifest_name in manifest_names
    }
    unknown = set(tiers) - known
    assert not unknown, (
        f"the data manifest lists sources the build does not know about: {sorted(unknown)}; "
        "either the build must label with them or the manifest must drop them"
    )


def test_malicious_and_safe_tiers_do_not_overlap():
    assert not (MALICIOUS_TIERS & SAFE_TIERS)


def test_label_policy_version_is_recorded_everywhere():
    """A split must be traceable to the policy that produced it."""
    with MANIFEST.open(encoding="utf-8") as handle:
        manifest = json.load(handle)

    assert manifest["label_policy_version"] == LABEL_POLICY_VERSION
    for path in (MAKE_SPLITS, CREATE_MANIFEST):
        assert _module_constant(path, "LABEL_POLICY_VERSION") == LABEL_POLICY_VERSION
        assert '"label_policy_version": LABEL_POLICY_VERSION' in path.read_text(encoding="utf-8")
