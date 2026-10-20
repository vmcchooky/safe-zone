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
"""

import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
MANIFEST = REPO_ROOT / "ml" / "data" / "data_manifest.json"
BUILD_SCRIPT = REPO_ROOT / "scripts" / "data_processing" / "build_domain_dataset.py"

MALICIOUS_TIERS = {"strong-malicious", "specialist-community-malicious", "weak-malicious"}
SAFE_TIERS = {"strong-safe", "weak-safe"}


def _manifest_tiers() -> dict[str, str]:
    with MANIFEST.open(encoding="utf-8") as handle:
        manifest = json.load(handle)
    return {
        entry["logical_name"]: entry["trust_tier"]
        for entry in manifest["raw_sources"]
        if entry.get("logical_name") and entry.get("trust_tier")
    }


def _build_script_policy() -> dict[str, object]:
    """Import the build module so the test reads the shipped policy.

    The module is imported by path because it lives outside the ``src``
    package the other tests import.
    """

    sys.path.insert(0, str(REPO_ROOT / "scripts" / "data_processing"))
    try:
        import build_domain_dataset  # type: ignore[import-not-found]

        return {
            "malicious_tiers": set(build_domain_dataset.MALICIOUS_TIERS),
            "safe_tiers": set(build_domain_dataset.SAFE_TIERS),
            "source_manifest_names": dict(build_domain_dataset.SOURCE_MANIFEST_NAMES),
        }
    finally:
        sys.path.pop(0)


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


def test_no_ad_tracker_source_can_supply_a_positive_label():
    """The core invariant: the build may not label with a non-malicious source."""
    policy = _build_script_policy()
    tiers = _manifest_tiers()
    malicious_tiers = policy["malicious_tiers"]

    for label, manifest_names in policy["source_manifest_names"].items():
        for manifest_name in manifest_names:
            tier = tiers.get(manifest_name)
            assert tier is not None, f"source {label} ({manifest_name}) is not in the manifest"
            if "ad" in tier or "tracker" in tier:
                assert tier not in malicious_tiers, (
                    f"source {label} ({manifest_name}) has trust tier {tier!r} and must not "
                    "be able to supply a positive label"
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
