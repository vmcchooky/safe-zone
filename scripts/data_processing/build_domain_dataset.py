#!/usr/bin/env python3
"""Build the reproducible, balanced domain classification dataset.

The raw feed files are intentionally ignored by Git.  Run this module from the
repository root after refreshing the feeds:

    python scripts/build_domain_dataset.py
"""

from __future__ import annotations

import concurrent.futures
import csv
import json
import random
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "data"
OUT = ROOT / "ml" / "data" / "processed"
RANDOM_STATE = 42
DOMAIN_RE = re.compile(r"^[a-z0-9]+([.\-][a-z0-9]+)*\.[a-z]{2,}$")
IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

ORG_CATEGORIES = {
    "bank": ["vietcombank", "techcombank", "mbbank", "tpbank", "vpbank", "bidv", "agribank", "sacombank", "acb", "hdbank", "vietinbank"],
    "ecommerce": ["shopee", "lazada", "tiki", "sendo", "tiktok shop"],
    "ewallet": ["momo", "zalopay", "vnpay", "viettel money"],
    "telecom": ["viettel", "vnpt", "mobifone", "fpt"],
    "government": ["chính phủ", "thuế", "bhxh", "dịch vụ công"],
    "delivery": ["giao hàng", "vận chuyển", "ghn", "ghtk", "j&t"],
    "social": ["facebook", "zalo", "telegram", "tiktok"],
}


def normalize_domain(raw: str | None) -> str | None:
    """Return a normalized RFC-1035-ish FQDN or ``None`` for invalid input."""
    if not raw:
        return None
    d = str(raw).strip().lower().lstrip("\ufeff")
    for prefix in ("https://", "http://", "http:/", "ftp://"):
        if d.startswith(prefix):
            d = d[len(prefix) :]
            break
    if d.startswith("*."):
        d = d[2:]
    if d.startswith("www."):
        d = d[4:]
    d = d.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0].split(":", 1)[0]
    d = re.sub(r"\s*\(.*?\)\s*", "", d).strip(". -")
    while ".." in d:
        d = d.replace("..", ".")
    if IP_RE.fullmatch(d) or not 4 <= len(d) <= 253 or not DOMAIN_RE.fullmatch(d):
        return None
    return d


def normalized(values: Iterable[str]) -> tuple[set[str], int]:
    result: set[str] = set()
    raw = 0
    for value in values:
        raw += 1
        if domain := normalize_domain(value):
            result.add(domain)
    return result, raw


def plain_values(path: Path) -> Iterable[str]:
    with path.open(encoding="utf-8-sig", errors="replace") as source:
        for line in source:
            value = line.strip()
            if value and not value.startswith(("#", "!", "[", "@@")):
                yield value


def parse_rank_csv(path: Path, limit: int | None = None) -> tuple[set[str], int]:
    def values() -> Iterable[str]:
        with path.open(encoding="utf-8-sig", newline="", errors="replace") as source:
            for index, row in enumerate(csv.reader(source)):
                if limit is not None and index >= limit:
                    break
                if len(row) >= 2:
                    yield row[1]

    return normalized(values())


def parse_plaintext(path: Path) -> tuple[set[str], int]:
    return normalized(plain_values(path))


def parse_adblock(path: Path) -> tuple[set[str], int]:
    def values() -> Iterable[str]:
        for rule in plain_values(path):
            if not rule.startswith("||") or "*" in rule or "/" in rule:
                continue
            # Rules may include ^$options.  The hostname is always before ^.
            yield rule[2:].split("^", 1)[0].split("$", 1)[0]

    return normalized(values())


def parse_hosts(path: Path) -> tuple[set[str], int]:
    def values() -> Iterable[str]:
        with path.open(encoding="utf-8-sig", errors="replace") as source:
            for line in source:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                fields = line.split()
                if len(fields) < 2:
                    continue
                host = fields[1]
                if any(bad in host.lower() for bad in ("localhost", "broadcasthost", "ip6-")) or host == "0.0.0.0":
                    continue
                yield host

    return normalized(values())


def hostname_from_url(value: str) -> str | None:
    value = value.strip()
    parsed = urlparse(value if "://" in value else f"//{value}", scheme="http")
    return parsed.hostname


def parse_url_csv(path: Path, url_column: str) -> tuple[set[str], int]:
    def data_lines() -> Iterable[str]:
        with path.open(encoding="utf-8-sig", errors="replace") as source:
            for line in source:
                # URLhaus has a blank separator between its comment banner and
                # a comment-prefixed header; DictReader must see the actual
                # header as its first row.
                if line.startswith("# id,"):
                    yield line[2:]
                elif line.strip() and not line.startswith("#"):
                    yield line

    reader = csv.DictReader(data_lines())
    return normalized(hostname_from_url(row.get(url_column, "")) or "" for row in reader)


def parse_url_list(path: Path) -> tuple[set[str], int]:
    return normalized(hostname_from_url(value) or "" for value in plain_values(path))


def category(org: str) -> str:
    org = org.lower()
    if not org:
        return "unknown"
    for name, keywords in ORG_CATEGORIES.items():
        if any(keyword in org for keyword in keywords):
            return name
    return "other"


def parse_vn_blacklist(path: Path) -> tuple[set[str], dict[str, dict[str, str]], int]:
    with path.open(encoding="utf-8-sig", errors="replace") as source:
        records = json.load(source)
    domains: set[str] = set()
    metadata: dict[str, dict[str, str]] = {}
    for record in records:
        if domain := normalize_domain(record.get("clean_domain") or record.get("raw_domain")):
            domains.add(domain)
            # Keep the first source record: scraping order is stable and reproducible.
            metadata.setdefault(
                domain,
                {
                    "impersonated_org": (record.get("impersonated_org") or "").strip(),
                    "impersonated_org_category": category(record.get("impersonated_org") or ""),
                    "detected_date": (record.get("detected_date") or "").strip(),
                },
            )
    return domains, metadata, len(records)


def parse_vn_whitelist_csv(path: Path) -> tuple[set[str], int]:
    with path.open(encoding="utf-8-sig", newline="", errors="replace") as source:
        return normalized(row.get("domain", "") for row in csv.DictReader(source))


def stat(raw: int, domains: set[str]) -> dict[str, int]:
    return {"raw": raw, "after_normalize": len(domains)}


def source_for(domain: str, candidates: list[tuple[str, set[str]]]) -> str:
    for name, domains in candidates:
        if domain in domains:
            return name
    raise RuntimeError(f"domain has no provenance source: {domain}")


# --- Label policy ---------------------------------------------------------
#
# The data manifest records the trust tier of every raw source. The manifest
# is the single source of truth for that tier, so the label policy is derived
# from it here instead of being restated as another hardcoded list.
#
# A source may only supply a positive (malicious) label when its tier says
# the source is about malware or phishing. The canonical plan forbids using a
# broad ad/tracker blocklist as malicious ground truth (§0.4, §2.3):
# stevenblack_hosts.txt is an ad/tracker list, the manifest already records
# it as "unwanted-ad-tracker", and this build used it as a positive source
# anyway. That inflated the measured recall and understated the real
# false-positive risk, because the negative side is full of ad-tech and CDN
# domains that a model trained on "ads are malicious" learns to block.
MANIFEST = ROOT / "ml" / "data" / "data_manifest.json"

MALICIOUS_TIERS = frozenset(
    {"strong-malicious", "specialist-community-malicious", "weak-malicious"}
)
SAFE_TIERS = frozenset({"strong-safe", "weak-safe"})

# Build label -> manifest logical name(s). A build label may be backed by
# more than one manifest source, for example the Vietnamese allow list,
# which is maintained as a text file and a CSV.
SOURCE_MANIFEST_NAMES = {
    "hagezi": ("hagezi_tif.txt",),
    "tempest_phishing": ("tempest_phishing.txt",),
    "phishtank": ("verified_online.csv",),
    "phishing_army": ("phishing_army.txt",),
    "urlhaus": ("urlhaus.csv",),
    "stevenblack": ("stevenblack_hosts.txt",),
    "openphish": ("openphish.txt",),
    "vietnam_blacklist": ("raw_scraped_domains.json",),
    "tranco": ("tranco_46ZYX.csv",),
    "top_1m": ("top-1m.csv",),
    "vietnam_whitelist": ("vietnam_domains.txt", "vietnam_websites.csv"),
}


def load_manifest_tiers(path: Path = MANIFEST) -> dict[str, str]:
    """Return {logical_name: trust_tier} from the data manifest."""
    with path.open(encoding="utf-8") as source:
        manifest = json.load(source)

    tiers: dict[str, str] = {}
    for entry in manifest.get("raw_sources", []):
        name = str(entry.get("logical_name", "")).strip()
        tier = str(entry.get("trust_tier", "")).strip()
        if name and tier:
            tiers[name] = tier
    return tiers


def resolve_source_tiers(tiers: dict[str, str]) -> dict[str, str]:
    """Map every build label to the trust tier the manifest records for it.

    A source that is not in the manifest is an error: the label policy cannot
    be resolved without it, and guessing is what produced the drift in the
    first place. When a build label is backed by several manifest sources,
    they must all carry the same tier.
    """
    resolved: dict[str, str] = {}
    for label, manifest_names in SOURCE_MANIFEST_NAMES.items():
        label_tiers = set()
        for manifest_name in manifest_names:
            tier = tiers.get(manifest_name)
            if tier is None:
                raise RuntimeError(
                    f"source {label!r} ({manifest_name}) is missing from {MANIFEST.name}; "
                    "refusing to guess its trust tier"
                )
            label_tiers.add(tier)
        if len(label_tiers) > 1:
            raise RuntimeError(
                f"source {label!r} is backed by manifest sources with different trust "
                f"tiers {sorted(label_tiers)}; the label policy is ambiguous"
            )
        resolved[label] = label_tiers.pop()
    return resolved


def split_sources_by_tier(source_tiers: dict[str, str]) -> tuple[list[str], list[str], dict[str, str]]:
    """Split the build labels into positive, negative and excluded."""
    positive = [label for label, tier in source_tiers.items() if tier in MALICIOUS_TIERS]
    negative = [label for label, tier in source_tiers.items() if tier in SAFE_TIERS]
    excluded = {
        label: tier
        for label, tier in source_tiers.items()
        if tier not in MALICIOUS_TIERS and tier not in SAFE_TIERS
    }
    return positive, negative, excluded


def main() -> None:
    # One RNG stream feeds the balance sampling, the negative downsample and
    # the lite sample. A change to the positive pool (for example excluding an
    # ad/tracker source) shifts every later draw, so lite rows can differ even
    # for sources that did not change. Datasets built on either side of a
    # policy change are not row-comparable; compare them on the full dataset,
    # or regenerate both sides before comparing lite-based metrics.
    randomizer = random.Random(RANDOM_STATE)
    stats: dict[str, dict[str, object]] = {}

    with concurrent.futures.ProcessPoolExecutor() as executor:
        f_tranco = executor.submit(parse_rank_csv, DATA / "whitelist/general/tranco_46ZYX.csv", 100_000)
        f_top_1m = executor.submit(parse_rank_csv, DATA / "whitelist/general/top-1m.csv")
        f_vn_txt = executor.submit(parse_plaintext, DATA / "whitelist/vietnam/vietnam_domains.txt")
        f_vn_csv = executor.submit(parse_vn_whitelist_csv, DATA / "whitelist/vietnam/vietnam_websites.csv")
        
        f_hagezi = executor.submit(parse_adblock, DATA / "blacklist/general/hagezi_tif.txt")
        f_tempest = executor.submit(parse_plaintext, DATA / "blacklist/general/tempest_phishing.txt")
        f_phishtank = executor.submit(parse_url_csv, DATA / "blacklist/general/verified_online.csv", "url")
        f_phishing_army = executor.submit(parse_plaintext, DATA / "blacklist/general/phishing_army.txt")
        f_urlhaus = executor.submit(parse_url_csv, DATA / "blacklist/general/urlhaus.csv", "url")
        f_stevenblack = executor.submit(parse_hosts, DATA / "blacklist/general/stevenblack_hosts.txt")
        f_openphish = executor.submit(parse_url_list, DATA / "blacklist/general/openphish.txt")
        f_vn_blacklist = executor.submit(parse_vn_blacklist, DATA / "blacklist/vietnam/raw_scraped_domains.json")

        tranco, tranco_raw = f_tranco.result()
        top_1m, top_raw = f_top_1m.result()
        vn_txt, vn_txt_raw = f_vn_txt.result()
        vn_csv, vn_csv_raw = f_vn_csv.result()
        
        hagezi, hagezi_raw = f_hagezi.result()
        tempest, tempest_raw = f_tempest.result()
        phishtank, phishtank_raw = f_phishtank.result()
        phishing_army, army_raw = f_phishing_army.result()
        urlhaus, urlhaus_raw = f_urlhaus.result()
        stevenblack, steven_raw = f_stevenblack.result()
        openphish, openphish_raw = f_openphish.result()
        vn_blacklist, vn_metadata, vn_blacklist_raw = f_vn_blacklist.result()

    stats["tranco"] = stat(tranco_raw, tranco)
    stats["top_1m"] = stat(top_raw, top_1m)
    stats["vietnam_whitelist"] = stat(vn_txt_raw, vn_txt)

    vn_added = vn_csv - vn_txt
    whitelist = tranco | top_1m | vn_txt | vn_csv
    stats["top_1m"].update({"new_vs_tranco": len(top_1m - tranco)})
    stats["vietnam_whitelist_csv_cross_check"] = {
        "total_in_csv": len(vn_csv), "missing_from_txt": len(vn_added), "added": len(vn_added), "raw": vn_csv_raw
    }

    for name, raw, domains in (
        ("hagezi", hagezi_raw, hagezi), ("tempest_phishing", tempest_raw, tempest),
        ("phishtank", phishtank_raw, phishtank), ("phishing_army", army_raw, phishing_army),
        ("urlhaus", urlhaus_raw, urlhaus), ("stevenblack", steven_raw, stevenblack),
        ("openphish", openphish_raw, openphish), ("vietnam_blacklist_json", vn_blacklist_raw, vn_blacklist),
    ):
        stats[name] = stat(raw, domains)

    # --- Label policy, resolved from the data manifest ---
    source_tiers = resolve_source_tiers(load_manifest_tiers())
    positive_labels, negative_labels, excluded_labels = split_sources_by_tier(source_tiers)
    for label, tier in sorted(excluded_labels.items()):
        print(
            f"excluded from the binary labels: {label} (trust_tier={tier})",
            flush=True,
        )

    source_sets: dict[str, set[str]] = {
        "hagezi": hagezi,
        "tempest_phishing": tempest,
        "phishtank": phishtank,
        "phishing_army": phishing_army,
        "urlhaus": urlhaus,
        "stevenblack": stevenblack,
        "openphish": openphish,
        "vietnam_blacklist": vn_blacklist,
        "tranco": tranco,
        "top_1m": top_1m,
        "vietnam_whitelist": vn_txt | vn_added,
    }
    # Only the manifest-approved sources may label a domain. A source that
    # the manifest does not classify as malicious never becomes a positive
    # label, no matter how large it is.
    positive_sets = {label: source_sets[label] for label in positive_labels}
    negative_sets = {label: source_sets[label] for label in negative_labels}

    mandatory_sources = [
        ("vietnam_blacklist", vn_blacklist), ("phishtank", phishtank),
        ("openphish", openphish), ("phishing_army", phishing_army), ("urlhaus", urlhaus),
    ]
    for label, _ in mandatory_sources:
        if source_tiers[label] not in MALICIOUS_TIERS:
            raise RuntimeError(
                f"mandatory positive source {label!r} has trust tier {source_tiers[label]!r}, "
                "which is not a malicious tier"
            )
    all_blacklist = set().union(*positive_sets.values())
    conflicts = whitelist & all_blacklist
    
    DERIVED = OUT.parent / "derived"
    DERIVED.mkdir(parents=True, exist_ok=True)
    
    with (DERIVED / "conflicts_excluded.csv").open("w", encoding="utf-8", newline="\n") as out_conflicts:
        writer = csv.writer(out_conflicts, lineterminator="\n")
        writer.writerow(("domain", "safe_sources", "malicious_sources"))
        for d in sorted(conflicts):
            ss = [name for name, doms in [("vietnam_whitelist", vn_txt | vn_csv | vn_added), ("tranco", tranco), ("top_1m", top_1m)] if d in doms]
            ms = [name for name, doms in source_sets.items() if d in doms]
            writer.writerow((d, "|".join(ss), "|".join(ms)))

    whitelist -= conflicts
    tranco -= conflicts
    top_1m -= conflicts
    vn_txt -= conflicts
    vn_csv -= conflicts
    vn_added -= conflicts

    hagezi -= conflicts
    tempest -= conflicts
    stevenblack -= conflicts
    phishtank -= conflicts
    phishing_army -= conflicts
    urlhaus -= conflicts
    openphish -= conflicts
    vn_blacklist -= conflicts

    # Keep every high-value phishing/Vietnam/malware record.  Fill the remaining
    # slots from large threat feeds deterministically to reach a 1:1 balance.
    mandatory = set().union(*(domains for _, domains in mandatory_sources))
    target_blacklist = len(whitelist)
    if len(mandatory) > target_blacklist:
        raise RuntimeError("mandatory malicious data exceeds whitelist; revise balance strategy")

    # The balance pool is built only from manifest-approved malicious sources.
    # Excluding a source shrinks the pool, and a pool that cannot fill the
    # 1:1 balance is not a reason to sample a source the manifest says is not
    # malicious: the negative side is shrunk to match instead.
    pool_labels = [label for label in positive_labels if label not in dict(mandatory_sources)]
    pool = set().union(*(source_sets[label] for label in pool_labels)) - mandatory
    wanted = target_blacklist - len(mandatory)
    if wanted > len(pool):
        target_blacklist = len(mandatory) + len(pool)
        wanted = len(pool)
        print(
            f"balance adjusted: the malicious pool holds {len(pool)} domains, "
            f"so the negative side is reduced to {target_blacklist} to keep the 1:1 ratio",
            flush=True,
        )
    sampled_background = set(randomizer.sample(sorted(pool), wanted))
    blacklist = mandatory | sampled_background

    # Keep the negative side at the same size as the positive side.
    if len(whitelist) > target_blacklist:
        whitelist = set(randomizer.sample(sorted(whitelist), target_blacklist))

    for name, domains in (("hagezi", hagezi), ("tempest_phishing", tempest), ("stevenblack", stevenblack)):
        stats[name]["final_sampled"] = len(blacklist & domains)
    for name, domains in mandatory_sources:
        stats[{"vietnam_blacklist": "vietnam_blacklist_json"}.get(name, name)]["final"] = len(blacklist & domains)
    for name, domains in (("tranco", tranco), ("top_1m", top_1m), ("vietnam_whitelist", vn_txt | vn_added)):
        stats[name]["final"] = len(whitelist & domains)
    for label, tier in sorted(excluded_labels.items()):
        stats[label]["excluded_from_labels"] = True
        stats[label]["trust_tier"] = tier

    org_counts = Counter(vn_metadata[d]["impersonated_org_category"] for d in (blacklist & vn_blacklist))
    stats["vietnam_blacklist_json"].update({
        "with_impersonated_org": sum(bool(vn_metadata[d]["impersonated_org"]) for d in (blacklist & vn_blacklist)),
        "org_categories": dict(sorted(org_counts.items())),
    })

    safe_sources = [
        (label, negative_sets[label])
        for label in ("vietnam_whitelist", "tranco", "top_1m")
        if label in negative_sets
    ]
    # The provenance of a positive label comes only from the
    # manifest-approved malicious sources. An excluded source contributes
    # nothing: it may not label a domain, and it may not appear in the
    # provenance of one.
    malicious_sources = mandatory_sources + [
        (label, domains) for label, domains in positive_sets.items() if label not in dict(mandatory_sources)
    ]
    rows: list[tuple[str, int]] = [(d, 0) for d in whitelist] + [(d, 1) for d in blacklist]
    randomizer.shuffle(rows)
    # See the RNG note at the top of main(): this sample is not comparable
    # across label-policy changes because the shared stream has advanced
    # differently.
    lite_safe = set(randomizer.sample(sorted(whitelist), min(150_000, len(whitelist))))
    lite_malicious = set(randomizer.sample(sorted(blacklist), min(150_000, len(blacklist))))
    lite_rows = [(d, 0) for d in lite_safe] + [(d, 1) for d in lite_malicious]
    randomizer.shuffle(lite_rows)

    OUT.mkdir(parents=True, exist_ok=True)
    with (OUT / "domain_dataset.csv").open("w", encoding="utf-8", newline="\n") as output:
        writer = csv.writer(output, lineterminator="\n")
        writer.writerow(("domain", "label"))
        writer.writerows(rows)
    with (OUT / "domain_dataset_lite.csv").open("w", encoding="utf-8", newline="\n") as output:
        writer = csv.writer(output, lineterminator="\n")
        writer.writerow(("domain", "label"))
        writer.writerows(lite_rows)
    with (OUT / "domain_dataset_provenance.csv").open("w", encoding="utf-8", newline="\n") as output:
        writer = csv.DictWriter(output, fieldnames=["domain", "label", "source", "impersonated_org", "impersonated_org_category", "detected_date"], lineterminator="\n")
        writer.writeheader()
        for domain, label in rows:
            source = source_for(domain, malicious_sources if label else safe_sources)
            meta = vn_metadata.get(domain, {}) if source == "vietnam_blacklist" else {}
            writer.writerow({"domain": domain, "label": label, "source": source, **meta})

    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "random_state": RANDOM_STATE,
        "label_policy": {
            "manifest": MANIFEST.name,
            "malicious_tiers": sorted(MALICIOUS_TIERS),
            "safe_tiers": sorted(SAFE_TIERS),
            "source_tiers": source_tiers,
            "positive_sources": sorted(positive_labels),
            "negative_sources": sorted(negative_labels),
            "excluded_sources": excluded_labels,
        },
        "sources": stats,
        "dedup_stats": {
            "cross_source_whitelist_removed": sum(len(s) for s in (tranco, top_1m, vn_txt, vn_csv)) - len(tranco | top_1m | vn_txt | vn_csv),
            "cross_source_blacklist_removed": sum(len(s) for s in positive_sets.values()) - len(all_blacklist),
            "cross_label_conflicts": len(conflicts),
            "cross_label_resolution": "quarantine",
        },
        "final_dataset": {
            "total": len(rows), "label_0_safe": len(whitelist), "label_1_malicious": len(blacklist),
            "ratio_safe_to_malicious": len(whitelist) / len(blacklist), "lite_version_total": len(lite_rows),
        },
    }
    with (OUT / "cleaning_report.json").open("w", encoding="utf-8", newline="\n") as output:
        json.dump(report, output, ensure_ascii=False, indent=2)
        output.write("\n")
    print(f"Wrote {len(rows):,} records ({len(whitelist):,} safe / {len(blacklist):,} malicious) to {OUT}")


if __name__ == "__main__":
    main()
