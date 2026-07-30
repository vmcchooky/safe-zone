#!/usr/bin/env python3
"""Build the reproducible, balanced domain classification dataset.

The raw feed files are intentionally ignored by Git.  Run this module from the
repository root after refreshing the feeds:

    python scripts/build_domain_dataset.py
"""

from __future__ import annotations

import csv
import json
import random
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parents[1]
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


def main() -> None:
    randomizer = random.Random(RANDOM_STATE)
    stats: dict[str, dict[str, object]] = {}

    tranco, tranco_raw = parse_rank_csv(DATA / "whitelist/general/tranco_46ZYX.csv", limit=100_000)
    top_1m, top_raw = parse_rank_csv(DATA / "whitelist/general/top-1m.csv")
    vn_txt, vn_txt_raw = parse_plaintext(DATA / "whitelist/vietnam/vietnam_domains.txt")
    vn_csv, vn_csv_raw = parse_vn_whitelist_csv(DATA / "whitelist/vietnam/vietnam_websites.csv")
    stats["tranco"] = stat(tranco_raw, tranco)
    stats["top_1m"] = stat(top_raw, top_1m)
    stats["vietnam_whitelist"] = stat(vn_txt_raw, vn_txt)

    vn_added = vn_csv - vn_txt
    whitelist = tranco | top_1m | vn_txt | vn_csv
    stats["top_1m"].update({"new_vs_tranco": len(top_1m - tranco)})
    stats["vietnam_whitelist_csv_cross_check"] = {
        "total_in_csv": len(vn_csv), "missing_from_txt": len(vn_added), "added": len(vn_added), "raw": vn_csv_raw
    }

    hagezi, hagezi_raw = parse_adblock(DATA / "blacklist/general/hagezi_tif.txt")
    tempest, tempest_raw = parse_plaintext(DATA / "blacklist/general/tempest_phishing.txt")
    phishtank, phishtank_raw = parse_url_csv(DATA / "blacklist/general/verified_online.csv", "url")
    phishing_army, army_raw = parse_plaintext(DATA / "blacklist/general/phishing_army.txt")
    urlhaus, urlhaus_raw = parse_url_csv(DATA / "blacklist/general/urlhaus.csv", "url")
    stevenblack, steven_raw = parse_hosts(DATA / "blacklist/general/stevenblack_hosts.txt")
    openphish, openphish_raw = parse_url_list(DATA / "blacklist/general/openphish.txt")
    vn_blacklist, vn_metadata, vn_blacklist_raw = parse_vn_blacklist(DATA / "blacklist/vietnam/raw_scraped_domains.json")

    for name, raw, domains in (
        ("hagezi", hagezi_raw, hagezi), ("tempest_phishing", tempest_raw, tempest),
        ("phishtank", phishtank_raw, phishtank), ("phishing_army", army_raw, phishing_army),
        ("urlhaus", urlhaus_raw, urlhaus), ("stevenblack", steven_raw, stevenblack),
        ("openphish", openphish_raw, openphish), ("vietnam_blacklist_json", vn_blacklist_raw, vn_blacklist),
    ):
        stats[name] = stat(raw, domains)

    mandatory_sources = [
        ("vietnam_blacklist", vn_blacklist), ("phishtank", phishtank),
        ("openphish", openphish), ("phishing_army", phishing_army), ("urlhaus", urlhaus),
    ]
    all_blacklist = set().union(*(domains for _, domains in mandatory_sources), hagezi, tempest, stevenblack)
    conflicts = whitelist & all_blacklist
    whitelist -= conflicts  # Blacklist priority.

    # Keep every high-value phishing/Vietnam/malware record.  Fill the remaining
    # slots from large threat feeds deterministically to reach a 1:1 balance.
    mandatory = set().union(*(domains for _, domains in mandatory_sources))
    target_blacklist = len(whitelist)
    if len(mandatory) > target_blacklist:
        raise RuntimeError("mandatory malicious data exceeds whitelist; revise balance strategy")
    pool = (hagezi | tempest | stevenblack) - mandatory
    sampled_background = set(randomizer.sample(sorted(pool), target_blacklist - len(mandatory)))
    blacklist = mandatory | sampled_background

    for name, domains in (("hagezi", hagezi), ("tempest_phishing", tempest), ("stevenblack", stevenblack)):
        stats[name]["final_sampled"] = len(blacklist & domains)
    for name, domains in mandatory_sources:
        stats[{"vietnam_blacklist": "vietnam_blacklist_json"}.get(name, name)]["final"] = len(blacklist & domains)
    for name, domains in (("tranco", tranco), ("top_1m", top_1m), ("vietnam_whitelist", vn_txt | vn_added)):
        stats[name]["final"] = len(whitelist & domains)

    org_counts = Counter(vn_metadata[d]["impersonated_org_category"] for d in (blacklist & vn_blacklist))
    stats["vietnam_blacklist_json"].update({
        "with_impersonated_org": sum(bool(vn_metadata[d]["impersonated_org"]) for d in (blacklist & vn_blacklist)),
        "org_categories": dict(sorted(org_counts.items())),
    })

    safe_sources = [("vietnam_whitelist", vn_txt | vn_added), ("tranco", tranco), ("top_1m", top_1m)]
    malicious_sources = mandatory_sources + [("hagezi", hagezi), ("tempest_phishing", tempest), ("stevenblack", stevenblack)]
    rows: list[tuple[str, int]] = [(d, 0) for d in whitelist] + [(d, 1) for d in blacklist]
    randomizer.shuffle(rows)
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
        "sources": stats,
        "dedup_stats": {
            "cross_source_whitelist_removed": sum(len(s) for s in (tranco, top_1m, vn_txt, vn_csv)) - len(tranco | top_1m | vn_txt | vn_csv),
            "cross_source_blacklist_removed": sum(len(s) for s in (hagezi, tempest, phishtank, phishing_army, urlhaus, stevenblack, openphish, vn_blacklist)) - len(all_blacklist),
            "cross_label_conflicts": len(conflicts),
            "cross_label_resolution": "blacklist_priority",
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
