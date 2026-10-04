#!/usr/bin/env python3
"""Scrape Vietnamese domain groups from the HackerTarget hostsearch API.

Replaces the former scraper_gov.py and scraper_biz_news.py, which were the same
program with a different query list and output filename. Both are folded into
the CATEGORIES table below so adding a group is a data change, not a new file.

HackerTarget's hostsearch endpoint returns "host,ip" lines for a TLD or
substring query. It is a passive source with a rate limit, so the sleep between
requests is deliberate.
"""

import argparse
import json
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = ROOT / "data"

API_URL = "https://api.hackertarget.com/hostsearch/?q={query}"
TLD_SUFFIX = ".vn"
REQUEST_TIMEOUT = 30
REQUEST_DELAY_SECONDS = 2

# key -> (queries, category_type). Adding a group means adding a row here.
CATEGORIES = {
    "gov": {
        "queries": ["gov.vn", "bank.com.vn"],
        "category_type": "Chính phủ & Ngân hàng",
    },
    "biz_news": {
        "queries": ["com.vn", "news.vn", "bao.vn", "tapchi.vn", "group.vn"],
        "category_type": "Doanh nghiệp & Báo chí",
    },
}


def fetch_query(query):
    """Return the raw hostsearch response for one query, or "" on failure."""
    request = urllib.request.Request(
        API_URL.format(query=query),
        headers={"User-Agent": "Mozilla/5.0"},
    )
    try:
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT) as response:
            return response.read().decode("utf-8")
    except (urllib.error.URLError, OSError) as error:
        print(f"[hackertarget] error fetching {query}: {error}")
        return ""


def parse_domains(content):
    """Pull the Vietnamese domains out of a hostsearch response.

    Each line is "host,ip". A malformed line yields an empty first field, so a
    length check alone is not enough -- the field has to look like a domain too.
    """
    domains = set()
    for line in content.split("\n"):
        host = line.split(",")[0].strip().lower()
        if host.endswith(TLD_SUFFIX):
            domains.add(host)
    return domains


def scrape(category):
    """Scrape one category and return its records."""
    spec = CATEGORIES[category]
    domains = set()
    for query in spec["queries"]:
        domains |= parse_domains(fetch_query(query))
        time.sleep(REQUEST_DELAY_SECONDS)
    return [
        {
            "domain": domain,
            "owner": "Unknown",
            "category_type": spec["category_type"],
            "source": "hackertarget",
        }
        for domain in sorted(domains)
    ]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "categories",
        nargs="*",
        choices=sorted(CATEGORIES),
        default=sorted(CATEGORIES),
        help="categories to scrape (default: all)",
    )
    args = parser.parse_args()
    categories = args.categories or sorted(CATEGORIES)

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    for category in categories:
        records = scrape(category)
        out_path = DATA_DIR / f"crawled_{category}.json"
        with out_path.open("w", encoding="utf-8") as handle:
            json.dump(records, handle, ensure_ascii=False, indent=2)
        print(f"[hackertarget] saved {len(records)} {category} domains to {out_path}")


if __name__ == "__main__":
    main()