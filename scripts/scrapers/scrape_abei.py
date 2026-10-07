#!/usr/bin/env python3
"""
Safe Zone DNS - ABEI Licensed Websites & Domains Scraper
Scrapes & compiles the complete official dataset of all licensed websites, social networks,
general electronic portals, and online games from Cục Phát thanh, truyền hình và thông tin điện tử (ABEI - Bộ TT&TT)
URL: https://giayphep.abei.gov.vn/
Backend API: https://gpttdt-api.abei.gov.vn/services/mcrlmtp/api/license/pivotPaging
"""

import argparse
import csv
import json
import os
import re
import ssl
import sys
import time
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

# Ensure stdout handles UTF-8 safely on Windows terminals
if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='backslashreplace')
    except Exception:
        pass

# TLS verification stays ON. This script feeds data/whitelist and
# data/blacklist, so a man-in-the-middle able to tamper with the response could
# inject arbitrary domains into a blocklist and deny service to legitimate
# sites. If a proxy in the network path breaks verification, trust that proxy's
# CA explicitly via SAFE_ZONE_CA_BUNDLE rather than turning the check off.
SSL_CTX = ssl.create_default_context()
_ca_bundle = os.environ.get("SAFE_ZONE_CA_BUNDLE", "").strip()
if _ca_bundle:
    SSL_CTX.load_verify_locations(cafile=_ca_bundle)

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Content-Type": "application/json",
    "Accept": "application/json, text/plain, */*",
    "Origin": "https://giayphep.abei.gov.vn",
    "Referer": "https://giayphep.abei.gov.vn/"
}

API_COUNT_URL = "https://gpttdt-api.abei.gov.vn/services/mcrlmtp/api/license/pivotCount"
API_PAGING_URL = "https://gpttdt-api.abei.gov.vn/services/mcrlmtp/api/license/pivotPaging"

def clean_host_string(host):
    """Normalizes hostname string."""
    if not host:
        return ""
    host = host.lower().strip()
    host = re.sub(r'^[;\s,/\\\'"]+|[;\s,/\\\'"]+$', '', host)
    host = re.sub(r'^www\d*\.', '', host)
    host = re.sub(r'^\.*|\.*$', '', host)

    if '.' not in host or len(host) < 4:
        return ""
    if re.search(r'[\s,<>\'"]', host):
        return ""
    return host

def extract_domains_from_text(raw_text):
    """Extracts multiple clean domain names from raw text string."""
    if not raw_text or not isinstance(raw_text, str):
        return []

    text = raw_text.strip()
    if not text or text.lower() in ["n/a", "none", "null", "chưa có", "không có", "dacbiet"]:
        return []

    # Split by semicolon, comma, space, newline
    parts = re.split(r'[;\s,\n\r]+', text)
    extracted = []

    for p in parts:
        p = p.strip()
        if not p:
            continue
        if not p.startswith(('http://', 'https://', 'ftp://')):
            p = 'http://' + p

        match = re.search(r'https?://([^/:\s?#]+)', p, re.IGNORECASE)
        if match:
            clean_dom = clean_host_string(match.group(1))
            if clean_dom:
                extracted.append(clean_dom)

    return extracted

def fetch_total_count():
    """Fetches total licensed records count from pivotCount API."""
    try:
        data = json.dumps({}).encode('utf-8')
        req = urllib.request.Request(API_COUNT_URL, data=data, headers=HEADERS, method="POST")
        with urllib.request.urlopen(req, context=SSL_CTX, timeout=15) as res:
            res_json = json.loads(res.read().decode('utf-8'))
            return res_json.get("data", 0)
    except Exception as e:
        print(f"[!] Warning: Failed to fetch total count ({e}). Defaulting to estimate 21000.")
        return 21000

def fetch_batch(start_row, batch_size=100, retries=3):
    """Fetches a single batch of records from pivotPaging API."""
    payload = {
        "startRow": start_row,
        "endRow": start_row + batch_size,
        "sortModel": [{"colId": "validFrom", "sort": "desc"}],
        "filterModel": {}
    }
    data = json.dumps(payload).encode('utf-8')

    for attempt in range(retries):
        try:
            req = urllib.request.Request(API_PAGING_URL, data=data, headers=HEADERS, method="POST")
            with urllib.request.urlopen(req, context=SSL_CTX, timeout=20) as res:
                res_json = json.loads(res.read().decode('utf-8'))
                return res_json.get("data", {}).get("data", []), None
        except Exception as e:
            if attempt < retries - 1:
                time.sleep(1.0 * (attempt + 1))
            else:
                return [], str(e)
    return [], "Max retries exceeded"

def run_scraper(concurrency=10, out_dir="data"):
    """Main orchestrator for ABEI Licensed Domains & Websites dataset compilation."""
    os.makedirs(out_dir, exist_ok=True)
    start_time = time.time()

    print("=" * 75)
    print("  Safe Zone DNS - ABEI Licensed Websites & Domains Scraper")
    print("  Source: Cục Phát thanh, truyền hình và thông tin điện tử (Bộ TT&TT)")
    print("=" * 75)

    total_records = fetch_total_count()
    print(f"[*] Total official licensed records in ABEI database: {total_records}")

    batch_size = 100
    start_rows = list(range(0, total_records + batch_size, batch_size))
    total_batches = len(start_rows)

    print(f"[*] Dispatching {total_batches} batch requests with concurrency={concurrency}...")

    raw_records = []
    errors = []
    completed = 0

    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        future_to_start = {executor.submit(fetch_batch, s, batch_size): s for s in start_rows}

        for future in as_completed(future_to_start):
            s = future_to_start[future]
            try:
                items, err = future.result()
                if err:
                    errors.append((s, err))
                else:
                    raw_records.extend(items)
                    completed += 1
                    if completed % 25 == 0 or completed == total_batches:
                        print(f"[+] Progress: {completed}/{total_batches} batches completed ({len(raw_records)} records fetched)")
            except Exception as exc:
                errors.append((s, str(exc)))

    print(f"[+] API Crawl Complete! Total raw records fetched: {len(raw_records)}")

    # Process and extract domains from all record fields
    unique_domains_dict = {}

    for item in raw_records:
        company_name = (item.get("companyName") or "").strip()
        category = (item.get("platformCategoryName") or "Trang thông tin điện tử").strip()
        license_num = (item.get("licenseNumber") or "").strip()
        valid_from = (item.get("validFrom") or item.get("issueDate") or "").strip()
        if len(valid_from) >= 10:
            valid_from = valid_from[:10]
        status = (item.get("cstatus") or item.get("status") or "valid").strip()

        # Extract URLs from licenseDetail and root
        detail = item.get("licenseDetail") or {}
        text_snippets = []

        if isinstance(detail, dict):
            for k in ["website", "gameHomepage", "socialName", "domain"]:
                v = detail.get(k)
                if v:
                    text_snippets.append(str(v))

        if item.get("website"):
            text_snippets.append(str(item.get("website")))

        # Extract clean domains
        extracted_domains = set()
        for snippet in text_snippets:
            doms = extract_domains_from_text(snippet)
            for d in doms:
                extracted_domains.add(d)

        for dom in extracted_domains:
            entry = {
                "domain": dom,
                "owner": company_name,
                "category_type": category,
                "certified_date": valid_from,
                "cert_level": "Giấy phép chính thức (ABEI - Bộ TT&TT)",
                "license_number": license_num,
                "status": status,
                "detail_url": "https://giayphep.abei.gov.vn/"
            }

            if dom not in unique_domains_dict:
                unique_domains_dict[dom] = entry
            else:
                existing = unique_domains_dict[dom]
                if not existing["owner"] and company_name:
                    existing["owner"] = company_name
                if not existing["license_number"] and license_num:
                    existing["license_number"] = license_num

    sorted_items = sorted(unique_domains_dict.values(), key=lambda x: x["domain"])
    unique_domains_list = sorted(list(unique_domains_dict.keys()))

    duration = round(time.time() - start_time, 2)

    print("\n" + "=" * 75)
    print("  Dataset Compilation Completed Successfully!")
    print("=" * 75)
    print(f"[*] Total raw ABEI records processed: {len(raw_records)}")
    print(f"[*] Total unique clean licensed domains extracted: {len(unique_domains_list)}")
    print(f"[*] Total elapsed time: {duration} seconds")

    # Export 1: JSON Dataset
    json_path = os.path.join(out_dir, "abei_websites.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(sorted_items, f, ensure_ascii=False, indent=2)
    print(f"[+] Saved structured JSON: {json_path}")

    # Export 2: Plain Domain List (TXT)
    txt_path = os.path.join(out_dir, "abei_domains.txt")
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write("# Safe Zone DNS - ABEI Licensed Websites & Domains List\n")
        f.write(f"# Source: Cục Phát thanh, truyền hình và thông tin điện tử (giayphep.abei.gov.vn)\n")
        f.write(f"# Total Licensed Domains: {len(unique_domains_list)}\n")
        f.write(f"# Generated: {datetime.now(timezone.utc).isoformat()}\n\n")
        for dom in unique_domains_list:
            f.write(dom + "\n")
    print(f"[+] Saved plain domain list: {txt_path}")

    # Export 3: CSV Dataset (with UTF-8 BOM)
    csv_path = os.path.join(out_dir, "abei_websites.csv")
    with open(csv_path, "w", encoding="utf-8-sig", newline="") as f:
        fieldnames = ["domain", "owner", "category_type", "certified_date", "cert_level", "license_number", "status", "detail_url"]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(sorted_items)
    print(f"[+] Saved CSV dataset: {csv_path}")

    # Export 4: Summary JSON
    type_counts = {}
    for item in sorted_items:
        t = item["category_type"]
        type_counts[t] = type_counts.get(t, 0) + 1

    tld_counts = {}
    for dom in unique_domains_list:
        parts = dom.split('.')
        tld = parts[-1] if len(parts) > 1 else "unknown"
        if len(parts) > 2 and parts[-1] == 'vn':
            tld = f"{parts[-2]}.vn"
        tld_counts[tld] = tld_counts.get(tld, 0) + 1

    summary = {
        "source": "https://giayphep.abei.gov.vn/ (Cục Phát thanh, truyền hình và thông tin điện tử - Bộ TT&TT)",
        "scraped_at": datetime.now(timezone.utc).isoformat(),
        "duration_seconds": duration,
        "total_raw_records": len(raw_records),
        "total_unique_domains": len(unique_domains_list),
        "category_breakdown": type_counts,
        "top_tlds": dict(sorted(tld_counts.items(), key=lambda x: x[1], reverse=True)[:15]),
        "error_count": len(errors)
    }
    summary_path = os.path.join(out_dir, "abei_summary.json")
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
    print(f"[+] Saved summary metrics: {summary_path}\n")

    return summary

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scrape ABEI Licensed Websites & Domains for Safe Zone DNS.")
    parser.add_argument("--concurrency", type=int, default=10, help="Concurrency (default: 10)")
    parser.add_argument("--out-dir", type=str, default="data", help="Output directory path (default: data)")
    args = parser.parse_args()

    run_scraper(
        concurrency=args.concurrency,
        out_dir=args.out_dir
    )
