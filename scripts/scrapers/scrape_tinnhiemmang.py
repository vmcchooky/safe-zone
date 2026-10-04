#!/usr/bin/env python3
"""
Safe Zone DNS - Tín Nhiệm Mạng Web Scraper
Scrapes legitimate certified website domains from https://tinnhiemmang.vn/website-tin-nhiem
Generates datasets for AI engine training and DNS whitelist rules.
"""

import argparse
import csv
import json
import os
import re
import sys
import time
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from html import unescape
from datetime import datetime, timezone

# Ensure stdout handles UTF-8 safely on Windows terminals
if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='backslashreplace')
    except Exception:
        pass

BASE_URL = "https://tinnhiemmang.vn/website-tin-nhiem"
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "vi-VN,vi;q=0.9,en-US;q=0.8,en;q=0.7",
}

def fetch_page(page_num, retries=3, backoff=1.5):
    """Fetches a single page HTML with retry logic."""
    url = f"{BASE_URL}?page={page_num}"
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers=HEADERS)
            with urllib.request.urlopen(req, timeout=15) as resp:
                html = resp.read().decode('utf-8', errors='replace')
                return page_num, html, None
        except Exception as e:
            if attempt < retries - 1:
                time.sleep(backoff * (attempt + 1))
            else:
                return page_num, None, str(e)

def parse_tinnhiemmang_page(html):
    """
    Parses a single HTML page of website-tin-nhiem and returns a list of dictionaries containing:
    - domain
    - owner
    - certified_date
    - cert_level
    - detail_url
    """
    items = []
    if not html:
        return items
        
    domain_blocks = re.finditer(
        r'<a\s+href="([^"]*tinnhiemmang\.vn/danh-ba-tin-nhiem/[^"]*)"[^>]*>\s*<span>\s*([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\s*</span>',
        html
    )
    
    matches = list(domain_blocks)
    for i, m in enumerate(matches):
        detail_url = m.group(1).strip()
        domain = m.group(2).strip().lower()
        
        # Clean domain (strip www., trailing dots)
        domain = re.sub(r'^\.*', '', domain).strip()
        
        start_idx = m.start()
        end_idx = matches[i+1].start() if i+1 < len(matches) else len(html)
        slice_html = html[start_idx:end_idx]
        
        # Date match
        date_m = re.search(r'T\xedn nhi\u1ec7m m\u1ea1ng:\s*([\d/]+)|Tín nhiệm mạng:\s*([\d/]+)', slice_html)
        certified_date = ""
        if date_m:
            certified_date = date_m.group(1) or date_m.group(2) or ""
            
        # Owner match
        owner_m = re.search(r'S\u1edf h\u1eefu b\u1edfi:.*?>\s*([^<]+)</a>|Sở hữu bởi:.*?>\s*([^<]+)</a>', slice_html, re.DOTALL)
        owner = ""
        if owner_m:
            raw_owner = owner_m.group(1) or owner_m.group(2) or ""
            owner = unescape(raw_owner).strip()
            
        # Cert level match
        cert_level = ""
        if 'Chứng nhận nâng cao' in slice_html or 'n\xe2ng cao' in slice_html or 'medal_advanced' in slice_html:
            cert_level = 'Chứng nhận nâng cao'
        elif 'Chứng nhận cơ bản' in slice_html or 'c\u01a1 b\u1ea3n' in slice_html or 'medal_basic' in slice_html:
            cert_level = 'Chứng nhận cơ bản'
            
        items.append({
            "domain": domain,
            "owner": owner,
            "certified_date": certified_date,
            "cert_level": cert_level,
            "detail_url": detail_url
        })
        
    return items

def get_max_pages():
    """Detects total pagination pages from page 1."""
    _, html, err = fetch_page(1)
    if err or not html:
        print(f"[!] Warning: Failed to fetch page 1 for page count detection ({err}). Defaulting to 610.")
        return 610, html
        
    pages = re.findall(r'page=(\d+)', html)
    if pages:
        max_p = max(int(p) for p in pages)
        return max_p, html
    return 1, html

def run_scraper(max_pages=None, concurrency=8, delay=0.05, out_dir="data"):
    """Main scraping orchestrator."""
    os.makedirs(out_dir, exist_ok=True)
    start_time = time.time()
    
    print("=" * 60)
    print("  Safe Zone DNS - Tin Nhiem Mang Web Scraper")
    print("=" * 60)
    
    detected_max, p1_html = get_max_pages()
    total_pages = max_pages if max_pages else detected_max
    print(f"[*] Detected total pages: {detected_max}")
    print(f"[*] Scraping pages 1 to {total_pages} with {concurrency} threads...")
    
    all_items = []
    errors = []
    
    if p1_html:
        p1_items = parse_tinnhiemmang_page(p1_html)
        all_items.extend(p1_items)
        remaining_pages = list(range(2, total_pages + 1))
    else:
        remaining_pages = list(range(1, total_pages + 1))
        
    completed_pages = 1 if p1_html and max_pages != 0 else 0
    
    if remaining_pages:
        with ThreadPoolExecutor(max_workers=concurrency) as executor:
            future_to_page = {executor.submit(fetch_page, p): p for p in remaining_pages}
            
            for future in as_completed(future_to_page):
                page_num = future_to_page[future]
                try:
                    p_num, html, err = future.result()
                    if err:
                        errors.append((page_num, err))
                        print(f"[-] Page {page_num}/{total_pages} failed: {err}")
                    else:
                        items = parse_tinnhiemmang_page(html)
                        all_items.extend(items)
                        completed_pages += 1
                        if completed_pages % 25 == 0 or completed_pages == total_pages:
                            print(f"[+] Progress: {completed_pages}/{total_pages} pages completed ({len(all_items)} items collected)")
                except Exception as exc:
                    errors.append((page_num, str(exc)))
                    print(f"[-] Page {page_num} generated exception: {exc}")
                
                if delay > 0:
                    time.sleep(delay)

    # Deduplicate items by domain while keeping richest metadata
    unique_domains_dict = {}
    for item in all_items:
        dom = item["domain"]
        if dom not in unique_domains_dict or (not unique_domains_dict[dom]["owner"] and item["owner"]):
            unique_domains_dict[dom] = item

    sorted_items = sorted(unique_domains_dict.values(), key=lambda x: x["domain"])
    unique_domains_list = sorted(list(unique_domains_dict.keys()))

    duration = round(time.time() - start_time, 2)
    
    print("\n" + "=" * 60)
    print("  Scraping Completed Successfully!")
    print("=" * 60)
    print(f"[*] Total raw entries parsed: {len(all_items)}")
    print(f"[*] Unique domains extracted: {len(unique_domains_list)}")
    print(f"[*] Total pages scraped: {completed_pages}/{total_pages}")
    print(f"[*] Total elapsed time: {duration} seconds")
    if errors:
        print(f"[!] Encountered {len(errors)} page errors.")

    # Export 1: JSON Dataset
    json_path = os.path.join(out_dir, "tinnhiemmang_websites.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(sorted_items, f, ensure_ascii=False, indent=2)
    print(f"[+] Saved structured JSON: {json_path}")

    # Export 2: Plain Domain List (TXT)
    txt_path = os.path.join(out_dir, "tinnhiemmang_domains.txt")
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write("# Safe Zone DNS - Tin Nhiem Mang Trusted Domain List\n")
        f.write(f"# Source: https://tinnhiemmang.vn/website-tin-nhiem\n")
        f.write(f"# Total Domains: {len(unique_domains_list)}\n")
        f.write(f"# Generated: {datetime.now(timezone.utc).isoformat()}\n\n")
        for dom in unique_domains_list:
            f.write(dom + "\n")
    print(f"[+] Saved plain domain list: {txt_path}")

    # Export 3: CSV Dataset (with UTF-8 BOM for Excel compatibility)
    csv_path = os.path.join(out_dir, "tinnhiemmang_websites.csv")
    with open(csv_path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["domain", "owner", "certified_date", "cert_level", "detail_url"])
        writer.writeheader()
        writer.writerows(sorted_items)
    print(f"[+] Saved CSV dataset: {csv_path}")

    # Export 4: Summary & Analytics JSON
    cert_level_counts = {}
    for item in sorted_items:
        lvl = item["cert_level"] or "Chưa rõ"
        cert_level_counts[lvl] = cert_level_counts.get(lvl, 0) + 1

    summary = {
        "source": "https://tinnhiemmang.vn/website-tin-nhiem",
        "scraped_at": datetime.now(timezone.utc).isoformat(),
        "duration_seconds": duration,
        "total_pages_scraped": completed_pages,
        "total_raw_records": len(all_items),
        "total_unique_domains": len(unique_domains_list),
        "cert_level_breakdown": cert_level_counts,
        "error_pages": [p[0] for p in errors]
    }
    summary_path = os.path.join(out_dir, "tinnhiemmang_summary.json")
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
    print(f"[+] Saved summary metrics: {summary_path}\n")

    return summary

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scrape Tín Nhiệm Mạng website list for Safe Zone DNS training dataset.")
    parser.add_argument("--max-pages", type=int, default=None, help="Maximum pages to scrape (default: auto-detect ~610)")
    parser.add_argument("--concurrency", type=int, default=8, help="Number of worker threads (default: 8)")
    parser.add_argument("--delay", type=float, default=0.05, help="Delay between page requests in seconds (default: 0.05)")
    parser.add_argument("--out-dir", type=str, default="data", help="Output directory path (default: data)")
    args = parser.parse_args()

    run_scraper(max_pages=args.max_pages, concurrency=args.concurrency, delay=args.delay, out_dir=args.out_dir)
