#!/usr/bin/env python3
"""
Safe Zone DNS - Trang Vàng Việt Nam Web Scraper
Scrapes legitimate business domains from https://trangvangvietnam.com/
Generates dataset for AI engine training and DNS safe zone lists.
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
from urllib.parse import urlparse, urljoin, unquote
from datetime import datetime, timezone

# Ensure stdout handles UTF-8 safely on Windows terminals
if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='backslashreplace')
    except Exception:
        pass

SEED_URLS = [
    "https://trangvangvietnam.com/",
    "https://trangvangvietnam.com/findex.asp",
    "https://trangvangvietnam.com/categories/484645/logistics-dich-vu-logistics.html",
    "https://trangvangvietnam.com/categories/246160/van-tai-cong-ty-van-tai-va-dai-ly-van-tai.html",
    "https://trangvangvietnam.com/categories/191570/in-bao-bi-cong-ty-thiet-ke-va-in-an-bao-bi.html",
    "https://trangvangvietnam.com/categories/159730/khuon-mau.html",
    "https://trangvangvietnam.com/categories/268180/may-dong-phuc-cong-ty-may-dong-phuc.html",
    "https://trangvangvietnam.com/categories/484507/bao-bi-giay.html",
    "https://trangvangvietnam.com/categories/152060/co-khi--gia-cong-va-che-tao.html",
    "https://trangvangvietnam.com/categories/419935/chuyen-phat-nhanh-cong-ty-chuyen-phat-nhanh.html",
    "https://trangvangvietnam.com/categories/112370/may-mac-cac-cong-ty-may-mac.html",
    "https://trangvangvietnam.com/categories/488209/co-khi-chinh-xac-gia-cong-chi-tiet-linh-kien-phu-tung-theo-yeu-cau.html",
    "https://trangvangvietnam.com/categories/112350/may-mac-nguyen-phu-lieu-may-mac.html",
    "https://trangvangvietnam.com/categories/95260/moi-truong-cong-ty-moi-truong.html",
    "https://trangvangvietnam.com/categories/186010/bao-bi-nhua.html",
    "https://trangvangvietnam.com/categories/256610/xu-ly-nuoc-xu-ly-nuoc-thai-he-thong-xu-ly-nuoc-nuoc-thai.html",
    "https://trangvangvietnam.com/categories/26360/vong-bi-bac-dan.html",
    "https://trangvangvietnam.com/categories/31960/oc-vit-bu-loong.html",
    "https://trangvangvietnam.com/categories/107560/van-chuyen-hang-hoa-giao-nhan-van-chuyen-hang-hoa.html"
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "vi-VN,vi;q=0.9,en-US;q=0.8,en;q=0.7",
    "Connection": "keep-alive"
}

IGNORE_DOMAINS = {
    'trangvangvietnam.com', 'pic.trangvangvietnam.com', 'logo.trangvangvietnam.com',
    'signup.trangvangvietnam.com', 'facebook.com', 'youtube.com', 'zalo.me',
    'online.gov.vn', 'schema.org', 'w3.org', 'google.com', 'googletagmanager.com',
    'shopee.vn', 'lazada.vn', 'tiktok.com', 'tiki.vn', 'sendo.vn'
}

def fetch_url(url, retries=3, backoff=1.0, timeout=15):
    """Fetches a URL with polite retries and backoff handling."""
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers=HEADERS)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                html = resp.read().decode('utf-8', errors='ignore')
                return url, html, None
        except Exception as e:
            if attempt < retries - 1:
                time.sleep(backoff * (attempt + 1))
            else:
                return url, None, str(e)

def extract_domain(raw_url):
    """Extracts clean domain name from URL or link target."""
    if not raw_url:
        return None
    try:
        raw_url = unquote(raw_url)
        if 'out.asp?url=' in raw_url:
            raw_url = raw_url.split('out.asp?url=')[-1]
        if not raw_url.startswith(('http://', 'https://')):
            if raw_url.startswith('//'):
                raw_url = 'http:' + raw_url
            else:
                raw_url = 'http://' + raw_url
        parsed = urlparse(raw_url)
        netloc = parsed.netloc.lower().split(':')[0]
        if netloc.startswith('www.'):
            netloc = netloc[4:]
        netloc = re.sub(r'^\.*', '', netloc).strip()
        
        if netloc and '.' in netloc and not any(ign in netloc for ign in IGNORE_DOMAINS):
            if re.match(r'^[a-z0-9.-]+\.[a-z]{2,}$', netloc):
                return netloc
    except Exception:
        pass
    return None

def extract_categories_from_html(html):
    """Finds category URLs in page HTML."""
    if not html:
        return set()
    matches = set(re.findall(r'href=["\'](https?://trangvangvietnam\.com/categories/\d+/[^"\']+\.html|/categories/\d+/[^"\']+\.html)["\']', html))
    categories = set()
    for m in matches:
        full_url = urljoin("https://trangvangvietnam.com/", m)
        categories.add(full_url)
    return categories

def extract_listings_from_html(html, category_url):
    """Extracts company listings and business domain names from a category HTML page."""
    listings = []
    if not html:
        return listings, set()

    page_numbers = re.findall(r'[?&]page=(\d+)', html)
    max_page = max([int(p) for p in page_numbers]) if page_numbers else 1

    cat_title_match = re.search(r'<h1[^>]*>(.*?)</h1>', html, re.DOTALL)
    cat_title = re.sub(r'<[^>]+>', '', cat_title_match.group(1)).strip() if cat_title_match else ""

    hrefs = re.findall(r'href=["\']([^"\']+)["\']', html)
    out_links = re.findall(r'out\.asp\?url=([^"\'&]+)', html)
    candidates = set(hrefs)
    for o in out_links:
        candidates.add(unquote(o))

    seen_domains = set()
    for c in candidates:
        domain = extract_domain(c)
        if domain and domain not in seen_domains:
            seen_domains.add(domain)
            listings.append({
                "domain": domain,
                "website_url": c if c.startswith('http') else f"http://{domain}",
                "category": cat_title,
                "category_url": category_url
            })

    return listings, max_page

def run_scraper(max_categories=50, max_pages_per_cat=5, concurrency=4, delay=0.15, out_dir="data"):
    """Main Trang Vàng Việt Nam scraping orchestrator."""
    os.makedirs(out_dir, exist_ok=True)
    start_time = time.time()

    print("=" * 60)
    print("  Safe Zone DNS - Trang Vang Viet Nam Web Scraper")
    print("=" * 60)
    print(f"[*] Max categories target: {max_categories}")
    print(f"[*] Max pages per category: {max_pages_per_cat}")
    print(f"[*] Concurrency: {concurrency} threads")

    # Step 1: Discover categories (Seed + Crawled)
    print("\n[*] Phase 1: Discovering category directory URLs...")
    discovered_cats = set([u for u in SEED_URLS if '/categories/' in u])
    
    with ThreadPoolExecutor(max_workers=min(3, len(SEED_URLS))) as executor:
        futures = {executor.submit(fetch_url, url): url for url in SEED_URLS}
        for future in as_completed(futures):
            _, html, err = future.result()
            if html:
                cats = extract_categories_from_html(html)
                discovered_cats.update(cats)

    cat_list = sorted(list(discovered_cats))[:max_categories]
    print(f"[+] Discovered {len(discovered_cats)} category URLs. Selected {len(cat_list)} categories to crawl.")

    # Step 2: Crawl category pages and extract listings
    print("\n[*] Phase 2: Crawling category pages & extracting business domains...")
    all_listings = []
    errors = []
    completed_cats = 0

    tasks = [(cat_url, 1) for cat_url in cat_list]

    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        future_to_task = {executor.submit(fetch_url, url): (url, page) for url, page in tasks}

        while future_to_task:
            done_futures = list(as_completed(future_to_task))
            for future in done_futures:
                url, page = future_to_task.pop(future)
                try:
                    _, html, err = future.result()
                    if err:
                        errors.append((url, err))
                    elif html:
                        listings, detected_max = extract_listings_from_html(html, url)
                        all_listings.extend(listings)
                        completed_cats += 1

                        if page == 1 and detected_max > 1:
                            pages_to_fetch = min(detected_max, max_pages_per_cat)
                            for p in range(2, pages_to_fetch + 1):
                                p_url = f"{url}?page={p}"
                                extra_future = executor.submit(fetch_url, p_url)
                                future_to_task[extra_future] = (p_url, p)

                        if completed_cats % 15 == 0:
                            print(f"[+] Progress: {completed_cats} category pages crawled ({len(all_listings)} raw domain records collected)")
                except Exception as exc:
                    errors.append((url, str(exc)))

                if delay > 0:
                    time.sleep(delay)

    # Step 3: Clean & Deduplicate domains
    unique_domains_dict = {}
    for item in all_listings:
        dom = item["domain"]
        if dom not in unique_domains_dict or (not unique_domains_dict[dom]["category"] and item["category"]):
            unique_domains_dict[dom] = item

    sorted_items = sorted(unique_domains_dict.values(), key=lambda x: x["domain"])
    unique_domains_list = sorted(list(unique_domains_dict.keys()))

    duration = round(time.time() - start_time, 2)

    print("\n" + "=" * 60)
    print("  Scraping Completed Successfully!")
    print("=" * 60)
    print(f"[*] Total raw entries collected: {len(all_listings)}")
    print(f"[*] Unique business domains extracted: {len(unique_domains_list)}")
    print(f"[*] Total category pages processed: {completed_cats}")
    print(f"[*] Total elapsed time: {duration} seconds")

    if len(unique_domains_list) == 0:
        print("[!] Warning: No domains extracted in this run. Skipping file save to preserve existing dataset.")
        return {}

    # Export 1: JSON Dataset
    json_path = os.path.join(out_dir, "trangvang_websites.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(sorted_items, f, ensure_ascii=False, indent=2)
    print(f"[+] Saved structured JSON: {json_path}")

    # Export 2: Plain Domain List (TXT)
    txt_path = os.path.join(out_dir, "trangvang_domains.txt")
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write("# Safe Zone DNS - Trang Vang Viet Nam Business Domain List\n")
        f.write(f"# Source: https://trangvangvietnam.com/\n")
        f.write(f"# Total Domains: {len(unique_domains_list)}\n")
        f.write(f"# Generated: {datetime.now(timezone.utc).isoformat()}\n\n")
        for dom in unique_domains_list:
            f.write(dom + "\n")
    print(f"[+] Saved plain domain list: {txt_path}")

    # Export 3: CSV Dataset (with UTF-8 BOM)
    csv_path = os.path.join(out_dir, "trangvang_websites.csv")
    with open(csv_path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["domain", "website_url", "category", "category_url"])
        writer.writeheader()
        writer.writerows(sorted_items)
    print(f"[+] Saved CSV dataset: {csv_path}")

    # Export 4: Summary JSON
    tld_counts = {}
    for dom in unique_domains_list:
        parts = dom.split('.')
        tld = parts[-1] if len(parts) > 1 else "unknown"
        if len(parts) > 2 and parts[-1] == 'vn':
            tld = f"{parts[-2]}.vn"
        tld_counts[tld] = tld_counts.get(tld, 0) + 1

    summary = {
        "source": "https://trangvangvietnam.com/",
        "scraped_at": datetime.now(timezone.utc).isoformat(),
        "duration_seconds": duration,
        "categories_processed": completed_cats,
        "total_raw_records": len(all_listings),
        "total_unique_domains": len(unique_domains_list),
        "top_tlds": dict(sorted(tld_counts.items(), key=lambda x: x[1], reverse=True)[:15]),
        "error_count": len(errors)
    }
    summary_path = os.path.join(out_dir, "trangvang_summary.json")
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
    print(f"[+] Saved summary metrics: {summary_path}\n")

    return summary

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scrape Trang Vàng Việt Nam business domain list for Safe Zone DNS AI training.")
    parser.add_argument("--max-categories", type=int, default=50, help="Maximum categories to crawl (default: 50)")
    parser.add_argument("--max-pages-per-cat", type=int, default=5, help="Maximum pages per category (default: 5)")
    parser.add_argument("--concurrency", type=int, default=4, help="Number of worker threads (default: 4)")
    parser.add_argument("--delay", type=float, default=0.15, help="Delay between page requests in seconds (default: 0.15)")
    parser.add_argument("--out-dir", type=str, default="data", help="Output directory path (default: data)")
    args = parser.parse_args()

    run_scraper(
        max_categories=args.max_categories,
        max_pages_per_cat=args.max_pages_per_cat,
        concurrency=args.concurrency,
        delay=args.delay,
        out_dir=args.out_dir
    )
