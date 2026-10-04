#!/usr/bin/env python3
"""
Scrapes all 6,281 pages of the Vietnam malicious website blacklist from
https://tinnhiemmang.vn/website-lua-dao

Key features:
- Asynchronous fetching with aiohttp using 20 concurrent worker tasks
- Custom browser User-Agent and headers to prevent HTTP 403 blocks
- 15s request timeout per page
- Up to 5 retries per page with exponential backoff on HTTP 429/5xx/timeout/connector errors
- Complete page verification and retry loop until all 6,281 pages succeed
- BeautifulSoup / lxml parsing of <li class="item1"> -> <span class="webkit-box-2"> with SVG removal
- Clean domain extraction formatting (strips scheme, path, query, port, www.)
- Saves raw scraped results to JSON and raw domains to TXT in data/blacklist/vietnam/
"""

import asyncio
import json
import logging
import os
import re
import sys
import time
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

import aiohttp
from bs4 import BeautifulSoup
from tqdm.asyncio import tqdm_asyncio

# Target configuration
BASE_URL = "https://tinnhiemmang.vn/website-lua-dao"
DEFAULT_TOTAL_PAGES = 6281
TOTAL_PAGES = int(os.environ.get("MAX_PAGES", DEFAULT_TOTAL_PAGES))
CONCURRENCY = 20
REQUEST_TIMEOUT = 15.0
MAX_RETRIES = 5
BACKOFF_FACTOR = 1.5

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML,"
        " like Gecko) Chrome/122.0.0.0 Safari/537.36"
    ),
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    ),
    "Accept-Language": "vi-VN,vi;q=0.9,en-US;q=0.8,en;q=0.7",
}

# Output paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUT_DIR = os.path.join(BASE_DIR, "data", "blacklist", "vietnam")
OUTPUT_JSON_PATH = os.path.join(OUTPUT_DIR, "raw_scraped_domains.json")
OUTPUT_TXT_PATH = os.path.join(OUTPUT_DIR, "raw_scraped_domains.txt")

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)


DOMAIN_REGEX = re.compile(r'^[a-z0-9]+([\-\.][a-z0-9]+)*\.[a-z]{2,}$')


def _finalize_clean(domain_str: str) -> str:
    """Strip wildcards (*.), www prefix, leading/trailing dots and hyphens."""
    if not domain_str:
        return ""
    s = domain_str.strip().lower()
    while True:
        prev = s
        s = re.sub(r'^[\*\.]+', '', s)
        if s.startswith('www.'):
            s = s[4:]
        s = s.lstrip('. -').rstrip('. -')
        if s == prev:
            break
    return s


def extract_clean_domain(raw_url_or_domain: str) -> str:
    """Extract clean hostname/domain string from raw scraped URL or domain text."""
    if not raw_url_or_domain:
        return ""
    
    s = raw_url_or_domain.strip().lower()
    if not s:
        return ""
    
    # Remove text in parentheses
    s = re.sub(r'\s*\(.*?\)', '', s)
    
    # Remove schemes
    s = re.sub(r'^[a-z0-9+-.]+:/+', '', s)
    s = re.sub(r'^[\*\.]+', '', s)
    
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9+-.]*://', s):
        url_str = 'http://' + s
    else:
        url_str = s

    try:
        parsed = urlparse(url_str)
        host = parsed.hostname
        if host:
            cleaned = _finalize_clean(host)
            return cleaned if DOMAIN_REGEX.match(cleaned) else ""
    except Exception:
        pass

    # Fallback formatting
    clean = re.sub(r'^(?:https?://)?(?:www\.)?', '', s, flags=re.IGNORECASE)
    clean = clean.split('/')[0].split('?')[0].split('#')[0].split(':')[0].strip()
    clean = clean.replace(' ', '')
    cleaned = _finalize_clean(clean)
    return cleaned if DOMAIN_REGEX.match(cleaned) else ""


def parse_page_html(html_content: str, page_num: int) -> List[Dict[str, str]]:
    """Parse HTML of a single page and extract all malicious site records."""
    soup = BeautifulSoup(html_content, 'lxml')
    items = soup.find_all('li', class_='item1')
    records = []
    
    for idx, item in enumerate(items, start=1):
        # 1. Extract domain/URL from span.webkit-box-2
        span = item.find('span', class_='webkit-box-2')
        raw_domain = ""
        clean_domain = ""
        if span:
            # Decompose inline SVG elements
            for svg in span.find_all('svg'):
                svg.decompose()
            raw_domain = span.get_text(strip=True)
            clean_domain = extract_clean_domain(raw_domain)
        
        # 2. Detection date
        date_div = item.find('div', class_=lambda c: c and 'date' in c)
        detected_date = ""
        if date_div:
            date_text = date_div.get_text(strip=True)
            m = re.search(r'(\d{2}/\d{2}/\d{4})', date_text)
            detected_date = m.group(1) if m else date_text

        # 3. Impersonated org
        org_a = item.find('div', class_=lambda c: c and 'org' in c)
        org_text = ""
        if org_a:
            org_text = org_a.get_text(strip=True)
        else:
            org_code = item.find('div', class_=lambda c: c and 'code' in c)
            if org_code:
                org_text = org_code.get_text(strip=True)
        
        # 4. Status
        status_div = item.find('div', class_=lambda c: c and 'status' in c)
        status_text = status_div.get_text(strip=True) if status_div else ""

        records.append({
            "page": page_num,
            "item_index": idx,
            "raw_domain": raw_domain,
            "clean_domain": clean_domain,
            "detected_date": detected_date,
            "impersonated_org": org_text,
            "status": status_text
        })
        
    return records


async def fetch_page(
    session: aiohttp.ClientSession,
    semaphore: asyncio.Semaphore,
    page_num: int
) -> Tuple[int, Optional[str], Optional[str]]:
    """Fetch a single page with retries and exponential backoff."""
    url = f"{BASE_URL}?page={page_num}"
    timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT)
    
    async with semaphore:
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                async with session.get(url, headers=HEADERS, timeout=timeout) as response:
                    if response.status == 200:
                        html = await response.text()
                        return page_num, html, None
                    elif response.status in (429, 500, 502, 503, 504):
                        err_msg = f"HTTP {response.status}"
                    else:
                        err_msg = f"HTTP {response.status}"
            except asyncio.TimeoutError:
                err_msg = "Timeout"
            except aiohttp.ClientError as e:
                err_msg = f"ClientError: {type(e).__name__}"
            except Exception as e:
                err_msg = f"Unexpected: {type(e).__name__}"
            
            if attempt < MAX_RETRIES:
                sleep_time = BACKOFF_FACTOR ** attempt
                await asyncio.sleep(sleep_time)
        
        return page_num, None, err_msg


async def scrape_all_pages() -> Dict[int, List[Dict[str, str]]]:
    """Scrape all pages from 1 to TOTAL_PAGES, ensuring 100% completion via retry passes."""
    pages_to_fetch = list(range(1, TOTAL_PAGES + 1))
    scraped_data: Dict[int, List[Dict[str, str]]] = {}
    
    semaphore = asyncio.Semaphore(CONCURRENCY)
    connector = aiohttp.TCPConnector(limit=CONCURRENCY * 2, ttl_dns_cache=300)
    
    async with aiohttp.ClientSession(connector=connector) as session:
        pass_num = 1
        while pages_to_fetch:
            logger.info(f"--- Starting Scraping Pass {pass_num} ({len(pages_to_fetch)} pages remaining) ---")
            
            tasks = [fetch_page(session, semaphore, page) for page in pages_to_fetch]
            results = await tqdm_asyncio.gather(*tasks, desc=f"Pass {pass_num} progress")
            
            failed_pages = []
            for page_num, html, err_msg in results:
                if html is not None:
                    records = parse_page_html(html, page_num)
                    scraped_data[page_num] = records
                else:
                    failed_pages.append(page_num)
            
            if failed_pages:
                logger.warning(f"Pass {pass_num} completed with {len(failed_pages)} failed pages: {failed_pages[:10]}...")
                pages_to_fetch = failed_pages
                pass_num += 1
                await asyncio.sleep(2)
            else:
                logger.info(f"Pass {pass_num} completed successfully! All requested pages scraped.")
                break
                
    return scraped_data


def save_and_summarize(scraped_data: Dict[int, List[Dict[str, str]]]):
    """Save scraped data to JSON and TXT output files and summarize stats."""
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    total_pages_scraped = len(scraped_data)
    all_records = []
    raw_domains_list = []
    unique_clean_domains: Set[str] = set()
    
    # Process in sorted order of page numbers
    for page_num in sorted(scraped_data.keys()):
        records = scraped_data[page_num]
        for rec in records:
            all_records.append(rec)
            if rec["raw_domain"]:
                raw_domains_list.append(rec["raw_domain"])
            if rec["clean_domain"]:
                unique_clean_domains.add(rec["clean_domain"])

    # 1. Save JSON output
    logger.info(f"Saving raw scraped records to JSON: {OUTPUT_JSON_PATH}")
    with open(OUTPUT_JSON_PATH, "w", encoding="utf-8") as f:
        json.dump(all_records, f, ensure_ascii=False, indent=2)
        
    # 2. Save TXT output (raw scraped domain list)
    logger.info(f"Saving raw scraped domain list to TXT: {OUTPUT_TXT_PATH}")
    with open(OUTPUT_TXT_PATH, "w", encoding="utf-8") as f:
        for domain_str in raw_domains_list:
            f.write(domain_str + "\n")
            
    # Summary report
    print("\n" + "=" * 60)
    print("SCRAPING EXECUTION VERIFICATION SUMMARY")
    print("=" * 60)
    print(f"Total Pages Scraped    : {total_pages_scraped} / {TOTAL_PAGES}")
    print(f"Total Raw Items Scraped: {len(all_records)}")
    print(f"Total Raw Domain Strings: {len(raw_domains_list)}")
    print(f"Total Unique Clean Domains: {len(unique_clean_domains)}")
    print(f"JSON Output Location   : {OUTPUT_JSON_PATH}")
    print(f"TXT Output Location    : {OUTPUT_TXT_PATH}")
    print("=" * 60 + "\n")


def main():
    start_time = time.time()
    logger.info(f"Starting scraping script for {TOTAL_PAGES} pages...")
    
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        
    scraped_data = asyncio.run(scrape_all_pages())
    save_and_summarize(scraped_data)
    
    elapsed = time.time() - start_time
    logger.info(f"Scraping script completed in {elapsed:.2f} seconds.")


if __name__ == "__main__":
    main()
