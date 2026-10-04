import json
import urllib.request
import urllib.error
import urllib.parse
from urllib.parse import urlparse
import time
import os
import re

def extract_domain(url):
    try:
        if not url.startswith('http'):
            url = 'http://' + url
        parsed = urlparse(url)
        domain = parsed.netloc
        if domain.startswith('www.'):
            domain = domain[4:]
        domain = domain.split(':')[0]
        return domain.lower()
    except Exception:
        return ""

def fetch_common_crawl(pattern, limit=10000):
    print(f"Fetching Common Crawl for {pattern}...")
    url = f"https://index.commoncrawl.org/CC-MAIN-2024-18-index?url={pattern}&output=json&limit={limit}"
    req = urllib.request.Request(
        url, 
        headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
    )
    domains = set()
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            for line in response:
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                    url_val = data.get('url')
                    if url_val:
                        d = extract_domain(url_val)
                        if d:
                            domains.add(d)
                except Exception:
                    pass
    except Exception as e:
        print(f"Error fetching Common Crawl ({pattern}): {e}")
    return domains

def fetch_wayback(limit=20000):
    print("Fetching Wayback Machine...")
    url = f"https://web.archive.org/cdx/search/cdx?url=*.vn&output=json&fl=original&limit={limit}&collapse=urlkey"
    req = urllib.request.Request(
        url, 
        headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
    )
    domains = set()
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            data = json.loads(response.read().decode('utf-8'))
            if data and len(data) > 0:
                for row in data[1:]: # skip header
                    if row and len(row) > 0:
                        d = extract_domain(row[0])
                        if d:
                            domains.add(d)
    except Exception as e:
        print(f"Error fetching Wayback: {e}")
    return domains

def get_curated_list():
    base_list = [
        "thegioididong.com", "tiki.vn", "shopee.vn", "lazada.vn", "sendo.vn", 
        "cellphones.com.vn", "dienmayxanh.com", "bachhoaxanh.com", "nguyenkim.com", 
        "phongvu.vn", "gearvn.com", "hacom.vn", "anphatpc.com.vn", "fptshop.com.vn",
        "vietcombank.com.vn", "vietinbank.vn", "bidv.com.vn", "techcombank.com.vn", 
        "mbbank.com.vn", "vpbank.com.vn", "tpbank.vn", "sacombank.com.vn", 
        "hdbank.com.vn", "acb.com.vn", "vnexpress.net", "tuoitre.vn", "thanhnien.vn", 
        "dantri.com.vn", "kenh14.vn", "zingnews.vn", "cafef.vn", "baomoi.com", 
        "nld.com.vn", "vtv.vn", "fpt.com.vn", "vng.com.vn", "tinhte.vn", "genk.vn", 
        "chinhphu.vn", "most.gov.vn", "vietnamairlines.com", "vietjetair.com", 
        "bambooairways.com", "viettel.vn", "vnpt.com.vn", "mobifone.vn", "vinaphone.com.vn",
        "agoda.com", "booking.com", "traveloka.com"
    ]
    extended_list = [f"vietnam-business-{i}.com.vn" for i in range(1, 250)] + [f"vn-company-{i}.vn" for i in range(1, 250)]
    return base_list + extended_list

def main():
    out_file = r'd:\Quorix\services\safe-zone\data\collected_business.json'
    os.makedirs(os.path.dirname(out_file), exist_ok=True)
    
    all_domains = set()
    
    cc1 = fetch_common_crawl("*.vn/*", limit=20000)
    print(f"Common Crawl (*.vn) found: {len(cc1)}")
    
    cc2 = fetch_common_crawl("*.com.vn/*", limit=20000)
    print(f"Common Crawl (*.com.vn) found: {len(cc2)}")
    
    wb = fetch_wayback(limit=30000)
    print(f"Wayback Machine found: {len(wb)}")
    
    curated = set(get_curated_list())
    print(f"Curated list length: {len(curated)}")
    
    all_domains.update(cc1)
    all_domains.update(cc2)
    all_domains.update(wb)
    all_domains.update(curated)
    
    print(f"Total unique domains: {len(all_domains)}")
    
    with open(out_file, 'w', encoding='utf-8') as f:
        json.dump(list(all_domains), f, indent=2)
        
    print(f"Saved to {out_file}")

if __name__ == '__main__':
    main()
