"""
Expansion 3: Public Search Indices & Open-Access Datasets (No Paid APIs)
Collects real Vietnamese domains from CT logs, open GitHub repositories,
Wayback CDX, and public web search index dumps.
"""
import urllib.request
import urllib.parse
import json
import os
import re
import ssl
import time

data_dir = r"d:\Quorix\services\safe-zone\data"
output_path = os.path.join(data_dir, "expansion_public_indices.json")

all_found_domains = set()

# TLS verification stays ON. Discovered domains land in the blocklist feeds, so
# a man-in-the-middle able to tamper with a response could inject arbitrary
# hosts. If a proxy in the network path breaks verification, trust that proxy's
# CA explicitly via SAFE_ZONE_CA_BUNDLE rather than turning the check off.
ssl_ctx = ssl.create_default_context()
_ca_bundle = os.environ.get("SAFE_ZONE_CA_BUNDLE", "").strip()
if _ca_bundle:
    ssl_ctx.load_verify_locations(cafile=_ca_bundle)

def fetch_url_text(url, timeout=15):
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/json,text/plain"
        })
        with urllib.request.urlopen(req, timeout=timeout, context=ssl_ctx) as resp:
            return resp.read().decode("utf-8", errors="ignore")
    except Exception as e:
        print(f"Error fetching {url[:60]}: {e}")
        return ""

def clean_and_add_domain(d):
    if not d:
        return
    d = d.lower().strip()
    d = re.sub(r"^\*\.", "", d)
    d = re.sub(r"^https?://", "", d)
    d = re.sub(r"^www\.", "", d)
    d = d.split("/")[0].split(":")[0].strip()
    
    # Must look like a valid domain
    if "." in d and not d.startswith(".") and not d.endswith(".") and ".." not in d and " " not in d:
        if d.endswith(".vn") or any(d.endswith(suffix) for suffix in [".com", ".net", ".org", ".io", ".tech", ".co", ".app"]):
            all_found_domains.add(d)

print("=== Source 3.1: Public GitHub Vietnam Domain Lists ===")
github_raw_urls = [
    "https://raw.githubusercontent.com/trilwu/VietnamDomains/master/dotcom.vn.txt",
    "https://raw.githubusercontent.com/trilwu/VietnamDomains/master/dotvn.txt",
    "https://raw.githubusercontent.com/bigdatalog/vietnam-domains/main/domains.txt",
    "https://raw.githubusercontent.com/abpvn/abpvn/master/filter/abpvn.txt",
    "https://raw.githubusercontent.com/bigdatalog/vietnam-domains/main/vietnam_websites.txt",
    "https://raw.githubusercontent.com/bigdatalog/vietnam-domains/main/vietnam_domains.txt"
]

for url in github_raw_urls:
    print(f"Fetching {url}...")
    content = fetch_url_text(url)
    if content:
        lines = content.splitlines()
        cnt_before = len(all_found_domains)
        for line in lines:
            line = line.strip()
            if line and not line.startswith("#") and not line.startswith("!"):
                # extract domain patterns
                matches = re.findall(r"([a-z0-9][a-z0-9.\-]+\.[a-z]{2,})", line, re.IGNORECASE)
                for m in matches:
                    clean_and_add_domain(m)
        print(f"  Found {len(all_found_domains) - cnt_before} new domains")

print(f"\nTotal domains so far: {len(all_found_domains)}")

print("\n=== Source 3.2: Certificate Transparency Logs (crt.sh expanded queries) ===")
crtsh_queries = [
    "%.com.vn", "%.vn", "%.net.vn", "%.org.vn", "%.edu.vn", "%.gov.vn", "%.biz.vn", "%.info.vn"
]

for q in crtsh_queries:
    url = f"https://crt.sh/?q={urllib.parse.quote(q)}&output=json"
    print(f"Querying crt.sh for {q}...")
    content = fetch_url_text(url, timeout=30)
    if content and content.startswith("["):
        try:
            records = json.loads(content)
            cnt_before = len(all_found_domains)
            for rec in records:
                name_val = rec.get("name_value", "")
                common_name = rec.get("common_name", "")
                for name in [name_val, common_name]:
                    for line in name.split("\n"):
                        clean_and_add_domain(line)
            print(f"  Found {len(all_found_domains) - cnt_before} new domains from {q}")
        except Exception as e:
            print(f"  Parse error for {q}: {e}")
    time.sleep(2)

print(f"\nTotal domains so far: {len(all_found_domains)}")

print("\n=== Source 3.3: Wayback Machine CDX API ===")
cdx_urls = [
    "https://web.archive.org/cdx/search/cdx?url=*.gov.vn&output=json&fl=original&limit=100000&collapse=urlkey",
    "https://web.archive.org/cdx/search/cdx?url=*.edu.vn&output=json&fl=original&limit=100000&collapse=urlkey",
    "https://web.archive.org/cdx/search/cdx?url=*.com.vn&output=json&fl=original&limit=100000&collapse=urlkey"
]

for url in cdx_urls:
    print(f"Querying Wayback CDX...")
    content = fetch_url_text(url, timeout=30)
    if content and content.startswith("["):
        try:
            records = json.loads(content)
            cnt_before = len(all_found_domains)
            for row in records[1:]:  # skip header
                if row:
                    clean_and_add_domain(row[0])
            print(f"  Found {len(all_found_domains) - cnt_before} new domains from CDX")
        except Exception as e:
            print(f"  CDX parse error: {e}")
    time.sleep(2)

print(f"\n==================================================")
print(f"FINAL TOTAL Public Indices & Repos Domains: {len(all_found_domains)}")
print(f"==================================================")

with open(output_path, "w", encoding="utf-8") as f:
    json.dump(sorted(list(all_found_domains)), f, ensure_ascii=False, indent=2)

print(f"Saved to {output_path}")
