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
    "User-Agent": "Mozilla/5.0",
    "Content-Type": "application/json",
    "Accept": "application/json, text/plain, */*",
    "Origin": "https://giayphep.abei.gov.vn",
    "Referer": "https://giayphep.abei.gov.vn/"
}

API_PAGING_URL = "https://gpttdt-api.abei.gov.vn/services/mcrlmtp/api/license/pivotPaging"

def clean_host_string(host):
    if not host: return ""
    host = host.lower().strip()
    host = re.sub(r'^[;\s,/\\\'"]+|[;\s,/\\\'"]+$', '', host)
    host = re.sub(r'^www\d*\.', '', host)
    host = re.sub(r'^\.*|\.*$', '', host)
    if '.' not in host or len(host) < 4: return ""
    if re.search(r'[\s,<>\'"]', host): return ""
    return host

def extract_domains_from_text(raw_text):
    if not raw_text or not isinstance(raw_text, str):
        return []
    text = raw_text.strip()
    if not text or text.lower() in ["n/a", "none", "null", "chưa có", "không có", "dacbiet"]:
        return []
    parts = re.split(r'[;\s,\n\r]+', text)
    extracted = []
    for p in parts:
        p = p.strip()
        if not p: continue
        if not p.startswith(('http://', 'https://', 'ftp://')):
            p = 'http://' + p
        match = re.search(r'https?://([^/:\s?#]+)', p, re.IGNORECASE)
        if match:
            clean_dom = clean_host_string(match.group(1))
            if clean_dom:
                extracted.append(clean_dom)
    return extracted

def fetch_category_batch(code, start_row, batch_size=100, retries=3):
    payload = {
        "startRow": start_row,
        "endRow": start_row + batch_size,
        "sortModel": [{"colId": "validFrom", "sort": "desc"}],
        "filterModel": {'platformCategoryCode': {'filterType': 'text', 'type': 'contains', 'filter': code}}
    }
    data = json.dumps(payload).encode('utf-8')
    for attempt in range(retries):
        try:
            req = urllib.request.Request(API_PAGING_URL, data=data, headers=HEADERS, method="POST")
            with urllib.request.urlopen(req, context=SSL_CTX, timeout=20) as res:
                res_json = json.loads(res.read().decode('utf-8'))
                return res_json.get("data", {}).get("data", [])
        except Exception as e:
            if attempt < retries - 1:
                time.sleep(1.0)
            else:
                print(f"Error fetching {code} at {start_row}: {e}")
                return []
    return []

def fetch_category_all(code):
    print(f"Loading category {code} from local file...")
    with open(f'raw_{code}.json', 'r', encoding='utf-8') as f:
        return json.load(f)

def process_records(raw_records, default_category):
    unique_domains_dict = {}
    for item in raw_records:
        company_name = (item.get("companyName") or "").strip()
        category = (item.get("platformCategoryName") or default_category).strip()
        license_num = (item.get("licenseNumber") or "").strip()
        valid_from = (item.get("validFrom") or item.get("issueDate") or "").strip()
        if len(valid_from) >= 10:
            valid_from = valid_from[:10]
        status = (item.get("cstatus") or item.get("status") or "valid").strip()

        text_snippets = []
        detail = item.get("licenseDetail") or {}
        if isinstance(detail, dict):
            for k, v in detail.items():
                if v and isinstance(v, str):
                    text_snippets.append(v)
        
        if item.get("website"):
            text_snippets.append(str(item.get("website")))
        if item.get("domain"):
            text_snippets.append(str(item.get("domain")))

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
    return sorted_items

def export_data(code, sorted_items, out_dir="data/v2"):
    os.makedirs(out_dir, exist_ok=True)
    json_path = os.path.join(out_dir, f"abei_{code}.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(sorted_items, f, ensure_ascii=False, indent=2)

    txt_path = os.path.join(out_dir, f"abei_{code}_domains.txt")
    with open(txt_path, "w", encoding="utf-8") as f:
        for dom in [x["domain"] for x in sorted_items]:
            f.write(dom + "\n")

    csv_path = os.path.join(out_dir, f"abei_{code}.csv")
    with open(csv_path, "w", encoding="utf-8-sig", newline="") as f:
        if sorted_items:
            fieldnames = ["domain", "owner", "category_type", "certified_date", "cert_level", "license_number", "status", "detail_url"]
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(sorted_items)

def main():
    codes = {'g': 'QUYẾT ĐỊNH PHÁT HÀNH TRÒ CHƠI ĐIỆN TỬ G1 TRÊN MẠNG',
             'g1': 'GIẤY XÁC NHẬN THÔNG BÁO PHÁT HÀNH TRÒ CHƠI ĐIỆN TỬ G2,G3,G4',
             'i': 'GIẤY PHÉP THIẾT LẬP TRANG THÔNG TIN ĐIỆN TỬ TỔNG HỢP',
             's': 'GIẤY PHÉP CUNG CẤP DỊCH VỤ MẠNG XÃ HỘI'}
    all_combined = []
    
    for code, default_cat in codes.items():
        raw_records = fetch_category_all(code)
        processed = process_records(raw_records, default_cat)
        export_data(code, processed)
        print(f"Code {code}: Processed {len(processed)} unique domains from {len(raw_records)} raw records.")
        all_combined.extend(processed)
        
    # Also save the combined
    export_data("websites", sorted(all_combined, key=lambda x: x["domain"]))
    print(f"Total Combined: {len(all_combined)} domains.")

if __name__ == "__main__":
    main()
