import csv
import json
import os
import re
import sys
from datetime import datetime

if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='backslashreplace')
    except Exception:
        pass

def is_ipv4(host):
    return re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', host) is not None

def clean_host_string(host):
    if not host: return ""
    host = host.lower().strip()
    host = re.sub(r'^[;\s,/\\\'"]+|[;\s,/\\\'"]+$', '', host)
    host = re.sub(r'^www\d*\.', '', host)
    host = re.sub(r'^\.*|\.*$', '', host)
    if '.' not in host or len(host) < 4: return ""
    if re.search(r'[\s,<>\'"]', host): return ""
    return host

def extract_hosts_from_text(raw_text):
    if not raw_text or not isinstance(raw_text, str):
        return set(), set()
    text = raw_text.strip()
    if not text or text.lower() in ["n/a", "none", "null", "chưa có", "không có", "dacbiet"]:
        return set(), set()
    parts = re.split(r'[;\s,\n\r]+', text)
    domains = set()
    ips = set()
    for p in parts:
        p = p.strip()
        if not p: continue
        if not p.startswith(('http://', 'https://', 'ftp://')):
            p = 'http://' + p
        match = re.search(r'https?://([^/:\s?#]+)', p, re.IGNORECASE)
        if match:
            clean_host = clean_host_string(match.group(1))
            if clean_host:
                # Remove port if exists (e.g. 1.1.1.1:8080)
                clean_host = clean_host.split(':')[0]
                if is_ipv4(clean_host):
                    ips.add(clean_host)
                else:
                    domains.add(clean_host)
    return domains, ips

def fetch_category_all(code):
    print(f"Loading category {code} from local file...")
    with open(f'raw_{code}.json', 'r', encoding='utf-8') as f:
        return json.load(f)

def process_records(raw_records, default_category):
    records_out = []
    
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
        extracted_ips = set()
        for snippet in text_snippets:
            doms, ips = extract_hosts_from_text(snippet)
            extracted_domains.update(doms)
            extracted_ips.update(ips)
            
        ip_string = ", ".join(sorted(extracted_ips))
        
        if not extracted_domains and not extracted_ips:
            continue
            
        # If there are domains, create one row per domain and attach all IPs to that row
        for dom in extracted_domains:
            records_out.append({
                "domain": dom,
                "ip": ip_string,
                "owner": company_name,
                "category_type": category,
                "certified_date": valid_from,
                "cert_level": "Giấy phép chính thức (ABEI - Bộ TT&TT)",
                "license_number": license_num,
                "status": status,
                "detail_url": "https://giayphep.abei.gov.vn/"
            })
            
        # If there are IPs but NO domains, create a single row for the IPs
        if extracted_ips and not extracted_domains:
            records_out.append({
                "domain": "",
                "ip": ip_string,
                "owner": company_name,
                "category_type": category,
                "certified_date": valid_from,
                "cert_level": "Giấy phép chính thức (ABEI - Bộ TT&TT)",
                "license_number": license_num,
                "status": status,
                "detail_url": "https://giayphep.abei.gov.vn/"
            })

    # Deduplicate keeping the most complete record
    unique_dict = {}
    for r in records_out:
        key = (r["domain"], r["ip"])
        if key not in unique_dict:
            unique_dict[key] = r
        else:
            existing = unique_dict[key]
            if not existing["owner"] and r["owner"]:
                existing["owner"] = r["owner"]
            if not existing["license_number"] and r["license_number"]:
                existing["license_number"] = r["license_number"]

    sorted_items = sorted(unique_dict.values(), key=lambda x: (x["domain"], x["ip"]))
    return sorted_items

def export_data(code, sorted_items, out_dir="data"):
    os.makedirs(out_dir, exist_ok=True)
    json_path = os.path.join(out_dir, f"abei_final_{code}.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(sorted_items, f, ensure_ascii=False, indent=2)

    txt_path = os.path.join(out_dir, f"abei_final_{code}_hosts.txt")
    with open(txt_path, "w", encoding="utf-8") as f:
        for item in sorted_items:
            if item["domain"]:
                f.write(item["domain"] + "\n")
            if item["ip"]:
                for ip in item["ip"].split(", "):
                    f.write(ip + "\n")

    csv_path = os.path.join(out_dir, f"abei_final_{code}.csv")
    with open(csv_path, "w", encoding="utf-8-sig", newline="") as f:
        if sorted_items:
            fieldnames = ["domain", "ip", "owner", "category_type", "certified_date", "cert_level", "license_number", "status", "detail_url"]
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
        export_data(code, processed, out_dir="data")
        print(f"Code {code}: Processed {len(processed)} unique records from {len(raw_records)} raw records.")
        all_combined.extend(processed)
        
    export_data("websites", sorted(all_combined, key=lambda x: (x["domain"], x["ip"])), out_dir="data")
    print(f"Total Combined: {len(all_combined)} records.")

if __name__ == "__main__":
    main()
