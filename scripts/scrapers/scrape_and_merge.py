import urllib.request
import json
import re
import os
import csv
from datetime import datetime
import time

categories = ['s', 'g', 'g1', 'i']
output_dir = 'data'
os.makedirs(output_dir, exist_ok=True)

def clean_domains(raw):
    if not raw: return []
    s = re.sub(r'(?i)\s+và\s+', ',', raw)
    s = re.sub(r'[;&\n]', ',', s)
    parts = s.split(',')
    clean = []
    for p in parts:
        p = p.strip().lower()
        if not p: continue
        p = re.sub(r'^https?://', '', p)
        p = re.sub(r'^htttps?://', '', p)
        p = re.sub(r'^www\.', '', p)
        p = p.split('/')[0]
        p = p.split(':')[0]
        p = p.split('?')[0]
        p = p.strip(' .,!?')
        if '.' in p and ' ' not in p:
            clean.append(p)
    return list(dict.fromkeys(clean))

all_records = []
unique_domains = set()
total_raw_records = 0

for code in categories:
    print(f"Fetching category '{code}'...")
    start_row = 0
    batch_size = 100
    category_records = 0
    while True:
        payload = {
            'startRow': start_row,
            'endRow': start_row + batch_size,
            'sortModel': [],
            'filterModel': {'platformCategoryCode': {'filterType': 'text', 'type': 'contains', 'filter': code}}
        }
        req = urllib.request.Request(
            'https://gpttdt-api.abei.gov.vn/services/mcrlmtp/api/license/pivotPaging',
            data=json.dumps(payload).encode('utf-8'),
            headers={'Content-Type': 'application/json'}
        )
        try:
            resp = urllib.request.urlopen(req)
            data = json.loads(resp.read().decode('utf-8'))
            records = data.get('data', {}).get('data', [])
            
            for item in records:
                total_raw_records += 1
                category_records += 1
                detail = item.get('licenseDetail', {})
                raw_domain = str(detail.get('domainName') or '') + ',' + str(detail.get('gameHomepage') or '') + ',' + str(detail.get('website') or '')
                normalized = clean_domains(raw_domain)
                
                for domain in normalized:
                    if domain in unique_domains:
                        continue
                    unique_domains.add(domain)
                    
                    date_str = item.get('issueDate', '')
                    if not date_str:
                        valid_from = item.get('validFrom', '')
                        if valid_from:
                            date_str = valid_from.split('T')[0]
                    
                    record = {
                        "domain": domain,
                        "owner": item.get('companyName', ''),
                        "category_type": item.get('platformCategoryName', ''),
                        "certified_date": date_str,
                        "cert_level": "Giấy phép chính thức (ABEI - Bộ TT&TT)",
                        "license_number": item.get('licenseNumber', ''),
                        "status": item.get('status', 'valid'),
                        "detail_url": "https://giayphep.abei.gov.vn/"
                    }
                    all_records.append(record)
                    
            if len(records) < batch_size:
                break
            start_row += batch_size
        except Exception as e:
            print(f"Code '{code}' at {start_row}: Error {e}")
            break
        time.sleep(0.5)
    print(f"  -> Fetched {category_records} raw records for '{code}'")

all_records.sort(key=lambda x: x['domain'])
all_domains = [r['domain'] for r in all_records]

# 1. Write JSON
with open(os.path.join(output_dir, 'abei_websites.json'), 'w', encoding='utf-8') as f:
    json.dump(all_records, f, ensure_ascii=False, indent=2)

# 2. Write CSV
if all_records:
    try:
        with open(os.path.join(output_dir, 'abei_websites.csv'), 'w', encoding='utf-8', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=all_records[0].keys())
            writer.writeheader()
            for r in all_records:
                writer.writerow(r)
    except PermissionError:
        print("Warning: abei_websites.csv is open/locked. Saving to abei_websites_new.csv instead.")
        with open(os.path.join(output_dir, 'abei_websites_new.csv'), 'w', encoding='utf-8', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=all_records[0].keys())
            writer.writeheader()
            for r in all_records:
                writer.writerow(r)

# 3. Write TXT
with open(os.path.join(output_dir, 'abei_domains.txt'), 'w', encoding='utf-8') as f:
    for d in all_domains:
        f.write(f"{d}\n")

# 4. Write Summary
summary = {
    "source": "https://giayphep.abei.gov.vn/",
    "scraped_at": datetime.utcnow().isoformat() + "Z",
    "total_raw_records": total_raw_records,
    "total_unique_domains": len(all_domains),
    "total_domains": len(all_domains),
    "last_updated": datetime.utcnow().isoformat() + "Z"
}

with open(os.path.join(output_dir, 'abei_summary.json'), 'w', encoding='utf-8') as f:
    json.dump(summary, f, ensure_ascii=False, indent=2)

print(f"\nDone. Processed {total_raw_records} total raw records from API.")
print(f"Extracted {len(all_domains)} unique clean domains.")
print(f"Generated 4 standardized files in {output_dir}")
