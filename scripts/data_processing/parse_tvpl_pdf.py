import pdfplumber
import json
import csv
import re
from urllib.parse import urlparse
import sys

# We will load the existing dataset
try:
    with open('data/tvpl_whitelist_websites.json', 'r', encoding='utf-8') as f:
        existing_data = json.load(f)
except Exception as e:
    print("Could not load existing dataset:", e)
    existing_data = []

existing_domains = {r['domain']: r for r in existing_data}

def extract_domain(url):
    if not url: return None
    url = str(url).strip()
    if not url: return None
    if not url.startswith('http'):
        url = 'http://' + url
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        if not domain: return None
        domain = re.sub(r'^www\.', '', domain)
        return domain
    except:
        return None

def is_social_media(url_str):
    url_str = url_str.lower()
    if 'tiktok.com' in url_str: return True
    if 'youtube.com' in url_str or 'youtu.be' in url_str: return True
    if 'facebook.com' in url_str or 'fb.com' in url_str: return True
    return False

pdf_path = r'C:\Users\vmcch\Downloads\White List sử dụng cho quảng cáo.pdf'

new_records = []
total_found = 0
filtered = 0

print("Parsing PDF...")
with pdfplumber.open(pdf_path) as pdf:
    for i, page in enumerate(pdf.pages):
        sys.stdout.write(f"\rProcessing page {i+1}/{len(pdf.pages)}...")
        sys.stdout.flush()
        tables = page.extract_tables()
        for table in tables:
            for row in table:
                if not row or len(row) < 3: continue
                # Skip header rows
                if row[0] and 'Loại' in row[0] and row[2] and 'Tên miền' in row[2]:
                    continue
                
                # Check column 2 and 3 for domains
                potential_urls = []
                if row[2]: potential_urls.extend(row[2].split('\n'))
                if len(row) > 3 and row[3]: potential_urls.extend(row[3].split('\n'))
                
                for url in potential_urls:
                    url = url.strip()
                    if not url: continue
                    
                    if is_social_media(url):
                        filtered += 1
                        continue
                        
                    domain = extract_domain(url)
                    if domain and '.' in domain:
                        total_found += 1
                        if domain not in existing_domains:
                            cat_type = row[0].replace('\n', ' ') if row[0] else ''
                            owner = row[1].replace('\n', ' ') if row[1] else ''
                            record = {
                                "domain": domain,
                                "owner": owner,
                                "category_type": cat_type,
                                "certified_date": "",
                                "cert_level": "Giấy phép (TVPL PDF)",
                                "license_number": "",
                                "status": "valid",
                                "detail_url": ""
                            }
                            new_records.append(record)
                            existing_domains[domain] = record

print(f"\nPDF parsing complete. Found {total_found} domains. Filtered {filtered} social media links.")
print(f"Added {len(new_records)} NEW unique domains to dataset.")

if new_records:
    # Merge and sort
    merged_data = list(existing_domains.values())
    merged_data.sort(key=lambda x: x['domain'])
    
    # Save formats
    # 1. JSON
    with open('data/tvpl_whitelist_websites.json', 'w', encoding='utf-8') as f:
        json.dump(merged_data, f, ensure_ascii=False, indent=2)
        
    # 2. CSV
    keys = list(merged_data[0].keys())
    with open('data/tvpl_whitelist_websites.csv', 'w', encoding='utf-8', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        writer.writerows(merged_data)
        
    # 3. TXT
    with open('data/tvpl_whitelist_domains.txt', 'w', encoding='utf-8') as f:
        for r in merged_data:
            f.write(r['domain'] + '\n')
            
    # 4. Summary
    try:
        with open('data/tvpl_whitelist_summary.json', 'r', encoding='utf-8') as f:
            summary = json.load(f)
    except:
        summary = {}
        
    summary['total_unique_domains'] = len(merged_data)
    summary['added_from_pdf'] = len(new_records)
    summary['filtered_social_from_pdf'] = filtered
    summary['source'] = 'Thuvienphapluat (ABEI API + PDF Merge)'
    
    with open('data/tvpl_whitelist_summary.json', 'w', encoding='utf-8') as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
        
    print("Successfully updated the 4 dataset files.")
else:
    print("No new domains were found that aren't already in the dataset.")
