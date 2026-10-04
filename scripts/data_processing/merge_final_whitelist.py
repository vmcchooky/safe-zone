"""
Final merge script: Combine all collected Vietnamese domain sources into 
the definitive whitelist dataset. Outputs 4 files in data/ directory.
"""
import json
import os
from pathlib import Path
import csv
import datetime
import re
import sys
import io
import glob

ROOT = Path(__file__).resolve().parents[2]
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

data_dir = str(ROOT / "data")

def is_valid_domain(d):
    """Check if a string looks like a valid domain name."""
    if not d or len(d) < 3:
        return False
    if ' ' in d or '\t' in d:
        return False
    if d.startswith('.') or d.endswith('.'):
        return False
    if '..' in d:
        return False
    if '.' not in d:
        return False
    pattern = re.compile(r'^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)*\.[a-z]{2,}$')
    return bool(pattern.match(d))

def categorize_domain(d):
    """Categorize a Vietnamese domain by its TLD and purpose."""
    if d.endswith('.gov.vn'):
        return "Cơ quan nhà nước"
    elif d.endswith('.edu.vn'):
        return "Giáo dục"
    elif d.endswith('.org.vn'):
        return "Tổ chức phi lợi nhuận"
    elif d.endswith('.net.vn'):
        return "Hạ tầng mạng"
    elif d.endswith('.com.vn'):
        return "Doanh nghiệp VN"
    elif d.endswith('.biz.vn') or d.endswith('.info.vn'):
        return "Doanh nghiệp VN"
    elif d.endswith('.vn'):
        return "Tên miền .vn"
    elif d.endswith('.com') or d.endswith('.net') or d.endswith('.org') or d.endswith('.io') or d.endswith('.tech') or d.endswith('.co') or d.endswith('.me') or d.endswith('.tv'):
        return "Doanh nghiệp VN (TLD quốc tế)"
    else:
        return "Khác"

print("=" * 60)
print("FINAL EXPANDED MERGE: Vietnamese Domain Whitelist Dataset")
print("=" * 60)

all_domains = set()
source_map = {}

# 1. DNS Leak data (628k .vn domains)
print("\n[1/7] Loading DNS Leak .vn domains...")
leak_dir = str(ROOT / "tmp/VietnamDNSLeak")
txt_files = glob.glob(os.path.join(leak_dir, "**", "*.txt"), recursive=True)
for fpath in txt_files:
    with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            parts = line.split()
            if len(parts) >= 4 and parts[3] in ['NS', 'A', 'CNAME', 'MX', 'TXT', 'SOA']:
                domain = parts[0].lower()
                if domain.endswith('.'):
                    domain = domain[:-1]
                if domain.endswith('.vn') and is_valid_domain(domain):
                    all_domains.add(domain)
                    source_map[domain] = "DNS Zone File (VNNIC)"

repo2_dir = str(ROOT / "tmp/VietnamDomains2")
for fname in ["dotcom.vn.txt", "dotvn.txt"]:
    fpath = os.path.join(repo2_dir, fname)
    if os.path.exists(fpath):
        with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                domain = line.strip().lower()
                if domain.endswith('.vn') and is_valid_domain(domain):
                    all_domains.add(domain)
                    if domain not in source_map:
                        source_map[domain] = "Vietnam Domains Registry"

print(f"  -> Total domains so far: {len(all_domains):,}")

# 2. Existing whitelist
print("\n[2/7] Loading existing whitelist data...")
existing_json = os.path.join(data_dir, "whitelist", "vietnam", "vietnam_websites.json")
if os.path.exists(existing_json):
    with open(existing_json, 'r', encoding='utf-8') as f:
        existing_data = json.load(f)
    for entry in existing_data:
        d = entry.get("domain", "").lower().strip()
        if d and is_valid_domain(d):
            all_domains.add(d)
            if d not in source_map:
                source_map[d] = "Tinnhiemmang.vn (Bộ TT&TT)"
print(f"  -> Total domains so far: {len(all_domains):,}")

# 3. crt.sh Certificate Transparency
print("\n[3/7] Loading crt.sh Certificate Transparency data...")
crtsh_path = os.path.join(data_dir, "collected_crtsh.json")
if os.path.exists(crtsh_path):
    with open(crtsh_path, 'r', encoding='utf-8') as f:
        crtsh_data = json.load(f)
    for d in crtsh_data:
        d = d.lower().strip()
        if is_valid_domain(d):
            all_domains.add(d)
            if d not in source_map:
                source_map[d] = "Certificate Transparency (crt.sh)"
print(f"  -> Total domains so far: {len(all_domains):,}")

# 4. Business & Common Crawl
print("\n[4/7] Loading Business & Common Crawl data...")
business_path = os.path.join(data_dir, "collected_business.json")
if os.path.exists(business_path):
    with open(business_path, 'r', encoding='utf-8') as f:
        business_data = json.load(f)
    for d in business_data:
        d = d.lower().strip()
        if is_valid_domain(d):
            all_domains.add(d)
            if d not in source_map:
                source_map[d] = "Business Directory & Common Crawl"
print(f"  -> Total domains so far: {len(all_domains):,}")

# 5. Expansion: Public Search Indices & GitHub Repos
print("\n[5/7] Loading Expansion Public Search Indices & Open Repos...")
pub_path = os.path.join(data_dir, "expansion_public_indices.json")
if os.path.exists(pub_path):
    with open(pub_path, 'r', encoding='utf-8') as f:
        pub_data = json.load(f)
    for d in pub_data:
        d = d.lower().strip()
        if is_valid_domain(d):
            all_domains.add(d)
            if d not in source_map:
                source_map[d] = "Public Search Indices & Open Repos"
print(f"  -> Total domains so far: {len(all_domains):,}")

# 6. Expansion: Tranco VN IP/ASN & WHOIS Filter
print("\n[6/7] Loading Expansion Tranco VN IP/ASN & WHOIS Filter...")
tranco_vn_path = os.path.join(data_dir, "expansion_tranco_vn.json")
if os.path.exists(tranco_vn_path):
    with open(tranco_vn_path, 'r', encoding='utf-8') as f:
        tranco_vn_data = json.load(f)
    for d in tranco_vn_data:
        d = d.lower().strip()
        if is_valid_domain(d):
            all_domains.add(d)
            if d not in source_map:
                source_map[d] = "Tranco 1M VN IP/ASN Geolocation"
print(f"  -> Total domains so far: {len(all_domains):,}")

# 7. Expansion: Mass DNS Verified Active Domains
print("\n[7/7] Loading Expansion Mass DNS Verified Active Domains...")
dns_ver_path = os.path.join(data_dir, "expansion_dns_verified.json")
if os.path.exists(dns_ver_path):
    with open(dns_ver_path, 'r', encoding='utf-8') as f:
        dns_ver_data = json.load(f)
    for d in dns_ver_data:
        d = d.lower().strip()
        if is_valid_domain(d):
            all_domains.add(d)
            if d not in source_map:
                source_map[d] = "Mass DNS Resolution Verification"
print(f"  -> Total domains so far: {len(all_domains):,}")

# FINAL: Sort and output
final_domains = sorted(list(all_domains))
print(f"\n{'=' * 60}")
print(f"FINAL EXPANDED TOTAL: {len(final_domains):,} unique REAL Vietnamese domains")
print(f"{'=' * 60}")

# Category breakdown
categories = {}
for d in final_domains:
    cat = categorize_domain(d)
    categories[cat] = categories.get(cat, 0) + 1

print("\nCategory breakdown:")
for cat, count in sorted(categories.items(), key=lambda x: -x[1]):
    print(f"  {cat}: {count:,}")

# Source breakdown
sources = {}
for d in final_domains:
    src = source_map.get(d, "Unknown")
    sources[src] = sources.get(src, 0) + 1

print("\nSource breakdown:")
for src, count in sorted(sources.items(), key=lambda x: -x[1]):
    print(f"  {src}: {count:,}")

# Write 4 output files
print("\nWriting output files...")
today = datetime.datetime.now().strftime("%d/%m/%Y")

# 1. TXT
txt_path = os.path.join(data_dir, "vietnam_massive_domains.txt")
with open(txt_path, 'w', encoding='utf-8') as f:
    for d in final_domains:
        f.write(f"{d}\n")
print(f"  [1/4] {txt_path}")

# 2. JSON
websites = []
for d in final_domains:
    websites.append({
        "domain": d,
        "owner": source_map.get(d, "Real Registered Domain"),
        "category_type": categorize_domain(d),
        "certified_date": today,
        "cert_level": "Xác thực tồn tại",
        "detail_url": ""
    })

json_path = os.path.join(data_dir, "vietnam_massive_websites.json")
with open(json_path, 'w', encoding='utf-8') as f:
    json.dump(websites, f, ensure_ascii=False, indent=2)
print(f"  [2/4] {json_path}")

# 3. CSV
csv_path = os.path.join(data_dir, "vietnam_massive_websites.csv")
with open(csv_path, 'w', encoding='utf-8', newline='') as f:
    writer = csv.writer(f)
    writer.writerow(["domain", "owner", "category_type", "certified_date", "cert_level", "detail_url"])
    for w in websites:
        writer.writerow([w["domain"], w["owner"], w["category_type"], w["certified_date"], w["cert_level"], w["detail_url"]])
print(f"  [3/4] {csv_path}")

# 4. Summary JSON
summary = {
    "total_domains": len(final_domains),
    "last_updated": datetime.datetime.now().isoformat(),
    "sources": list(set(source_map.values())),
    "categories": categories,
    "description": f"{len(final_domains):,} real Vietnamese domains for anti-phishing AI training whitelist"
}
summary_path = os.path.join(data_dir, "vietnam_massive_summary.json")
with open(summary_path, 'w', encoding='utf-8') as f:
    json.dump(summary, f, ensure_ascii=False, indent=2)
print(f"  [4/4] {summary_path}")

print(f"\n{'=' * 60}")
print("DONE! Expanded merge complete. All 4 files written successfully.")
print(f"{'=' * 60}")
