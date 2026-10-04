import os
from pathlib import Path
import csv
import json
import urllib.request
import zipfile
import datetime

ROOT = Path(__file__).resolve().parents[2]
data_dir = str(ROOT / "data")
zip_path = os.path.join(data_dir, "top-1m.csv.zip")

url = "https://tranco-list.eu/top-1m.csv.zip"
print(f"Downloading {url}...")
urllib.request.urlretrieve(url, zip_path)

print("Extracting...")
extracted_csv = None
with zipfile.ZipFile(zip_path, 'r') as zip_ref:
    extracted_csv_name = zip_ref.namelist()[0]
    zip_ref.extractall(data_dir)
    extracted_csv = os.path.join(data_dir, extracted_csv_name)

print(f"Extracted to {extracted_csv}")

domains = []
with open(extracted_csv, 'r', encoding='utf-8') as f:
    for line in f:
        parts = line.strip().split(',')
        if len(parts) >= 2:
            domains.append(parts[1])

print(f"Loaded {len(domains)} domains.")

print("Generating JSON...")
websites = []
today = datetime.datetime.now().strftime("%d/%m/%Y")
for d in domains:
    websites.append({
        "domain": d,
        "owner": "Tranco Top 1M",
        "category_type": "Global",
        "certified_date": today,
        "cert_level": "Top 1M",
        "detail_url": "https://tranco-list.eu/"
    })

json_path = os.path.join(data_dir, "massive_websites.json")
with open(json_path, 'w', encoding='utf-8') as f:
    json.dump(websites, f, ensure_ascii=False, indent=2)

print("Generating CSV...")
out_csv_path = os.path.join(data_dir, "massive_websites.csv")
with open(out_csv_path, 'w', encoding='utf-8', newline='') as f:
    writer = csv.writer(f)
    writer.writerow(["domain", "owner", "category_type", "certified_date", "cert_level", "detail_url"])
    for w in websites:
        writer.writerow([w["domain"], w["owner"], w["category_type"], w["certified_date"], w["cert_level"], w["detail_url"]])

print("Generating TXT...")
txt_path = os.path.join(data_dir, "massive_domains.txt")
with open(txt_path, 'w', encoding='utf-8') as f:
    for d in domains:
        f.write(f"{d}\n")

print("Generating SUMMARY...")
summary = {
    "total_domains": len(domains),
    "last_updated": datetime.datetime.now().isoformat(),
    "sources": [
        "tranco_top_1m"
    ]
}
summary_path = os.path.join(data_dir, "massive_summary.json")
with open(summary_path, 'w', encoding='utf-8') as f:
    json.dump(summary, f, ensure_ascii=False, indent=2)

# Cleanup
if os.path.exists(zip_path):
    os.remove(zip_path)
if os.path.exists(extracted_csv) and extracted_csv != out_csv_path:
    os.remove(extracted_csv)

print("Done generating 4 files in data directory.")
