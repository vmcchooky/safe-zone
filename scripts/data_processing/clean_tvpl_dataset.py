import json
import re
import os
import csv
from datetime import datetime

def clean_dataset(data_dir="D:\\Quorix\\services\\safe-zone\\data", prefix="tvpl_whitelist"):
    json_path = os.path.join(data_dir, f"{prefix}_websites.json")
    csv_path = os.path.join(data_dir, f"{prefix}_websites.csv")
    txt_path = os.path.join(data_dir, f"{prefix}_domains.txt")
    summary_path = os.path.join(data_dir, f"{prefix}_summary.json")

    with open(json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    # Domain regex: Allows internationalized domain names (IDN) or ascii
    # Must have at least one dot and end with a TLD of 2+ characters
    domain_regex = re.compile(r"^xn--[a-z0-9-]+(\.[a-z0-9-]+)*\.[a-z]{2,}$|^[a-z0-9\u00A1-\uFFFF]([a-z0-9\u00A1-\uFFFF-]*[a-z0-9\u00A1-\uFFFF])?(\.[a-z0-9\u00A1-\uFFFF]([a-z0-9\u00A1-\uFFFF-]*[a-z0-9\u00A1-\uFFFF])?)*\.[a-z\u00A1-\uFFFF]{2,}$")

    cleaned_data = []
    seen_domains = set()
    
    for item in data:
        raw_domain = str(item.get("domain", ""))
        
        # Split by separators: ;, ,, and spaces
        tokens = re.split(r'[;,\s]+', raw_domain)
        
        for token in tokens:
            # Clean protocol prefix
            token = token.replace("http://", "").replace("https://", "")
            
            token = token.strip(" .\t\n\r/").lower()
            if not token:
                continue
            
            # Simple URL fix: if it has paths like domain.com/path, get the first part
            token = token.split('/')[0]

            if domain_regex.match(token) and not re.search(r'\d{5,}', token):
                if token not in seen_domains:
                    new_item = item.copy()
                    new_item["domain"] = token
                    cleaned_data.append(new_item)
                    seen_domains.add(token)

    # Backup original files before overwriting just in case
    import shutil
    for path in [json_path, csv_path, txt_path, summary_path]:
        if os.path.exists(path):
            shutil.copy2(path, path + ".bak")

    # Rewrite JSON
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(cleaned_data, f, ensure_ascii=False, indent=2)

    # Rewrite CSV
    if os.path.exists(csv_path) and cleaned_data:
        keys = cleaned_data[0].keys()
        with open(csv_path, 'w', encoding='utf-8', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            writer.writerows(cleaned_data)

    # Rewrite TXT
    if os.path.exists(txt_path):
        with open(txt_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        new_lines = []
        # Keep comments
        for line in lines:
            if line.startswith('#'):
                new_lines.append(line)
                
        # Append sorted domains
        for domain in sorted(seen_domains):
            new_lines.append(domain + "\n")
            
        with open(txt_path, 'w', encoding='utf-8') as f:
            f.writelines(new_lines)

    # Update Summary
    if os.path.exists(summary_path):
        with open(summary_path, 'r', encoding='utf-8') as f:
            summary = json.load(f)
        
        summary['total_domains'] = len(seen_domains)
        summary['last_updated'] = datetime.now().isoformat()
        
        with open(summary_path, 'w', encoding='utf-8') as f:
            json.dump(summary, f, ensure_ascii=False, indent=2)

    print(f"Cleaned dataset. Total unique valid domains: {len(seen_domains)}")

if __name__ == '__main__':
    clean_dataset()
