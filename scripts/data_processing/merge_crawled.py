import json
import os
import csv
from datetime import datetime
import shutil

def load_json(filepath):
    if not os.path.exists(filepath):
        return []
    with open(filepath, 'r', encoding='utf-8') as f:
        return json.load(f)

def merge_crawled():
    data_dir = r"D:\Quorix\services\safe-zone\data"
    vietnam_dir = os.path.join(data_dir, r"whitelist\vietnam")
    
    edu_path = os.path.join(data_dir, "crawled_edu.json")
    gov_path = os.path.join(data_dir, "crawled_gov.json")
    
    vietnam_json = os.path.join(vietnam_dir, "vietnam_websites.json")
    vietnam_csv = os.path.join(vietnam_dir, "vietnam_websites.csv")
    vietnam_txt = os.path.join(vietnam_dir, "vietnam_domains.txt")
    vietnam_summary = os.path.join(vietnam_dir, "vietnam_summary.json")

    # Backup vietnam files
    for path in [vietnam_json, vietnam_csv, vietnam_txt, vietnam_summary]:
        if os.path.exists(path):
            shutil.copy2(path, path + ".bak")

    edu_data = load_json(edu_path)
    gov_data = load_json(gov_path)
    vietnam_data = load_json(vietnam_json)

    merged = {}
    all_keys = set()

    # Process vietnam first, then new data overrides/adds
    for dataset in [vietnam_data, edu_data, gov_data]:
        for item in dataset:
            domain = str(item.get("domain", "")).strip().lower()
            if not domain:
                continue

            all_keys.update(item.keys())

            if domain not in merged:
                merged[domain] = {k: v for k, v in item.items()}
                merged[domain]["domain"] = domain
            else:
                for k, v in item.items():
                    if k == "domain":
                        continue
                    v_str = str(v).strip() if v is not None else ""
                    
                    if k not in merged[domain]:
                        merged[domain][k] = v
                    else:
                        existing_v = merged[domain][k]
                        existing_v_str = str(existing_v).strip() if existing_v is not None else ""
                        
                        if not existing_v_str and v_str:
                            merged[domain][k] = v
                        elif existing_v_str and v_str and existing_v_str != v_str:
                            if v_str not in existing_v_str and existing_v_str not in v_str:
                                merged[domain][k] = f"{existing_v_str} | {v_str}"
                            elif len(v_str) > len(existing_v_str):
                                merged[domain][k] = v
                                
    merged_list = list(merged.values())

    # Write JSON
    with open(vietnam_json, 'w', encoding='utf-8') as f:
        json.dump(merged_list, f, ensure_ascii=False, indent=2)

    # Write CSV
    if merged_list:
        with open(vietnam_csv, 'w', encoding='utf-8', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=list(all_keys))
            writer.writeheader()
            writer.writerows(merged_list)

    # Write TXT
    sorted_domains = sorted(merged.keys())
    with open(vietnam_txt, 'w', encoding='utf-8') as f:
        for d in sorted_domains:
            f.write(d + "\n")

    # Write Summary
    summary = {
        "total_domains": len(sorted_domains),
        "last_updated": datetime.now().isoformat(),
        "sources": ["vietnam", "crawled_edu", "crawled_gov"]
    }
    with open(vietnam_summary, 'w', encoding='utf-8') as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    print(f"Update successful. Total domains in vietnam dataset: {len(sorted_domains)}")

if __name__ == '__main__':
    merge_crawled()
