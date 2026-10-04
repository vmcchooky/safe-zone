import json
import os
import csv
from collections import defaultdict
from datetime import datetime

def load_json(filepath):
    if not os.path.exists(filepath):
        print(f"File not found: {filepath}")
        return []
    with open(filepath, 'r', encoding='utf-8') as f:
        return json.load(f)

def merge_datasets():
    data_dir = r"D:\Quorix\services\safe-zone\data"
    tvpl_path = os.path.join(data_dir, "tvpl_whitelist_websites.json")
    abei_path = os.path.join(data_dir, "abei_websites.json")
    vietnam_path = os.path.join(data_dir, r"whitelist\vietnam\vietnam_websites.json")

    out_json = os.path.join(data_dir, "merged_websites.json")
    out_csv = os.path.join(data_dir, "merged_websites.csv")
    out_txt = os.path.join(data_dir, "merged_domains.txt")
    out_summary = os.path.join(data_dir, "merged_summary.json")

    tvpl_data = load_json(tvpl_path)
    abei_data = load_json(abei_path)
    vietnam_data = load_json(vietnam_path)

    merged = {}
    all_keys = set()

    # We will process in order of priority or just sequentially
    for dataset in [tvpl_data, abei_data, vietnam_data]:
        for item in dataset:
            domain = str(item.get("domain", "")).strip().lower()
            if not domain:
                continue

            all_keys.update(item.keys())

            if domain not in merged:
                merged[domain] = {k: v for k, v in item.items()}
                merged[domain]["domain"] = domain # ensure clean domain
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
                            # Avoid appending if one is a substring of another
                            if v_str not in existing_v_str and existing_v_str not in v_str:
                                merged[domain][k] = f"{existing_v_str} | {v_str}"
                            elif len(v_str) > len(existing_v_str):
                                merged[domain][k] = v
                                
    merged_list = list(merged.values())

    # Write JSON
    with open(out_json, 'w', encoding='utf-8') as f:
        json.dump(merged_list, f, ensure_ascii=False, indent=2)

    # Write CSV
    if merged_list:
        with open(out_csv, 'w', encoding='utf-8', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=list(all_keys))
            writer.writeheader()
            writer.writerows(merged_list)

    # Write TXT
    sorted_domains = sorted(merged.keys())
    with open(out_txt, 'w', encoding='utf-8') as f:
        for d in sorted_domains:
            f.write(d + "\n")

    # Write Summary
    summary = {
        "total_domains": len(sorted_domains),
        "last_updated": datetime.now().isoformat(),
        "sources": ["tvpl", "abei", "vietnam"]
    }
    with open(out_summary, 'w', encoding='utf-8') as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    print(f"Merge successful. Total domains: {len(sorted_domains)}")
    print(f"All keys: {all_keys}")

if __name__ == '__main__':
    merge_datasets()
