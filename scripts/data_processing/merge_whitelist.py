import json
import csv
import os
import glob
from collections import OrderedDict
from datetime import datetime

def merge_datasets():
    data_dir = r"D:\Quorix\services\safe-zone\data"
    whitelist_vn_dir = os.path.join(data_dir, "whitelist", "vietnam")
    blacklist_dir = os.path.join(data_dir, "blacklist")
    
    # Create directories
    os.makedirs(whitelist_vn_dir, exist_ok=True)
    os.makedirs(blacklist_dir, exist_ok=True)
    print(f"Created directories:\n- {whitelist_vn_dir}\n- {blacklist_dir}")

    # Get all json files (excluding trash and the new consolidated ones if they exist)
    json_files = glob.glob(os.path.join(data_dir, "*_websites.json"))
    
    all_domains_data = OrderedDict()
    
    # Read and merge
    for file in json_files:
        basename = os.path.basename(file)
        if basename.startswith("trash"):
            continue
            
        with open(file, 'r', encoding='utf-8') as f:
            data = json.load(f)
            
        for item in data:
            domain = item.get("domain")
            if not domain:
                continue
                
            # If domain already exists, we can merge or just skip. 
            # We will keep the first occurrence.
            if domain not in all_domains_data:
                all_domains_data[domain] = item
            else:
                # Merge missing fields if any
                for k, v in item.items():
                    if k not in all_domains_data[domain] or not all_domains_data[domain][k]:
                        all_domains_data[domain][k] = v

    final_data = list(all_domains_data.values())
    print(f"Merged {len(final_data)} unique domains.")

    # Paths for new files
    out_json = os.path.join(whitelist_vn_dir, "vietnam_websites.json")
    out_csv = os.path.join(whitelist_vn_dir, "vietnam_websites.csv")
    out_txt = os.path.join(whitelist_vn_dir, "vietnam_domains.txt")
    out_summary = os.path.join(whitelist_vn_dir, "vietnam_summary.json")

    # 1. Write JSON
    with open(out_json, 'w', encoding='utf-8') as f:
        json.dump(final_data, f, ensure_ascii=False, indent=2)
    print(f"Wrote {out_json}")

    # 2. Write CSV
    if final_data:
        # Collect all possible keys from all dicts
        all_keys = set()
        for item in final_data:
            all_keys.update(item.keys())
        keys = list(all_keys)
        
        with open(out_csv, 'w', encoding='utf-8', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            writer.writerows(final_data)
        print(f"Wrote {out_csv}")

    # 3. Write TXT
    with open(out_txt, 'w', encoding='utf-8') as f:
        f.write("# Consolidated Vietnam Whitelist Domains\n")
        f.write(f"# Generated: {datetime.now().isoformat()}\n")
        f.write(f"# Total Domains: {len(final_data)}\n\n")
        for domain in all_domains_data.keys():
            f.write(f"{domain}\n")
    print(f"Wrote {out_txt}")

    # 4. Write Summary
    summary = {
        "dataset": "Vietnam Consolidated Whitelist",
        "total_domains": len(final_data),
        "last_updated": datetime.now().isoformat(),
        "sources_merged": [os.path.basename(f) for f in json_files if not os.path.basename(f).startswith("trash")]
    }
    with open(out_summary, 'w', encoding='utf-8') as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
    print(f"Wrote {out_summary}")
    
    # Optionally, we can move original files to an 'archive' folder to clean up root data dir.
    # But for now, we'll just leave them.
    
if __name__ == "__main__":
    merge_datasets()
