import json
import os

def load_json(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        return json.load(f)

def verify():
    data_dir = r"D:\Quorix\services\safe-zone\data"
    tvpl_path = os.path.join(data_dir, "tvpl_whitelist_websites.json")
    abei_path = os.path.join(data_dir, "abei_websites.json")
    vietnam_path = os.path.join(data_dir, r"whitelist\vietnam\vietnam_websites.json")
    merged_path = os.path.join(data_dir, "merged_websites.json")

    tvpl_data = load_json(tvpl_path)
    abei_data = load_json(abei_path)
    vietnam_data = load_json(vietnam_path)
    merged_data = load_json(merged_path)

    # 1. Gather all unique domains from sources
    source_domains = set()
    for item in tvpl_data + abei_data + vietnam_data:
        d = str(item.get("domain", "")).strip().lower()
        if d:
            source_domains.add(d)

    # 2. Gather all unique domains from merged
    merged_domains = set()
    merged_dict = {}
    for item in merged_data:
        d = str(item.get("domain", "")).strip().lower()
        if d:
            merged_domains.add(d)
            merged_dict[d] = item

    print(f"Total source unique domains: {len(source_domains)}")
    print(f"Total merged unique domains: {len(merged_domains)}")

    missing_in_merged = source_domains - merged_domains
    if missing_in_merged:
        print(f"ERROR: {len(missing_in_merged)} domains are missing in the merged file!")
    else:
        print("SUCCESS: All source domains are present in the merged file.")

    missing_in_source = merged_domains - source_domains
    if missing_in_source:
        print(f"ERROR: {len(missing_in_source)} domains are in merged but NOT in source!")
    else:
        print("SUCCESS: No extra garbage domains in the merged file.")

    # 3. Verify fields
    all_keys = set()
    for item in tvpl_data + abei_data + vietnam_data:
        all_keys.update(item.keys())

    merged_keys = set()
    for item in merged_data:
        merged_keys.update(item.keys())
    
    missing_keys = all_keys - merged_keys
    if missing_keys:
        print(f"ERROR: Missing keys in merged data: {missing_keys}")
    else:
        print(f"SUCCESS: All {len(all_keys)} keys are preserved: {all_keys}")

    # Check for empty fields if original had data
    data_loss_detected = False
    for dataset in [tvpl_data, abei_data, vietnam_data]:
        for item in dataset:
            d = str(item.get("domain", "")).strip().lower()
            if not d: continue
            
            merged_item = merged_dict[d]
            for k, v in item.items():
                if v:
                    merged_v = merged_item.get(k)
                    if not merged_v:
                        print(f"ERROR: Data loss for domain {d} field {k}. Original: '{v}', Merged: '{merged_v}'")
                        data_loss_detected = True
                        break
            if data_loss_detected: break
        if data_loss_detected: break
        
    if not data_loss_detected:
        print("SUCCESS: No data loss detected for non-empty fields.")

if __name__ == '__main__':
    verify()
