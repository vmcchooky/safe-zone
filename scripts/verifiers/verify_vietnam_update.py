import json
import os

def load_json(filepath):
    if not os.path.exists(filepath):
        return []
    with open(filepath, 'r', encoding='utf-8') as f:
        return json.load(f)

def verify():
    data_dir = r"D:\Quorix\services\safe-zone\data"
    merged_path = os.path.join(data_dir, "merged_websites.json")
    
    vietnam_dir = os.path.join(data_dir, r"whitelist\vietnam")
    vietnam_json = os.path.join(vietnam_dir, "vietnam_websites.json")
    vietnam_bak = os.path.join(vietnam_dir, "vietnam_websites.json.bak")

    merged_data = load_json(merged_path)
    vietnam_new_data = load_json(vietnam_json)
    vietnam_old_data = load_json(vietnam_bak)

    # 1. Gather domains
    source_domains = set()
    for item in merged_data + vietnam_old_data:
        d = str(item.get("domain", "")).strip().lower()
        if d:
            source_domains.add(d)

    new_domains = set()
    new_dict = {}
    for item in vietnam_new_data:
        d = str(item.get("domain", "")).strip().lower()
        if d:
            new_domains.add(d)
            new_dict[d] = item

    print(f"Total source unique domains: {len(source_domains)}")
    print(f"Total new unique domains: {len(new_domains)}")

    missing_in_new = source_domains - new_domains
    if missing_in_new:
        print(f"ERROR: {len(missing_in_new)} domains are missing in the updated vietnam file!")
    else:
        print("SUCCESS: All source domains are present in the updated file.")

    missing_in_source = new_domains - source_domains
    if missing_in_source:
        print(f"ERROR: {len(missing_in_source)} domains are in updated but NOT in source!")
    else:
        print("SUCCESS: No extra garbage domains in the updated file.")

    # 2. Check keys
    all_keys = set()
    for item in merged_data + vietnam_old_data:
        all_keys.update(item.keys())

    new_keys = set()
    for item in vietnam_new_data:
        new_keys.update(item.keys())
    
    missing_keys = all_keys - new_keys
    if missing_keys:
        print(f"ERROR: Missing keys in updated data: {missing_keys}")
    else:
        print(f"SUCCESS: All keys are preserved: {all_keys}")

    # 3. Check for data loss
    data_loss_detected = False
    for dataset in [merged_data, vietnam_old_data]:
        for item in dataset:
            d = str(item.get("domain", "")).strip().lower()
            if not d: continue
            
            new_item = new_dict.get(d)
            if not new_item:
                continue
            for k, v in item.items():
                if v:
                    new_v = new_item.get(k)
                    if not new_v:
                        print(f"ERROR: Data loss for domain {d} field {k}. Original: '{v}', Updated: '{new_v}'")
                        data_loss_detected = True
                        break
            if data_loss_detected: break
        if data_loss_detected: break
        
    if not data_loss_detected:
        print("SUCCESS: No data loss detected for non-empty fields.")

if __name__ == '__main__':
    verify()
