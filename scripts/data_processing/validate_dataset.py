import sys
import json
import csv
import socket
import os
from datetime import datetime
import time

def check_domain(domain):
    try:
        # Some domains might have http/https, strip it
        clean_domain = domain.replace('http://', '').replace('https://', '').split('/')[0]
        socket.gethostbyname(clean_domain)
        return True
    except socket.gaierror:
        return False
    except Exception:
        return False

def validate_dataset(prefix, data_dir="D:\\Quorix\\services\\safe-zone\\data"):
    json_path = os.path.join(data_dir, f"{prefix}_websites.json")
    csv_path = os.path.join(data_dir, f"{prefix}_websites.csv")
    txt_path = os.path.join(data_dir, f"{prefix}_domains.txt")
    summary_path = os.path.join(data_dir, f"{prefix}_summary.json")
    trash_path = os.path.join(data_dir, f"trash_{prefix}.json")

    if not os.path.exists(json_path):
        print(f"Error: {json_path} does not exist.")
        return

    with open(json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    valid_data = []
    invalid_data = []

    print(f"Checking {len(data)} domains for prefix '{prefix}' sequentially...")
    
    for i, item in enumerate(data):
        domain = item.get('domain', '')
        if not domain:
            continue
            
        if check_domain(domain):
            valid_data.append(item)
        else:
            invalid_data.append(item)
            
        if (i + 1) % 100 == 0:
            print(f"[{prefix}] Processed {i + 1}/{len(data)} domains...")
            
    print(f"[{prefix}] Validation complete. Valid: {len(valid_data)}, Invalid: {len(invalid_data)}")

    if invalid_data:
        # Save invalid to trash
        if os.path.exists(trash_path):
            with open(trash_path, 'r', encoding='utf-8') as f:
                existing_trash = json.load(f)
            invalid_data.extend(existing_trash)
            
        with open(trash_path, 'w', encoding='utf-8') as f:
            json.dump(invalid_data, f, ensure_ascii=False, indent=2)

    # Rewrite JSON always to ensure sync
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(valid_data, f, ensure_ascii=False, indent=2)

    # Rewrite CSV always
    if os.path.exists(csv_path) and valid_data:
        keys = valid_data[0].keys()
        try:
            with open(csv_path, 'w', encoding='utf-8', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=keys)
                writer.writeheader()
                writer.writerows(valid_data)
        except PermissionError:
            print(f"[{prefix}] PermissionError: Could not write to {csv_path}. Skipping CSV update.")
        except Exception as e:
            print(f"[{prefix}] Error writing CSV: {e}")

    # Rewrite TXT always
    if os.path.exists(txt_path):
        with open(txt_path, 'r', encoding='utf-8') as f:
            txt_lines = f.readlines()
        
        # Keep header comments, but filter domains
        new_lines = []
        valid_domains_set = set(item['domain'] for item in valid_data)
        
        for line in txt_lines:
            if line.startswith('#') or line.strip() == '':
                new_lines.append(line)
            else:
                d = line.strip()
                if d in valid_domains_set:
                    new_lines.append(line)
                    
        with open(txt_path, 'w', encoding='utf-8') as f:
            f.writelines(new_lines)

    # Update Summary always
    if os.path.exists(summary_path):
        with open(summary_path, 'r', encoding='utf-8') as f:
            summary = json.load(f)
        
        summary['total_domains'] = len(valid_data)
        summary['last_updated'] = datetime.now().isoformat()
        
        with open(summary_path, 'w', encoding='utf-8') as f:
            json.dump(summary, f, ensure_ascii=False, indent=2)

    print(f"[{prefix}] Successfully synced all files.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python validate_dataset.py <prefix>")
        sys.exit(1)
    
    prefix = sys.argv[1]
    validate_dataset(prefix)
