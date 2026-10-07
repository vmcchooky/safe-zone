import sys
import json
import csv
import os
from pathlib import Path
from datetime import datetime

ROOT = Path(__file__).resolve().parents[2]

def restore_dataset(prefix, data_dir=str(ROOT / "data")):
    json_path = os.path.join(data_dir, f"{prefix}_websites.json")
    csv_path = os.path.join(data_dir, f"{prefix}_websites.csv")
    txt_path = os.path.join(data_dir, f"{prefix}_domains.txt")
    summary_path = os.path.join(data_dir, f"{prefix}_summary.json")
    trash_path = os.path.join(data_dir, f"trash_{prefix}.json")

    if not os.path.exists(trash_path):
        print(f"Error: {trash_path} does not exist. Nothing to restore.")
        return

    with open(json_path, 'r', encoding='utf-8') as f:
        valid_data = json.load(f)
        
    with open(trash_path, 'r', encoding='utf-8') as f:
        trash_data = json.load(f)
        
    if not trash_data:
        print("Trash is empty. Nothing to restore.")
        return

    # Merge and remove duplicates based on domain
    merged_data = valid_data + trash_data
    unique_data = {item['domain']: item for item in merged_data if 'domain' in item}
    final_data = list(unique_data.values())

    print(f"Restoring {len(trash_data)} domains from trash. New total: {len(final_data)}.")

    # Rewrite JSON
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(final_data, f, ensure_ascii=False, indent=2)

    # Rewrite CSV
    if final_data:
        keys = final_data[0].keys()
        try:
            with open(csv_path, 'w', encoding='utf-8', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=keys)
                writer.writeheader()
                writer.writerows(final_data)
        except PermissionError:
            print(f"[{prefix}] PermissionError: Could not write to {csv_path}. Skipping CSV update.")
        except Exception as e:
            print(f"[{prefix}] Error writing CSV: {e}")

    # Rewrite TXT
    if os.path.exists(txt_path):
        with open(txt_path, 'r', encoding='utf-8') as f:
            txt_lines = f.readlines()
        
        # Keep header comments
        header_lines = []
        for line in txt_lines:
            if line.startswith('#') or line.strip() == '':
                header_lines.append(line)
            else:
                # We stop reading header at the first domain
                break
                
        with open(txt_path, 'w', encoding='utf-8') as f:
            f.writelines(header_lines)
            for item in final_data:
                f.write(f"{item['domain']}\n")

    # Update Summary
    if os.path.exists(summary_path):
        with open(summary_path, 'r', encoding='utf-8') as f:
            summary = json.load(f)
        
        summary['total_domains'] = len(final_data)
        summary['last_updated'] = datetime.now().isoformat()
        
        with open(summary_path, 'w', encoding='utf-8') as f:
            json.dump(summary, f, ensure_ascii=False, indent=2)
            
    # Clear trash
    os.remove(trash_path)
    print(f"Successfully restored '{prefix}' dataset and deleted trash file.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python restore_dataset.py <prefix>")
        sys.exit(1)
    
    prefix = sys.argv[1]
    restore_dataset(prefix)
