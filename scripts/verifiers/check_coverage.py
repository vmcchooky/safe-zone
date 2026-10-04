import json
import os
import glob

def load_json(filepath):
    if not os.path.exists(filepath):
        return []
    with open(filepath, 'r', encoding='utf-8') as f:
        return json.load(f)

def check_coverage():
    data_dir = r"D:\Quorix\services\safe-zone\data"
    vietnam_json = os.path.join(data_dir, r"whitelist\vietnam\vietnam_websites.json")
    
    vietnam_data = load_json(vietnam_json)
    vietnam_domains = set()
    for item in vietnam_data:
        d = str(item.get("domain", "")).strip().lower()
        if d:
            vietnam_domains.add(d)
            
    print(f"Total domains in vietnam dataset: {len(vietnam_domains)}")

    # List of all json datasets in data directory
    json_files = glob.glob(os.path.join(data_dir, "*_websites.json"))
    
    coverage_results = {}
    missing_all = set()

    for file in json_files:
        if "merged" in file.lower():
            continue
            
        dataset_name = os.path.basename(file)
        dataset_data = load_json(file)
        
        source_domains = set()
        for item in dataset_data:
            d = str(item.get("domain", "")).strip().lower()
            if d:
                source_domains.add(d)
                
        missing = source_domains - vietnam_domains
        missing_all.update(missing)
        
        coverage_results[dataset_name] = {
            "total": len(source_domains),
            "missing": len(missing)
        }
        
    print("\n--- Coverage Report ---")
    all_covered = True
    for dataset, stats in coverage_results.items():
        if stats["missing"] == 0:
            print(f"[OK] {dataset}: Fully covered ({stats['total']} domains)")
        else:
            print(f"[FAIL] {dataset}: MISSING {stats['missing']} out of {stats['total']} domains")
            all_covered = False
            
    print("\nTotal unique missing domains across all datasets:", len(missing_all))
    
    if all_covered:
        print("\nCONCLUSION: The vietnam dataset FULLY COVERS all source datasets.")
    else:
        print("\nCONCLUSION: The vietnam dataset DOES NOT fully cover all source datasets.")
        print("Sample of missing domains:")
        print(list(missing_all)[:20])

if __name__ == '__main__':
    check_coverage()
