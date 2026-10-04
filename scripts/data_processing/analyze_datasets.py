import json
import os
import glob
from collections import Counter

def analyze_datasets(data_dir="D:\\Quorix\\services\\safe-zone\\data"):
    json_files = glob.glob(os.path.join(data_dir, "*_websites.json"))
    
    total_domains = 0
    all_domains = set()
    category_counts = Counter()
    dataset_sizes = {}
    overlaps = Counter()
    domain_to_datasets = {}
    
    metadata_fields = set()
    missing_metadata = Counter()
    
    for file in json_files:
        basename = os.path.basename(file)
        if basename.startswith("trash"):
            continue
            
        dataset_name = basename.replace("_websites.json", "")
        with open(file, 'r', encoding='utf-8') as f:
            data = json.load(f)
            
        dataset_sizes[dataset_name] = len(data)
        total_domains += len(data)
        
        for item in data:
            domain = item.get('domain', '')
            if not domain:
                continue
                
            all_domains.add(domain)
            
            if domain not in domain_to_datasets:
                domain_to_datasets[domain] = []
            domain_to_datasets[domain].append(dataset_name)
            
            cat = item.get('category_type') or item.get('category') or 'Unknown'
            category_counts[cat] += 1
            
            # Record metadata fields
            metadata_fields.update(item.keys())
            
            # Check missing standard fields (assuming we want owner, category, cert_level)
            for field in ['owner', 'category_type', 'cert_level']:
                if not item.get(field) or item.get(field) == '':
                    missing_metadata[field] += 1
                    
    # Calculate overlaps
    for domain, datasets in domain_to_datasets.items():
        if len(datasets) > 1:
            overlaps[tuple(sorted(datasets))] += 1

    report = []
    report.append("=== DATASET ANALYSIS REPORT ===")
    report.append(f"Total entries across files: {total_domains}")
    report.append(f"Total unique domains: {len(all_domains)}")
    report.append(f"Duplicates/Overlaps: {total_domains - len(all_domains)}")
    
    report.append("\n--- Dataset Sizes ---")
    for name, size in dataset_sizes.items():
        report.append(f"{name}: {size}")
        
    report.append("\n--- Category Distribution (Top 15) ---")
    for cat, count in category_counts.most_common(15):
        report.append(f"{cat}: {count}")
        
    report.append("\n--- Overlap Breakdown ---")
    for dset_tuple, count in overlaps.most_common():
        report.append(f"{' & '.join(dset_tuple)}: {count} domains")
        
    report.append("\n--- Metadata Completeness ---")
    report.append(f"Available fields: {', '.join(metadata_fields)}")
    report.append("Missing fields count across all entries:")
    for field, count in missing_metadata.items():
        report.append(f"  {field}: {count} ({count/total_domains*100:.1f}%)")
        
    with open(os.path.join(data_dir, "analysis_report.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(report))
        
    print("\n".join(report))

if __name__ == "__main__":
    analyze_datasets()
