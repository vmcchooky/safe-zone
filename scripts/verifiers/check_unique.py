import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
unique_file = str(ROOT / "tmp/unique_vn_domains.txt")
whitelist_file = str(ROOT / "data/whitelist/vietnam/vietnam_domains.txt")

print("Reading unique_vn_domains.txt...")
with open(unique_file, 'r', encoding='utf-8') as f:
    unique_set = set(line.strip().lower() for line in f if line.strip())

print(f"Loaded {len(unique_set)} domains from unique_vn_domains.txt")

print("Reading whitelist vietnam_domains.txt...")
with open(whitelist_file, 'r', encoding='utf-8') as f:
    whitelist_set = set(line.strip().lower() for line in f if line.strip())

print(f"Loaded {len(whitelist_set)} domains from whitelist")

missing = unique_set - whitelist_set
print(f"Number of domains in unique_vn_domains.txt that are NOT in whitelist: {len(missing)}")

if missing:
    print("Some examples of missing domains:")
    for i, d in enumerate(list(missing)[:10]):
        print(f" - {d}")
else:
    print("SUCCESS: 100% of domains in unique_vn_domains.txt are already in the whitelist!")
