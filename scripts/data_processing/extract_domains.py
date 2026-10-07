import os
from pathlib import Path
import glob

ROOT = Path(__file__).resolve().parents[2]
data_dir = str(ROOT / "tmp/VietnamDNSLeak")
txt_files = glob.glob(os.path.join(data_dir, "**", "*.txt"), recursive=True)

unique_domains = set()

for fpath in txt_files:
    with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            # typical line: 000.com.vn.		43200	IN	NS	ns1.pavietnam.vn.
            parts = line.split()
            if len(parts) >= 4 and parts[3] in ["NS", "A", "CNAME", "MX", "TXT", "SOA"]:
                domain = parts[0]
                if domain.endswith('.'):
                    domain = domain[:-1]
                if domain.endswith('.vn'):
                    unique_domains.add(domain)

print(f"Extracted {len(unique_domains)} unique .vn domains.")

# Save to a temporary file just to check. tmp/ is gitignored, so it is absent
# from a fresh clone and the write below would fail without this.
tmp_out = ROOT / "tmp/unique_vn_domains.txt"
tmp_out.parent.mkdir(parents=True, exist_ok=True)
with tmp_out.open('w', encoding='utf-8') as f:
    for d in unique_domains:
        f.write(f"{d}\n")
