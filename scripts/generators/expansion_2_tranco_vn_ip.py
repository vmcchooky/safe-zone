"""
Expansion 2: Tranco 1M & Global Datasets IP/ASN & WHOIS Filter
Resolves global domains and filters those hosted in Vietnam IPv4 CIDR blocks
or belonging to Vietnamese TLDs / organizations.
"""
import socket
import urllib.request
import ipaddress
import json
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

data_dir = r"d:\Quorix\services\safe-zone\data"
output_path = os.path.join(data_dir, "expansion_tranco_vn.json")

print("Downloading official Vietnam IPv4 CIDR blocks...")
vn_networks = []
try:
    url = "https://ipverse.net/ipblocks/data/countries/vn.zone"
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        for line in resp.read().decode().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                try:
                    vn_networks.append(ipaddress.ip_network(line))
                except Exception:
                    pass
    print(f"Loaded {len(vn_networks)} Vietnamese IPv4 CIDR networks!")
except Exception as e:
    print(f"Error fetching CIDRs: {e}")

# Helper to check if IP is in Vietnam CIDR
def is_vn_ip(ip_str):
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return any(ip_obj in net for net in vn_networks)
    except Exception:
        return False

print("Loading domains from massive_domains.txt...")
domains_to_scan = []
massive_path = os.path.join(data_dir, "massive_domains.txt")
if os.path.exists(massive_path):
    with open(massive_path, "r", encoding="utf-8") as f:
        for line in f:
            d = line.strip()
            if d:
                domains_to_scan.append(d)

print(f"Loaded {len(domains_to_scan)} domains to scan.")

vn_matched_domains = set()

# Include all .vn domains immediately
for d in domains_to_scan:
    if d.endswith(".vn"):
        vn_matched_domains.add(d)

print(f"Direct .vn domains in dataset: {len(vn_matched_domains)}")

# Check IP location of top non-.vn domains
candidates = [d for d in domains_to_scan[:50000] if not d.endswith(".vn")]
print(f"Checking IP geolocation for {len(candidates)} top non-.vn domains...")

def check_domain_ip(domain):
    try:
        ip_str = socket.gethostbyname(domain)
        if is_vn_ip(ip_str):
            return domain, ip_str
    except Exception:
        pass
    return None, None

t0 = time.time()
with ThreadPoolExecutor(max_workers=100) as executor:
    futures = {executor.submit(check_domain_ip, d): d for d in candidates}
    done = 0
    total = len(candidates)
    for future in as_completed(futures):
        done += 1
        dom, ip = future.result()
        if dom:
            vn_matched_domains.add(dom)
        if done % 5000 == 0 or done == total:
            print(f"Processed {done}/{total} - Total VN Matched Domains: {len(vn_matched_domains)} ({time.time()-t0:.1f}s)")

print(f"\nFinal Matched VN / VN-hosted Domains: {len(vn_matched_domains)}")
with open(output_path, "w", encoding="utf-8") as f:
    json.dump(sorted(list(vn_matched_domains)), f, ensure_ascii=False, indent=2)
print(f"Saved to {output_path}")
