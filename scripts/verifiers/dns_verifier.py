import json
import sys
import socket
import concurrent.futures
import time
import os

# Set a global timeout just in case, though NXDOMAIN returns fast
socket.setdefaulttimeout(3.0)

def check_domain(item):
    domain = item.get("domain", "").strip()
    try:
        # Check if the domain has a DNS A record
        socket.gethostbyname(domain)
        return item
    except Exception:
        # If it fails to resolve (NXDOMAIN or Timeout), we discard it
        return None

def verify_file(filepath):
    if not os.path.exists(filepath):
        print(f"File not found: {filepath}")
        return

    print(f"Starting DNS verification for: {filepath}")
    with open(filepath, 'r', encoding='utf-8') as f:
        data = json.load(f)
        
    print(f"Total domains to check: {len(data)}")
    
    start_time = time.time()
    valid_data = []
    
    # Using 200 threads to speed up the process for 60,000 domains
    with concurrent.futures.ThreadPoolExecutor(max_workers=200) as executor:
        results = list(executor.map(check_domain, data))
        
    for res in results:
        if res is not None:
            valid_data.append(res)
            
    end_time = time.time()
    print(f"Finished {filepath} in {end_time - start_time:.2f} seconds.")
    print(f"Original: {len(data)}, Valid (Real): {len(valid_data)}, Removed: {len(data) - len(valid_data)}")
    
    # Save only valid domains back to the file
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(valid_data, f, ensure_ascii=False, indent=2)
    print(f"Saved cleaned data to {filepath}\n")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python dns_verifier.py <filepath>")
    else:
        verify_file(sys.argv[1])
