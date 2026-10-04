import json
import sys
import socket
import concurrent.futures
import time
import os

def check_port(host, port, timeout=3.0):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False

def check_domain(item):
    domain = item.get("domain", "").strip()
    # Try HTTPS first, then HTTP
    if check_port(domain, 443) or check_port(domain, 80):
        return item
    return None

def verify_file_deep(filepath):
    if not os.path.exists(filepath):
        print(f"File not found: {filepath}")
        return

    print(f"Starting DEEP verification (TCP 80/443) for: {filepath}")
    with open(filepath, 'r', encoding='utf-8') as f:
        data = json.load(f)
        
    print(f"Total domains to deep-check: {len(data)}")
    
    start_time = time.time()
    valid_data = []
    
    # 300 threads to speed through 30,000 domains
    with concurrent.futures.ThreadPoolExecutor(max_workers=300) as executor:
        results = list(executor.map(check_domain, data))
        
    for res in results:
        if res is not None:
            valid_data.append(res)
            
    end_time = time.time()
    print(f"Finished {filepath} in {end_time - start_time:.2f} seconds.")
    print(f"Original: {len(data)}, Accessible (Real): {len(valid_data)}, Removed: {len(data) - len(valid_data)}")
    
    # Save only valid domains back to the file
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(valid_data, f, ensure_ascii=False, indent=2)
    print(f"Saved deeply cleaned data to {filepath}\n")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python deep_verifier.py <filepath>")
    else:
        verify_file_deep(sys.argv[1])
