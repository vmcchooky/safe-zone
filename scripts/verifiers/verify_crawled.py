import json
import sys
import os
import re

def verify(filepath):
    if not os.path.exists(filepath):
        print(f"[Verifier] Error: {filepath} not found.")
        return
        
    with open(filepath, 'r', encoding='utf-8') as f:
        data = json.load(f)
        
    valid_domains = []
    invalid_domains = []
    
    # A robust domain regex
    domain_regex = re.compile(r"^xn--[a-z0-9-]+(\.[a-z0-9-]+)*\.[a-z]{2,}$|^[a-z0-9\u00A1-\uFFFF]([a-z0-9\u00A1-\uFFFF-]*[a-z0-9\u00A1-\uFFFF])?(\.[a-z0-9\u00A1-\uFFFF]([a-z0-9\u00A1-\uFFFF-]*[a-z0-9\u00A1-\uFFFF])?)*\.[a-z\u00A1-\uFFFF]{2,}$")
    
    for item in data:
        domain = str(item.get("domain", "")).strip().lower()
        if domain_regex.match(domain) and not " " in domain:
            valid_domains.append(item)
        else:
            invalid_domains.append(domain)
            
    print(f"[Verifier] Checked {len(data)} domains in {os.path.basename(filepath)}")
    print(f"[Verifier] Valid: {len(valid_domains)}, Invalid: {len(invalid_domains)}")
    
    if invalid_domains:
        print(f"[Verifier] Saving cleaned version over original...")
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(valid_domains, f, ensure_ascii=False, indent=2)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python verify_crawled.py <filepath>")
    else:
        verify(sys.argv[1])
