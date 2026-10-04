import json
import urllib.request
import time
import re
import os

QUERIES = [
    "https://crt.sh/?q=%.com.vn&output=json",
    "https://crt.sh/?q=%.vn&output=json",
    "https://crt.sh/?q=%.net.vn&output=json",
    "https://crt.sh/?q=%.org.vn&output=json",
    "https://crt.sh/?q=%.edu.vn&output=json",
    "https://crt.sh/?q=%.gov.vn&output=json",
    "https://crt.sh/?q=%.biz.vn&output=json",
    "https://crt.sh/?q=%.info.vn&output=json"
]

OUTPUT_FILE = r"d:\Quorix\services\safe-zone\data\collected_crtsh.json"

def clean_domain(domain):
    domain = domain.strip().lower()
    if domain.startswith('*.'):
        domain = domain[2:]
    return domain

def is_valid_domain(domain):
    if ' ' in domain:
        return False
    if '.' not in domain:
        return False
    if not re.match(r'^[a-z0-9.-]+$', domain):
        return False
    return True

def main():
    domains = set()
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
    
    # Ensure directory exists
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    
    for url in QUERIES:
        print(f"Querying: {url}")
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=60) as response:
                if response.status == 200:
                    data = json.loads(response.read().decode('utf-8'))
                    for entry in data:
                        cn = entry.get('common_name', '')
                        nv = entry.get('name_value', '')
                        
                        if cn:
                            for d in cn.split('\n'):
                                cd = clean_domain(d)
                                if is_valid_domain(cd):
                                    domains.add(cd)
                        if nv:
                            for d in nv.split('\n'):
                                cd = clean_domain(d)
                                if is_valid_domain(cd):
                                    domains.add(cd)
        except Exception as e:
            print(f"Error querying {url}: {e}")
            
        time.sleep(3)
        
    unique_domains = list(domains)
    print(f"Total unique domains collected: {len(unique_domains)}")
    
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        json.dump(unique_domains, f, indent=2)
    print(f"Domains saved to {OUTPUT_FILE}")

if __name__ == '__main__':
    main()
