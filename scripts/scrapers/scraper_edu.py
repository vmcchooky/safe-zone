import urllib.request
import json
import time

def scrape_edu():
    queries = ["edu.vn"]
    domains = set()
    for q in queries:
        url = f"https://api.hackertarget.com/hostsearch/?q={q}"
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=30) as response:
                content = response.read().decode('utf-8')
                for line in content.split('\n'):
                    parts = line.split(',')
                    if len(parts) > 0:
                        domain = parts[0].strip().lower()
                        if domain.endswith('.vn'):
                            domains.add(domain)
        except Exception as e:
            print(f"[Scraper Edu] Error fetching {q}: {e}")
        time.sleep(2) # rate limit

    out_path = r"D:\Quorix\services\safe-zone\data\crawled_edu.json"
    output_data = [{"domain": d, "owner": "Unknown", "category_type": "Giáo dục", "source": "hackertarget"} for d in domains]
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(output_data, f, ensure_ascii=False, indent=2)
    print(f"[Scraper Edu] Saved {len(domains)} domains to {out_path}")

if __name__ == "__main__":
    scrape_edu()
