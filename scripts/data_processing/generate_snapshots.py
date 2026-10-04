#!/usr/bin/env python3
"""Generate frozen analysis snapshots for ML feature extraction contract.

Reads Go definition constants from internal/analysis and internal/config,
fetches the official Public Suffix List, and writes machine-readable JSON / DAT
artifacts to ml/contracts/snapshots/.
"""

import json
import hashlib
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SNAPSHOTS_DIR = ROOT / "ml" / "contracts" / "snapshots"

# 1. 40 Default Trusted Brands from internal/analysis/brand.go
BRANDS = [
    {"name": "google", "official_domain": "google.com", "alt_domains": [
        "google.com.vn", "google.co.uk", "google.com.sg", "googleusercontent.com",
        "googlesyndication.com", "googletagservices.com", "googletagmanager.com",
        "google-analytics.com", "googleapis.com", "gstatic.com", "googlevideo.com",
        "youtube.com", "youtu.be", "ytimg.com", "ggpht.com", "gvt1.com", "doubleclick.net"
    ]},
    {"name": "binance", "official_domain": "binance.com", "alt_domains": ["binance.us", "binance.info"]},
    {"name": "paypal", "official_domain": "paypal.com", "alt_domains": ["paypal.me"]},
    {"name": "facebook", "official_domain": "facebook.com", "alt_domains": [
        "fb.com", "messenger.com", "fbcdn.net", "fbsbx.com"
    ]},
    {"name": "apple", "official_domain": "apple.com", "alt_domains": ["icloud.com"]},
    {"name": "microsoft", "official_domain": "microsoft.com", "alt_domains": [
        "live.com", "outlook.com", "office.com", "microsoftonline.com", "sharepoint.com",
        "office365.com", "windows.net", "windows.com", "azure.com", "visualstudio.com",
        "aspnetcdn.com", "msn.com", "bing.com"
    ]},
    {"name": "amazon", "official_domain": "amazon.com", "alt_domains": []},
    {"name": "netflix", "official_domain": "netflix.com", "alt_domains": []},
    {"name": "instagram", "official_domain": "instagram.com", "alt_domains": ["cdninstagram.com"]},
    {"name": "twitter", "official_domain": "twitter.com", "alt_domains": ["x.com"]},
    {"name": "metamask", "official_domain": "metamask.io", "alt_domains": []},
    {"name": "coinbase", "official_domain": "coinbase.com", "alt_domains": []},
    {"name": "trustwallet", "official_domain": "trustwallet.com", "alt_domains": []},
    {"name": "yahoo", "official_domain": "yahoo.com", "alt_domains": ["yimg.com"]},
    {"name": "linkedin", "official_domain": "linkedin.com", "alt_domains": []},

    {"name": "chinhphu", "official_domain": "chinhphu.vn", "alt_domains": ["chinhphu.gov.vn"]},
    {"name": "bocongan", "official_domain": "bocongan.gov.vn", "alt_domains": ["mps.gov.vn"]},
    {"name": "baohiemxahoi", "official_domain": "baohiemxahoi.gov.vn", "alt_domains": ["bhxh.gov.vn"]},
    {"name": "vneid", "official_domain": "vneid.gov.vn", "alt_domains": []},
    {"name": "vtv", "official_domain": "vtv.vn", "alt_domains": []},

    {"name": "vietcombank", "official_domain": "vietcombank.com.vn", "alt_domains": ["vietcombank.com"]},
    {"name": "techcombank", "official_domain": "techcombank.com.vn", "alt_domains": ["techcombank.com"]},
    {"name": "bidv", "official_domain": "bidv.com.vn", "alt_domains": ["bidv.com"]},
    {"name": "vietinbank", "official_domain": "vietinbank.vn", "alt_domains": ["vietinbank.co.vn"]},
    {"name": "mbbank", "official_domain": "mbbank.com.vn", "alt_domains": ["mbbank.com"]},
    {"name": "agribank", "official_domain": "agribank.com.vn", "alt_domains": ["agribank.com"]},
    {"name": "vpbank", "official_domain": "vpbank.com.vn", "alt_domains": ["vpbank.com"]},
    {"name": "acb", "official_domain": "acb.com.vn", "alt_domains": ["acb.com"]},
    {"name": "sacombank", "official_domain": "sacombank.com.vn", "alt_domains": ["sacombank.com"]},
    {"name": "tpbank", "official_domain": "tpb.vn", "alt_domains": ["tpbank.com.vn"]},
    {"name": "vib", "official_domain": "vib.com.vn", "alt_domains": []},
    {"name": "hdbank", "official_domain": "hdbank.com.vn", "alt_domains": []},
    {"name": "shb", "official_domain": "shb.com.vn", "alt_domains": []},
    {"name": "scb", "official_domain": "scb.com.vn", "alt_domains": []},

    {"name": "momo", "official_domain": "momo.vn", "alt_domains": []},
    {"name": "zalopay", "official_domain": "zalopay.vn", "alt_domains": []},
    {"name": "vnpay", "official_domain": "vnpay.vn", "alt_domains": []},
    {"name": "shopee", "official_domain": "shopee.vn", "alt_domains": ["shopee.com"]},
    {"name": "tiki", "official_domain": "tiki.vn", "alt_domains": []},
    {"name": "lazada", "official_domain": "lazada.vn", "alt_domains": ["lazada.com"]}
]

# 2. 15 Default Phishing Keywords from internal/config/analysis.go
KEYWORDS = [
    "login", "secure", "verify", "account", "update", "support", "wallet",
    "dichvucong", "congan", "vneid", "phatnguoi", "xulyphat", "nganhang", "xacthuc", "cungcap"
]

# 3. 17 Suspicious TLDs map from internal/analysis/brand.go
TLD_RISK = {
    "xyz": True, "top": True, "cc": True, "info": True, "work": True,
    "club": True, "fit": True, "vip": True, "cf": True, "gq": True,
    "ga": True, "ml": True, "tk": True, "icu": True, "asia": True,
    "buzz": True, "bid": True
}

# 4. 36 CDN / Shared Hosting Roots from internal/analysis/brand.go
SHARED_HOSTING = [
    "akamaihd.net", "akamaized.net", "amazonaws.com", "azurecontainerapps.io",
    "azureedge.net", "azurefd.net", "azurestaticapps.net", "azurewebsites.net",
    "b-cdn.net", "cachefly.net", "cdn77.org", "cloudflare.net",
    "cloudfront.net", "edgekey.net", "edgesuite.net", "fastly.net",
    "fastlylb.net", "firebaseapp.com", "fly.dev", "github.io",
    "githubusercontent.com", "glitch.me", "herokuapp.com", "hwcdn.net",
    "netlify.app", "onrender.com", "pages.dev", "railway.app",
    "repl.co", "replit.app", "r2.dev", "stackpathdns.com",
    "surge.sh", "trafficmanager.net", "vercel.app", "workers.dev"
]

# 5. Go homoglyph rune map from internal/analysis/brand.go
HOMOGLYPHS = {
    "а": "a", "б": "b", "с": "c", "ԁ": "d", "е": "e", "f": "f", "g": "g", "һ": "h",
    "і": "i", "ј": "j", "k": "k", "l": "l", "m": "m", "п": "n", "о": "o", "р": "p",
    "q": "q", "г": "r", "ѕ": "s", "т": "t", "υ": "u", "ѵ": "v", "ԝ": "w", "х": "x",
    "у": "y", "z": "z",
    "А": "a", "В": "b", "С": "c", "Е": "e", "Н": "h", "І": "i", "Ј": "j", "К": "k",
    "М": "m", "О": "o", "Р": "p", "Ѕ": "s", "Т": "t", "Х": "x", "Ү": "y",
    "α": "a", "β": "b", "ε": "e", "ι": "i", "κ": "k", "ο": "o", "ρ": "p", "τ": "t",
    "χ": "x"
}

# 6. QWERTY Keyboard Adjacency map from internal/analysis/brand.go
KEYBOARD_ADJACENCY = {
    "a": "qwsz", "b": "vghn", "c": "xdfv", "d": "ersfxc",
    "e": "wsdr34", "f": "rtgvcd", "g": "tyhbvf", "h": "yujnbg",
    "i": "ujko89", "j": "uikmnh", "k": "ijlm09", "l": "okp",
    "m": "njk", "n": "bhjm", "o": "iklp90", "p": "ol0",
    "q": "w12a", "r": "edft45", "s": "wedxza", "t": "rfgy56",
    "u": "yhji78", "v": "cfgb", "w": "qase23", "x": "zsdc",
    "y": "tghu67", "z": "asx"
}

# 7. Analysis Parameters from internal/config/analysis.go
ANALYSIS_CONFIG = {
    "punycode_score": 35,
    "long_domain_length": 24,
    "long_domain_score": 15,
    "hyphen_count_threshold": 3,
    "hyphen_score": 10,
    "digit_ratio_threshold": 0.25,
    "digit_ratio_score": 10,
    "mixed_script_score": 25,
    "keywords": KEYWORDS,
    "keyword_base_score": 15,
    "keyword_match_score": 10,
    "keyword_multiple_bonus": 10,
    "brand_spoofing_score": 50,
    "entropy_threshold": 3.0,
    "entropy_score": 35
}

PSL_URL = "https://raw.githubusercontent.com/publicsuffix/list/master/public_suffix_list.dat"

def main():
    SNAPSHOTS_DIR.mkdir(parents=True, exist_ok=True)

    files_written = []

    def write_json(name: str, content: object):
        path = SNAPSHOTS_DIR / name
        with path.open("w", encoding="utf-8", newline="\n") as f:
            json.dump(content, f, ensure_ascii=False, indent=2)
            f.write("\n")
        files_written.append(path)
        print(f"Wrote {name}")

    write_json("brands.v1.json", BRANDS)
    write_json("keywords.v1.json", KEYWORDS)
    write_json("tld_risk.v1.json", TLD_RISK)
    write_json("shared_hosting.v1.json", SHARED_HOSTING)
    write_json("homoglyphs.v1.json", HOMOGLYPHS)
    write_json("keyboard_adjacency.v1.json", KEYBOARD_ADJACENCY)
    write_json("analysis_config.v1.json", ANALYSIS_CONFIG)

    # Pin Public Suffix List
    psl_dat_path = SNAPSHOTS_DIR / "public_suffix_list.v1.dat"
    print(f"Fetching PSL from {PSL_URL}...")
    req = urllib.request.Request(PSL_URL, headers={"User-Agent": "SafeZone-ML-Preflight/1.0"})
    with urllib.request.urlopen(req) as resp:
        psl_bytes = resp.read()

    with psl_dat_path.open("wb") as f:
        f.write(psl_bytes)

    psl_sha256 = hashlib.sha256(psl_bytes).hexdigest()
    psl_size = len(psl_bytes)
    print(f"Wrote public_suffix_list.v1.dat ({psl_size:,} bytes, sha256={psl_sha256})")

    psl_meta = {
        "snapshot_version": 1,
        "source_url": PSL_URL,
        "retrieved_at": datetime.now(timezone.utc).isoformat(),
        "bytes": psl_size,
        "sha256": psl_sha256,
        "sections": ["ICANN DOMAINS", "PRIVATE DOMAINS"]
    }
    write_json("psl_metadata.v1.json", psl_meta)

    print("\nAll snapshots successfully generated in ml/contracts/snapshots/")

if __name__ == "__main__":
    main()
