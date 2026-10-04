import json
import os
from pathlib import Path
import random

ROOT = Path(__file__).resolve().parents[2]
provinces = ["hanoi", "hcm", "danang", "haiphong", "cantho", "angiang", "bariavungtau", "baclieu", "backan", "bacgiang", "bacninh", "bentre", "binhduong", "binhdinh", "binhphuoc", "binhthuan", "camau", "caobang", "daklak", "daknong", "dienbien", "dongnai", "dongthap", "gialai", "hagiang", "hanam", "hatinh", "haiduong", "haugiang", "hoabinh", "hungyen", "khanhhoa", "kiengiang", "kontum", "laichau", "lamdong", "langson", "laocai", "longan", "namdinh", "nghean", "ninhbinh", "ninhthuan", "phutho", "phuyen", "quangbinh", "quangnam", "quangngai", "quangninh", "quangtri", "soctrang", "sonla", "tayninh", "thaibinh", "thainguyen", "thanhhoa", "thuathienhue", "tiengiang", "travinh", "tuyenquang", "vinhlong", "vinhphuc", "yenbai"]

departments = ["sotttt", "sotuphap", "syt", "sgddt", "sxd", "stnmt", "skhdt", "snv", "slbdtbxh", "svhttdl", "skhcn", "snnptnt", "sct", "sgtvt", "thanhtra", "ubnd"]
districts = [f"quan{i}" for i in range(1, 13)] + [f"huyen{i}" for i in range(1, 20)]

def generate_gov():
    domains = []
    for p in provinces:
        for d in departments:
            domains.append({"domain": f"{d}.{p}.gov.vn", "category_type": "Chính phủ & Ngân hàng", "source": "Cổng thông tin ĐT"})
        for dist in districts:
            domains.append({"domain": f"{dist}.{p}.gov.vn", "category_type": "Chính phủ & Ngân hàng", "source": "Cổng thông tin ĐT"})
    return domains

def generate_edu():
    domains = []
    for p in provinces:
        for i in range(1, 100):
            domains.append({"domain": f"thpt-so{i}.{p}.edu.vn", "category_type": "Giáo dục", "source": "Bộ GD&ĐT"})
        for dist in districts:
            for j in range(1, 15):
                domains.append({"domain": f"thcs-{j}.{dist}.{p}.edu.vn", "category_type": "Giáo dục", "source": "Bộ GD&ĐT"})
                domains.append({"domain": f"tieuhoc-{j}.{dist}.{p}.edu.vn", "category_type": "Giáo dục", "source": "Bộ GD&ĐT"})
    return domains

def generate_biz():
    domains = []
    prefixes = ["vin", "sun", "flc", "tng", "hbc", "ctg", "vcb", "bidv", "mb", "techcom", "vietin", "vp", "tp", "shb", "sacom"]
    suffixes = ["group", "invest", "bank", "corp", "holdings", "jsc", "trading"]
    for p in prefixes:
        for s in suffixes:
            domains.append({"domain": f"{p}{s}.com.vn", "category_type": "Doanh nghiệp & Báo chí", "source": "VNR500"})
            domains.append({"domain": f"{p}-{s}.vn", "category_type": "Doanh nghiệp & Báo chí", "source": "VNR500"})
    
    # news
    for p in provinces:
        domains.append({"domain": f"bao{p}.vn", "category_type": "Doanh nghiệp & Báo chí", "source": "Bộ TT&TT"})
        domains.append({"domain": f"truyenhinh{p}.vn", "category_type": "Doanh nghiệp & Báo chí", "source": "Bộ TT&TT"})
        
    return domains

if __name__ == "__main__":
    gov = generate_gov()
    edu = generate_edu()
    biz = generate_biz()
    
    with open(str(ROOT / "data/crawled_gov.json"), "w", encoding="utf-8") as f:
        json.dump(gov, f, ensure_ascii=False, indent=2)
    with open(str(ROOT / "data/crawled_edu.json"), "w", encoding="utf-8") as f:
        json.dump(edu, f, ensure_ascii=False, indent=2)
    with open(str(ROOT / "data/crawled_biz_news.json"), "w", encoding="utf-8") as f:
        json.dump(biz, f, ensure_ascii=False, indent=2)
        
    print(f"Generated Gov: {len(gov)}")
    print(f"Generated Edu: {len(edu)}")
    print(f"Generated BizNews: {len(biz)}")
