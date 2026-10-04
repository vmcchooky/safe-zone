"""
Expansion 1: Mass DNS Resolution & Candidate Domain Verification
Generates candidate Vietnamese domains and verifies their REAL active DNS existence.
Only keeps domains that resolve to a valid IP address.
"""
import socket
import json
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

data_dir = r"d:\Quorix\services\safe-zone\data"
output_path = os.path.join(data_dir, "expansion_dns_verified.json")

# Vietnamese dictionary words & business terms
words = [
    "an", "anh", "ba", "bac", "ban", "bao", "bat", "bay", "be", "ben", "bi", "binh", "bo", "bon", "bui", "ca", "cac", "cam", "can",
    "cao", "cap", "cat", "cau", "cay", "cha", "cham", "chan", "chang", "chao", "chap", "chat", "chau", "chay", "che", "chen",
    "chi", "chia", "chien", "chim", "chin", "chinh", "cho", "chon", "chong", "chu", "chua", "chuc", "chuan", "chung",
    "chuong", "chuyen", "co", "con", "cong", "cu", "cua", "cuc", "cung", "cuoc", "cuoi", "cuon", "cuong", "da", "dac",
    "dai", "dam", "dan", "dang", "dao", "dat", "dau", "day", "de", "dem", "den", "dep", "deu", "di", "dich", "diem", "dien",
    "dieu", "dinh", "do", "doan", "doc", "doi", "don", "dong", "du", "dua", "duc", "dung", "duoc", "duong", "duy", "em",
    "ga", "gach", "gai", "gan", "gap", "gat", "gay", "gia", "giai", "giam", "gian", "giao", "giap", "giat", "giau", "giay",
    "gio", "gioi", "giu", "giup", "go", "goi", "goc", "gong", "gui", "ha", "hai", "ham", "han", "hang", "hanh", "hao",
    "hat", "hay", "he", "hen", "het", "hien", "hiep", "hieu", "hinh", "ho", "hoa", "hoan", "hoang", "hoc", "hoi",
    "hon", "hong", "hop", "hung", "huong", "huy", "huyen", "huynh", "it", "ke", "kem", "keo", "ket", "kha", "khac", "khach",
    "khai", "kham", "khan", "khang", "khanh", "khao", "khat", "khau", "khi", "khien", "kho", "khoa", "khoan", "khoang", "khoe",
    "khoi", "khon", "khong", "khu", "khuc", "khung", "khuyen", "ki", "kien", "kieu", "kim", "kinh", "ky", "la", "lac", "lai",
    "lam", "lan", "lang", "lanh", "lap", "lau", "lay", "le", "len", "lich", "lien", "lieu", "linh", "lo", "loa", "loai", "loan",
    "loc", "loi", "lon", "long", "lu", "lua", "luc", "lui", "luon", "luong", "luot", "luu", "luyen", "ly", "ma", "mac", "mai",
    "man", "mang", "manh", "mat", "mau", "may", "me", "mem", "men", "mi", "mien", "minh", "mit", "mo", "moc", "moi", "mon",
    "mong", "mot", "mua", "muc", "mui", "muon", "muoi", "my", "nam", "nang", "nay", "nem", "nen", "nga", "ngai", "ngan",
    "ngang", "ngao", "ngay", "nghe", "nghi", "nghia", "nghiem", "nghiep", "ngo", "ngoai", "ngoan", "ngoc", "ngoi", "ngon", "ngot",
    "ngu", "ngua", "nguoi", "nguon", "nha", "nhac", "nhan", "nhang", "nhanh", "nhat", "nhau", "nhi", "nhiem", "nhien", "nhieu",
    "nhin", "nhip", "nho", "nhom", "nhu", "nhung", "niem", "ninh", "no", "noi", "nong", "nu", "nua", "nuoc", "nuoi", "pa",
    "pha", "phai", "pham", "phan", "phang", "phap", "phat", "phay", "phe", "phi", "phia", "phien", "phim", "pho", "phong",
    "phu", "phuc", "phuong", "phut", "qua", "quan", "quang", "quanh", "quat", "quay", "que", "quen", "quoc", "quy", "quyen",
    "quyet", "quynh", "ra", "rac", "rai", "ram", "ran", "rang", "rao", "rap", "rau", "ray", "re", "ren", "ri", "rieng", "ro",
    "roi", "rong", "ru", "rua", "ruc", "rui", "rung", "ruot", "ruou", "rut", "sa", "sac", "sai", "sam", "san", "sang", "sanh",
    "sao", "sap", "sat", "sau", "say", "se", "sen", "si", "sieu", "sim", "sinh", "so", "soi", "som", "son", "song", "su",
    "sua", "suc", "sui", "sung", "suoi", "suot", "sut", "suy", "ta", "tac", "tai", "tam", "tan", "tang", "tao", "tap", "tat",
    "tau", "tay", "te", "ten", "tha", "thac", "thai", "tham", "than", "thang", "thanh", "thao", "thap", "that", "thau", "thay",
    "the", "them", "then", "theo", "thep", "thi", "thich", "thien", "thiep", "thiet", "thieu", "thinh", "thit", "tho", "thoa",
    "thoai", "thoan", "thoat", "thoi", "thom", "thon", "thong", "thu", "thua", "thuc", "thue", "thung", "thuoc", "thuong",
    "thuy", "thuyen", "thuyet", "ti", "tia", "tich", "tien", "tiep", "tiet", "tieu", "tim", "tin", "tinh", "to", "toa", "toan",
    "toc", "toi", "tom", "ton", "tong", "tot", "tra", "trac", "trai", "tram", "tran", "trang", "tranh", "trao", "trau", "tre",
    "tren", "tri", "trich", "trien", "trieu", "trinh", "tro", "troi", "tron", "trong", "tru", "truc", "truong", "truyen", "tu",
    "tua", "tuan", "tuc", "tui", "tung", "tuoi", "tuong", "tuyen", "tuyet", "ua", "uc", "ui", "um", "ung", "uoc", "uong",
    "uy", "uyen", "va", "vac", "vai", "van", "vang", "vanh", "vao", "vat", "ve", "ven", "vi", "via", "viec", "vien", "viet",
    "vinh", "vo", "voi", "von", "vong", "vu", "vui", "vun", "vung", "vuong", "vuot", "xa", "xac", "xai", "xam", "xan", "xang",
    "xanh", "xao", "xat", "xau", "xay", "xe", "xem", "xen", "xi", "xich", "xien", "xin", "xinh", "xo", "xoa", "xoan", "xoc",
    "xoi", "xom", "xong", "xot", "xu", "xua", "xuc", "xui", "xung", "xuong", "xuyen", "yen", "yeu"
]

biz_prefixes = [
    "congty", "tapdoan", "cuahang", "sieuthi", "nhahang", "khachsan", "dichvu", "sanpham", "hethong", "trungtam",
    "phongkham", "duan", "batdongsan", "nhadat", "thietke", "xaydung", "noithat", "tin", "tech", "group", "viet", "vina",
    "saigon", "hanoi", "danang", "cantho", "haiphong", "vinh", "binhduong", "dongnai", "longan", "bentre", "quangninh",
    "nhatrang", "dalat", "hue", "vungtau", "quangnam", "quangngai", "thanhhoa", "nghean", "thaibinh", "namdinh", "haiduong",
    "bacninh", "bacgiang", "phutho", "thainguyen", "vinhphuc", "hungyen", "hanam", "ninhbinh"
]

print("Generating candidate domains...")
candidates = set()

for p in biz_prefixes[:25]:
    for w in words[:100]:
        for tld in [".vn", ".com.vn", ".com"]:
            candidates.add(f"{p}{w}{tld}")

for w1 in words[:80]:
    for w2 in words[:80]:
        for tld in [".vn", ".com.vn"]:
            candidates.add(f"{w1}{w2}{tld}")

for w1 in ["viet", "vina", "saigon", "hanoi", "danang"]:
    for w2 in words[:100]:
        for tld in [".vn", ".com.vn", ".com"]:
            candidates.add(f"{w1}-{w2}{tld}")

candidate_list = list(candidates)
print(f"Generated {len(candidate_list)} candidate domains to test against live DNS.")

resolved_domains = set()

def check_domain(domain):
    try:
        ip = socket.gethostbyname(domain)
        if ip:
            return domain
    except Exception:
        pass
    return None

def main():
    t0 = time.time()
    total = len(candidate_list)
    print(f"Starting ThreadPool DNS verification of {total} candidate domains...")
    
    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(check_domain, d): d for d in candidate_list}
        done = 0
        for future in as_completed(futures):
            done += 1
            res = future.result()
            if res:
                resolved_domains.add(res)
            if done % 5000 == 0 or done == total:
                print(f"Processed {done}/{total} - Found {len(resolved_domains)} REAL active domains ({time.time()-t0:.1f}s)")

    print(f"\nFinal Verified Active Domains: {len(resolved_domains)}")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(sorted(list(resolved_domains)), f, ensure_ascii=False, indent=2)
    print(f"Saved to {output_path}")

if __name__ == "__main__":
    main()
