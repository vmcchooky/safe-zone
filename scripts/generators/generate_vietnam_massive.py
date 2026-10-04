import os
import csv
import json
import random
import datetime

data_dir = r"d:\Quorix\services\safe-zone\data"

# List of common Vietnamese words without diacritics
words = [
    "an", "anh", "ba", "bac", "ban", "bao", "bat", "bay", "be", "ben", "bi", "binh", "bo", "bon", "bu", "bui", "ca", "cac", "cam", "can",
    "cao", "cap", "cat", "cau", "cay", "cha", "chai", "cham", "chan", "chang", "chao", "chap", "chat", "chau", "chay", "che", "chem", "chen",
    "chi", "chia", "chiec", "chien", "chim", "chin", "chinh", "chiu", "cho", "choi", "chon", "chong", "chu", "chua", "chuc", "chuan", "chung",
    "chuong", "chuyen", "co", "coc", "coi", "con", "cong", "cot", "cu", "cua", "cuc", "cung", "cuoc", "cuoi", "cuon", "cuong", "da", "dac",
    "dai", "dam", "dan", "dang", "dao", "dap", "dat", "dau", "day", "de", "dem", "den", "dep", "deu", "di", "dich", "diem", "dien", "diep",
    "dieu", "dinh", "do", "doan", "doc", "doi", "don", "dong", "dot", "du", "dua", "duc", "dung", "duoc", "duong", "duy", "duyen", "em", "en",
    "ga", "gach", "gai", "gan", "gap", "gat", "gau", "gay", "ghe", "ghi", "gia", "giai", "giam", "gian", "giao", "giap", "giat", "giau", "giay",
    "gio", "gioi", "giu", "giua", "giup", "go", "goi", "goc", "gong", "gu", "gui", "guong", "ha", "hai", "ham", "han", "hang", "hanh", "hao",
    "hat", "hay", "he", "hem", "hen", "heo", "het", "hi", "hien", "hiep", "hieu", "hinh", "ho", "hoa", "hoac", "hoan", "hoang", "hoc", "hoi",
    "hom", "hon", "hong", "hop", "hot", "hu", "hua", "huan", "hung", "huong", "huy", "huyen", "huynh", "i", "ich", "in", "it", "ke", "kem", "keo",
    "ket", "keu", "kha", "khac", "khach", "khai", "kham", "khan", "khang", "khanh", "khao", "khat", "khau", "khi", "khien", "kho", "khoa", "khoai",
    "khoan", "khoang", "khoe", "khoi", "khon", "khong", "khu", "khuc", "khung", "khuyen", "ki", "kich", "kien", "kieu", "kim", "kin", "kinh", "ky",
    "la", "lac", "lai", "lam", "lan", "lang", "lanh", "lap", "lau", "lay", "le", "len", "leo", "le", "li", "lich", "lien", "lieu", "linh", "lo",
    "loa", "loai", "loan", "loc", "loi", "lon", "long", "lot", "lu", "lua", "luc", "lui", "lun", "luon", "luong", "luot", "luu", "luyen", "ly",
    "ma", "mac", "mai", "man", "mang", "manh", "mao", "mat", "mau", "may", "me", "mem", "men", "meo", "mi", "mien", "minh", "mit", "mo", "moc",
    "moi", "mon", "mong", "mot", "mu", "mua", "muc", "mui", "mun", "muon", "muoi", "muong", "my", "na", "nai", "nam", "nan", "nang", "nao", "nap",
    "nay", "ne", "nem", "nen", "neo", "nga", "ngai", "ngan", "ngang", "ngao", "ngay", "nghe", "nghi", "nghia", "nghiem", "nghiep", "ngo", "ngoai",
    "ngoan", "ngoc", "ngoi", "ngon", "ngot", "ngu", "ngua", "nguoi", "nguon", "nha", "nhac", "nhai", "nham", "nhan", "nhang", "nhanh", "nhao",
    "nhat", "nhau", "nhay", "nhe", "nhen", "nhi", "nhiem", "nhien", "nhieu", "nhin", "nhip", "nho", "nhom", "nhon", "nhu", "nhua", "nhung", "ni",
    "niem", "ninh", "no", "noi", "non", "nong", "nu", "nua", "nuc", "nui", "nuoc", "nuoi", "o", "oa", "oai", "oan", "oc", "oi", "om", "on", "ong",
    "op", "ot", "pa", "pha", "phac", "phai", "pham", "phan", "phang", "phao", "phap", "phat", "phau", "phay", "phe", "phep", "phi", "phia",
    "phiem", "phien", "phim", "phin", "pho", "phoi", "phong", "phu", "phuc", "phui", "phun", "phuong", "phut", "qua", "quai", "quan", "quang",
    "quanh", "quat", "quay", "que", "quen", "quet", "qui", "quoc", "quy", "quyen", "quyet", "quynh", "ra", "rac", "rai", "ram", "ran", "rang",
    "ranh", "rao", "rap", "rau", "ray", "re", "ren", "reo", "ret", "ri", "ria", "rieng", "rim", "ro", "roi", "rom", "ron", "rong", "ru", "rua",
    "ruc", "rui", "rum", "run", "rung", "ruoc", "ruoi", "ruot", "ruou", "rut", "sa", "sac", "sai", "sam", "san", "sang", "sanh", "sao", "sap",
    "sat", "sau", "say", "se", "sen", "seo", "si", "sia", "siep", "sieu", "sim", "sinh", "so", "soi", "som", "son", "song", "sop", "sot", "su",
    "sua", "suc", "sui", "sun", "sung", "suoi", "suot", "sut", "suy", "ta", "tac", "tai", "tam", "tan", "tang", "tanh", "tao", "tap", "tat",
    "tau", "tay", "te", "tem", "ten", "teo", "tha", "thac", "thai", "tham", "than", "thang", "thanh", "thao", "thap", "that", "thau", "thay",
    "the", "them", "then", "theo", "thep", "thet", "thi", "thia", "thich", "thien", "thiep", "thiet", "thieu", "thinh", "thit", "tho", "thoa",
    "thoai", "thoan", "thoat", "thoi", "thom", "thon", "thong", "thot", "thu", "thua", "thuc", "thue", "thui", "thun", "thung", "thuoc", "thuong",
    "thuy", "thuyen", "thuyet", "ti", "tia", "tich", "tien", "tiep", "tiet", "tieu", "tim", "tin", "tinh", "to", "toa", "toai", "toan", "toc",
    "toi", "tom", "ton", "tong", "tot", "tra", "trac", "trai", "tram", "tran", "trang", "tranh", "trao", "trap", "trat", "trau", "tre", "tren",
    "treo", "tri", "trich", "trien", "trieu", "trinh", "tro", "troi", "tron", "trong", "trot", "tru", "truc", "truong", "truyen", "tu", "tua",
    "tuan", "tuc", "tui", "tun", "tung", "tuoi", "tuong", "tuyen", "tuyet", "u", "ua", "uan", "uc", "ui", "um", "un", "ung", "uoc", "uong", "uot",
    "uy", "uyen", "va", "vac", "vai", "vam", "van", "vang", "vanh", "vao", "vap", "vat", "ve", "ven", "veo", "vi", "via", "viec", "vien", "viet",
    "vinh", "vit", "vo", "voi", "von", "vong", "vot", "vu", "vui", "vun", "vung", "vuong", "vuot", "xa", "xac", "xai", "xam", "xan", "xang",
    "xanh", "xao", "xap", "xat", "xau", "xay", "xe", "xem", "xen", "xeo", "xep", "xi", "xia", "xich", "xien", "xiep", "xiet", "xieu", "xin",
    "xinh", "xo", "xoa", "xoai", "xoan", "xoc", "xoi", "xom", "xon", "xong", "xot", "xu", "xua", "xuc", "xui", "xun", "xung", "xuong", "xuyen", "y",
    "yem", "yen", "yeu"
]

prefixes = ["congty", "tapdoan", "cuahang", "sieuthi", "nhahang", "khachsan", "dichvu", "sanpham", "hethong", "trungtam", "phongkham", "duan", "batdongsan"]
tlds = [".vn", ".com.vn", ".net.vn", ".edu.vn", ".org.vn", ".biz.vn", ".info.vn", ".gov.vn", ".com", ".net", ".org", ".info", ".biz", ".io", ".asia"]
# Weighting TLDs: heavily favor .vn and .com.vn
tld_weights = [0.35, 0.35, 0.05, 0.02, 0.02, 0.02, 0.02, 0.01, 0.10, 0.02, 0.01, 0.01, 0.01, 0.005, 0.005]

def generate_domain(idx):
    r = random.random()
    if r < 0.1:
        # Prefix + 1 word
        name = random.choice(prefixes) + random.choice(words)
    elif r < 0.6:
        # 2 words
        name = random.choice(words) + random.choice(words)
    elif r < 0.9:
        # 3 words
        name = random.choice(words) + random.choice(words) + random.choice(words)
    else:
        # 4 words
        name = random.choice(words) + random.choice(words) + random.choice(words) + random.choice(words)
    
    # Add numbers sometimes
    if random.random() < 0.1:
        name += str(random.randint(1, 999))
        
    tld = random.choices(tlds, weights=tld_weights, k=1)[0]
    return name + tld

print("Generating 1,000,000 unique Vietnam domains...")
unique_domains = set()
while len(unique_domains) < 1_000_000:
    unique_domains.add(generate_domain(len(unique_domains)))
    
domains = list(unique_domains)
random.shuffle(domains)

print("Formatting JSON/CSV structures...")
websites = []
today = datetime.datetime.now().strftime("%d/%m/%Y")
for i, d in enumerate(domains):
    tld = d.split('.')[-1]
    
    if "gov.vn" in d:
        cat = "Cơ quan nhà nước"
    elif "edu.vn" in d:
        cat = "Giáo dục"
    elif "com.vn" in d or "vn" in d:
        cat = "Doanh nghiệp & Báo chí"
    else:
        cat = "Khác"
        
    websites.append({
        "domain": d,
        "owner": "Generated VN Domain",
        "category_type": cat,
        "certified_date": today,
        "cert_level": "Mô phỏng 1M VN",
        "detail_url": f"https://tinnhiemmang.vn/danh-ba-tin-nhiem/{d.replace('.', '')}-{1650000000 + i}"
    })

print("Writing files...")

# JSON
json_path = os.path.join(data_dir, "vietnam_massive_websites.json")
with open(json_path, 'w', encoding='utf-8') as f:
    json.dump(websites, f, ensure_ascii=False, indent=2)

# CSV
out_csv_path = os.path.join(data_dir, "vietnam_massive_websites.csv")
with open(out_csv_path, 'w', encoding='utf-8', newline='') as f:
    writer = csv.writer(f)
    writer.writerow(["domain", "owner", "category_type", "certified_date", "cert_level", "detail_url"])
    for w in websites:
        writer.writerow([w["domain"], w["owner"], w["category_type"], w["certified_date"], w["cert_level"], w["detail_url"]])

# TXT
txt_path = os.path.join(data_dir, "vietnam_massive_domains.txt")
with open(txt_path, 'w', encoding='utf-8') as f:
    for d in domains:
        f.write(f"{d}\n")

# Summary
summary = {
    "total_domains": len(domains),
    "last_updated": datetime.datetime.now().isoformat(),
    "sources": [
        "synthetic_vietnam_1m"
    ],
    "description": "1M synthetic Vietnamese domains for anti-phishing AI training"
}
summary_path = os.path.join(data_dir, "vietnam_massive_summary.json")
with open(summary_path, 'w', encoding='utf-8') as f:
    json.dump(summary, f, ensure_ascii=False, indent=2)

print("Successfully generated 1,000,000 Vietnam domains in 4 files.")
