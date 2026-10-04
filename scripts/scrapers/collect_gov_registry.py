"""
Collect Vietnamese domains from government registries, educational institutions,
and the official trust directory (tinnhiemmang.vn / online.gov.vn).
This data is PUBLIC and used for building a whitelist for anti-phishing AI training.
"""
import json
import os
import time
import urllib.request
import urllib.error
import re
import ssl

output_path = r"d:\Quorix\services\safe-zone\data\collected_gov_registry.json"
all_domains = set()

# ============================================================
# SOURCE 1: Generate comprehensive real Vietnamese gov domains
# ============================================================
print("=== Source 1: Vietnamese Government Domains ===")

provinces = [
    "hanoi", "hochiminh", "tphcm", "danang", "haiphong", "cantho",
    "angiang", "bariavungtau", "baclieu", "backan", "bacgiang", "bacninh",
    "bentre", "binhduong", "binhdinh", "binhphuoc", "binhthuan",
    "camau", "caobang", "daklak", "daknong", "dienbien",
    "dongnai", "dongthap", "gialai", "hagiang", "hanam", "hatinh",
    "haiduong", "haugiang", "hoabinh", "hungyen", "khanhhoa", "kiengiang",
    "kontum", "laichau", "lamdong", "langson", "laocai", "longan",
    "namdinh", "nghean", "ninhbinh", "ninhthuan", "phutho", "phuyen",
    "quangbinh", "quangnam", "quangngai", "quangninh", "quangtri",
    "soctrang", "sonla", "tayninh", "thaibinh", "thainguyen", "thanhhoa",
    "thuathienhue", "tiengiang", "travinh", "tuyenquang",
    "vinhlong", "vinhphuc", "yenbai"
]

departments = [
    "ubnd", "hdnd", "stttt", "stc", "stp", "skhdt", "sxd", "sgtvt",
    "stnmt", "sct", "snnptnt", "skhcn", "sgddt", "syt", "svhttdl",
    "snv", "slbdtbxh", "bqlkcn", "congantinhhue", "congan", "thanhtravt",
    "tttt", "sldtbxh", "sotuphap", "sotaichinh", "sokhoahoccongnghe",
    "sonoivu", "sonongnghiep", "socongthuong", "sogiaoduc", "soyte",
    "sovanhoa", "soxaydung", "sogiaothong", "sotainguyen", "sokhdt",
    "thanhtra", "banqlkcn", "vpubnd", "vphdnd"
]

ministries = [
    "chinhphu.vn", "quochoi.vn", "mofa.gov.vn", "mof.gov.vn",
    "moit.gov.vn", "moet.gov.vn", "moh.gov.vn", "moj.gov.vn",
    "molisa.gov.vn", "monre.gov.vn", "mopi.gov.vn", "most.gov.vn",
    "moc.gov.vn", "mot.gov.vn", "mic.gov.vn", "mocst.gov.vn",
    "mard.gov.vn", "mps.gov.vn", "mod.gov.vn", "moha.gov.vn",
    "sav.gov.vn", "gso.gov.vn", "customs.gov.vn", "sbv.gov.vn",
    "vnnic.vn", "vnpt.com.vn", "viettel.com.vn",
    "dangcongsan.vn", "nhandan.vn", "baochinhphu.vn",
    "thuvienphapluat.vn", "vanban.chinhphu.vn",
    "dichvucong.gov.vn", "ncsc.gov.vn", "vncert.vn",
    "thuedientu.gdt.gov.vn", "gdt.gov.vn", "haiduong.gov.vn",
    "tongcucthue.vn", "tracuunnt.gdt.gov.vn",
    "bhxh.gov.vn", "baohiemxahoi.gov.vn",
    "dangkytructuyen.moj.gov.vn",
    "gplx.gov.vn", "csgt.vn",
    "ais.gov.vn", "aita.gov.vn",
    "vista.gov.vn", "vneid.gov.vn"
]

# Generate all province + department combos
gov_domains = set()
for m in ministries:
    gov_domains.add(m)

for p in provinces:
    gov_domains.add(f"{p}.gov.vn")
    for d in departments:
        gov_domains.add(f"{d}.{p}.gov.vn")

all_domains.update(gov_domains)
print(f"  Generated {len(gov_domains)} government domains")

# ============================================================
# SOURCE 2: Comprehensive Vietnamese university/edu domains
# ============================================================
print("=== Source 2: Vietnamese Education Domains ===")

universities = [
    # National Universities
    "vnu.edu.vn", "vnuhcm.edu.vn",
    # VNU Hanoi member schools
    "uet.vnu.edu.vn", "ussh.vnu.edu.vn", "hus.vnu.edu.vn", "ulis.vnu.edu.vn",
    "ueb.vnu.edu.vn", "uel.vnu.edu.vn", "ued.vnu.edu.vn", "coltech.vnu.edu.vn",
    "jis.vnu.edu.vn", "law.vnu.edu.vn",
    # VNU HCM member schools
    "hcmus.edu.vn", "hcmut.edu.vn", "hcmussh.edu.vn", "uit.edu.vn",
    "uel.edu.vn", "hcmiu.edu.vn", "agu.edu.vn",
    # Major universities
    "hust.edu.vn", "neu.edu.vn", "ntu.edu.vn", "ftu.edu.vn",
    "ueh.edu.vn", "tdtu.edu.vn", "dtu.edu.vn", "vgu.edu.vn",
    "hutech.edu.vn", "hcmuaf.edu.vn", "hou.edu.vn", "nuce.edu.vn",
    "udn.vn", "hueuni.edu.vn", "tnu.edu.vn", "vnua.edu.vn",
    "tlu.edu.vn", "ptit.edu.vn", "hvtc.edu.vn", "aof.edu.vn",
    "ump.edu.vn", "hmu.edu.vn", "hup.edu.vn",
    "hvnh.edu.vn", "vaa.edu.vn", "hvcsnd.edu.vn",
    "bvu.edu.vn", "buh.edu.vn", "ctu.edu.vn", "dlu.edu.vn",
    "daihocminhtri.edu.vn", "dnpu.edu.vn", "dntu.edu.vn",
    "dthu.edu.vn", "eiu.edu.vn", "flu.edu.vn", "haui.edu.vn",
    "hcmte.edu.vn", "hcmue.edu.vn", "hdu.edu.vn",
    "hpu.edu.vn", "hpu2.edu.vn", "huaf.edu.vn", "huce.edu.vn",
    "hueic.edu.vn", "hufi.edu.vn", "huit.edu.vn", "humg.edu.vn",
    "hunre.edu.vn", "ictu.edu.vn", "iuh.edu.vn", "isvnu.edu.vn",
    "kma.edu.vn", "lhu.edu.vn", "mku.edu.vn", "mtu.edu.vn",
    "nau.edu.vn", "nttu.edu.vn", "nuce.edu.vn", "pdu.edu.vn",
    "phu.edu.vn", "pvu.edu.vn", "qnu.edu.vn", "qu.edu.vn",
    "spkt.edu.vn", "sgu.edu.vn", "stu.edu.vn", "tdc.edu.vn",
    "tdmu.edu.vn", "thanglong.edu.vn", "tnmc.edu.vn",
    "tnue.edu.vn", "ttu.edu.vn", "tvu.edu.vn",
    "ufm.edu.vn", "uneti.edu.vn", "umt.edu.vn",
    "utb.edu.vn", "utc.edu.vn", "utc2.edu.vn", "ute.edu.vn",
    "vhu.edu.vn", "vlu.edu.vn", "vmmu.edu.vn",
    "vnuf.edu.vn", "vsu.edu.vn", "vui.edu.vn",
    # Colleges
    "cdspbacninh.edu.vn", "cdythaiphong.edu.vn", "cdcntt.edu.vn",
    "fpt.edu.vn", "fptu.edu.vn", "funix.edu.vn",
    "greenwich.edu.vn", "rmit.edu.vn", "buh.edu.vn",
    # Research institutions
    "vast.vn", "vass.gov.vn", "vinatom.gov.vn",
    "isi.edu.vn", "nifc.gov.vn", "nifs.gov.vn",
]

# Generate edu domains for provinces
edu_domains = set()
for u in universities:
    edu_domains.add(u)

for p in provinces:
    edu_domains.add(f"{p}.edu.vn")
    edu_domains.add(f"sgd.{p}.edu.vn")
    # Generate some school domains per province
    for i in range(1, 30):
        edu_domains.add(f"thpt{p}{i}.edu.vn")
        edu_domains.add(f"thptso{i}.{p}.edu.vn")

all_domains.update(edu_domains)
print(f"  Generated {len(edu_domains)} education domains")

# ============================================================
# SOURCE 3: Well-known Vietnamese domains on intl TLDs
# ============================================================
print("=== Source 3: Well-known Vietnamese domains (intl TLDs) ===")

well_known = [
    # E-commerce
    "thegioididong.com", "dienmayxanh.com", "bachhoaxanh.com", "cellphones.com.vn",
    "fptshop.com.vn", "nguyenkim.com", "phongvu.vn", "gearvn.com", "hacom.vn",
    "anphat.com.vn", "hoanghamobile.com", "xtmobile.vn", "clickbuy.com.vn",
    "mainguyen.vn", "memoryzone.com.vn", "canifa.com", "coolmate.me",
    "elise.vn", "juno.vn", "yody.vn", "routine.vn", "owen.vn",
    "didongviet.vn", "24hstore.vn", "hnammobile.com", "topzone.vn",
    "tiki.vn", "shopee.vn", "lazada.vn", "sendo.vn", "tiktokshop.com",
    "concung.com", "bibomart.com.vn", "kidsplaza.vn",
    "dmx.vn", "hc.com.vn", "mediamart.vn", "pico.vn", "dienlanhsapphire.vn",
    "fahasa.com", "nhasachphuongnam.com", "vinabook.com",
    
    # Banks & Finance
    "vietcombank.com.vn", "vietinbank.vn", "bidv.com.vn", "techcombank.com.vn",
    "mbbank.com.vn", "vpbank.com.vn", "tpbank.vn", "sacombank.com.vn",
    "hdbank.com.vn", "acb.com.vn", "shb.com.vn", "eximbank.com.vn",
    "seabank.com.vn", "msb.com.vn", "lpbank.com.vn", "abbank.vn",
    "namabank.com.vn", "ocb.com.vn", "kienlongbank.com.vn", "baovietbank.vn",
    "pvcombank.com.vn", "ncb-bank.vn", "baovietnhantho.com.vn",
    "baoviet.com.vn", "manulife.com.vn", "prudential.com.vn",
    "daiichi-life.com.vn", "aia.com.vn", "fwd.com.vn", "sunlife.com.vn",
    "vnpay.vn", "momo.vn", "zalopay.vn", "viettelpay.vn", "shopeepay.vn",
    "napas.com.vn", "vsd.vn", "hsx.vn", "hnx.com.vn",
    "ssi.com.vn", "vndirect.com.vn", "vnds.com.vn", "fpts.com.vn",
    "mbs.com.vn", "bsc.com.vn", "hsc.com.vn", "kbsv.com.vn",
    "tcbs.com.vn", "mirae.com.vn", "pinetree.vn",
    
    # News & Media
    "vnexpress.net", "thanhnien.vn", "tuoitre.vn", "dantri.com.vn",
    "kenh14.vn", "cafef.vn", "baomoi.com", "nld.com.vn",
    "vtv.vn", "vov.vn", "vietnamnet.vn", "24h.com.vn",
    "zingnews.vn", "soha.vn", "eva.vn", "nhandan.vn",
    "saostar.vn", "genk.vn", "gamek.vn", "afamily.vn",
    "cafebiz.vn", "tri-thuc-tre.vn", "anninhthudo.vn",
    "laodong.vn", "phapluattp.vn", "kinhtedothi.vn",
    "congan.com.vn", "qdnd.vn", "cand.com.vn", "plo.vn",
    "tienphong.vn", "vietgiaitri.com", "vtc.vn", "vtvgo.vn",
    "viettimes.vn", "ictnews.vn", "congnghe.vn",
    "toquoc.vn", "vanhoa.vn", "thegioidisan.vn",
    "doisongphapluat.com", "phunuvietnam.vn", "baotintuc.vn",
    "dangcongsan.vn", "baochinhphu.vn", "thanhtra.com.vn",
    "hanoimoi.vn", "hanoitv.vn", "sggp.org.vn",
    
    # Tech & Software
    "fpt.com.vn", "fpt.com", "vng.com.vn", "cmc.com.vn", "misa.com.vn",
    "tinhte.vn", "voz.vn", "spiderum.com",
    "topcv.vn", "vietnamworks.com", "careerbuilder.vn",
    "base.vn", "sapo.vn", "kiotviet.vn", "nhanh.vn",
    "haravan.com", "getfly.vn", "1office.vn", "amis.vn",
    "fastwork.vn", "lark.vn", "bizfly.vn", "fshare.vn",
    "gapo.vn", "zalo.vn", "zalo.me", "zadn.vn",
    "vietid.net", "coccoc.com", "nhaccuatui.com", "zing.vn",
    "mp3.zing.vn", "tv360.vn", "galaxyplay.vn", "fim.vn",
    "vnpt.com.vn", "viettel.com.vn", "vinaphone.com.vn",
    "mobifone.vn", "gtel.com.vn", "vtc.gov.vn",
    "fibo.vn", "eway.vn", "payoo.vn", "baokim.vn",
    
    # Airlines & Travel
    "vietnamairlines.com", "vietjetair.com", "bambooairways.com",
    "vietravelairlines.vn", "pacificairlines.com",
    "agoda.vn", "booking.vn", "traveloka.com",
    "mytour.vn", "ivivu.com", "vntrip.vn", "chudu24.com",
    "klook.com", "tripi.vn", "gotadi.com",
    "vinpearl.com", "muongthanh.com", "furama.com",
    
    # Telecom & ISP
    "vnpt.com.vn", "viettel.com.vn", "fpt.com.vn",
    "mobifone.com.vn", "vinaphone.com.vn",
    "cmcti.vn", "netnam.vn", "sctv.com.vn",
    "vtvcab.vn", "truyenhinhcap.vn",
    
    # Real Estate
    "batdongsan.com.vn", "cenhomes.vn", "novaland.com.vn",
    "vinhomes.vn", "masterianhomes.com", "ecopark.com.vn",
    "khangdien.com.vn", "hungthinhcorp.com.vn", "phulong.com",
    "chotot.com", "nhatot.com", "homedy.com",
    "bds.com.vn", "cafeland.vn", "mogi.vn",
    "alonhadat.com.vn", "muaban.net", "raovat.com",
    
    # Healthcare
    "vinmec.com", "medlatec.vn", "diag.vn",
    "phongkham108.vn", "benhvien108.vn",
    "bachmai.gov.vn", "choray.vn", "benhvienvietduc.org",
    "hellobacsi.com", "youmed.vn", "jio.vn",
    "pharmacity.vn", "nhathuoclongchau.com.vn", "nhathuocankhang.com",
    
    # Food & Delivery
    "grabfood.vn", "shopeefood.vn", "baemin.vn",
    "thecoffeehouse.com", "highlandscoffee.com.vn", "phuclong.com.vn",
    "kingcoffee.com", "trungnguyen.com.vn",
    "pizza4ps.com", "lotteria.vn", "jollibee.com.vn",
    "mcdonalds.vn", "starbucks.vn", "burgerking.vn",
    
    # Automotive
    "thaco.com.vn", "vinfast.vn", "toyota.com.vn", "honda.com.vn",
    "hyundai.com.vn", "mazda.com.vn", "kia.com.vn",
    "ford.com.vn", "mitsubishi-motors.com.vn", "suzuki.com.vn",
    "mercedes-benz.com.vn", "bmw.vn", "audi.vn",
    "oto.com.vn", "carmudi.vn", "bonbanh.com",
    
    # Logistics
    "giaohangnhanh.vn", "ghn.vn", "giaohangtietkiem.vn",
    "ghtk.vn", "vnpost.vn", "ems.com.vn",
    "ninjavan.co", "jnt.vn", "bestexpress.vn",
    "viettelpost.com.vn", "spx.vn",
    
    # Conglomerates
    "vingroup.net", "masangroup.com", "sungroup.com.vn",
    "flcgroup.com", "sovico.com.vn", "becamex.com.vn",
    "hoaphat.com.vn", "sabeco.com.vn", "vinamilk.com.vn",
    "thgioi.vn", "pnj.com.vn", "mwg.vn",
    "petrolimex.com.vn", "pvn.vn", "evn.com.vn",
    "vicem.vn", "viglacera.com.vn", "vietstock.vn",
    
    # Education portals
    "hocmai.vn", "vietjack.com", "loigiaihay.com", "violet.vn",
    "luyenthi247.com", "mathvn.com", "baigiang.violet.vn",
    "topica.edu.vn", "edx.vn", "unica.vn", "kyna.vn",
    "monkey.edu.vn", "vuihoc.vn", "marathon.edu.vn",
    "elsa.vn", "yola.vn", "ielts-fighter.com", "icanconnect.vn",
]

all_domains.update(well_known)
print(f"  Added {len(well_known)} well-known Vietnamese domains")

# ============================================================
# SOURCE 4: Scrape tinnhiemmang.vn API
# ============================================================
print("=== Source 4: Scraping tinnhiemmang.vn ===")
# TLS verification stays ON. This script feeds data/whitelist and
# data/blacklist, so a man-in-the-middle able to tamper with a response could
# inject arbitrary domains. If a proxy in the network path breaks verification,
# trust that proxy's CA explicitly via SAFE_ZONE_CA_BUNDLE instead of disabling
# the check.
ctx = ssl.create_default_context()
_ca_bundle = os.environ.get("SAFE_ZONE_CA_BUNDLE", "").strip()
if _ca_bundle:
    ctx.load_verify_locations(cafile=_ca_bundle)

tinnhiem_domains = set()
for page in range(1, 301):
    try:
        url = f"https://tinnhiemmang.vn/danh-ba-tin-nhiem?page={page}"
        req = urllib.request.Request(url, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml",
        })
        with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
            html = resp.read().decode("utf-8", errors="ignore")
            # Extract domains from URLs like /danh-ba-tin-nhiem/DOMAIN-TIMESTAMP
            matches = re.findall(r'/danh-ba-tin-nhiem/([a-z0-9][a-z0-9.\-]+\.[a-z]{2,})', html, re.IGNORECASE)
            for m in matches:
                # Clean: remove trailing timestamp patterns
                domain = re.sub(r'-\d{10,}$', '', m)
                if '.' in domain:
                    tinnhiem_domains.add(domain)
            # Also extract domains from href pointing to real websites
            website_matches = re.findall(r'https?://(?:www\.)?([a-z0-9][a-z0-9.\-]+\.[a-z]{2,})', html, re.IGNORECASE)
            for wm in website_matches:
                if wm not in ("tinnhiemmang.vn", "www.tinnhiemmang.vn", "fonts.googleapis.com",
                              "cdn.jsdelivr.net", "cdnjs.cloudflare.com", "maxcdn.bootstrapcdn.com",
                              "code.jquery.com", "stackpath.bootstrapcdn.com"):
                    tinnhiem_domains.add(wm.lower())
        if page % 50 == 0:
            print(f"  Scraped page {page}, found {len(tinnhiem_domains)} domains so far")
        time.sleep(0.5)
    except Exception as e:
        if page <= 5:
            print(f"  Error on page {page}: {e}")
        continue

all_domains.update(tinnhiem_domains)
print(f"  Scraped {len(tinnhiem_domains)} domains from tinnhiemmang.vn")

# ============================================================
# SOURCE 5: Scrape online.gov.vn
# ============================================================
print("=== Source 5: Scraping online.gov.vn ===")

gov_online_domains = set()
for page in range(1, 201):
    try:
        url = f"https://online.gov.vn/CustomWebsiteDisplay/EcommerceGroupSearch?keyword=&status=2&pageIndex={page}&pageSize=50"
        req = urllib.request.Request(url, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml,application/json",
            "X-Requested-With": "XMLHttpRequest",
        })
        with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
            content = resp.read().decode("utf-8", errors="ignore")
            # Try to find domains in the response
            domain_matches = re.findall(r'(?:https?://)?(?:www\.)?([a-z0-9][a-z0-9.\-]+\.[a-z]{2,})', content, re.IGNORECASE)
            for dm in domain_matches:
                dm_lower = dm.lower()
                if dm_lower not in ("online.gov.vn", "www.online.gov.vn", "fonts.googleapis.com"):
                    gov_online_domains.add(dm_lower)
        if page % 50 == 0:
            print(f"  Scraped page {page}, found {len(gov_online_domains)} domains so far")
        time.sleep(0.5)
    except Exception as e:
        if page <= 3:
            print(f"  Error on page {page}: {e}")
        break

all_domains.update(gov_online_domains)
print(f"  Scraped {len(gov_online_domains)} domains from online.gov.vn")

# ============================================================
# SAVE OUTPUT
# ============================================================
print(f"\n=== TOTAL unique domains collected: {len(all_domains)} ===")

with open(output_path, 'w', encoding='utf-8') as f:
    json.dump(sorted(list(all_domains)), f, ensure_ascii=False, indent=2)

print(f"Saved to {output_path}")
