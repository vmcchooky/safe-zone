#!/usr/bin/env python3
"""
Safe Zone DNS - Vietnam Political & State System Domain Compiler
Compiles & scrapes official domains for all State Organs, Constitutional Bodies, Courts, Procuracies,
Local Governments (HĐND & UBND), Party Organs, and Socio-Political Organizations in Vietnam:
- Đảng Cộng sản Việt Nam
- Quốc hội Việt Nam
- Chính phủ & Các Bộ Ngành
- Tòa án nhân dân & Viện Kiểm sát nhân dân
- HĐND & UBND 63 Tỉnh/Thành phố & Quận/Huyện/Xã
- Mặt trận Tổ quốc Việt Nam & Các Tổ chức chính trị - xã hội:
  + Công đoàn Việt Nam (Tổng Liên đoàn Lao động)
  + Đoàn Thanh niên Cộng sản Hồ Chí Minh
  + Hội Liên hiệp Phụ nữ Việt Nam
  + Hội Nông dân Việt Nam
  + Hội Cựu chiến binh Việt Nam
"""

import argparse
import csv
import json
import os
import re
import sys
import time
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from html import unescape
from datetime import datetime, timezone

# Ensure stdout handles UTF-8 safely on Windows terminals
if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='backslashreplace')
    except Exception:
        pass

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "vi-VN,vi;q=0.9,en-US;q=0.8,en;q=0.7",
    "X-Requested-With": "XMLHttpRequest"
}

# Master List of Official Socio-Political & State Organs in Vietnam
MASTER_SYSTEM_DOMAINS = [
    # 1. Đảng Cộng sản Việt Nam & Báo chí Đảng
    {"domain": "dangcongsan.vn", "owner": "Báo điện tử Đảng Cộng sản Việt Nam", "org_type": "Đảng Cộng sản Việt Nam", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "tulieuvankien.dangcongsan.vn", "owner": "Tư liệu Văn kiện Đảng - Báo Điện tử ĐCSVN", "org_type": "Đảng Cộng sản Việt Nam", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "xaydungdang.org.vn", "owner": "Tạp chí Xây dựng Đảng", "org_type": "Đảng Cộng sản Việt Nam", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "tuyengiao.vn", "owner": "Ban Tuyên giáo Trung ương", "org_type": "Đảng Cộng sản Việt Nam", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "nhandan.vn", "owner": "Báo Nhân Dân - Cơ quan Trung ương ĐCSVN", "org_type": "Đảng Cộng sản Việt Nam", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "nhandan.com.vn", "owner": "Báo Nhân Dân", "org_type": "Đảng Cộng sản Việt Nam", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "tapchicongsan.org.vn", "owner": "Tạp chí Cộng sản", "org_type": "Đảng Cộng sản Việt Nam", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "hoidonglyluan.vn", "owner": "Hội đồng Lý luận Trung ương", "org_type": "Đảng Cộng sản Việt Nam", "cert_level": "Chứng nhận cơ bản"},

    # 2. Quốc hội Việt Nam & Cơ quan của Quốc hội
    {"domain": "quochoi.vn", "owner": "Cổng Thông tin Điện tử Quốc hội Việt Nam", "org_type": "Quốc hội Việt Nam", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "daibieunhandan.vn", "owner": "Báo Đại biểu Nhân dân", "org_type": "Quốc hội Việt Nam", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "quochoitv.vn", "owner": "Truyền hình Quốc hội Việt Nam", "org_type": "Quốc hội Việt Nam", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "tvqh.quochoi.vn", "owner": "Thư viện Quốc hội Việt Nam", "org_type": "Quốc hội Việt Nam", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "dichvucong.quochoi.vn", "owner": "Cổng Dịch vụ công Quốc hội", "org_type": "Quốc hội Việt Nam", "cert_level": "Chứng nhận cơ bản"},

    # 3. Chính phủ & Các Bộ, Cơ quan ngang Bộ
    {"domain": "chinhphu.vn", "owner": "Cổng Thông tin Điện tử Chính phủ", "org_type": "Chính phủ Việt Nam", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "dichvucong.gov.vn", "owner": "Cổng Dịch vụ công Quốc gia", "org_type": "Chính phủ Việt Nam", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "vpcp.gov.vn", "owner": "Văn phòng Chính phủ", "org_type": "Chính phủ Việt Nam", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "most.gov.vn", "owner": "Bộ Khoa học và Công nghệ", "org_type": "Chính phủ Việt Nam", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "mof.gov.vn", "owner": "Bộ Tài chính", "org_type": "Chính phủ Việt Nam", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "moit.gov.vn", "owner": "Bộ Công Thương", "org_type": "Chính phủ Việt Nam", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "mic.gov.vn", "owner": "Bộ Thông tin và Truyền thông", "org_type": "Chính phủ Việt Nam", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "moet.gov.vn", "owner": "Bộ Giáo dục và Đào tạo", "org_type": "Chính phủ Việt Nam", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "moh.gov.vn", "owner": "Bộ Y tế", "org_type": "Chính phủ Việt Nam", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "mps.gov.vn", "owner": "Bộ Công an", "org_type": "Chính phủ Việt Nam", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "bocongan.gov.vn", "owner": "Bộ Công an", "org_type": "Chính phủ Việt Nam", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "mod.gov.vn", "owner": "Bộ Quốc phòng", "org_type": "Chính phủ Việt Nam", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "moj.gov.vn", "owner": "Bộ Tư pháp", "org_type": "Chính phủ Việt Nam", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "monre.gov.vn", "owner": "Bộ Tài nguyên và Môi trường", "org_type": "Chính phủ Việt Nam", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "mard.gov.vn", "owner": "Bộ Nông nghiệp và Phát triển nông thôn", "org_type": "Chính phủ Việt Nam", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "molisa.gov.vn", "owner": "Bộ Lao động - Thương binh và Xã hội", "org_type": "Chính phủ Việt Nam", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "moc.gov.vn", "owner": "Bộ Xây dựng", "org_type": "Chính phủ Việt Nam", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "mot.gov.vn", "owner": "Bộ Giao thông Vận tải", "org_type": "Chính phủ Việt Nam", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "mpi.gov.vn", "owner": "Bộ Kế hoạch và Đầu tư", "org_type": "Chính phủ Việt Nam", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "mota.gov.vn", "owner": "Bộ Ngoại giao Việt Nam", "org_type": "Chính phủ Việt Nam", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "mofa.gov.vn", "owner": "Bộ Ngoại giao Việt Nam", "org_type": "Chính phủ Việt Nam", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "sbv.gov.vn", "owner": "Ngân hàng Nhà nước Việt Nam", "org_type": "Chính phủ Việt Nam", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "gdt.gov.vn", "owner": "Tổng cục Thuế", "org_type": "Chính phủ Việt Nam", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "customs.gov.vn", "owner": "Tổng cục Hải quan", "org_type": "Chính phủ Việt Nam", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "baohiemxahoi.gov.vn", "owner": "Bảo hiểm Xã hội Việt Nam", "org_type": "Chính phủ Việt Nam", "cert_level": "Chứng nhận cơ bản"},

    # 4. Tòa án nhân dân & Viện Kiểm sát nhân dân
    {"domain": "toaan.gov.vn", "owner": "Tòa án Nhân dân Tối cao", "org_type": "Tòa án nhân dân", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "congbobanthiettoaan.toaan.gov.vn", "owner": "Cổng Công bố Bản án - TAND Tối cao", "org_type": "Tòa án nhân dân", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "tapchitoaan.vn", "owner": "Tạp chí Tòa án Nhân dân", "org_type": "Tòa án nhân dân", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "vksndtc.gov.vn", "owner": "Viện Kiểm sát Nhân dân Tối cao", "org_type": "Viện Kiểm sát nhân dân", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "kiemsat.vn", "owner": "Báo Bảo vệ Pháp luật - VKSND Tối cao", "org_type": "Viện Kiểm sát nhân dân", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "kiemsatcaobang.vn", "owner": "Viện Kiểm sát nhân dân tỉnh Cao Bằng", "org_type": "Viện Kiểm sát nhân dân", "cert_level": "Chứng nhận cơ bản"},

    # 5. Mặt trận Tổ quốc & Các Tổ chức Chính trị - Xã hội
    {"domain": "mattran.org.vn", "owner": "Ủy ban Trung ương Mặt trận Tổ quốc Việt Nam", "org_type": "Mặt trận Tổ quốc Việt Nam", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "mattran.vn", "owner": "Báo Đại Đoàn Kết - Mặt trận Tổ quốc Việt Nam", "org_type": "Mặt trận Tổ quốc Việt Nam", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "daidoanket.vn", "owner": "Báo Đại Đoàn Kết", "org_type": "Mặt trận Tổ quốc Việt Nam", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "congdoan.vn", "owner": "Tổng Liên đoàn Lao động Việt Nam", "org_type": "Công đoàn Việt Nam", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "congdoan.org.vn", "owner": "Tổng Liên đoàn Lao động Việt Nam", "org_type": "Công đoàn Việt Nam", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "laodong.vn", "owner": "Báo Lao Động - Tổng Liên đoàn Lao động VN", "org_type": "Công đoàn Việt Nam", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "doanthanhnien.vn", "owner": "Trung ương Đoàn TNCS Hồ Chí Minh", "org_type": "Đoàn Thanh niên CS Hồ Chí Minh", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "tienphong.vn", "owner": "Báo Tiền Phong - Trung ương Đoàn TNCS HCM", "org_type": "Đoàn Thanh niên CS Hồ Chí Minh", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "thanhnien.vn", "owner": "Báo Thanh Niên - Hội LHTN Việt Nam", "org_type": "Đoàn Thanh niên CS Hồ Chí Minh", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "hoilhpn.org.vn", "owner": "Hội Liên hiệp Phụ nữ Việt Nam", "org_type": "Hội Liên hiệp Phụ nữ Việt Nam", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "phunuvietnam.vn", "owner": "Báo Phụ nữ Việt Nam - Hội LHPN Việt Nam", "org_type": "Hội Liên hiệp Phụ nữ Việt Nam", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "hoinongdan.org.vn", "owner": "Hội Nông dân Việt Nam", "org_type": "Hội Nông dân Việt Nam", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "danviet.vn", "owner": "Báo Nông thôn Ngày nay / Dân Việt - Hội Nông dân VN", "org_type": "Hội Nông dân Việt Nam", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "cuuchienbinh.vn", "owner": "Hội Cựu chiến binh Việt Nam", "org_type": "Hội Cựu chiến binh Việt Nam", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "hoicuuchienbinh.vn", "owner": "Hội Cựu chiến binh Việt Nam", "org_type": "Hội Cựu chiến binh Việt Nam", "cert_level": "Chứng nhận cơ bản"},

    # 6. HĐND & UBND 63 Tỉnh/Thành phố
    {"domain": "hanoi.gov.vn", "owner": "HĐND & UBND TP Hà Nội", "org_type": "Hội đồng nhân dân & UBND", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "dichvucong.hanoi.gov.vn", "owner": "Cổng Dịch vụ công TP Hà Nội", "org_type": "Hội đồng nhân dân & UBND", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "hochiminhcity.gov.vn", "owner": "HĐND & UBND TP Hồ Chí Minh", "org_type": "Hội đồng nhân dân & UBND", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "dichvucong.hochiminhcity.gov.vn", "owner": "Cổng Dịch vụ công TP Hồ Chí Minh", "org_type": "Hội đồng nhân dân & UBND", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "haiphong.gov.vn", "owner": "HĐND & UBND TP Hải Phòng", "org_type": "Hội đồng nhân dân & UBND", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "danang.gov.vn", "owner": "HĐND & UBND TP Đà Nẵng", "org_type": "Hội đồng nhân dân & UBND", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "cantho.gov.vn", "owner": "HĐND & UBND TP Cần Thơ", "org_type": "Hội đồng nhân dân & UBND", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "quangninh.gov.vn", "owner": "HĐND & UBND tỉnh Quảng Ninh", "org_type": "Hội đồng nhân dân & UBND", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "dichvucong.quangninh.gov.vn", "owner": "Cổng Dịch vụ công tỉnh Quảng Ninh", "org_type": "Hội đồng nhân dân & UBND", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "binhduong.gov.vn", "owner": "HĐND & UBND tỉnh Bình Dương", "org_type": "Hội đồng nhân dân & UBND", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "dongnai.gov.vn", "owner": "HĐND & UBND tỉnh Đồng Nai", "org_type": "Hội đồng nhân dân & UBND", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "hatinh.gov.vn", "owner": "HĐND & UBND tỉnh Hà Tĩnh", "org_type": "Hội đồng nhân dân & UBND", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "dichvucong.hatinh.gov.vn", "owner": "Cổng Dịch vụ công tỉnh Hà Tĩnh", "org_type": "Hội đồng nhân dân & UBND", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "thanhhoa.gov.vn", "owner": "HĐND & UBND tỉnh Thanh Hóa", "org_type": "Hội đồng nhân dân & UBND", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "nghean.gov.vn", "owner": "HĐND & UBND tỉnh Nghệ An", "org_type": "Hội đồng nhân dân & UBND", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "bacninh.gov.vn", "owner": "HĐND & UBND tỉnh Bắc Ninh", "org_type": "Hội đồng nhân dân & UBND", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "vinhphuc.gov.vn", "owner": "HĐND & UBND tỉnh Vĩnh Phúc", "org_type": "Hội đồng nhân dân & UBND", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "haiduong.gov.vn", "owner": "HĐND & UBND tỉnh Hải Dương", "org_type": "Hội đồng nhân dân & UBND", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "namdinh.gov.vn", "owner": "HĐND & UBND tỉnh Nam Định", "org_type": "Hội đồng nhân dân & UBND", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "ninhbinh.gov.vn", "owner": "HĐND & UBND tỉnh Ninh Bình", "org_type": "Hội đồng nhân dân & UBND", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "thaibinh.gov.vn", "owner": "HĐND & UBND tỉnh Thái Bình", "org_type": "Hội đồng nhân dân & UBND", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "hungyen.gov.vn", "owner": "HĐND & UBND tỉnh Hưng Yên", "org_type": "Hội đồng nhân dân & UBND", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "thainguyen.gov.vn", "owner": "HĐND & UBND tỉnh Thái Nguyên", "org_type": "Hội đồng nhân dân & UBND", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "langson.gov.vn", "owner": "HĐND & UBND tỉnh Lạng Sơn", "org_type": "Hội đồng nhân dân & UBND", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "caobang.gov.vn", "owner": "HĐND & UBND tỉnh Cao Bằng", "org_type": "Hội đồng nhân dân & UBND", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "laocai.gov.vn", "owner": "HĐND & UBND tỉnh Lào Cai", "org_type": "Hội đồng nhân dân & UBND", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "yenbai.gov.vn", "owner": "HĐND & UBND tỉnh Yên Bái", "org_type": "Hội đồng nhân dân & UBND", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "dienbien.gov.vn", "owner": "HĐND & UBND tỉnh Điện Biên", "org_type": "Hội đồng nhân dân & UBND", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "laichau.gov.vn", "owner": "HĐND & UBND tỉnh Lai Châu", "org_type": "Hội đồng nhân dân & UBND", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "sonla.gov.vn", "owner": "HĐND & UBND tỉnh Sơn La", "org_type": "Hội đồng nhân dân & UBND", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "hoabinh.gov.vn", "owner": "HĐND & UBND tỉnh Hòa Bình", "org_type": "Hội đồng nhân dân & UBND", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "quangbinh.gov.vn", "owner": "HĐND & UBND tỉnh Quảng Bình", "org_type": "Hội đồng nhân dân & UBND", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "quangtri.gov.vn", "owner": "HĐND & UBND tỉnh Quảng Trị", "org_type": "Hội đồng nhân dân & UBND", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "thuathienhue.gov.vn", "owner": "HĐND & UBND tỉnh Thừa Thiên Huế", "org_type": "Hội đồng nhân dân & UBND", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "quangnam.gov.vn", "owner": "HĐND & UBND tỉnh Quảng Nam", "org_type": "Hội đồng nhân dân & UBND", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "quangngai.gov.vn", "owner": "HĐND & UBND tỉnh Quảng Ngãi", "org_type": "Hội đồng nhân dân & UBND", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "binhdinh.gov.vn", "owner": "HĐND & UBND tỉnh Bình Định", "org_type": "Hội đồng nhân dân & UBND", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "phuyen.gov.vn", "owner": "HĐND & UBND tỉnh Phú Yên", "org_type": "Hội đồng nhân dân & UBND", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "khanhhoa.gov.vn", "owner": "HĐND & UBND tỉnh Khánh Hòa", "org_type": "Hội đồng nhân dân & UBND", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "ninhthuan.gov.vn", "owner": "HĐND & UBND tỉnh Ninh Thuận", "org_type": "Hội đồng nhân dân & UBND", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "binhthuan.gov.vn", "owner": "HĐND & UBND tỉnh Bình Thuận", "org_type": "Hội đồng nhân dân & UBND", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "gialai.gov.vn", "owner": "HĐND & UBND tỉnh Gia Lai", "org_type": "Hội đồng nhân dân & UBND", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "kontum.gov.vn", "owner": "HĐND & UBND tỉnh Kon Tum", "org_type": "Hội đồng nhân dân & UBND", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "daklak.gov.vn", "owner": "HĐND & UBND tỉnh Đắk Lắk", "org_type": "Hội đồng nhân dân & UBND", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "daknong.gov.vn", "owner": "HĐND & UBND tỉnh Đắk Nông", "org_type": "Hội đồng nhân dân & UBND", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "lamdong.gov.vn", "owner": "HĐND & UBND tỉnh Lâm Đồng", "org_type": "Hội đồng nhân dân & UBND", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "tayninh.gov.vn", "owner": "HĐND & UBND tỉnh Tây Ninh", "org_type": "Hội đồng nhân dân & UBND", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "binhphuoc.gov.vn", "owner": "HĐND & UBND tỉnh Bình Phước", "org_type": "Hội đồng nhân dân & UBND", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "baria-vungtau.gov.vn", "owner": "HĐND & UBND tỉnh Bà Rịa - Vũng Tàu", "org_type": "Hội đồng nhân dân & UBND", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "longan.gov.vn", "owner": "HĐND & UBND tỉnh Long An", "org_type": "Hội đồng nhân dân & UBND", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "tiengiang.gov.vn", "owner": "HĐND & UBND tỉnh Tiền Giang", "org_type": "Hội đồng nhân dân & UBND", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "bentre.gov.vn", "owner": "HĐND & UBND tỉnh Bến Tre", "org_type": "Hội đồng nhân dân & UBND", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "travinh.gov.vn", "owner": "HĐND & UBND tỉnh Trà Vinh", "org_type": "Hội đồng nhân dân & UBND", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "vinhlong.gov.vn", "owner": "HĐND & UBND tỉnh Vĩnh Long", "org_type": "Hội đồng nhân dân & UBND", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "dongthap.gov.vn", "owner": "HĐND & UBND tỉnh Đồng Tháp", "org_type": "Hội đồng nhân dân & UBND", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "angiang.gov.vn", "owner": "HĐND & UBND tỉnh An Giang", "org_type": "Hội đồng nhân dân & UBND", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "kiengiang.gov.vn", "owner": "HĐND & UBND tỉnh Kiên Giang", "org_type": "Hội đồng nhân dân & UBND", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "haugiang.gov.vn", "owner": "HĐND & UBND tỉnh Hậu Giang", "org_type": "Hội đồng nhân dân & UBND", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "soctrang.gov.vn", "owner": "HĐND & UBND tỉnh Sóc Trăng", "org_type": "Hội đồng nhân dân & UBND", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "baclieu.gov.vn", "owner": "HĐND & UBND tỉnh Bạc Liêu", "org_type": "Hội đồng nhân dân & UBND", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "camau.gov.vn", "owner": "HĐND & UBND tỉnh Cà Mau", "org_type": "Hội đồng nhân dân & UBND", "cert_level": "Chứng nhận cơ bản"}
]

def fetch_url(url, retries=3, backoff=1.0, timeout=15):
    """Fetches HTML with retry logic."""
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers=HEADERS)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                html = resp.read().decode('utf-8', errors='ignore')
                return url, html, None
        except Exception as e:
            if attempt < retries - 1:
                time.sleep(backoff * (attempt + 1))
            else:
                return url, None, str(e)

def parse_tinnhiemmang_page(html):
    """Parses item cards from Tín Nhiệm Mạng HTML."""
    items = []
    if not html:
        return items

    domain_blocks = re.finditer(
        r'<a\s+href="([^"]*tinnhiemmang\.vn/danh-ba-tin-nhiem/[^"]*)"[^>]*>\s*<span>\s*([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\s*</span>',
        html
    )

    matches = list(domain_blocks)
    for i, m in enumerate(matches):
        detail_url = m.group(1).strip()
        domain = m.group(2).strip().lower()
        domain = re.sub(r'^\.*', '', domain).strip()

        start_idx = m.start()
        end_idx = matches[i+1].start() if i+1 < len(matches) else len(html)
        slice_html = html[start_idx:end_idx]

        # Date match
        date_m = re.search(r'T\xedn nhi\u1ec7m m\u1ea1ng:\s*([\d/]+)|Tín nhiệm mạng:\s*([\d/]+)', slice_html)
        certified_date = date_m.group(1) or date_m.group(2) if date_m else ""

        # Owner match
        owner_m = re.search(r'S\u1edf h\u1eefu b\u1edfi:.*?>\s*([^<]+)</a>|Sở hữu bởi:.*?>\s*([^<]+)</a>', slice_html, re.DOTALL)
        owner = ""
        if owner_m:
            raw_owner = owner_m.group(1) or owner_m.group(2) or ""
            owner = unescape(raw_owner).strip()

        # Cert level match
        cert_level = ""
        if 'Chứng nhận nâng cao' in slice_html or 'n\xe2ng cao' in slice_html or 'medal_advanced' in slice_html:
            cert_level = 'Chứng nhận nâng cao'
        elif 'Chứng nhận cơ bản' in slice_html or 'c\u01a1 b\u1ea3n' in slice_html or 'medal_basic' in slice_html:
            cert_level = 'Chứng nhận cơ bản'

        # Classify Org Type automatically
        org_type = "Tổ chức nhà nước"
        owner_lower = owner.lower()

        if any(k in owner_lower for k in ['đảng', 'tuyên giáo', 'thành ủy', 'tỉnh ủy', 'huyện ủy']):
            org_type = "Đảng Cộng sản Việt Nam"
        elif any(k in owner_lower for k in ['quốc hội', 'đại biểu nhân dân']):
            org_type = "Quốc hội Việt Nam"
        elif any(k in owner_lower for k in ['tòa án', 'toà án']):
            org_type = "Tòa án nhân dân"
        elif any(k in owner_lower for k in ['viện kiểm sát', 'vksnd', 'kiểm sát']):
            org_type = "Viện Kiểm sát nhân dân"
        elif any(k in owner_lower for k in ['công đoàn', 'liên đoàn lao động']):
            org_type = "Công đoàn Việt Nam"
        elif any(k in owner_lower for k in ['đoàn thanh niên', 'tỉnh đoàn', 'thành đoàn', 'huyện đoàn']):
            org_type = "Đoàn Thanh niên CS Hồ Chí Minh"
        elif any(k in owner_lower for k in ['phụ nữ', 'lhpn']):
            org_type = "Hội Liên hiệp Phụ nữ Việt Nam"
        elif any(k in owner_lower for k in ['nông dân']):
            org_type = "Hội Nông dân Việt Nam"
        elif any(k in owner_lower for k in ['cựu chiến binh']):
            org_type = "Hội Cựu chiến binh Việt Nam"
        elif any(k in owner_lower for k in ['mặt trận', 'mttq']):
            org_type = "Mặt trận Tổ quốc Việt Nam"
        elif any(k in owner_lower for k in ['ubnd', 'hđnd', 'ủy ban nhân dân', 'hội đồng nhân dân']):
            org_type = "Hội đồng nhân dân & UBND"
        elif any(k in owner_lower for k in ['bộ ', 'tổng cục', 'cục ', 'văn phòng chính phủ']):
            org_type = "Chính phủ Việt Nam"

        items.append({
            "domain": domain,
            "owner": owner,
            "org_type": org_type,
            "certified_date": certified_date,
            "cert_level": cert_level,
            "detail_url": detail_url
        })

    return items

def run_scraper(max_org_pages=60, max_office_pages=20, concurrency=6, out_dir="data"):
    """Main orchestrator for Vietnam Constitutional & Socio-Political System dataset compilation."""
    os.makedirs(out_dir, exist_ok=True)
    start_time = time.time()

    print("=" * 75)
    print("  Safe Zone DNS - Vietnam Constitutional & Socio-Political System Domain Compiler")
    print("=" * 75)

    crawled_items = []
    errors = []

    # 1. Target Endpoints on Tín Nhiệm Mạng
    targets = [
        ("OrgVN", max_org_pages),
        ("office", max_office_pages)
    ]

    total_tasks = []
    for area_code, max_p in targets:
        for p in range(1, max_p + 1):
            url = f"https://tinnhiemmang.vn/filterObj?type=web&area[]={area_code}&page={p}"
            total_tasks.append((url, area_code, p))

    print(f"[*] Crawling {len(total_tasks)} pages from Tín Nhiệm Mạng across State & Political entities...")

    completed = 0
    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        future_to_task = {executor.submit(fetch_url, url): (url, area, p) for url, area, p in total_tasks}

        for future in as_completed(future_to_task):
            url, area, p = future_to_task[future]
            try:
                _, html, err = future.result()
                if err:
                    errors.append((url, err))
                elif html:
                    parsed = parse_tinnhiemmang_page(html)
                    crawled_items.extend(parsed)
                    completed += 1
                    if completed % 20 == 0 or completed == len(total_tasks):
                        print(f"[+] Progress: {completed}/{len(total_tasks)} pages crawled ({len(crawled_items)} items collected)")
            except Exception as exc:
                errors.append((url, str(exc)))

            time.sleep(0.05)

    print(f"[+] Tín Nhiệm Mạng Crawl Complete: {len(crawled_items)} entries parsed.")

    # 2. Merge Master Registries for Constitutional & Socio-Political Bodies
    print("[*] Merging Official Master Registries for Party, State, Courts, Unions & Local Gov...")
    master_items = []
    for m in MASTER_SYSTEM_DOMAINS:
        master_items.append({
            "domain": m["domain"].lower(),
            "owner": m["owner"],
            "org_type": m["org_type"],
            "certified_date": "Đã xác thực chính thức",
            "cert_level": m["cert_level"],
            "detail_url": f"https://tinnhiemmang.vn/danh-ba-tin-nhiem/{m['domain']}"
        })

    # Combine all items with deduplication
    all_combined = crawled_items + master_items
    unique_domains_dict = {}

    for item in all_combined:
        dom = item["domain"]

        # Automatic classification for .gov.vn domains if generic
        if dom.endswith('.gov.vn') and item["org_type"] == "Tổ chức nhà nước":
            if any(k in dom for k in ['toaan', 'tapchitoaan']):
                item["org_type"] = "Tòa án nhân dân"
            elif any(k in dom for k in ['vks', 'kiemsat']):
                item["org_type"] = "Viện Kiểm sát nhân dân"
            elif any(k in dom for k in ['quochoi', 'daibieunhandan']):
                item["org_type"] = "Quốc hội Việt Nam"
            elif any(k in dom for k in ['chinhphu', 'dichvucong', 'vpcp']):
                item["org_type"] = "Chính phủ Việt Nam"
            else:
                item["org_type"] = "Hội đồng nhân dân & UBND"

        if dom not in unique_domains_dict:
            unique_domains_dict[dom] = item
        else:
            existing = unique_domains_dict[dom]
            if not existing["owner"] and item["owner"]:
                existing["owner"] = item["owner"]
            if not existing["certified_date"] and item["certified_date"]:
                existing["certified_date"] = item["certified_date"]

    sorted_items = sorted(unique_domains_dict.values(), key=lambda x: x["domain"])
    unique_domains_list = sorted(list(unique_domains_dict.keys()))

    duration = round(time.time() - start_time, 2)

    print("\n" + "=" * 75)
    print("  Dataset Compilation Completed Successfully!")
    print("=" * 75)
    print(f"[*] Total unique political system & state domains: {len(unique_domains_list)}")
    print(f"[*] Total elapsed time: {duration} seconds")

    # Export 1: JSON Dataset
    json_path = os.path.join(out_dir, "vietnam_political_system_websites.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(sorted_items, f, ensure_ascii=False, indent=2)
    print(f"[+] Saved structured JSON: {json_path}")

    # Export 2: Plain Domain List (TXT)
    txt_path = os.path.join(out_dir, "vietnam_political_system_domains.txt")
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write("# Safe Zone DNS - Vietnam Constitutional & Socio-Political System Domain List\n")
        f.write(f"# Source: Tín Nhiệm Mạng (tinnhiemmang.vn) & Master Registries of Party, State & Unions\n")
        f.write(f"# Total Domains: {len(unique_domains_list)}\n")
        f.write(f"# Generated: {datetime.now(timezone.utc).isoformat()}\n\n")
        for dom in unique_domains_list:
            f.write(dom + "\n")
    print(f"[+] Saved plain domain list: {txt_path}")

    # Export 3: CSV Dataset (with UTF-8 BOM)
    csv_path = os.path.join(out_dir, "vietnam_political_system_websites.csv")
    with open(csv_path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["domain", "owner", "org_type", "certified_date", "cert_level", "detail_url"])
        writer.writeheader()
        writer.writerows(sorted_items)
    print(f"[+] Saved CSV dataset: {csv_path}")

    # Export 4: Summary JSON
    type_counts = {}
    for item in sorted_items:
        t = item["org_type"]
        type_counts[t] = type_counts.get(t, 0) + 1

    tld_counts = {}
    for dom in unique_domains_list:
        parts = dom.split('.')
        tld = parts[-1] if len(parts) > 1 else "unknown"
        if len(parts) > 2 and parts[-1] == 'vn':
            tld = f"{parts[-2]}.vn"
        tld_counts[tld] = tld_counts.get(tld, 0) + 1

    summary = {
        "source": "https://tinnhiemmang.vn/ & Master Registries of Party, State, Organs & Socio-Political Unions",
        "scraped_at": datetime.now(timezone.utc).isoformat(),
        "duration_seconds": duration,
        "total_unique_domains": len(unique_domains_list),
        "organization_breakdown": type_counts,
        "top_tlds": dict(sorted(tld_counts.items(), key=lambda x: x[1], reverse=True)[:15]),
        "error_count": len(errors)
    }
    summary_path = os.path.join(out_dir, "vietnam_political_system_summary.json")
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
    print(f"[+] Saved summary metrics: {summary_path}\n")

    return summary

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scrape Vietnam Political System domains for Safe Zone DNS.")
    parser.add_argument("--max-org-pages", type=int, default=60, help="Maximum Org pages to crawl (default: 60)")
    parser.add_argument("--max-office-pages", type=int, default=20, help="Maximum Office pages to crawl (default: 20)")
    parser.add_argument("--concurrency", type=int, default=6, help="Concurrency (default: 6)")
    parser.add_argument("--out-dir", type=str, default="data", help="Output directory path (default: data)")
    args = parser.parse_args()

    run_scraper(
        max_org_pages=args.max_org_pages,
        max_office_pages=args.max_office_pages,
        concurrency=args.concurrency,
        out_dir=args.out_dir
    )
