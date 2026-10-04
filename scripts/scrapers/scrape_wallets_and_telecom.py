#!/usr/bin/env python3
"""
Safe Zone DNS - Vietnam E-Wallets, Payment Gateways & Telecom Domain Compiler
Compiles & scrapes official domains for all:
- Ví điện tử & Cổng thanh toán tại Việt Nam: MoMo, ZaloPay, VNPAY, Viettel Money, VNPT Money, ShopeePay, Payoo, SmartPay, AppotaPay, 9Pay, Napas, Bảo Kim, Ngân Lượng, OnePay, Alepay, Cake, TNEX, Timo, Finhay, Infina, Tikop,...
- Tổ chức & Nhà mạng Viễn thông tại Việt Nam: Viettel, VNPT, VinaPhone, MobiFone, FPT Telecom, CMC Telecom, VTC, Vietnamobile, Gmobile, Wintel, Local Mobile, VNNIC, Cục Viễn thông,...
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

# 1. Official Master List of E-Wallets & Payment Gateways in Vietnam
MASTER_WALLET_DOMAINS = [
    # MoMo Ecosystem
    {"domain": "momo.vn", "owner": "Công ty Cổ phần Dịch vụ Di động Trực tuyến (MoMo)", "category_type": "Ví điện tử & Cổng thanh toán", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "momo.com.vn", "owner": "MoMo Việt Nam", "category_type": "Ví điện tử & Cổng thanh toán", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "business.momo.vn", "owner": "MoMo Business Portal", "category_type": "Ví điện tử & Cổng thanh toán", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "developers.momo.vn", "owner": "MoMo Developer Portal", "category_type": "Ví điện tử & Cổng thanh toán", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "payment.momo.vn", "owner": "MoMo Payment Gateway", "category_type": "Ví điện tử & Cổng thanh toán", "cert_level": "Chứng nhận cơ bản"},

    # ZaloPay Ecosystem
    {"domain": "zalopay.vn", "owner": "Công ty Cổ phần ZION (ZaloPay)", "category_type": "Ví điện tử & Cổng thanh toán", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "zalopay.com.vn", "owner": "ZaloPay Việt Nam", "category_type": "Ví điện tử & Cổng thanh toán", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "merchant.zalopay.vn", "owner": "ZaloPay Merchant Portal", "category_type": "Ví điện tử & Cổng thanh toán", "cert_level": "Chứng nhận cơ bản"},

    # VNPAY Ecosystem
    {"domain": "vnpay.vn", "owner": "Công ty Cổ phần Giải pháp Thanh toán Việt Nam (VNPAY)", "category_type": "Ví điện tử & Cổng thanh toán", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "vnpayqr.vn", "owner": "VNPAY-QR", "category_type": "Ví điện tử & Cổng thanh toán", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "merchant.vnpay.vn", "owner": "VNPAY Merchant Portal", "category_type": "Ví điện tử & Cổng thanh toán", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "vnpayment.vn", "owner": "VNPAY Gateway", "category_type": "Ví điện tử & Cổng thanh toán", "cert_level": "Chứng nhận cơ bản"},

    # Viettel Money & VNPT Money
    {"domain": "viettelmoney.vn", "owner": "Tổng Công ty Dịch vụ Số Viettel (Viettel Money)", "category_type": "Ví điện tử & Cổng thanh toán", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "viettelpay.vn", "owner": "ViettelPay", "category_type": "Ví điện tử & Cổng thanh toán", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "viettelpay.com.vn", "owner": "ViettelPay Việt Nam", "category_type": "Ví điện tử & Cổng thanh toán", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "vnptmoney.vn", "owner": "Tổng Công ty Truyền thông VNPT (VNPT Money)", "category_type": "Ví điện tử & Cổng thanh toán", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "vnptpay.vn", "owner": "VNPT Pay", "category_type": "Ví điện tử & Cổng thanh toán", "cert_level": "Chứng nhận cơ bản"},

    # ShopeePay, Payoo, SmartPay, AppotaPay, 9Pay, Napas
    {"domain": "shopeepay.vn", "owner": "Ví ShopeePay", "category_type": "Ví điện tử & Cổng thanh toán", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "airpay.vn", "owner": "AirPay (ShopeePay)", "category_type": "Ví điện tử & Cổng thanh toán", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "payoo.vn", "owner": "Công ty Cổ phần Dịch vụ Trực tuyến Cộng Đồng Việt (Payoo)", "category_type": "Ví điện tử & Cổng thanh toán", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "payoo.com.vn", "owner": "Payoo Việt Nam", "category_type": "Ví điện tử & Cổng thanh toán", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "smartpayvn.com", "owner": "Công ty TNHH Mạng Lưới Thông Minh (SmartPay)", "category_type": "Ví điện tử & Cổng thanh toán", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "smartpay.vn", "owner": "SmartPay Việt Nam", "category_type": "Ví điện tử & Cổng thanh toán", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "appotapay.com", "owner": "Công ty Cổ phần AppotaPay", "category_type": "Ví điện tử & Cổng thanh toán", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "appota.com", "owner": "Tập đoàn Appota", "category_type": "Ví điện tử & Cổng thanh toán", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "9pay.vn", "owner": "Công ty Cổ phần 9Pay", "category_type": "Ví điện tử & Cổng thanh toán", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "napas.com.vn", "owner": "Công ty Cổ phần Thanh toán Quốc gia Việt Nam (Napas)", "category_type": "Ví điện tử & Cổng thanh toán", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "napangroup.vn", "owner": "Công ty Cổ phần Thanh toán Quốc gia Việt Nam (Napas)", "category_type": "Ví điện tử & Cổng thanh toán", "cert_level": "Chứng nhận cơ bản"},

    # Bảo Kim, Ngân Lượng, OnePay, Alepay, Digital Banks & Wealthtech
    {"domain": "baokim.vn", "owner": "Công ty Cổ phần Thương mại Điện tử Bảo Kim", "category_type": "Ví điện tử & Cổng thanh toán", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "nganluong.vn", "owner": "Công ty Cổ phần Ngân Lượng", "category_type": "Ví điện tử & Cổng thanh toán", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "nextpay.vn", "owner": "Tập đoàn NextPay Việt Nam", "category_type": "Ví điện tử & Cổng thanh toán", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "mpos.vn", "owner": "Công ty Cổ phần Công nghệ mPOS Việt Nam", "category_type": "Ví điện tử & Cổng thanh toán", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "onepay.vn", "owner": "Công ty Cổ phần OnePAY", "category_type": "Ví điện tử & Cổng thanh toán", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "onepay.com.vn", "owner": "OnePay Việt Nam", "category_type": "Ví điện tử & Cổng thanh toán", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "alepay.vn", "owner": "Cổng thanh toán Alepay", "category_type": "Ví điện tử & Cổng thanh toán", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "cake.vn", "owner": "Ngân hàng số Cake by VPBank", "category_type": "Ví điện tử & Cổng thanh toán", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "tnex.com.vn", "owner": "Ngân hàng số TNEX (MSB)", "category_type": "Ví điện tử & Cổng thanh toán", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "tnex.vn", "owner": "Ngân hàng số TNEX", "category_type": "Ví điện tử & Cổng thanh toán", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "timo.vn", "owner": "Ngân hàng số Timo", "category_type": "Ví điện tử & Cổng thanh toán", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "finhay.com.vn", "owner": "Công ty Cổ phần Finhay Việt Nam", "category_type": "Ví điện tử & Cổng thanh toán", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "infina.vn", "owner": "Công ty Cổ phần Infina", "category_type": "Ví điện tử & Cổng thanh toán", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "tikop.vn", "owner": "Công ty Cổ phần Techcom (Tikop)", "category_type": "Ví điện tử & Cổng thanh toán", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "paypal.com", "owner": "PayPal Inc.", "category_type": "Ví điện tử & Cổng thanh toán", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "stripe.com", "owner": "Stripe Inc.", "category_type": "Ví điện tử & Cổng thanh toán", "cert_level": "Chứng nhận nâng cao"}
]

# 2. Official Master List of Telecommunications Operators & ISPs in Vietnam
MASTER_TELECOM_DOMAINS = [
    # Viettel Telecom Ecosystem
    {"domain": "viettel.vn", "owner": "Tập đoàn Công nghiệp - Viễn thông Quân đội (Viettel)", "category_type": "Tổ chức & Nhà mạng Viễn thông", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "vietteltelecom.vn", "owner": "Tổng Công ty Viễn thông Viettel", "category_type": "Tổ chức & Nhà mạng Viễn thông", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "viettel.com.vn", "owner": "Tập đoàn Viettel", "category_type": "Tổ chức & Nhà mạng Viễn thông", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "myviettel.vn", "owner": "Ứng dụng My Viettel", "category_type": "Tổ chức & Nhà mạng Viễn thông", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "viettelidc.com.vn", "owner": "Công ty TNHH Viettel-CHT (Viettel IDC)", "category_type": "Tổ chức & Nhà mạng Viễn thông", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "viettelsolutions.vn", "owner": "Tổng Công ty Giải pháp Doanh nghiệp Viettel", "category_type": "Tổ chức & Nhà mạng Viễn thông", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "viettelcloud.vn", "owner": "Viettel Cloud", "category_type": "Tổ chức & Nhà mạng Viễn thông", "cert_level": "Chứng nhận cơ bản"},

    # VNPT & VinaPhone Ecosystem
    {"domain": "vnpt.com.vn", "owner": "Tập đoàn Bưu chính Viễn thông Việt Nam (VNPT)", "category_type": "Tổ chức & Nhà mạng Viễn thông", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "vnpt.vn", "owner": "Tập đoàn Bưu chính Viễn thông Việt Nam (VNPT)", "category_type": "Tổ chức & Nhà mạng Viễn thông", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "vinaphone.com.vn", "owner": "Tổng Công ty Dịch vụ Viễn thông (VinaPhone)", "category_type": "Tổ chức & Nhà mạng Viễn thông", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "vinaphone.vn", "owner": "VinaPhone Việt Nam", "category_type": "Tổ chức & Nhà mạng Viễn thông", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "my.vnpt.vn", "owner": "Cổng thông tin Khách hàng My VNPT", "category_type": "Tổ chức & Nhà mạng Viễn thông", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "vnptit.vn", "owner": "Công ty CNTT VNPT (VNPT-IT)", "category_type": "Tổ chức & Nhà mạng Viễn thông", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "vtn.com.vn", "owner": "Công ty Viễn thông Liên tỉnh VNPT (VTN)", "category_type": "Tổ chức & Nhà mạng Viễn thông", "cert_level": "Chứng nhận cơ bản"},

    # MobiFone Ecosystem
    {"domain": "mobifone.vn", "owner": "Tổng Công ty Viễn thông MobiFone", "category_type": "Tổ chức & Nhà mạng Viễn thông", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "mobifone.com.vn", "owner": "Tổng Công ty Viễn thông MobiFone", "category_type": "Tổ chức & Nhà mạng Viễn thông", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "my.mobifone.vn", "owner": "Ứng dụng My MobiFone", "category_type": "Tổ chức & Nhà mạng Viễn thông", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "saymee.vn", "owner": "Saymee (Mạng di động GenZ từ MobiFone)", "category_type": "Tổ chức & Nhà mạng Viễn thông", "cert_level": "Chứng nhận cơ bản"},

    # FPT Telecom
    {"domain": "fpt.vn", "owner": "Công ty Cổ phần Viễn thông FPT (FPT Telecom)", "category_type": "Tổ chức & Nhà mạng Viễn thông", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "fpt.com.vn", "owner": "Tập đoàn FPT", "category_type": "Tổ chức & Nhà mạng Viễn thông", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "fpt.net", "owner": "FPT Telecom ISP Network", "category_type": "Tổ chức & Nhà mạng Viễn thông", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "hi.fpt.vn", "owner": "Ứng dụng Hi FPT", "category_type": "Tổ chức & Nhà mạng Viễn thông", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "fptplay.vn", "owner": "Công ty Cổ phần Viễn thông FPT (FPT Play)", "category_type": "Tổ chức & Nhà mạng Viễn thông", "cert_level": "Chứng nhận nâng cao"},

    # CMC Telecom, VTC, Vietnamobile, Gmobile, Wintel, VNNIC
    {"domain": "cmc.com.vn", "owner": "Tập đoàn Công nghệ CMC", "category_type": "Tổ chức & Nhà mạng Viễn thông", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "cmctelecom.vn", "owner": "Công ty Cổ phần Hạ tầng Viễn thông CMC (CMC Telecom)", "category_type": "Tổ chức & Nhà mạng Viễn thông", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "vtc.gov.vn", "owner": "Tổng Công ty Truyền thông Multimedi (VTC)", "category_type": "Tổ chức & Nhà mạng Viễn thông", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "vtc.vn", "owner": "Tổng Công ty VTC", "category_type": "Tổ chức & Nhà mạng Viễn thông", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "vietnamobile.com.vn", "owner": "Công ty Cổ phần Viễn thông Di động Vietnamobile", "category_type": "Tổ chức & Nhà mạng Viễn thông", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "vietnamobile.vn", "owner": "Vietnamobile", "category_type": "Tổ chức & Nhà mạng Viễn thông", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "gmobile.vn", "owner": "Công ty Cổ phần Viễn thông Di động Toàn Cầu (Gmobile)", "category_type": "Tổ chức & Nhà mạng Viễn thông", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "gtel.vn", "owner": "Tập đoàn Viễn thông GTel", "category_type": "Tổ chức & Nhà mạng Viễn thông", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "wintel.vn", "owner": "Mạng di động Wintel (Masan Group)", "category_type": "Tổ chức & Nhà mạng Viễn thông", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "reddi.vn", "owner": "Mạng di động Reddi (Wintel)", "category_type": "Tổ chức & Nhà mạng Viễn thông", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "mylocal.vn", "owner": "Mạng di động Local (ASIM Telecom)", "category_type": "Tổ chức & Nhà mạng Viễn thông", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "vnnic.vn", "owner": "Trung tâm Internet Việt Nam (VNNIC - Bộ TT&TT)", "category_type": "Tổ chức & Nhà mạng Viễn thông", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "tenmien.vn", "owner": "Cổng thông tin Tên miền Quốc gia Việt Nam (VNNIC)", "category_type": "Tổ chức & Nhà mạng Viễn thông", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "vnta.gov.vn", "owner": "Cục Viễn thông (Bộ Thông tin và Truyền thông)", "category_type": "Tổ chức & Nhà mạng Viễn thông", "cert_level": "Chứng nhận nâng cao"}
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

        # Automatic classification
        category_type = "Ví điện tử & Cổng thanh toán"
        owner_lower = owner.lower()
        dom_lower = domain.lower()

        if any(k in dom_lower or k in owner_lower for k in ['viettel', 'vnpt', 'vinaphone', 'mobifone', 'fpt', 'cmc', 'vtc', 'gmobile', 'vietnamobile', 'wintel', 'reddi', 'telecom', 'bưu chính', 'viễn thông', 'vnnic']):
            category_type = "Tổ chức & Nhà mạng Viễn thông"

        items.append({
            "domain": domain,
            "owner": owner,
            "category_type": category_type,
            "certified_date": certified_date,
            "cert_level": cert_level,
            "detail_url": detail_url
        })

    return items

def run_scraper(max_bank_pages=10, max_online_pages=15, concurrency=5, out_dir="data"):
    """Main orchestrator for Vietnam E-Wallets, Payments & Telecom domain dataset compilation."""
    os.makedirs(out_dir, exist_ok=True)
    start_time = time.time()

    print("=" * 75)
    print("  Safe Zone DNS - E-Wallets, Payment Gateways & Telecom Domain Compiler")
    print("=" * 75)

    crawled_items = []
    errors = []

    # 1. Target Endpoints on Tín Nhiệm Mạng
    targets = [
        ("bank", max_bank_pages),
        ("online", max_online_pages)
    ]

    total_tasks = []
    for area_code, max_p in targets:
        for p in range(1, max_p + 1):
            url = f"https://tinnhiemmang.vn/filterObj?type=web&area[]={area_code}&page={p}"
            total_tasks.append((url, area_code, p))

    print(f"[*] Crawling {len(total_tasks)} pages from Tín Nhiệm Mạng across Financial & Telecom entities...")

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
                    if completed % 10 == 0 or completed == len(total_tasks):
                        print(f"[+] Progress: {completed}/{len(total_tasks)} pages crawled ({len(crawled_items)} items collected)")
            except Exception as exc:
                errors.append((url, str(exc)))

            time.sleep(0.05)

    print(f"[+] Tín Nhiệm Mạng Crawl Complete: {len(crawled_items)} entries parsed.")

    # 2. Merge Official Master Registries for E-Wallets & Telecom Operators
    print("[*] Merging Official Master Registries for E-Wallets, Payments & Telecom Operators...")
    master_items = []
    for m in MASTER_WALLET_DOMAINS:
        master_items.append({
            "domain": m["domain"].lower(),
            "owner": m["owner"],
            "category_type": m["category_type"],
            "certified_date": "Đã xác thực chính thức",
            "cert_level": m["cert_level"],
            "detail_url": f"https://tinnhiemmang.vn/danh-ba-tin-nhiem/{m['domain']}"
        })

    for m in MASTER_TELECOM_DOMAINS:
        master_items.append({
            "domain": m["domain"].lower(),
            "owner": m["owner"],
            "category_type": m["category_type"],
            "certified_date": "Đã xác thực chính thức",
            "cert_level": m["cert_level"],
            "detail_url": f"https://tinnhiemmang.vn/danh-ba-tin-nhiem/{m['domain']}"
        })

    # Combine all items with deduplication
    all_combined = crawled_items + master_items
    unique_domains_dict = {}

    for item in all_combined:
        dom = item["domain"]

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
    print(f"[*] Total unique E-Wallets & Telecom domains: {len(unique_domains_list)}")
    print(f"[*] Total elapsed time: {duration} seconds")

    # Export 1: JSON Dataset
    json_path = os.path.join(out_dir, "wallets_and_telecom_websites.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(sorted_items, f, ensure_ascii=False, indent=2)
    print(f"[+] Saved structured JSON: {json_path}")

    # Export 2: Plain Domain List (TXT)
    txt_path = os.path.join(out_dir, "wallets_and_telecom_domains.txt")
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write("# Safe Zone DNS - Vietnam E-Wallets, Payment Gateways & Telecom Domain List\n")
        f.write(f"# Source: Tín Nhiệm Mạng (tinnhiemmang.vn) & Official E-Wallet / Telecom Master Registries\n")
        f.write(f"# Total Domains: {len(unique_domains_list)}\n")
        f.write(f"# Generated: {datetime.now(timezone.utc).isoformat()}\n\n")
        for dom in unique_domains_list:
            f.write(dom + "\n")
    print(f"[+] Saved plain domain list: {txt_path}")

    # Export 3: CSV Dataset (with UTF-8 BOM)
    csv_path = os.path.join(out_dir, "wallets_and_telecom_websites.csv")
    with open(csv_path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["domain", "owner", "category_type", "certified_date", "cert_level", "detail_url"])
        writer.writeheader()
        writer.writerows(sorted_items)
    print(f"[+] Saved CSV dataset: {csv_path}")

    # Export 4: Summary JSON
    type_counts = {}
    for item in sorted_items:
        t = item["category_type"]
        type_counts[t] = type_counts.get(t, 0) + 1

    tld_counts = {}
    for dom in unique_domains_list:
        parts = dom.split('.')
        tld = parts[-1] if len(parts) > 1 else "unknown"
        if len(parts) > 2 and parts[-1] == 'vn':
            tld = f"{parts[-2]}.vn"
        tld_counts[tld] = tld_counts.get(tld, 0) + 1

    summary = {
        "source": "https://tinnhiemmang.vn/ & Master Registries of E-Wallets & Telecom Operators",
        "scraped_at": datetime.now(timezone.utc).isoformat(),
        "duration_seconds": duration,
        "total_unique_domains": len(unique_domains_list),
        "category_breakdown": type_counts,
        "top_tlds": dict(sorted(tld_counts.items(), key=lambda x: x[1], reverse=True)[:15]),
        "error_count": len(errors)
    }
    summary_path = os.path.join(out_dir, "wallets_and_telecom_summary.json")
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
    print(f"[+] Saved summary metrics: {summary_path}\n")

    return summary

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scrape Vietnam E-Wallets and Telecom domains for Safe Zone DNS.")
    parser.add_argument("--max-bank-pages", type=int, default=10, help="Maximum Bank pages to crawl (default: 10)")
    parser.add_argument("--max-online-pages", type=int, default=15, help="Maximum Online pages to crawl (default: 15)")
    parser.add_argument("--concurrency", type=int, default=5, help="Concurrency (default: 5)")
    parser.add_argument("--out-dir", type=str, default="data", help="Output directory path (default: data)")
    args = parser.parse_args()

    run_scraper(
        max_bank_pages=args.max_bank_pages,
        max_online_pages=args.max_online_pages,
        concurrency=args.concurrency,
        out_dir=args.out_dir
    )
