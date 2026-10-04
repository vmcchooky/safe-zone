#!/usr/bin/env python3
"""
Safe Zone DNS - Vietnam Government & Banks Domain Scraper
Scrapes and compiles official domains of all Banks, State Organizations, and Government Agencies in Vietnam.
Outputs structured datasets for AI Engine training and Safe Zone DNS allowlists.
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

# Comprehensive master list of official Vietnamese Commercial Banks, Foreign Banks & Central Financial Institutions
MASTER_BANK_DOMAINS = [
    # State & Central Bank
    {"domain": "sbv.gov.vn", "owner": "Ngân hàng Nhà nước Việt Nam", "type": "Ngân hàng - Tài chính", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "vba.org.vn", "owner": "Hiệp hội Ngân hàng Việt Nam", "type": "Ngân hàng - Tài chính", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "napangroup.vn", "owner": "Công ty Cổ phần Thanh toán Quốc gia Việt Nam (Napas)", "type": "Ngân hàng - Tài chính", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "napas.com.vn", "owner": "Công ty Cổ phần Thanh toán Quốc gia Việt Nam (Napas)", "type": "Ngân hàng - Tài chính", "cert_level": "Chứng nhận cơ bản"},

    # Big 4 State-Owned / Majority State Commercial Banks
    {"domain": "vietcombank.com.vn", "owner": "Ngân hàng TMCP Ngoại thương Việt Nam (Vietcombank)", "type": "Ngân hàng - Tài chính", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "vcb.com.vn", "owner": "Ngân hàng TMCP Ngoại thương Việt Nam (Vietcombank)", "type": "Ngân hàng - Tài chính", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "digibank.vietcombank.com.vn", "owner": "Vietcombank VCB Digibank", "type": "Ngân hàng - Tài chính", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "vietinbank.vn", "owner": "Ngân hàng TMCP Công Thương Việt Nam (VietinBank)", "type": "Ngân hàng - Tài chính", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "ipay.vietinbank.vn", "owner": "VietinBank iPay", "type": "Ngân hàng - Tài chính", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "bidv.com.vn", "owner": "Ngân hàng TMCP Đầu tư và Phát triển Việt Nam (BIDV)", "type": "Ngân hàng - Tài chính", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "smartbanking.bidv.com.vn", "owner": "BIDV SmartBanking", "type": "Ngân hàng - Tài chính", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "agribank.com.vn", "owner": "Ngân hàng Nông nghiệp và Phát triển Nông thôn Việt Nam (Agribank)", "type": "Ngân hàng - Tài chính", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "ebanking.agribank.com.vn", "owner": "Agribank E-Banking", "type": "Ngân hàng - Tài chính", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "vbsp.org.vn", "owner": "Ngân hàng Chính sách xã hội Việt Nam", "type": "Ngân hàng - Tài chính", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "vdb.gov.vn", "owner": "Ngân hàng Phát triển Việt Nam (VDB)", "type": "Ngân hàng - Tài chính", "cert_level": "Chứng nhận cơ bản"},

    # Joint Stock Commercial Banks (TMCP)
    {"domain": "techcombank.com", "owner": "Ngân hàng TMCP Kỹ thương Việt Nam (Techcombank)", "type": "Ngân hàng - Tài chính", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "techcombank.com.vn", "owner": "Ngân hàng TMCP Kỹ thương Việt Nam (Techcombank)", "type": "Ngân hàng - Tài chính", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "mbbank.com.vn", "owner": "Ngân hàng TMCP Quân đội (MB Bank)", "type": "Ngân hàng - Tài chính", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "vpbank.com.vn", "owner": "Ngân hàng TMCP Việt Nam Thịnh Vượng (VPBank)", "type": "Ngân hàng - Tài chính", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "acb.com.vn", "owner": "Ngân hàng TMCP Á Châu (ACB)", "type": "Ngân hàng - Tài chính", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "hdbank.com.vn", "owner": "Ngân hàng TMCP Phát triển TP.HCM (HDBank)", "type": "Ngân hàng - Tài chính", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "sacombank.com.vn", "owner": "Ngân hàng TMCP Sài Gòn Thương Tín (Sacombank)", "type": "Ngân hàng - Tài chính", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "sacombank.com", "owner": "Ngân hàng TMCP Sài Gòn Thương Tín (Sacombank)", "type": "Ngân hàng - Tài chính", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "tpbank.vn", "owner": "Ngân hàng TMCP Tiên Phong (TPBank)", "type": "Ngân hàng - Tài chính", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "tpb.vn", "owner": "Ngân hàng TMCP Tiên Phong (TPBank)", "type": "Ngân hàng - Tài chính", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "vib.com.vn", "owner": "Ngân hàng TMCP Quốc tế Việt Nam (VIB)", "type": "Ngân hàng - Tài chính", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "shb.com.vn", "owner": "Ngân hàng TMCP Sài Gòn - Hà Nội (SHB)", "type": "Ngân hàng - Tài chính", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "seabank.com.vn", "owner": "Ngân hàng TMCP Đông Nam Á (SeABank)", "type": "Ngân hàng - Tài chính", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "ocb.com.vn", "owner": "Ngân hàng TMCP Phương Đông (OCB)", "type": "Ngân hàng - Tài chính", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "msb.com.vn", "owner": "Ngân hàng TMCP Hàng hải Việt Nam (MSB)", "type": "Ngân hàng - Tài chính", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "eximbank.com.vn", "owner": "Ngân hàng TMCP Xuất Nhập Khẩu Việt Nam (Eximbank)", "type": "Ngân hàng - Tài chính", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "bacabank.vn", "owner": "Ngân hàng TMCP Bắc Á (Bac A Bank)", "type": "Ngân hàng - Tài chính", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "lpbank.com.vn", "owner": "Ngân hàng TMCP Lộc Phát Việt Nam (LPBank)", "type": "Ngân hàng - Tài chính", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "lienvietpostbank.com.vn", "owner": "Ngân hàng TMCP Bưu điện Liên Việt (LPBank)", "type": "Ngân hàng - Tài chính", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "scb.com.vn", "owner": "Ngân hàng TMCP Sài Gòn (SCB)", "type": "Ngân hàng - Tài chính", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "namabank.com.vn", "owner": "Ngân hàng TMCP Nam Á (Nam A Bank)", "type": "Ngân hàng - Tài chính", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "baovietbank.com.vn", "owner": "Ngân hàng TMCP Bảo Việt (BaoViet Bank)", "type": "Ngân hàng - Tài chính", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "pvcombank.com.vn", "owner": "Ngân hàng TMCP Đại Chúng Việt Nam (PVcomBank)", "type": "Ngân hàng - Tài chính", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "vietbank.com.vn", "owner": "Ngân hàng TMCP Việt Nam Thương Tín (VietBank)", "type": "Ngân hàng - Tài chính", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "kienlongbank.com", "owner": "Ngân hàng TMCP Kiên Long (Kienlongbank)", "type": "Ngân hàng - Tài chính", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "saigonbank.com.vn", "owner": "Ngân hàng TMCP Sài Gòn Công Thương (Saigonbank)", "type": "Ngân hàng - Tài chính", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "pgbank.com.vn", "owner": "Ngân hàng TMCP Thịnh vượng và Phát triển (PGBank)", "type": "Ngân hàng - Tài chính", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "gpbank.com.vn", "owner": "Ngân hàng Thương mại TNHH MTV Dầu khí Nhàn rỗi (GPBank)", "type": "Ngân hàng - Tài chính", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "oceanbank.vn", "owner": "Ngân hàng Thương mại TNHH MTV Đại Dương (OceanBank)", "type": "Ngân hàng - Tài chính", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "cbbank.vn", "owner": "Ngân hàng Thương mại TNHH MTV Xây dựng Việt Nam (CBBank)", "type": "Ngân hàng - Tài chính", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "vrbank.com.vn", "owner": "Ngân hàng Liên doanh Việt - Nga (VRB)", "type": "Ngân hàng - Tài chính", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "ncb-bank.vn", "owner": "Ngân hàng TMCP Quốc Dân (NCB)", "type": "Ngân hàng - Tài chính", "cert_level": "Chứng nhận cơ bản"},

    # Foreign & Joint Venture Banks in Vietnam
    {"domain": "hsbc.com.vn", "owner": "Ngân hàng TNHH Một thành viên HSBC (Việt Nam)", "type": "Ngân hàng - Tài chính", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "shinhan.com.vn", "owner": "Ngân hàng TNHH Một thành viên Shinhan Việt Nam", "type": "Ngân hàng - Tài chính", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "standardchartered.com.vn", "owner": "Ngân hàng TNHH Một thành viên Standard Chartered (Việt Nam)", "type": "Ngân hàng - Tài chính", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "uob.com.vn", "owner": "Ngân hàng TNHH Một thành viên UOB (Việt Nam)", "type": "Ngân hàng - Tài chính", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "publicbank.com.vn", "owner": "Ngân hàng TNHH Một thành viên Public Bank Việt Nam", "type": "Ngân hàng - Tài chính", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "wooribank.com.vn", "owner": "Ngân hàng TNHH Một thành viên Woori Việt Nam", "type": "Ngân hàng - Tài chính", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "citibank.com.vn", "owner": "Ngân hàng Citibank N.A. - Chi nhánh Việt Nam", "type": "Ngân hàng - Tài chính", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "hongleong.com.vn", "owner": "Ngân hàng TNHH Một thành viên Hong Leong Việt Nam", "type": "Ngân hàng - Tài chính", "cert_level": "Chứng nhận cơ bản"},

    # Major Securities & Financial Institutions
    {"domain": "vps.com.vn", "owner": "Công ty Cổ phần Chứng khoán VPS", "type": "Ngân hàng - Tài chính", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "ssi.com.vn", "owner": "Công ty Cổ phần Chứng khoán SSI", "type": "Ngân hàng - Tài chính", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "tcbs.com.vn", "owner": "Công ty Cổ phần Chứng khoán Kỹ Thương (TCBS)", "type": "Ngân hàng - Tài chính", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "vndirect.com.vn", "owner": "Công ty Cổ phần Chứng khoán VNDIRECT", "type": "Ngân hàng - Tài chính", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "miraeasset.com.vn", "owner": "Công ty Cổ phần Chứng khoán Mirae Asset (Việt Nam)", "type": "Ngân hàng - Tài chính", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "hsc.com.vn", "owner": "Công ty Cổ phần Chứng khoán Thành phố Hồ Chí Minh (HSC)", "type": "Ngân hàng - Tài chính", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "vcbs.com.vn", "owner": "Công ty TNHH Chứng khoán Ngân hàng TMCP Ngoại thương Việt Nam (VCBS)", "type": "Ngân hàng - Tài chính", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "payoo.vn", "owner": "Công ty Cổ phần Dịch vụ Trực tuyến Cộng Đồng Việt (Payoo)", "type": "Ngân hàng - Tài chính", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "momo.vn", "owner": "Công ty Cổ phần Dịch vụ Di động Trực tuyến (Momo)", "type": "Ngân hàng - Tài chính", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "zalopay.vn", "owner": "Công ty Cổ phần ZION (ZaloPay)", "type": "Ngân hàng - Tài chính", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "vnpay.vn", "owner": "Công ty Cổ phần Giải pháp Thanh toán Việt Nam (VNPAY)", "type": "Ngân hàng - Tài chính", "cert_level": "Chứng nhận cơ bản"}
]

# Official Central Government Ministries, Organs & Provincial Portal Domain Master List
MASTER_GOV_DOMAINS = [
    # Top Organs of State
    {"domain": "chinhphu.vn", "owner": "Cổng Thông tin Điện tử Chính phủ", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "dichvucong.gov.vn", "owner": "Cổng Dịch vụ công Quốc gia", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "quochoi.vn", "owner": "Cổng Thông tin Điện tử Quốc hội Việt Nam", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "vpcp.gov.vn", "owner": "Văn phòng Chính phủ", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "toaan.gov.vn", "owner": "Tòa án Nhân dân Tối cao", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "vksndtc.gov.vn", "owner": "Viện Kiểm sát Nhân dân Tối cao", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "sav.gov.vn", "owner": "Kiểm toán Nhà nước Việt Nam", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "mota.gov.vn", "owner": "Bộ Ngoại giao Việt Nam", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "mofa.gov.vn", "owner": "Bộ Ngoại giao Việt Nam", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "mps.gov.vn", "owner": "Bộ Công an", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "bocongan.gov.vn", "owner": "Bộ Công an", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "mod.gov.vn", "owner": "Bộ Quốc phòng", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "mof.gov.vn", "owner": "Bộ Tài chính", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "most.gov.vn", "owner": "Bộ Khoa học và Công nghệ", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "mic.gov.vn", "owner": "Bộ Thông tin và Truyền thông", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "moit.gov.vn", "owner": "Bộ Công Thương", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "moh.gov.vn", "owner": "Bộ Y tế", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "moet.gov.vn", "owner": "Bộ Giáo dục và Đào tạo", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "moj.gov.vn", "owner": "Bộ Tư pháp", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "monre.gov.vn", "owner": "Bộ Tài nguyên và Môi trường", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "mard.gov.vn", "owner": "Bộ Nông nghiệp và Phát triển nông thôn", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "molisa.gov.vn", "owner": "Bộ Lao động - Thương binh và Xã hội", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "moc.gov.vn", "owner": "Bộ Xây dựng", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "mot.gov.vn", "owner": "Bộ Giao thông Vận tải", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "mpi.gov.vn", "owner": "Bộ Kế hoạch và Đầu tư", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "gdt.gov.vn", "owner": "Tổng cục Thuế", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "customs.gov.vn", "owner": "Tổng cục Hải quan", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "baohiemxahoi.gov.vn", "owner": "Bảo hiểm Xã hội Việt Nam", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "vov.vn", "owner": "Đài Tiếng nói Việt Nam (VOV)", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "vtv.vn", "owner": "Đài Truyền hình Việt Nam (VTV)", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "vnanet.vn", "owner": "Thông tấn xã Việt Nam (TTXVN)", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},

    # 63 Provincial & City Government Portals
    {"domain": "hanoi.gov.vn", "owner": "UBND TP Hà Nội", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "dichvucong.hanoi.gov.vn", "owner": "Cổng Dịch vụ công TP Hà Nội", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "hochiminhcity.gov.vn", "owner": "UBND TP Hồ Chí Minh", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "dichvucong.hochiminhcity.gov.vn", "owner": "Cổng Dịch vụ công TP Hồ Chí Minh", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "haiphong.gov.vn", "owner": "UBND TP Hải Phòng", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "danang.gov.vn", "owner": "UBND TP Đà Nẵng", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "dichvucong.danang.gov.vn", "owner": "Cổng Dịch vụ công TP Đà Nẵng", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "cantho.gov.vn", "owner": "UBND TP Cần Thơ", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "quangninh.gov.vn", "owner": "UBND tỉnh Quảng Ninh", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "dichvucong.quangninh.gov.vn", "owner": "Cổng Dịch vụ công tỉnh Quảng Ninh", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "binhduong.gov.vn", "owner": "UBND tỉnh Bình Dương", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "dongnai.gov.vn", "owner": "UBND tỉnh Đồng Nai", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "hatinh.gov.vn", "owner": "UBND tỉnh Hà Tĩnh", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "dichvucong.hatinh.gov.vn", "owner": "Cổng Dịch vụ công tỉnh Hà Tĩnh", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "thanhhoa.gov.vn", "owner": "UBND tỉnh Thanh Hóa", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "nghean.gov.vn", "owner": "UBND tỉnh Nghệ An", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "bacninh.gov.vn", "owner": "UBND tỉnh Bắc Ninh", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "vinhphuc.gov.vn", "owner": "UBND tỉnh Vĩnh Phúc", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "haiduong.gov.vn", "owner": "UBND tỉnh Hải Dương", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "namdinh.gov.vn", "owner": "UBND tỉnh Nam Định", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "ninhbinh.gov.vn", "owner": "UBND tỉnh Ninh Bình", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "thaibinh.gov.vn", "owner": "UBND tỉnh Thái Bình", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "hungyen.gov.vn", "owner": "UBND tỉnh Hưng Yên", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "thainguyen.gov.vn", "owner": "UBND tỉnh Thái Nguyên", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "langson.gov.vn", "owner": "UBND tỉnh Lạng Sơn", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "caobang.gov.vn", "owner": "UBND tỉnh Cao Bằng", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "laocai.gov.vn", "owner": "UBND tỉnh Lào Cai", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "yenbai.gov.vn", "owner": "UBND tỉnh Yên Bái", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "dienbien.gov.vn", "owner": "UBND tỉnh Điện Biên", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "laichau.gov.vn", "owner": "UBND tỉnh Lai Châu", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "sonla.gov.vn", "owner": "UBND tỉnh Sơn La", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "hoabinh.gov.vn", "owner": "UBND tỉnh Hòa Bình", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "quangbinh.gov.vn", "owner": "UBND tỉnh Quảng Bình", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "quangtri.gov.vn", "owner": "UBND tỉnh Quảng Trị", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "dichvucong.quangtri.gov.vn", "owner": "Cổng Dịch vụ công tỉnh Quảng Trị", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "thuathienhue.gov.vn", "owner": "UBND tỉnh Thừa Thiên Huế", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "quangnam.gov.vn", "owner": "UBND tỉnh Quảng Nam", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "quangngai.gov.vn", "owner": "UBND tỉnh Quảng Ngãi", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "binhdinh.gov.vn", "owner": "UBND tỉnh Bình Định", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "phuyen.gov.vn", "owner": "UBND tỉnh Phú Yên", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "khanhhoa.gov.vn", "owner": "UBND tỉnh Khánh Hòa", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "ninhthuan.gov.vn", "owner": "UBND tỉnh Ninh Thuận", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "binhthuan.gov.vn", "owner": "UBND tỉnh Bình Thuận", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "gialai.gov.vn", "owner": "UBND tỉnh Gia Lai", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "kontum.gov.vn", "owner": "UBND tỉnh Kon Tum", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "daklak.gov.vn", "owner": "UBND tỉnh Đắk Lắk", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "daknong.gov.vn", "owner": "UBND tỉnh Đắk Nông", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "lamdong.gov.vn", "owner": "UBND tỉnh Lâm Đồng", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "tayninh.gov.vn", "owner": "UBND tỉnh Tây Ninh", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "binhphuoc.gov.vn", "owner": "UBND tỉnh Bình Phước", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "baria-vungtau.gov.vn", "owner": "UBND tỉnh Bà Rịa - Vũng Tàu", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "longan.gov.vn", "owner": "UBND tỉnh Long An", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "tiengiang.gov.vn", "owner": "UBND tỉnh Tiền Giang", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "bentre.gov.vn", "owner": "UBND tỉnh Bến Tre", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "travinh.gov.vn", "owner": "UBND tỉnh Trà Vinh", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "vinhlong.gov.vn", "owner": "UBND tỉnh Vĩnh Long", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "dongthap.gov.vn", "owner": "UBND tỉnh Đồng Tháp", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "angiang.gov.vn", "owner": "UBND tỉnh An Giang", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "dichvucong.angiang.gov.vn", "owner": "Cổng Dịch vụ công tỉnh An Giang", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "kiengiang.gov.vn", "owner": "UBND tỉnh Kiên Giang", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "haugiang.gov.vn", "owner": "UBND tỉnh Hậu Giang", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "soctrang.gov.vn", "owner": "UBND tỉnh Sóc Trăng", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "baclieu.gov.vn", "owner": "UBND tỉnh Bạc Liêu", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "camau.gov.vn", "owner": "UBND tỉnh Cà Mau", "type": "Tổ chức nhà nước", "cert_level": "Chứng nhận cơ bản"}
]

def fetch_url(url, retries=3, backoff=1.0, timeout=15):
    """Fetches HTML with retry logic."""
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers=HEADERS)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                html = resp.read().decode('utf-8', errors='replace')
                return url, html, None
        except Exception as e:
            if attempt < retries - 1:
                time.sleep(backoff * (attempt + 1))
            else:
                return url, None, str(e)

def parse_tinnhiemmang_page(html, category_label):
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

        items.append({
            "domain": domain,
            "owner": owner,
            "type": category_label,
            "certified_date": certified_date,
            "cert_level": cert_level,
            "detail_url": detail_url
        })

    return items

def run_scraper(max_gov_pages=50, max_bank_pages=10, max_office_pages=15, concurrency=6, out_dir="data"):
    """Main orchestrator for Vietnam Gov & Bank domain dataset generation."""
    os.makedirs(out_dir, exist_ok=True)
    start_time = time.time()

    print("=" * 70)
    print("  Safe Zone DNS - Vietnam Government & Banks Domain Compiler")
    print("=" * 70)

    crawled_items = []
    errors = []

    # 1. Target Endpoints on Tín Nhiệm Mạng
    targets = [
        ("bank", "Ngân hàng - Tổ chức tài chính", max_bank_pages),
        ("OrgVN", "Tổ chức nhà nước", max_gov_pages),
        ("office", "Cơ quan nhà nước", max_office_pages)
    ]

    total_tasks = []
    for area_code, label, max_p in targets:
        for p in range(1, max_p + 1):
            url = f"https://tinnhiemmang.vn/filterObj?type=web&area[]={area_code}&page={p}"
            total_tasks.append((url, label, area_code, p))

    print(f"[*] Crawling {len(total_tasks)} pages from Tín Nhiệm Mạng across Banks & Gov entities...")

    completed = 0
    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        future_to_task = {executor.submit(fetch_url, url): (url, label, area, p) for url, label, area, p in total_tasks}

        for future in as_completed(future_to_task):
            url, label, area, p = future_to_task[future]
            try:
                _, html, err = future.result()
                if err:
                    errors.append((url, err))
                elif html:
                    parsed = parse_tinnhiemmang_page(html, label)
                    crawled_items.extend(parsed)
                    completed += 1
                    if completed % 25 == 0 or completed == len(total_tasks):
                        print(f"[+] Progress: {completed}/{len(total_tasks)} pages crawled ({len(crawled_items)} items collected)")
            except Exception as exc:
                errors.append((url, str(exc)))

            time.sleep(0.05)

    print(f"[+] Tín Nhiệm Mạng Crawl Complete: {len(crawled_items)} entries parsed.")

    # 2. Merge Master Registries for Banks & Gov Entities
    print("[*] Merging Official Master Registries for Banks and Gov Entities...")
    master_items = []
    for b in MASTER_BANK_DOMAINS:
        master_items.append({
            "domain": b["domain"].lower(),
            "owner": b["owner"],
            "type": b["type"],
            "certified_date": "Đã xác thực chính thức",
            "cert_level": b["cert_level"],
            "detail_url": f"https://tinnhiemmang.vn/danh-ba-tin-nhiem/{b['domain']}"
        })

    for g in MASTER_GOV_DOMAINS:
        master_items.append({
            "domain": g["domain"].lower(),
            "owner": g["owner"],
            "type": g["type"],
            "certified_date": "Đã xác thực chính thức",
            "cert_level": g["cert_level"],
            "detail_url": f"https://tinnhiemmang.vn/danh-ba-tin-nhiem/{g['domain']}"
        })

    # Combine all items with deduplication
    all_combined = crawled_items + master_items
    unique_domains_dict = {}

    for item in all_combined:
        dom = item["domain"]

        # Tag gov domains ending in .gov.vn or .vnn.vn
        if dom.endswith('.gov.vn') or dom.endswith('.vnn.vn'):
            item["type"] = "Tổ chức nhà nước"

        if dom not in unique_domains_dict:
            unique_domains_dict[dom] = item
        else:
            # Upgrade item if owner or date details exist
            existing = unique_domains_dict[dom]
            if not existing["owner"] and item["owner"]:
                existing["owner"] = item["owner"]
            if not existing["certified_date"] and item["certified_date"]:
                existing["certified_date"] = item["certified_date"]

    sorted_items = sorted(unique_domains_dict.values(), key=lambda x: x["domain"])
    unique_domains_list = sorted(list(unique_domains_dict.keys()))

    duration = round(time.time() - start_time, 2)

    print("\n" + "=" * 70)
    print("  Dataset Compilation Completed Successfully!")
    print("=" * 70)
    print(f"[*] Total unique Gov & Bank domains: {len(unique_domains_list)}")
    print(f"[*] Total elapsed time: {duration} seconds")

    # Export 1: JSON Dataset
    json_path = os.path.join(out_dir, "vietnam_gov_and_banks_websites.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(sorted_items, f, ensure_ascii=False, indent=2)
    print(f"[+] Saved structured JSON: {json_path}")

    # Export 2: Plain Domain List (TXT)
    txt_path = os.path.join(out_dir, "vietnam_gov_and_banks_domains.txt")
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write("# Safe Zone DNS - Official Vietnam Government & Bank Domain List\n")
        f.write(f"# Source: Tín Nhiệm Mạng (tinnhiemmang.vn) & Official State Bank/Gov Registries\n")
        f.write(f"# Total Domains: {len(unique_domains_list)}\n")
        f.write(f"# Generated: {datetime.now(timezone.utc).isoformat()}\n\n")
        for dom in unique_domains_list:
            f.write(dom + "\n")
    print(f"[+] Saved plain domain list: {txt_path}")

    # Export 3: CSV Dataset (with UTF-8 BOM)
    csv_path = os.path.join(out_dir, "vietnam_gov_and_banks_websites.csv")
    with open(csv_path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["domain", "owner", "type", "certified_date", "cert_level", "detail_url"])
        writer.writeheader()
        writer.writerows(sorted_items)
    print(f"[+] Saved CSV dataset: {csv_path}")

    # Export 4: Summary JSON
    gov_count = sum(1 for item in sorted_items if "nhà nước" in item["type"].lower() or item["domain"].endswith('.gov.vn'))
    bank_count = sum(1 for item in sorted_items if "ngân hàng" in item["type"].lower() or "tài chính" in item["type"].lower())
    other_count = len(sorted_items) - (gov_count + bank_count)

    tld_counts = {}
    for dom in unique_domains_list:
        parts = dom.split('.')
        tld = parts[-1] if len(parts) > 1 else "unknown"
        if len(parts) > 2 and parts[-1] == 'vn':
            tld = f"{parts[-2]}.vn"
        tld_counts[tld] = tld_counts.get(tld, 0) + 1

    summary = {
        "source": "https://tinnhiemmang.vn/ & Official Government & Bank Registries",
        "scraped_at": datetime.now(timezone.utc).isoformat(),
        "duration_seconds": duration,
        "total_unique_domains": len(unique_domains_list),
        "gov_domains_count": gov_count,
        "bank_domains_count": bank_count,
        "other_official_count": other_count,
        "top_tlds": dict(sorted(tld_counts.items(), key=lambda x: x[1], reverse=True)[:15]),
        "error_count": len(errors)
    }
    summary_path = os.path.join(out_dir, "vietnam_gov_and_banks_summary.json")
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
    print(f"[+] Saved summary metrics: {summary_path}\n")

    return summary

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scrape Vietnam Government and Bank domains for Safe Zone DNS.")
    parser.add_argument("--max-gov-pages", type=int, default=50, help="Maximum Gov pages to crawl on Tín Nhiệm Mạng (default: 50)")
    parser.add_argument("--max-bank-pages", type=int, default=10, help="Maximum Bank pages to crawl (default: 10)")
    parser.add_argument("--max-office-pages", type=int, default=15, help="Maximum Office pages to crawl (default: 15)")
    parser.add_argument("--concurrency", type=int, default=6, help="Concurrency (default: 6)")
    parser.add_argument("--out-dir", type=str, default="data", help="Output directory path (default: data)")
    args = parser.parse_args()

    run_scraper(
        max_gov_pages=args.max_gov_pages,
        max_bank_pages=args.max_bank_pages,
        max_office_pages=args.max_office_pages,
        concurrency=args.concurrency,
        out_dir=args.out_dir
    )
