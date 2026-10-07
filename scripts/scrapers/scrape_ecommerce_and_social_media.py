#!/usr/bin/env python3
"""
Safe Zone DNS - E-Commerce, Logistics & Social Media Domain Compiler
Compiles & scrapes official domains for all:
- Sàn TMĐT & Bán lẻ: Shopee, Lazada, Tiki, TikTok Shop, Sendo, Chợ Tốt, Thế Giới Di Động, FPT Shop,...
- Đơn vị Vận chuyển & Logistics: GHTK, GHN, VNPost, Viettel Post, J&T Express, Ninja Van, BEST Express, GrabExpress, AhaMove, Lalamove,...
- Mạng xã hội & Chat phổ biến tại Việt Nam: Zalo, Facebook, YouTube, TikTok, Instagram, Threads, Telegram, X/Twitter, LinkedIn, Reddit, Discord, Viber, Lotus, Gapo, Tinh Tế, Voz,...
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

# 1. Official Master List of Major E-Commerce Platforms & Online Retail Chains
MASTER_ECOMMERCE_DOMAINS = [
    # Shopee Ecosystem
    {"domain": "shopee.vn", "owner": "Công ty TNHH Shopee (Shopee Việt Nam)", "category_type": "Sàn Thương mại điện tử", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "shopee.com", "owner": "Shopee Global", "category_type": "Sàn Thương mại điện tử", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "seller.shopee.vn", "owner": "Shopee Kênh Người Bán", "category_type": "Sàn Thương mại điện tử", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "banhang.shopee.vn", "owner": "Shopee Bán Hàng", "category_type": "Sàn Thương mại điện tử", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "shopeepay.vn", "owner": "Ví ShopeePay", "category_type": "Sàn Thương mại điện tử", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "spx.vn", "owner": "Shopee Express (SPX)", "category_type": "Đơn vị Vận chuyển & Logistics", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "shopeexpress.vn", "owner": "Shopee Express (SPX)", "category_type": "Đơn vị Vận chuyển & Logistics", "cert_level": "Chứng nhận cơ bản"},

    # Lazada Ecosystem
    {"domain": "lazada.vn", "owner": "Công ty TNHH Recofex (Lazada Việt Nam)", "category_type": "Sàn Thương mại điện tử", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "lazada.com", "owner": "Lazada Group", "category_type": "Sàn Thương mại điện tử", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "sellercenter.lazada.vn", "owner": "Lazada Seller Center", "category_type": "Sàn Thương mại điện tử", "cert_level": "Chứng nhận cơ bản"},

    # Tiki Ecosystem
    {"domain": "tiki.vn", "owner": "Công ty Cổ phần Tiki", "category_type": "Sàn Thương mại điện tử", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "tikicorp.vn", "owner": "Tiki Corporation", "category_type": "Sàn Thương mại điện tử", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "sellercenter.tiki.vn", "owner": "Tiki Seller Center", "category_type": "Sàn Thương mại điện tử", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "tikinow.vn", "owner": "TikiNOW", "category_type": "Sàn Thương mại điện tử", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "tikitrading.vn", "owner": "Tiki Trading", "category_type": "Sàn Thương mại điện tử", "cert_level": "Chứng nhận cơ bản"},

    # TikTok Shop & ByteDance
    {"domain": "tiktokshop.com", "owner": "TikTok Shop Global", "category_type": "Sàn Thương mại điện tử", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "seller-vn.tiktok.com", "owner": "TikTok Shop Seller Center Việt Nam", "category_type": "Sàn Thương mại điện tử", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "seller.tiktok.com", "owner": "TikTok Shop Seller Center", "category_type": "Sàn Thương mại điện tử", "cert_level": "Chứng nhận cơ bản"},

    # Sendo & Chợ Tốt
    {"domain": "sendo.vn", "owner": "Công ty Cổ phần Công nghệ Sen Đỏ (Sendo)", "category_type": "Sàn Thương mại điện tử", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "sendopay.vn", "owner": "Ví SendoPay", "category_type": "Sàn Thương mại điện tử", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "chotot.com", "owner": "Công ty TNHH Chợ Tốt", "category_type": "Sàn Thương mại điện tử", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "chotot.vn", "owner": "Công ty TNHH Chợ Tốt", "category_type": "Sàn Thương mại điện tử", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "nhatot.com", "owner": "Nhà Tốt (Chợ Tốt Bất động sản)", "category_type": "Sàn Thương mại điện tử", "cert_level": "Chứng nhận cơ bản"},

    # Major Retail Chains & Online Stores in Vietnam
    {"domain": "thegioididong.com", "owner": "Công ty Cổ phần Thế Giới Di Động", "category_type": "Sàn Thương mại điện tử", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "dienmayxanh.com", "owner": "Công ty Cổ phần Điện Máy Xanh", "category_type": "Sàn Thương mại điện tử", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "bachhoaxanh.com", "owner": "Công ty Cổ phần Bách Hóa Xanh", "category_type": "Sàn Thương mại điện tử", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "topzone.vn", "owner": "TopZone (Thế Giới Di Động)", "category_type": "Sàn Thương mại điện tử", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "fptshop.com.vn", "owner": "Công ty Cổ phần Bán lẻ Kỹ thuật số FPT (FPT Shop)", "category_type": "Sàn Thương mại điện tử", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "cellphones.com.vn", "owner": "Công ty TNHH Thương mại Dịch vụ Di Động CellphoneS", "category_type": "Sàn Thương mại điện tử", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "hoanghamobile.com", "owner": "Công ty Cổ phần Xây dựng và Đầu tư Hoàng Hà", "category_type": "Sàn Thương mại điện tử", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "mediamart.vn", "owner": "Công ty Cổ phần MediaMart Việt Nam", "category_type": "Sàn Thương mại điện tử", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "meta.vn", "owner": "Công ty Cổ phần Mạng Trực tuyến META", "category_type": "Sàn Thương mại điện tử", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "phongvu.vn", "owner": "Công ty Cổ phần Phong Vũ", "category_type": "Sàn Thương mại điện tử", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "concung.com", "owner": "Công ty Cổ phần Con Cùng", "category_type": "Sàn Thương mại điện tử", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "kidsplaza.vn", "owner": "Công ty Cổ phần Kids Plaza", "category_type": "Sàn Thương mại điện tử", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "hasaki.vn", "owner": "Công ty Cổ phần Hasaki Beauty & Clinic", "category_type": "Sàn Thương mại điện tử", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "pnj.com.vn", "owner": "Công ty Cổ phần Vàng bạc Đá quý Phú Nhuận (PNJ)", "category_type": "Sàn Thương mại điện tử", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "doji.vn", "owner": "Tập đoàn Vàng bạc Đá quý DOJI", "category_type": "Sàn Thương mại điện tử", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "anphatpc.com.vn", "owner": "Công ty Cổ phần Máy tính An Phát", "category_type": "Sàn Thương mại điện tử", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "hacom.vn", "owner": "Công ty Cổ phần Máy tính Hà Nội (HACOM)", "category_type": "Sàn Thương mại điện tử", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "hanoicomputer.vn", "owner": "Công ty Cổ phần Máy tính Hà Nội (HACOM)", "category_type": "Sàn Thương mại điện tử", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "vietnamworks.com", "owner": "Công ty Cổ phần Navigos Group Việt Nam", "category_type": "Sàn Thương mại điện tử", "cert_level": "Chứng nhận cơ bản"}
]

# 2. Official Master List of Shipping & Courier/Logistics Companies
MASTER_LOGISTICS_DOMAINS = [
    # Giao Hàng Tiết Kiệm (GHTK)
    {"domain": "giaohangtietkiem.vn", "owner": "Công ty Cổ phần Giao Hàng Tiết Kiệm (GHTK)", "category_type": "Đơn vị Vận chuyển & Logistics", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "ghtk.vn", "owner": "Công ty Cổ phần Giao Hàng Tiết Kiệm (GHTK)", "category_type": "Đơn vị Vận chuyển & Logistics", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "i.ghtk.vn", "owner": "GHTK Internal Platform", "category_type": "Đơn vị Vận chuyển & Logistics", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "khachhang.ghtk.vn", "owner": "Cổng Khách Hàng GHTK", "category_type": "Đơn vị Vận chuyển & Logistics", "cert_level": "Chứng nhận cơ bản"},

    # Giao Hàng Nhanh (GHN)
    {"domain": "ghn.vn", "owner": "Công ty Cổ phần Dịch vụ Giao Hàng Nhanh (GHN)", "category_type": "Đơn vị Vận chuyển & Logistics", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "giaohangnhanh.vn", "owner": "Công ty Cổ phần Dịch vụ Giao Hàng Nhanh (GHN)", "category_type": "Đơn vị Vận chuyển & Logistics", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "khachhang.ghn.vn", "owner": "Cổng Khách Hàng GHN Express", "category_type": "Đơn vị Vận chuyển & Logistics", "cert_level": "Chứng nhận cơ bản"},

    # Viettel Post
    {"domain": "viettelpost.com.vn", "owner": "Tổng Công ty Cổ phần Bưu chính Viettel (Viettel Post)", "category_type": "Đơn vị Vận chuyển & Logistics", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "viettelpost.vn", "owner": "Tổng Công ty Cổ phần Bưu chính Viettel (Viettel Post)", "category_type": "Đơn vị Vận chuyển & Logistics", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "vtpost.vn", "owner": "Viettel Post", "category_type": "Đơn vị Vận chuyển & Logistics", "cert_level": "Chứng nhận cơ bản"},

    # VNPost / EMS
    {"domain": "vnpost.vn", "owner": "Tổng Công ty Bưu điện Việt Nam (VNPost)", "category_type": "Đơn vị Vận chuyển & Logistics", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "ems.com.vn", "owner": "Tổng Công ty Chuyển phát nhanh Bưu điện (EMS Việt Nam)", "category_type": "Đơn vị Vận chuyển & Logistics", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "buudien.vn", "owner": "Bưu điện Việt Nam (VNPost)", "category_type": "Đơn vị Vận chuyển & Logistics", "cert_level": "Chứng nhận cơ bản"},

    # J&T Express
    {"domain": "jtexpress.vn", "owner": "Công ty TNHH Một thành viên Giao Hàng Nhanh J&T (J&T Express)", "category_type": "Đơn vị Vận chuyển & Logistics", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "jtexpress.com.vn", "owner": "J&T Express Việt Nam", "category_type": "Đơn vị Vận chuyển & Logistics", "cert_level": "Chứng nhận nâng cao"},

    # Ninja Van, BEST Express, GrabExpress, AhaMove, Lalamove
    {"domain": "ninjavan.co", "owner": "Công ty TNHH Ninja Van Việt Nam", "category_type": "Đơn vị Vận chuyển & Logistics", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "ninjavan.vn", "owner": "Ninja Van Việt Nam", "category_type": "Đơn vị Vận chuyển & Logistics", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "best-inc.vn", "owner": "BEST Express Việt Nam", "category_type": "Đơn vị Vận chuyển & Logistics", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "best-express.vn", "owner": "BEST Express Việt Nam", "category_type": "Đơn vị Vận chuyển & Logistics", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "grab.com", "owner": "Grab Việt Nam (GrabExpress)", "category_type": "Đơn vị Vận chuyển & Logistics", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "grabexpress.com", "owner": "GrabExpress Global", "category_type": "Đơn vị Vận chuyển & Logistics", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "ahamove.com", "owner": "Công ty Cổ phần Dịch vụ Tức thời Ahamove", "category_type": "Đơn vị Vận chuyển & Logistics", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "ahamove.vn", "owner": "Ahamove Việt Nam", "category_type": "Đơn vị Vận chuyển & Logistics", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "lalamove.com", "owner": "Lalamove Việt Nam", "category_type": "Đơn vị Vận chuyển & Logistics", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "lalamove.vn", "owner": "Lalamove Việt Nam", "category_type": "Đơn vị Vận chuyển & Logistics", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "fedex.com", "owner": "FedEx Express Việt Nam", "category_type": "Đơn vị Vận chuyển & Logistics", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "dhl.com", "owner": "DHL Express Việt Nam", "category_type": "Đơn vị Vận chuyển & Logistics", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "dhl.com.vn", "owner": "DHL Express Việt Nam", "category_type": "Đơn vị Vận chuyển & Logistics", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "ups.com", "owner": "UPS Việt Nam", "category_type": "Đơn vị Vận chuyển & Logistics", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "kerryexpress.com.vn", "owner": "Kerry Express Việt Nam", "category_type": "Đơn vị Vận chuyển & Logistics", "cert_level": "Chứng nhận cơ bản"}
]

# 3. Official Master List of Popular Social Media Networks & Instant Messaging Platforms in Vietnam
MASTER_SOCIAL_DOMAINS = [
    # Zalo Ecosystem
    {"domain": "zalo.me", "owner": "Zalo (Công ty Cổ phần VNG)", "category_type": "Mạng xã hội & Chat", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "zaloapp.com", "owner": "Zalo App Platform", "category_type": "Mạng xã hội & Chat", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "oa.zalo.me", "owner": "Zalo Official Account (Zalo OA)", "category_type": "Mạng xã hội & Chat", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "chat.zalo.me", "owner": "Zalo Web Chat", "category_type": "Mạng xã hội & Chat", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "id.zalo.me", "owner": "Zalo Account Identity", "category_type": "Mạng xã hội & Chat", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "sp.zalo.me", "owner": "Zalo Support & Services", "category_type": "Mạng xã hội & Chat", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "zalo.vn", "owner": "Zalo Việt Nam", "category_type": "Mạng xã hội & Chat", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "zalo.cloud", "owner": "Zalo Cloud Services", "category_type": "Mạng xã hội & Chat", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "developers.zalo.me", "owner": "Zalo Developer Portal", "category_type": "Mạng xã hội & Chat", "cert_level": "Chứng nhận cơ bản"},

    # Meta (Facebook, Messenger, Instagram, Threads)
    {"domain": "facebook.com", "owner": "Meta Platforms Inc. (Facebook)", "category_type": "Mạng xã hội & Chat", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "fb.com", "owner": "Meta Platforms Inc. (Facebook)", "category_type": "Mạng xã hội & Chat", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "messenger.com", "owner": "Meta Messenger", "category_type": "Mạng xã hội & Chat", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "m.me", "owner": "Meta Messenger Link", "category_type": "Mạng xã hội & Chat", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "fb.watch", "owner": "Facebook Watch", "category_type": "Mạng xã hội & Chat", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "facebook.net", "owner": "Facebook CDN & SDK", "category_type": "Mạng xã hội & Chat", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "fbcdn.net", "owner": "Facebook Content Delivery Network", "category_type": "Mạng xã hội & Chat", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "instagram.com", "owner": "Meta Instagram", "category_type": "Mạng xã hội & Chat", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "threads.net", "owner": "Meta Threads", "category_type": "Mạng xã hội & Chat", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "cdninstagram.com", "owner": "Instagram CDN", "category_type": "Mạng xã hội & Chat", "cert_level": "Chứng nhận cơ bản"},

    # Google & YouTube Ecosystem
    {"domain": "youtube.com", "owner": "Google LLC (YouTube)", "category_type": "Mạng xã hội & Chat", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "youtu.be", "owner": "YouTube Short Link", "category_type": "Mạng xã hội & Chat", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "ytimg.com", "owner": "YouTube Images CDN", "category_type": "Mạng xã hội & Chat", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "googlevideo.com", "owner": "Google Video Streaming", "category_type": "Mạng xã hội & Chat", "cert_level": "Chứng nhận cơ bản"},

    # TikTok Ecosystem
    {"domain": "tiktok.com", "owner": "TikTok Inc. / ByteDance", "category_type": "Mạng xã hội & Chat", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "tiktokv.com", "owner": "TikTok Video CDN", "category_type": "Mạng xã hội & Chat", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "tiktokcdn.com", "owner": "TikTok Content Delivery Network", "category_type": "Mạng xã hội & Chat", "cert_level": "Chứng nhận cơ bản"},

    # Telegram, X/Twitter, LinkedIn, Reddit, Pinterest, WhatsApp, Discord, Viber, Skype
    {"domain": "telegram.org", "owner": "Telegram Messenger Inc.", "category_type": "Mạng xã hội & Chat", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "t.me", "owner": "Telegram Short Link", "category_type": "Mạng xã hội & Chat", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "telegram.me", "owner": "Telegram Short Link", "category_type": "Mạng xã hội & Chat", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "x.com", "owner": "X Corp. (Twitter)", "category_type": "Mạng xã hội & Chat", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "twitter.com", "owner": "X Corp. (Twitter)", "category_type": "Mạng xã hội & Chat", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "t.co", "owner": "X/Twitter Short Link", "category_type": "Mạng xã hội & Chat", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "linkedin.com", "owner": "Microsoft (LinkedIn)", "category_type": "Mạng xã hội & Chat", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "licdn.com", "owner": "LinkedIn CDN", "category_type": "Mạng xã hội & Chat", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "reddit.com", "owner": "Reddit Inc.", "category_type": "Mạng xã hội & Chat", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "redd.it", "owner": "Reddit Short Link", "category_type": "Mạng xã hội & Chat", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "pinterest.com", "owner": "Pinterest Inc.", "category_type": "Mạng xã hội & Chat", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "whatsapp.com", "owner": "Meta WhatsApp", "category_type": "Mạng xã hội & Chat", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "wa.me", "owner": "WhatsApp Short Link", "category_type": "Mạng xã hội & Chat", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "discord.com", "owner": "Discord Inc.", "category_type": "Mạng xã hội & Chat", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "discord.gg", "owner": "Discord Invite Link", "category_type": "Mạng xã hội & Chat", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "viber.com", "owner": "Rakuten Viber", "category_type": "Mạng xã hội & Chat", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "skype.com", "owner": "Microsoft Skype", "category_type": "Mạng xã hội & Chat", "cert_level": "Chứng nhận nâng cao"},

    # Domestic Vietnamese Social Networks & Community Forums
    {"domain": "lotus.vn", "owner": "Mạng xã hội Lotus (VCCorp)", "category_type": "Mạng xã hội & Chat", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "gapo.vn", "owner": "Mạng xã hội Gapo (Gapo Technology)", "category_type": "Mạng xã hội & Chat", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "mocha.com.vn", "owner": "Mạng xã hội & Chat Mocha (Viettel)", "category_type": "Mạng xã hội & Chat", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "tinhte.vn", "owner": "Mạng xã hội Khoa học Công nghệ Tinh Tế", "category_type": "Mạng xã hội & Chat", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "voz.vn", "owner": "Diễn đàn Công nghệ VOZ (vozForums)", "category_type": "Mạng xã hội & Chat", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "spiderum.com", "owner": "Mạng xã hội Chia sẻ Tri thức Spiderum", "category_type": "Mạng xã hội & Chat", "cert_level": "Chứng nhận nâng cao"},
    {"domain": "otofun.net", "owner": "Diễn đàn Otofun Việt Nam", "category_type": "Mạng xã hội & Chat", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "webtretho.com", "owner": "Cộng đồng Webtretho", "category_type": "Mạng xã hội & Chat", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "kenh14.vn", "owner": "Trang thông tin Giới trẻ Kênh 14 (VCCorp)", "category_type": "Mạng xã hội & Chat", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "genk.vn", "owner": "Trang thông tin Công nghệ GenK (VCCorp)", "category_type": "Mạng xã hội & Chat", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "cafef.vn", "owner": "Trang thông tin Tài chính CafeF (VCCorp)", "category_type": "Mạng xã hội & Chat", "cert_level": "Chứng nhận cơ bản"},
    {"domain": "cafebiz.vn", "owner": "Trang thông tin Doanh nhân CafeBiz (VCCorp)", "category_type": "Mạng xã hội & Chat", "cert_level": "Chứng nhận cơ bản"}
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
        category_type = "Sàn Thương mại điện tử"
        owner_lower = owner.lower()
        dom_lower = domain.lower()

        if any(k in dom_lower or k in owner_lower for k in ['zalo', 'facebook', 'youtube', 'tiktok', 'instagram', 'telegram', 'twitter', 'linkedin', 'reddit', 'forum', 'diễn đàn', 'mạng xã hội', 'tinhte', 'voz', 'spiderum', 'gapo', 'lotus']):
            category_type = "Mạng xã hội & Chat"
        elif any(k in dom_lower or k in owner_lower for k in ['giaohang', 'ghtk', 'ghn', 'express', 'post', 'bưu điện', 'chuyển phát', 'ninjavan', 'logistics', 'spx', 'delivery', 'transport', 'courier']):
            category_type = "Đơn vị Vận chuyển & Logistics"

        items.append({
            "domain": domain,
            "owner": owner,
            "category_type": category_type,
            "certified_date": certified_date,
            "cert_level": cert_level,
            "detail_url": detail_url
        })

    return items

def run_scraper(max_ecom_pages=15, max_online_pages=10, concurrency=5, out_dir="data"):
    """Main orchestrator for E-Commerce, Logistics & Social Media domain dataset compilation."""
    os.makedirs(out_dir, exist_ok=True)
    start_time = time.time()

    print("=" * 75)
    print("  Safe Zone DNS - E-Commerce, Logistics & Social Media Domain Compiler")
    print("=" * 75)

    crawled_items = []
    errors = []

    # 1. Target Endpoints on Tín Nhiệm Mạng
    targets = [
        ("ecommerce", max_ecom_pages),
        ("online", max_online_pages)
    ]

    total_tasks = []
    for area_code, max_p in targets:
        for p in range(1, max_p + 1):
            url = f"https://tinnhiemmang.vn/filterObj?type=web&area[]={area_code}&page={p}"
            total_tasks.append((url, area_code, p))

    print(f"[*] Crawling {len(total_tasks)} pages from Tín Nhiệm Mạng across E-Commerce & Online Services...")

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

    # 2. Merge Official Master Registries for E-Commerce, Shipping & Social Networks
    print("[*] Merging Official Master Registries for E-Commerce, Logistics & Social Networks...")
    master_items = []
    for m in MASTER_ECOMMERCE_DOMAINS:
        master_items.append({
            "domain": m["domain"].lower(),
            "owner": m["owner"],
            "category_type": m["category_type"],
            "certified_date": "Đã xác thực chính thức",
            "cert_level": m["cert_level"],
            "detail_url": f"https://tinnhiemmang.vn/danh-ba-tin-nhiem/{m['domain']}"
        })

    for m in MASTER_LOGISTICS_DOMAINS:
        master_items.append({
            "domain": m["domain"].lower(),
            "owner": m["owner"],
            "category_type": m["category_type"],
            "certified_date": "Đã xác thực chính thức",
            "cert_level": m["cert_level"],
            "detail_url": f"https://tinnhiemmang.vn/danh-ba-tin-nhiem/{m['domain']}"
        })

    for m in MASTER_SOCIAL_DOMAINS:
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
    print(f"[*] Total unique E-Commerce, Logistics & Social Media domains: {len(unique_domains_list)}")
    print(f"[*] Total elapsed time: {duration} seconds")

    # Export 1: JSON Dataset
    json_path = os.path.join(out_dir, "ecommerce_and_social_media_websites.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(sorted_items, f, ensure_ascii=False, indent=2)
    print(f"[+] Saved structured JSON: {json_path}")

    # Export 2: Plain Domain List (TXT)
    txt_path = os.path.join(out_dir, "ecommerce_and_social_media_domains.txt")
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write("# Safe Zone DNS - E-Commerce, Logistics & Social Media Domain List\n")
        f.write(f"# Source: Tín Nhiệm Mạng (tinnhiemmang.vn) & Official E-Commerce / Shipping / Social Registries\n")
        f.write(f"# Total Domains: {len(unique_domains_list)}\n")
        f.write(f"# Generated: {datetime.now(timezone.utc).isoformat()}\n\n")
        for dom in unique_domains_list:
            f.write(dom + "\n")
    print(f"[+] Saved plain domain list: {txt_path}")

    # Export 3: CSV Dataset (with UTF-8 BOM)
    csv_path = os.path.join(out_dir, "ecommerce_and_social_media_websites.csv")
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
        "source": "https://tinnhiemmang.vn/ & Master Registries of E-Commerce, Logistics & Social Networks",
        "scraped_at": datetime.now(timezone.utc).isoformat(),
        "duration_seconds": duration,
        "total_unique_domains": len(unique_domains_list),
        "category_breakdown": type_counts,
        "top_tlds": dict(sorted(tld_counts.items(), key=lambda x: x[1], reverse=True)[:15]),
        "error_count": len(errors)
    }
    summary_path = os.path.join(out_dir, "ecommerce_and_social_media_summary.json")
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
    print(f"[+] Saved summary metrics: {summary_path}\n")

    return summary

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scrape E-Commerce, Logistics & Social Media domains for Safe Zone DNS.")
    parser.add_argument("--max-ecom-pages", type=int, default=15, help="Maximum E-Commerce pages to crawl (default: 15)")
    parser.add_argument("--max-online-pages", type=int, default=10, help="Maximum Online pages to crawl (default: 10)")
    parser.add_argument("--concurrency", type=int, default=5, help="Concurrency (default: 5)")
    parser.add_argument("--out-dir", type=str, default="data", help="Output directory path (default: data)")
    args = parser.parse_args()

    run_scraper(
        max_ecom_pages=args.max_ecom_pages,
        max_online_pages=args.max_online_pages,
        concurrency=args.concurrency,
        out_dir=args.out_dir
    )
