import pytest
import sys
import os

# Add ml root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.canonicalize import canonicalize_domain, CanonicalResult, PublicSuffixList, is_ip_address


def test_psl_loading():
    psl = PublicSuffixList()
    assert len(psl.exact_rules) > 0
    assert "com.vn" in psl.exact_rules
    assert "co.uk" in psl.exact_rules


def test_canonicalize_standard_domains():
    res = canonicalize_domain("google.com")
    assert res.is_valid
    assert res.domain_ascii == "google.com"
    assert res.domain_unicode == "google.com"
    assert res.suffix == "com"
    assert res.registrable_domain == "google.com"
    assert res.main_label == "google"
    assert res.subdomain_labels == []
    assert res.subdomain_depth == 0


def test_canonicalize_urls_and_www_stripping():
    res = canonicalize_domain("https://www.google.com/path?q=1#frag")
    assert res.is_valid
    assert res.domain_ascii == "google.com"

    res2 = canonicalize_domain("ebank.tpb.vn/retail/vX/")
    assert res2.is_valid
    assert res2.domain_ascii == "ebank.tpb.vn"
    assert res2.suffix == "vn"
    assert res2.registrable_domain == "tpb.vn"
    assert res2.main_label == "tpb"
    assert res2.subdomain_labels == ["ebank"]
    assert res2.subdomain_depth == 1


def test_canonicalize_cctld():
    res = canonicalize_domain("sub.google.com.vn")
    assert res.is_valid
    assert res.domain_ascii == "sub.google.com.vn"
    assert res.suffix == "com.vn"
    assert res.registrable_domain == "google.com.vn"
    assert res.main_label == "google"
    assert res.subdomain_labels == ["sub"]
    assert res.subdomain_depth == 1


def test_canonicalize_idn_punycode():
    res = canonicalize_domain("xn--g1act.xn--p1ai")
    assert res.is_valid
    assert res.domain_ascii == "xn--g1act.xn--p1ai"
    assert res.domain_unicode == "пзи.рф"

    res2 = canonicalize_domain("http://dịchvụcông.com")
    assert res2.is_valid
    assert res2.domain_ascii.startswith("xn--")
    assert "dịchvụcông.com" in res2.domain_unicode


def test_canonicalize_bare_ip():
    res = canonicalize_domain("192.168.1.1")
    assert not res.is_valid
    assert res.is_ip_like
    assert res.error == "bare_ip"

    res2 = canonicalize_domain("http://10.0.0.1:8080/index.html")
    assert not res2.is_valid
    assert res2.is_ip_like
    assert res2.error == "bare_ip"


def test_canonicalize_invalid_inputs():
    # Empty
    res1 = canonicalize_domain("")
    assert not res1.is_valid
    assert res1.error == "empty_input"

    # Malformed empty label
    res2 = canonicalize_domain("foo..bar.com")
    assert not res2.is_valid
    assert res2.error == "empty_label"

    # Label > 63 chars
    long_label = "a" * 64 + ".com"
    res3 = canonicalize_domain(long_label)
    assert not res3.is_valid
    assert res3.error == "label_length_exceeded"

    # Total length > 253 chars
    long_domain = "a" * 60 + "." + "b" * 60 + "." + "c" * 60 + "." + "d" * 60 + "." + "e" * 20 + ".com"
    res4 = canonicalize_domain(long_domain)
    assert not res4.is_valid
    assert res4.error == "fqdn_length_exceeded"

