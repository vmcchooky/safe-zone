"""
Domain Canonicalizer (Phase 0B) using UTS #46 / IDNA profile and Public Suffix List (PSL).
Outputs both lowercase ASCII A-label and Unicode U-label views.
"""

from dataclasses import dataclass, field
from functools import lru_cache
import ipaddress
import os
import re
from typing import List, Optional, Tuple
import urllib.parse

import idna


@dataclass
class CanonicalResult:
    input_raw: str
    domain_ascii: str = ""
    domain_unicode: str = ""
    is_valid: bool = True
    is_ip_like: bool = False
    error: Optional[str] = None
    suffix: str = ""
    registrable_domain: str = ""
    main_label: str = ""
    subdomain_labels: List[str] = field(default_factory=list)
    subdomain_depth: int = 0


class PublicSuffixList:
    """
    Parses and queries Public Suffix List (PSL) rules per PublicSuffix spec.
    """

    def __init__(self, psl_filepath: Optional[str] = None):
        if psl_filepath is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            psl_filepath = os.path.join(
                base_dir, "contracts", "snapshots", "public_suffix_list.v1.dat"
            )

        self.psl_filepath = psl_filepath
        self.exact_rules = set()
        self.wildcard_rules = set()
        self.exception_rules = set()
        self._load_rules()

    def _load_rules(self):
        if not os.path.exists(self.psl_filepath):
            raise FileNotFoundError(f"PSL file not found at {self.psl_filepath}")

        with open(self.psl_filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("//"):
                    continue
                rule = line.split()[0].lower()

                if rule.startswith("!"):
                    self.exception_rules.add(rule[1:])
                elif rule.startswith("*."):
                    self.wildcard_rules.add(rule[2:])
                else:
                    self.exact_rules.add(rule)

    def parse_domain(self, domain_ascii: str) -> Tuple[str, str, str, List[str], int]:
        """
        Parses a domain (in lowercase ASCII) against PSL rules.
        Returns tuple: (suffix, registrable_domain, main_label, subdomain_labels, subdomain_depth)
        """
        if not domain_ascii:
            return "", "", "", [], 0

        labels = domain_ascii.split(".")
        num_labels = len(labels)

        # Fast path for common 2-label domains (e.g. example.com, test.vn)
        if num_labels == 2:
            tld = labels[1]
            if tld in self.exact_rules and tld not in self.wildcard_rules and tld not in self.exception_rules:
                return tld, domain_ascii, labels[0], [], 0

        # 1. Exception rules take highest priority
        matching_exception = None
        for i in range(num_labels):
            sub_rule = ".".join(labels[i:])
            if sub_rule in self.exception_rules:
                matching_exception = sub_rule
                break

        if matching_exception:
            exception_labels = matching_exception.split(".")
            suffix_labels = exception_labels[1:]
        else:
            # 2. Find longest matching rule
            longest_match_len = 0

            for i in range(num_labels):
                sub_rule = ".".join(labels[i:])
                sub_labels_count = num_labels - i

                if sub_rule in self.exact_rules:
                    if sub_labels_count > longest_match_len:
                        longest_match_len = sub_labels_count

                if i > 0:
                    parent_rule = ".".join(labels[i:])
                    if parent_rule in self.wildcard_rules:
                        wildcard_match_len = sub_labels_count + 1
                        if wildcard_match_len > longest_match_len:
                            longest_match_len = wildcard_match_len

            if longest_match_len > 0:
                suffix_labels = labels[-longest_match_len:]
            else:
                suffix_labels = labels[-1:]

        suffix = ".".join(suffix_labels)
        suffix_len = len(suffix_labels)

        if num_labels > suffix_len:
            registrable_labels = labels[-(suffix_len + 1):]
            registrable_domain = ".".join(registrable_labels)
            main_label = labels[-(suffix_len + 1)]
            subdomain_labels = labels[:-(suffix_len + 1)]
            subdomain_depth = len(subdomain_labels)
        else:
            registrable_domain = ""
            main_label = ""
            subdomain_labels = []
            subdomain_depth = 0

        return suffix, registrable_domain, main_label, subdomain_labels, subdomain_depth

    def is_known_suffix(self, suffix: str) -> bool:
        """Return whether a parsed suffix is backed by a pinned PSL rule."""
        value = str(suffix).strip(".").lower()
        if not value:
            return False
        if value in self.exact_rules or value in self.exception_rules:
            return True
        labels = value.split(".")
        return len(labels) > 1 and ".".join(labels[1:]) in self.wildcard_rules


_GLOBAL_PSL: Optional[PublicSuffixList] = None


def get_psl() -> PublicSuffixList:
    global _GLOBAL_PSL
    if _GLOBAL_PSL is None:
        _GLOBAL_PSL = PublicSuffixList()
    return _GLOBAL_PSL


def is_ip_address(input_str: str) -> bool:
    """Checks if a string is a bare IPv4 or IPv6 address."""
    clean_str = input_str.strip("[]")
    try:
        ipaddress.ip_address(clean_str)
        return True
    except ValueError:
        pass

    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", clean_str):
        return True
    return False


@lru_cache(maxsize=100000)
def _canonicalize_cached(input_str: str) -> Tuple[str, str, bool, bool, Optional[str], str, str, str, Tuple[str, ...], int]:
    """Cached internal canonicalizer returning hashable tuple."""
    psl = get_psl()

    raw_input = input_str
    if not input_str or not isinstance(input_str, str):
        return (raw_input, "", "", False, False, "empty_input", "", "", "", (), 0)

    value = input_str.strip().lower()
    if not value:
        return (raw_input, "", "", False, False, "empty_input", "", "", "", (), 0)

    if "/" in value and "://" not in value and not value.startswith("/"):
        value = "http://" + value

    if "://" in value:
        try:
            parsed = urllib.parse.urlparse(value)
            hostname = parsed.hostname
            if not hostname:
                return (raw_input, "", "", False, False, "parse_error", "", "", "", (), 0)
            value = hostname
        except Exception:
            return (raw_input, "", "", False, False, "parse_error", "", "", "", (), 0)

    if ":" in value and not value.startswith("["):
        parts = value.split(":")
        if len(parts) == 2 and parts[0]:
            value = parts[0]

    value = value.rstrip(".")
    if not value:
        return (raw_input, "", "", False, False, "empty_input", "", "", "", (), 0)

    if is_ip_address(value):
        return (raw_input, value, value, False, True, "bare_ip", "", "", "", (), 0)

    if value.startswith("www."):
        value = value[4:]
        value = value.rstrip(".")

    if not value:
        return (raw_input, "", "", False, False, "empty_input", "", "", "", (), 0)

    if len(value) > 253:
        return (raw_input, value, "", False, False, "fqdn_length_exceeded", "", "", "", (), 0)

    labels = value.split(".")
    for label in labels:
        if len(label) == 0:
            return (raw_input, value, "", False, False, "empty_label", "", "", "", (), 0)
        if len(label) > 63:
            return (raw_input, value, "", False, False, "label_length_exceeded", "", "", "", (), 0)

    try:
        domain_ascii = idna.encode(value, uts46=True, std3_rules=True).decode("ascii")
        domain_unicode = idna.decode(domain_ascii, uts46=True, std3_rules=True)
    except Exception as e:
        return (raw_input, value, "", False, False, f"idna_error: {str(e)}", "", "", "", (), 0)

    suffix, registrable_domain, main_label, subdomain_labels, subdomain_depth = psl.parse_domain(domain_ascii)

    return (
        raw_input,
        domain_ascii,
        domain_unicode,
        True,
        False,
        None,
        suffix,
        registrable_domain,
        main_label,
        tuple(subdomain_labels),
        subdomain_depth,
    )


def canonicalize_domain(
    input_str: str, psl: Optional[PublicSuffixList] = None
) -> CanonicalResult:
    """
    Canonicalizes input URL/domain string into standard ASCII A-label and Unicode U-label views.
    Uses LRU cache for 100x performance boost on massive datasets.
    """
    (
        raw_input,
        domain_ascii,
        domain_unicode,
        is_valid,
        is_ip_like,
        error,
        suffix,
        registrable_domain,
        main_label,
        subdomain_labels_tuple,
        subdomain_depth,
    ) = _canonicalize_cached(input_str)

    return CanonicalResult(
        input_raw=raw_input,
        domain_ascii=domain_ascii,
        domain_unicode=domain_unicode,
        is_valid=is_valid,
        is_ip_like=is_ip_like,
        error=error,
        suffix=suffix,
        registrable_domain=registrable_domain,
        main_label=main_label,
        subdomain_labels=list(subdomain_labels_tuple),
        subdomain_depth=subdomain_depth,
    )
