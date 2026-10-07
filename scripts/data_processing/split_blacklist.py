#!/usr/bin/env python3
"""
Vietnam Malicious Blacklist Domain Cleaning, Deduplication & 4-Part File Splitter.

This script processes raw scraped domain records from:
- data/blacklist/vietnam/raw_scraped_domains.json (or raw_scraped_domains.txt)

Processing Steps:
1. Load raw domain data from JSON or TXT file.
2. Clean and format domain strings:
   - Strip leading and trailing whitespace.
   - Convert to lowercase.
   - Strip URL schemes (http://, https://, etc.).
   - Strip inline note parentheticals e.g. (TikTok).
   - Strip paths, query strings, fragments, and port numbers.
   - Strip www. prefix and trailing dots.
   - Remove empty or invalid entries.
3. Deduplicate domain list to extract unique clean domains.
4. Sort domain list deterministically.
5. Split total unique domains evenly into EXACTLY 4 part text files:
   - part1.txt
   - part2.txt
   - part3.txt
   - part4.txt
6. Perform self-verification of file existence, line counts, total sum, and cross-file uniqueness.
"""

import argparse
import json
import os
import re
import sys
from typing import List, Set, Tuple
from urllib.parse import urlparse

# Default file paths relative to script location
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(SCRIPT_DIR)
DEFAULT_INPUT_JSON = os.path.join(BASE_DIR, "data", "blacklist", "vietnam", "raw_scraped_domains.json")
DEFAULT_INPUT_TXT = os.path.join(BASE_DIR, "data", "blacklist", "vietnam", "raw_scraped_domains.txt")
DEFAULT_OUTPUT_DIR = os.path.join(BASE_DIR, "data", "blacklist", "vietnam")


DOMAIN_REGEX = re.compile(r'^[a-z0-9]+([\-\.][a-z0-9]+)*\.[a-z]{2,}$')


def _finalize_clean(domain_str: str) -> str:
    """Strip wildcards (*.), www prefix, leading/trailing dots and hyphens."""
    if not domain_str:
        return ""
    s = domain_str.strip().lower()
    while True:
        prev = s
        s = re.sub(r'^[\*\.]+', '', s)
        if s.startswith('www.'):
            s = s[4:]
        s = s.lstrip('. -').rstrip('. -')
        if s == prev:
            break
    return s


def clean_domain(raw_url_or_domain: str) -> str:
    """Clean and standardize raw domain/URL string."""
    if not raw_url_or_domain:
        return ""
    
    s = raw_url_or_domain.strip().lower()
    if not s:
        return ""
    
    # Remove text in parentheses (e.g. "tkbe.shop (TikTok)" -> "tkbe.shop")
    s = re.sub(r'\s*\(.*?\)', '', s)
    
    # Remove schemes (http://, https://, http:/, etc.)
    s = re.sub(r'^[a-z0-9+-.]+:/+', '', s)
    
    # Strip leading wildcards (*. or *)
    s = re.sub(r'^[\*\.]+', '', s)
    
    # Try parsing host using urllib.parse urlparse
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9+-.]*://', s):
        url_str = 'http://' + s
    else:
        url_str = s

    try:
        parsed = urlparse(url_str)
        host = parsed.hostname
        if host:
            return _finalize_clean(host)
    except Exception:
        pass

    # Fallback string stripping
    clean = re.sub(r'^(?:https?://)?(?:www\.)?', '', s, flags=re.IGNORECASE)
    clean = clean.split('/')[0].split('?')[0].split('#')[0].split(':')[0].strip()
    clean = clean.replace(' ', '')
    return _finalize_clean(clean)


def is_valid_domain(domain: str) -> bool:
    """Validate if domain string meets strict RFC 1035 domain regex."""
    if not domain or len(domain) < 1 or len(domain) > 253:
        return False
    return bool(DOMAIN_REGEX.match(domain))


def load_raw_domains(input_path: str) -> List[str]:
    """Load raw domain strings from JSON or TXT file."""
    if not os.path.exists(input_path):
        raise FileNotFoundError(f"Input file not found: {input_path}")
    
    raw_list = []
    if input_path.endswith('.json'):
        with open(input_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        # Use clean_domain if present, otherwise fallback to raw_domain
                        domain_val = item.get('clean_domain') or item.get('raw_domain') or ''
                        if domain_val:
                            raw_list.append(str(domain_val))
                    elif isinstance(item, str):
                        raw_list.append(item)
    else:
        with open(input_path, 'r', encoding='utf-8') as f:
            for line in f:
                line_str = line.strip()
                if line_str:
                    raw_list.append(line_str)
                    
    return raw_list


def deduplicate_and_clean(raw_domains: List[str]) -> List[str]:
    """Deduplicate raw domain list and return sorted list of unique clean domains."""
    unique_domains: Set[str] = set()
    for item in raw_domains:
        cleaned = clean_domain(item)
        if is_valid_domain(cleaned):
            unique_domains.add(cleaned)
            
    return sorted(unique_domains)


def split_list_evenly(items: List[str], num_parts: int = 4) -> List[List[str]]:
    """Split a list evenly into num_parts sublists."""
    n = len(items)
    base_size, remainder = divmod(n, num_parts)
    parts = []
    start = 0
    for i in range(num_parts):
        # Distribute remainder across the first 'remainder' parts
        size = base_size + (1 if i < remainder else 0)
        end = start + size
        parts.append(items[start:end])
        start = end
    return parts


def verify_generated_files(output_dir: str, expected_total_unique: int) -> bool:
    """Verify generated part files for existence, line counts, sum match, and zero duplicates."""
    part_files = [os.path.join(output_dir, f"part{i}.txt") for i in range(1, 5)]
    
    print("\n" + "=" * 60)
    print("VERIFICATION & INTEGRITY CHECK FOR 4-PART FILE SPLIT")
    print("=" * 60)
    
    # 1. Existence check
    all_exist = True
    line_counts = []
    domains_per_file = []
    
    for idx, filepath in enumerate(part_files, 1):
        exists = os.path.exists(filepath)
        if not exists:
            print(f"FAILED: File part{idx}.txt does not exist at {filepath}")
            all_exist = False
            continue
        
        with open(filepath, 'r', encoding='utf-8') as f:
            lines = [line.strip() for line in f if line.strip()]
        
        line_counts.append(len(lines))
        domains_per_file.append(set(lines))
        print(f"part{idx}.txt : Exists | Line Count = {len(lines):,}")

    if not all_exist:
        print("VERIFICATION RESULT: FAILED (Missing files)")
        return False
        
    # 2. Line sum check
    total_lines = sum(line_counts)
    sum_matches = (total_lines == expected_total_unique)
    print(f"Total Lines Across 4 Files: {total_lines:,} | Expected: {expected_total_unique:,} | Match: {sum_matches}")
    
    # 3. Cross-file duplicate check and DOMAIN_REGEX / wildcard verification
    all_combined_domains: Set[str] = set()
    cross_duplicates = 0
    invalid_regex_count = 0
    wildcard_count = 0
    
    for idx, domain_set in enumerate(domains_per_file, 1):
        for domain in domain_set:
            if domain in all_combined_domains:
                cross_duplicates += 1
            else:
                all_combined_domains.add(domain)
            if domain.startswith('*.'):
                wildcard_count += 1
            if not DOMAIN_REGEX.match(domain):
                invalid_regex_count += 1
                
    no_duplicates = (cross_duplicates == 0 and len(all_combined_domains) == expected_total_unique)
    all_valid_regex = (invalid_regex_count == 0)
    zero_wildcards = (wildcard_count == 0)
    
    print(f"Cross-File Duplicates Count : {cross_duplicates} | Zero Duplicates: {no_duplicates}")
    print(f"RFC 1035 Regex Conformance  : {len(all_combined_domains) - invalid_regex_count}/{len(all_combined_domains)} (100% Pass: {all_valid_regex})")
    print(f"Wildcards Count (*.)        : {wildcard_count} (Zero Wildcards: {zero_wildcards})")
    print("=" * 60)
    
    overall_success = all_exist and sum_matches and no_duplicates and all_valid_regex and zero_wildcards
    if overall_success:
        print("VERIFICATION RESULT: PASSED (100% Verified Genuine Split)")
    else:
        print("VERIFICATION RESULT: FAILED")
        
    return overall_success


def main():
    parser = argparse.ArgumentParser(description="Clean, deduplicate, and split domain blacklist into 4 equal files.")
    parser.add_argument("--input", type=str, default=None, help="Input JSON or TXT file path.")
    parser.add_argument("--output-dir", type=str, default=DEFAULT_OUTPUT_DIR, help="Output directory for part files.")
    args = parser.parse_args()

    # Determine input path
    input_path = args.input
    if not input_path:
        if os.path.exists(DEFAULT_INPUT_JSON):
            input_path = DEFAULT_INPUT_JSON
        elif os.path.exists(DEFAULT_INPUT_TXT):
            input_path = DEFAULT_INPUT_TXT
        else:
            print(f"Error: Neither {DEFAULT_INPUT_JSON} nor {DEFAULT_INPUT_TXT} exists.", file=sys.stderr)
            sys.exit(1)

    output_dir = os.path.abspath(args.output_dir)
    os.makedirs(output_dir, exist_ok=True)

    print(f"Loading raw domain data from: {input_path}")
    raw_domains = load_raw_domains(input_path)
    print(f"Total raw items loaded: {len(raw_domains):,}")

    print("Cleaning, validating, and deduplicating domain list...")
    unique_domains = deduplicate_and_clean(raw_domains)
    total_unique = len(unique_domains)
    print(f"Total unique clean domains extracted: {total_unique:,}")

    print("Splitting unique domain list evenly into 4 parts...")
    parts = split_list_evenly(unique_domains, num_parts=4)

    # Write parts to part1.txt, part2.txt, part3.txt, part4.txt
    for i, part in enumerate(parts, 1):
        filename = f"part{i}.txt"
        file_path = os.path.join(output_dir, filename)
        print(f"Writing {len(part):,} domains to {file_path}...")
        with open(file_path, 'w', encoding='utf-8') as f:
            for domain in part:
                f.write(domain + '\n')

    # Verify output integrity
    success = verify_generated_files(output_dir, total_unique)
    if not success:
        sys.exit(1)


if __name__ == "__main__":
    main()
