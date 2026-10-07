#!/usr/bin/env python3
"""
Merge vietnam_massive_* datasets into whitelist/vietnam/
with backup, conflict detection, deduplication, and verification.

Steps:
1. Backup both datasets
2. Load both JSON datasets
3. Normalize and deduplicate domains
4. Detect and report conflicts
5. Merge with field-level conflict resolution
6. Write 4-file output bundle (JSON, CSV, TXT, Summary JSON)
7. Verify merge integrity
"""

import json
import csv
import os
import shutil
import sys
from datetime import datetime
from collections import OrderedDict

# Paths
DATA_DIR = os.path.dirname(os.path.abspath(__file__))
WHITELIST_DIR = os.path.join(DATA_DIR, "whitelist", "vietnam")
BACKUP_WHITELIST_DIR = os.path.join(DATA_DIR, "whitelist", "vietnam_backup_20260728")
BACKUP_MASSIVE_DIR = os.path.join(DATA_DIR, "archive", "vietnam_massive_backup_20260728")

# Source files
MASSIVE_JSON = os.path.join(DATA_DIR, "vietnam_massive_websites.json")
MASSIVE_CSV = os.path.join(DATA_DIR, "vietnam_massive_websites.csv")
MASSIVE_DOMAINS = os.path.join(DATA_DIR, "vietnam_massive_domains.txt")
MASSIVE_SUMMARY = os.path.join(DATA_DIR, "vietnam_massive_summary.json")

# Target files
WHITELIST_JSON = os.path.join(WHITELIST_DIR, "vietnam_websites.json")
WHITELIST_CSV = os.path.join(WHITELIST_DIR, "vietnam_websites.csv")
WHITELIST_DOMAINS = os.path.join(WHITELIST_DIR, "vietnam_domains.txt")
WHITELIST_SUMMARY = os.path.join(WHITELIST_DIR, "vietnam_summary.json")

# Report files
CONFLICT_REPORT = os.path.join(DATA_DIR, "conflict_report.json")
MERGE_LOG = os.path.join(DATA_DIR, "merge_massive_log.txt")


def log(msg, log_lines):
    """Print and record log message."""
    print(msg)
    log_lines.append(msg)


def backup_files(log_lines):
    """Create backups of both datasets."""
    log("\n" + "=" * 70, log_lines)
    log("STEP 1: BACKUP", log_lines)
    log("=" * 70, log_lines)

    # Backup whitelist
    if os.path.exists(BACKUP_WHITELIST_DIR):
        log(f"  [SKIP] Whitelist backup already exists: {BACKUP_WHITELIST_DIR}", log_lines)
    else:
        os.makedirs(BACKUP_WHITELIST_DIR, exist_ok=True)
        for fname in os.listdir(WHITELIST_DIR):
            src = os.path.join(WHITELIST_DIR, fname)
            dst = os.path.join(BACKUP_WHITELIST_DIR, fname)
            if os.path.isfile(src):
                shutil.copy2(src, dst)
                log(f"  [OK] Backed up: {fname} -> vietnam_backup_20260728/", log_lines)
        log(f"  Whitelist backup complete: {BACKUP_WHITELIST_DIR}", log_lines)

    # Backup massive
    if os.path.exists(BACKUP_MASSIVE_DIR):
        log(f"  [SKIP] Massive backup already exists: {BACKUP_MASSIVE_DIR}", log_lines)
    else:
        os.makedirs(BACKUP_MASSIVE_DIR, exist_ok=True)
        massive_files = [
            ("vietnam_massive_websites.json", MASSIVE_JSON),
            ("vietnam_massive_websites.csv", MASSIVE_CSV),
            ("vietnam_massive_domains.txt", MASSIVE_DOMAINS),
            ("vietnam_massive_summary.json", MASSIVE_SUMMARY),
        ]
        for fname, src in massive_files:
            if os.path.exists(src):
                dst = os.path.join(BACKUP_MASSIVE_DIR, fname)
                shutil.copy2(src, dst)
                log(f"  [OK] Backed up: {fname} -> archive/vietnam_massive_backup_20260728/", log_lines)
            else:
                log(f"  [WARN] File not found: {src}", log_lines)
        log(f"  Massive backup complete: {BACKUP_MASSIVE_DIR}", log_lines)

    # Verify backups
    log("\n  Verifying backups...", log_lines)
    backup_ok = True

    for fname in ["vietnam_websites.json", "vietnam_websites.csv", "vietnam_domains.txt", "vietnam_summary.json"]:
        src = os.path.join(WHITELIST_DIR, fname)
        dst = os.path.join(BACKUP_WHITELIST_DIR, fname)
        if os.path.exists(src) and os.path.exists(dst):
            src_size = os.path.getsize(src)
            dst_size = os.path.getsize(dst)
            if src_size == dst_size:
                log(f"  [VERIFIED] {fname}: {src_size:,} bytes", log_lines)
            else:
                log(f"  [ERROR] Size mismatch for {fname}: src={src_size}, dst={dst_size}", log_lines)
                backup_ok = False
        elif os.path.exists(src):
            log(f"  [ERROR] Backup missing for {fname}", log_lines)
            backup_ok = False

    for fname in ["vietnam_massive_websites.json", "vietnam_massive_websites.csv",
                   "vietnam_massive_domains.txt", "vietnam_massive_summary.json"]:
        src = os.path.join(DATA_DIR, fname)
        dst = os.path.join(BACKUP_MASSIVE_DIR, fname)
        if os.path.exists(src) and os.path.exists(dst):
            src_size = os.path.getsize(src)
            dst_size = os.path.getsize(dst)
            if src_size == dst_size:
                log(f"  [VERIFIED] {fname}: {src_size:,} bytes", log_lines)
            else:
                log(f"  [ERROR] Size mismatch for {fname}: src={src_size}, dst={dst_size}", log_lines)
                backup_ok = False
        elif os.path.exists(src):
            log(f"  [ERROR] Backup missing for {fname}", log_lines)
            backup_ok = False

    if not backup_ok:
        log("  [FATAL] Backup verification failed! Aborting.", log_lines)
        sys.exit(1)

    log("  [OK] All backups verified successfully.", log_lines)
    return True


def load_json(filepath, log_lines):
    """Load a JSON file and return the data."""
    log(f"  Loading {os.path.basename(filepath)}...", log_lines)
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)
    log(f"  Loaded {len(data):,} records from {os.path.basename(filepath)}", log_lines)
    return data


def normalize_domain(domain):
    """Normalize a domain string."""
    if not domain:
        return ""
    return domain.strip().lower()


def merge_field_value(existing_val, new_val):
    """
    Merge two field values following project conventions:
    - New non-empty replaces empty existing
    - If both differ and neither is substring: join with ' | '
    - If one is substring: keep longer
    - If identical: keep as-is
    
    Returns: (merged_value, conflict_type)
      conflict_type: None (no conflict), "filled_empty", "kept_longer", "concatenated", "identical"
    """
    existing_str = str(existing_val).strip() if existing_val else ""
    new_str = str(new_val).strip() if new_val else ""

    # Both empty
    if not existing_str and not new_str:
        return "", None

    # Only one has value
    if not existing_str and new_str:
        return new_str, "filled_empty"
    if existing_str and not new_str:
        return existing_str, None  # Keep existing, no action needed

    # Both have values
    if existing_str == new_str:
        return existing_str, None  # Identical, no conflict

    # Check substring relationship
    if existing_str in new_str:
        return new_str, "kept_longer"
    if new_str in existing_str:
        return existing_str, "kept_longer"

    # Check if already concatenated (prevent double concatenation)
    if new_str in existing_str.split(" | "):
        return existing_str, None
    if existing_str in new_str.split(" | "):
        return new_str, "kept_longer"

    # Truly different values - concatenate
    return f"{existing_str} | {new_str}", "concatenated"


def merge_datasets(whitelist_data, massive_data, log_lines):
    """
    Merge massive dataset into whitelist dataset.
    Returns: (merged_dict, conflicts, stats)
    """
    log("\n" + "=" * 70, log_lines)
    log("STEP 2: MERGE DATASETS", log_lines)
    log("=" * 70, log_lines)

    merged = OrderedDict()
    conflicts = []
    stats = {
        "whitelist_only": 0,
        "massive_only": 0,
        "overlapping": 0,
        "fields_filled": 0,
        "fields_concatenated": 0,
        "fields_kept_longer": 0,
        "duplicates_removed": 0,
    }

    # Track all unique field keys
    all_keys = set()

    # Phase 1: Load whitelist records first (priority)
    log("\n  Phase 1: Loading whitelist records (priority)...", log_lines)
    whitelist_domains_seen = set()
    whitelist_dup_count = 0
    for item in whitelist_data:
        domain = normalize_domain(item.get("domain", ""))
        if not domain:
            continue
        all_keys.update(item.keys())
        if domain in whitelist_domains_seen:
            whitelist_dup_count += 1
            # Still merge fields from duplicate
            existing = merged[domain]
            for k, v in item.items():
                if k == "domain":
                    continue
                merged_val, conflict_type = merge_field_value(existing.get(k, ""), v)
                if merged_val:
                    existing[k] = merged_val
        else:
            whitelist_domains_seen.add(domain)
            merged[domain] = dict(item)
            merged[domain]["domain"] = domain  # Normalized

    log(f"  Whitelist: {len(whitelist_domains_seen):,} unique domains loaded", log_lines)
    if whitelist_dup_count:
        log(f"  Whitelist internal duplicates found and merged: {whitelist_dup_count}", log_lines)
        stats["duplicates_removed"] += whitelist_dup_count

    # Phase 2: Merge massive records
    log("\n  Phase 2: Merging massive records...", log_lines)
    massive_domains_seen = set()
    massive_dup_count = 0
    for item in massive_data:
        domain = normalize_domain(item.get("domain", ""))
        if not domain:
            continue
        all_keys.update(item.keys())

        if domain in massive_domains_seen:
            massive_dup_count += 1
            # If also in merged, still try to fill fields
            if domain in merged:
                existing = merged[domain]
                for k, v in item.items():
                    if k == "domain":
                        continue
                    merged_val, _ = merge_field_value(existing.get(k, ""), v)
                    if merged_val:
                        existing[k] = merged_val
            continue

        massive_domains_seen.add(domain)

        if domain in merged:
            # Overlapping domain - merge fields with conflict detection
            stats["overlapping"] += 1
            existing = merged[domain]
            domain_conflicts = []

            for k, v in item.items():
                if k == "domain":
                    continue
                old_val = existing.get(k, "")
                merged_val, conflict_type = merge_field_value(old_val, v)

                if conflict_type == "filled_empty":
                    stats["fields_filled"] += 1
                    existing[k] = merged_val
                elif conflict_type == "kept_longer":
                    stats["fields_kept_longer"] += 1
                    existing[k] = merged_val
                elif conflict_type == "concatenated":
                    stats["fields_concatenated"] += 1
                    existing[k] = merged_val
                    domain_conflicts.append({
                        "field": k,
                        "whitelist_value": str(old_val),
                        "massive_value": str(v).strip() if v else "",
                        "merged_value": merged_val,
                        "resolution": "concatenated with ' | '"
                    })
                elif merged_val and not existing.get(k):
                    existing[k] = merged_val

            if domain_conflicts:
                conflicts.append({
                    "domain": domain,
                    "conflicts": domain_conflicts
                })
        else:
            # New domain from massive only
            stats["massive_only"] += 1
            merged[domain] = dict(item)
            merged[domain]["domain"] = domain  # Normalized

    if massive_dup_count:
        log(f"  Massive internal duplicates found and merged: {massive_dup_count}", log_lines)
        stats["duplicates_removed"] += massive_dup_count

    stats["whitelist_only"] = len(whitelist_domains_seen) - stats["overlapping"]

    log(f"\n  Massive: {len(massive_domains_seen):,} unique domains processed", log_lines)
    log(f"  Overlapping domains: {stats['overlapping']:,}", log_lines)
    log(f"  Whitelist-only domains: {stats['whitelist_only']:,}", log_lines)
    log(f"  Massive-only domains (new): {stats['massive_only']:,}", log_lines)
    log(f"  Total merged domains: {len(merged):,}", log_lines)
    log(f"  Total duplicates removed: {stats['duplicates_removed']:,}", log_lines)
    log(f"  Fields filled (empty -> value): {stats['fields_filled']:,}", log_lines)
    log(f"  Fields kept longer substring: {stats['fields_kept_longer']:,}", log_lines)
    log(f"  Fields concatenated (conflicts): {stats['fields_concatenated']:,}", log_lines)
    log(f"  Domains with conflicts: {len(conflicts):,}", log_lines)

    return merged, conflicts, stats, all_keys


def categorize_domain(domain):
    """Categorize a domain by its TLD (same logic as merge_final_whitelist.py)."""
    d = domain.lower()
    if d.endswith(".gov.vn"):
        return "Cơ quan nhà nước"
    elif d.endswith(".edu.vn"):
        return "Giáo dục"
    elif d.endswith(".org.vn"):
        return "Tổ chức phi lợi nhuận"
    elif d.endswith(".net.vn") or d.endswith(".info.vn") or d.endswith(".pro.vn"):
        return "Hạ tầng mạng"
    elif d.endswith(".com.vn") or d.endswith(".biz.vn"):
        return "Doanh nghiệp VN"
    elif d.endswith(".vn"):
        return "Tên miền .vn"
    else:
        return "Doanh nghiệp VN (TLD quốc tế)"


def write_output(merged, conflicts, stats, all_keys, whitelist_sources, massive_sources, log_lines):
    """Write merged data to all 4 output files."""
    log("\n" + "=" * 70, log_lines)
    log("STEP 3: WRITE OUTPUT FILES", log_lines)
    log("=" * 70, log_lines)

    merged_list = list(merged.values())
    total_domains = len(merged_list)

    # Compute category stats
    categories = {}
    for item in merged_list:
        cat = item.get("category_type", "")
        if not cat:
            cat = categorize_domain(item.get("domain", ""))
        if cat:
            categories[cat] = categories.get(cat, 0) + 1

    # 1. Write JSON
    log(f"\n  Writing vietnam_websites.json ({total_domains:,} records)...", log_lines)
    with open(WHITELIST_JSON, "w", encoding="utf-8") as f:
        json.dump(merged_list, f, ensure_ascii=False, indent=2)
    json_size = os.path.getsize(WHITELIST_JSON)
    log(f"  [OK] vietnam_websites.json: {json_size:,} bytes", log_lines)

    # 2. Write CSV - union of all keys
    # Determine column order: put known columns first, then extras
    known_cols = ["domain", "owner", "category_type", "certified_date", "cert_level",
                  "detail_url", "license_number", "category_url", "org_type",
                  "status", "website_url", "source", "category", "type"]
    extra_cols = sorted(k for k in all_keys if k not in known_cols)
    csv_columns = [c for c in known_cols if c in all_keys] + extra_cols

    log(f"  Writing vietnam_websites.csv ({total_domains:,} rows, {len(csv_columns)} columns)...", log_lines)
    try:
        with open(WHITELIST_CSV, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=csv_columns, extrasaction="ignore")
            writer.writeheader()
            for item in merged_list:
                writer.writerow(item)
    except PermissionError:
        log("  [ERROR] PermissionError writing CSV - file may be open", log_lines)
        raise
    csv_size = os.path.getsize(WHITELIST_CSV)
    log(f"  [OK] vietnam_websites.csv: {csv_size:,} bytes", log_lines)

    # 3. Write domains TXT (sorted)
    all_domain_strings = sorted(set(item.get("domain", "") for item in merged_list if item.get("domain")))
    log(f"  Writing vietnam_domains.txt ({len(all_domain_strings):,} domains)...", log_lines)
    with open(WHITELIST_DOMAINS, "w", encoding="utf-8") as f:
        for d in all_domain_strings:
            f.write(d + "\n")
    txt_size = os.path.getsize(WHITELIST_DOMAINS)
    log(f"  [OK] vietnam_domains.txt: {txt_size:,} bytes", log_lines)

    # 4. Write summary JSON
    merged_sources = list(set(whitelist_sources + massive_sources))
    summary = {
        "total_domains": total_domains,
        "last_updated": datetime.now().isoformat(),
        "sources": sorted(merged_sources),
        "categories": dict(sorted(categories.items(), key=lambda x: -x[1])),
        "merge_info": {
            "merged_from": ["whitelist/vietnam", "vietnam_massive"],
            "whitelist_original_count": stats.get("whitelist_original", 0),
            "massive_original_count": stats.get("massive_original", 0),
            "overlapping_domains": stats["overlapping"],
            "duplicates_removed": stats["duplicates_removed"],
            "conflicts_detected": len(conflicts),
        },
        "description": f"{total_domains:,} Vietnamese domains merged from whitelist + massive datasets"
    }
    log(f"  Writing vietnam_summary.json...", log_lines)
    with open(WHITELIST_SUMMARY, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
    log(f"  [OK] vietnam_summary.json", log_lines)

    # 5. Write conflict report
    if conflicts:
        log(f"\n  Writing conflict_report.json ({len(conflicts):,} domains with conflicts)...", log_lines)
        conflict_data = {
            "generated_at": datetime.now().isoformat(),
            "total_conflicting_domains": len(conflicts),
            "total_field_conflicts": sum(len(c["conflicts"]) for c in conflicts),
            "details": conflicts
        }
        with open(CONFLICT_REPORT, "w", encoding="utf-8") as f:
            json.dump(conflict_data, f, ensure_ascii=False, indent=2)
        log(f"  [OK] conflict_report.json written", log_lines)
    else:
        log(f"\n  No conflicts detected - no conflict_report.json needed", log_lines)

    return total_domains, len(all_domain_strings), categories


def verify_merge(merged, whitelist_data, massive_data, total_domains, txt_domain_count, log_lines):
    """Verify merge integrity - ensure no data loss."""
    log("\n" + "=" * 70, log_lines)
    log("STEP 4: VERIFICATION", log_lines)
    log("=" * 70, log_lines)

    errors = []

    # Build domain sets
    whitelist_domains = set()
    for item in whitelist_data:
        d = normalize_domain(item.get("domain", ""))
        if d:
            whitelist_domains.add(d)

    massive_domains = set()
    for item in massive_data:
        d = normalize_domain(item.get("domain", ""))
        if d:
            massive_domains.add(d)

    merged_domains = set(merged.keys())

    # Check 1: All whitelist domains present
    missing_whitelist = whitelist_domains - merged_domains
    if missing_whitelist:
        errors.append(f"MISSING from whitelist: {len(missing_whitelist)} domains")
        for d in sorted(list(missing_whitelist))[:10]:
            log(f"    Missing: {d}", log_lines)
    else:
        log(f"  [OK] All {len(whitelist_domains):,} whitelist domains present in merged", log_lines)

    # Check 2: All massive domains present
    missing_massive = massive_domains - merged_domains
    if missing_massive:
        errors.append(f"MISSING from massive: {len(missing_massive)} domains")
        for d in sorted(list(missing_massive))[:10]:
            log(f"    Missing: {d}", log_lines)
    else:
        log(f"  [OK] All {len(massive_domains):,} massive domains present in merged", log_lines)

    # Check 3: No extra domains (merged should be union of both)
    expected_union = whitelist_domains | massive_domains
    extra_domains = merged_domains - expected_union
    if extra_domains:
        errors.append(f"EXTRA domains not in either source: {len(extra_domains)}")
    else:
        log(f"  [OK] No extra domains in merged (exact union)", log_lines)

    # Check 4: Count consistency
    if total_domains != len(merged_domains):
        errors.append(f"JSON count ({total_domains}) != merged dict count ({len(merged_domains)})")
    else:
        log(f"  [OK] JSON record count matches: {total_domains:,}", log_lines)

    if txt_domain_count != len(merged_domains):
        errors.append(f"TXT domain count ({txt_domain_count}) != merged dict count ({len(merged_domains)})")
    else:
        log(f"  [OK] TXT domain count matches: {txt_domain_count:,}", log_lines)

    # Check 5: Verify whitelist field preservation
    log("\n  Verifying whitelist field preservation (spot check)...", log_lines)
    check_count = 0
    field_issues = 0
    for item in whitelist_data[:500]:  # Check first 500 records
        domain = normalize_domain(item.get("domain", ""))
        if not domain or domain not in merged:
            continue
        check_count += 1
        merged_record = merged[domain]
        for k, v in item.items():
            if k == "domain":
                continue
            if not v:
                continue
            merged_v = merged_record.get(k, "")
            v_str = str(v).strip()
            merged_v_str = str(merged_v).strip()
            if v_str and v_str not in merged_v_str:
                field_issues += 1
                if field_issues <= 5:
                    log(f"    [WARN] Field value possibly lost: domain={domain}, field={k}", log_lines)
                    log(f"           Original: {v_str[:80]}", log_lines)
                    log(f"           Merged:   {merged_v_str[:80]}", log_lines)

    if field_issues:
        log(f"  [WARN] {field_issues} field value issues found in {check_count} spot-checked records", log_lines)
    else:
        log(f"  [OK] All fields preserved in {check_count} spot-checked whitelist records", log_lines)

    # Check 6: No empty/null domains
    empty_domains = sum(1 for item in merged.values() if not item.get("domain"))
    if empty_domains:
        errors.append(f"Found {empty_domains} records with empty domain")
    else:
        log(f"  [OK] No empty/null domains in merged data", log_lines)

    # Check 7: Re-read and verify output files
    log("\n  Verifying output file readability...", log_lines)
    try:
        with open(WHITELIST_JSON, "r", encoding="utf-8") as f:
            reloaded = json.load(f)
        if len(reloaded) == total_domains:
            log(f"  [OK] JSON file re-read successfully: {len(reloaded):,} records", log_lines)
        else:
            errors.append(f"JSON re-read count mismatch: expected {total_domains}, got {len(reloaded)}")
    except Exception as e:
        errors.append(f"JSON re-read failed: {e}")

    try:
        with open(WHITELIST_CSV, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            header = next(reader)
            csv_count = sum(1 for row in reader if row)
        if csv_count == total_domains:
            log(f"  [OK] CSV file re-read successfully: {csv_count:,} data rows", log_lines)
        else:
            errors.append(f"CSV re-read count mismatch: expected {total_domains}, got {csv_count}")
    except Exception as e:
        errors.append(f"CSV re-read failed: {e}")

    try:
        with open(WHITELIST_DOMAINS, "r", encoding="utf-8") as f:
            txt_lines = [line.strip() for line in f if line.strip()]
        if len(txt_lines) == txt_domain_count:
            log(f"  [OK] TXT file re-read successfully: {len(txt_lines):,} domains", log_lines)
        else:
            errors.append(f"TXT re-read count mismatch: expected {txt_domain_count}, got {len(txt_lines)}")
    except Exception as e:
        errors.append(f"TXT re-read failed: {e}")

    # Summary
    log("\n" + "-" * 70, log_lines)
    if errors:
        log(f"  VERIFICATION FAILED - {len(errors)} errors:", log_lines)
        for err in errors:
            log(f"    [ERROR] {err}", log_lines)
        return False
    else:
        log("  VERIFICATION PASSED - All checks OK!", log_lines)
        return True


def main():
    log_lines = []
    log("=" * 70, log_lines)
    log("MERGE MASSIVE VIETNAM INTO WHITELIST", log_lines)
    log(f"Started at: {datetime.now().isoformat()}", log_lines)
    log("=" * 70, log_lines)

    # Verify source files exist
    for filepath in [MASSIVE_JSON, WHITELIST_JSON]:
        if not os.path.exists(filepath):
            log(f"[FATAL] Source file not found: {filepath}", log_lines)
            sys.exit(1)

    # Step 1: Backup
    backup_files(log_lines)

    # Step 2: Load data
    log("\n" + "=" * 70, log_lines)
    log("LOADING DATA", log_lines)
    log("=" * 70, log_lines)

    whitelist_data = load_json(WHITELIST_JSON, log_lines)
    massive_data = load_json(MASSIVE_JSON, log_lines)

    # Load summaries for source info
    whitelist_sources = []
    massive_sources = []
    try:
        with open(WHITELIST_SUMMARY, "r", encoding="utf-8") as f:
            ws = json.load(f)
            whitelist_sources = ws.get("sources", [])
    except:
        pass
    try:
        with open(MASSIVE_SUMMARY, "r", encoding="utf-8") as f:
            ms = json.load(f)
            massive_sources = ms.get("sources", [])
    except:
        pass

    # Step 3: Merge
    merged, conflicts, stats, all_keys = merge_datasets(whitelist_data, massive_data, log_lines)
    stats["whitelist_original"] = len(whitelist_data)
    stats["massive_original"] = len(massive_data)

    # Step 4: Write output
    total_domains, txt_domain_count, categories = write_output(
        merged, conflicts, stats, all_keys, whitelist_sources, massive_sources, log_lines
    )

    # Step 5: Verify
    verified = verify_merge(merged, whitelist_data, massive_data, total_domains, txt_domain_count, log_lines)

    # Final summary
    log("\n" + "=" * 70, log_lines)
    log("FINAL SUMMARY", log_lines)
    log("=" * 70, log_lines)
    log(f"  Whitelist original: {len(whitelist_data):,} records", log_lines)
    log(f"  Massive original:   {len(massive_data):,} records", log_lines)
    log(f"  Merged total:       {total_domains:,} domains", log_lines)
    log(f"  Overlapping:        {stats['overlapping']:,} domains", log_lines)
    log(f"  Duplicates removed: {stats['duplicates_removed']:,}", log_lines)
    log(f"  Conflicts detected: {len(conflicts):,} domains", log_lines)
    log(f"  Verification:       {'PASSED' if verified else 'FAILED'}", log_lines)
    log(f"  Completed at:       {datetime.now().isoformat()}", log_lines)
    log("=" * 70, log_lines)

    # Write log file
    with open(MERGE_LOG, "w", encoding="utf-8") as f:
        f.write("\n".join(log_lines))
    print(f"\n  Log saved to: {MERGE_LOG}")

    if not verified:
        print("\n  [FATAL] Merge verification FAILED. Check logs.")
        sys.exit(1)

    return 0


if __name__ == "__main__":
    sys.exit(main())
