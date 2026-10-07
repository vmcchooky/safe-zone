#!/usr/bin/env python3
"""Validate an ML human-label review queue against the runbook rubric.

The queue is the ``labels.csv`` file inside a representative replay packet
(see docs/runbooks/ml-shadow-representative-replay.md). Reviewers fill only
the human-review fields; every other column is produced by the replay
generator and must stay consistent with the packet manifest.

Exit status:
    0  no errors (warnings allowed unless --strict)
    1  validation errors, or pending rows remain with --require-complete
    2  usage / IO failure

Usage:
    python scripts/ops/ml_label_check.py <packet>/labels.csv
    python scripts/ops/ml_label_check.py <packet>/labels.csv --require-complete
    python scripts/ops/ml_label_check.py <packet>/labels.csv --json
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from datetime import datetime
from pathlib import Path

TEMPLATE_COLUMNS = [
    "case_id", "domain", "traffic_stratum", "source_ref", "source_trust_tier",
    "model_revision", "model_threshold", "shadow_would_block", "shadow_probability",
    "human_label", "label_confidence", "evidence_type", "reviewer_id", "reviewed_at",
    "evidence_refs", "review_outcome", "review_notes",
]

HUMAN_LABELS = {"benign", "malicious", "compromised", "shared_hosting", "unknown"}
BINARY_LABELS = {"benign", "malicious"}
LABEL_CONFIDENCE = {"high", "medium", "low"}
EVIDENCE_TYPES = {
    "verified_owner", "official_source", "live_content_review",
    "strong_feed_current", "incident_ticket", "insufficient_evidence",
}
REVIEW_OUTCOMES = {
    "correct_allow", "correct_block", "false_positive",
    "false_negative", "unresolved_disagreement",
}
REVIEW_FIELDS = [
    "human_label", "label_confidence", "evidence_type", "reviewer_id",
    "reviewed_at", "evidence_refs", "review_outcome", "review_notes",
]

# Rubric: the ML prediction, LLM output, or list membership must not be the
# sole evidence for a human label.
ML_ONLY_EVIDENCE = re.compile(
    r"model_predictions|shadow_probability|ml[_-]only|llm[_-]only|list[_-]membership",
    re.IGNORECASE,
)

EXPECTED_OUTCOME = {
    (True, "benign"): "false_positive",
    (True, "malicious"): "correct_block",
    (False, "benign"): "correct_allow",
    (False, "malicious"): "false_negative",
}


def _is_iso8601(value: str) -> bool:
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return True


def validate_row(row: dict, line_no: int, errors: list, warnings: list) -> str:
    """Validate one CSV row. Returns 'pending' or 'complete'."""
    case_id = (row.get("case_id") or "").strip()
    where = f"line {line_no} ({case_id or 'missing case_id'})"

    if not case_id:
        errors.append(f"{where}: case_id is empty")
    if not (row.get("domain") or "").strip():
        errors.append(f"{where}: domain is empty")

    would_block_raw = (row.get("shadow_would_block") or "").strip().lower()
    if would_block_raw not in {"true", "false"}:
        errors.append(f"{where}: shadow_would_block must be true/false, got {would_block_raw!r}")
        would_block = None
    else:
        would_block = would_block_raw == "true"

    prob_raw = (row.get("shadow_probability") or "").strip()
    try:
        prob = float(prob_raw)
        if not 0.0 <= prob <= 1.0:
            errors.append(f"{where}: shadow_probability {prob} outside [0, 1]")
    except ValueError:
        errors.append(f"{where}: shadow_probability {prob_raw!r} is not a number")

    filled = {f: (row.get(f) or "").strip() for f in REVIEW_FIELDS}
    if all(value == "" for value in filled.values()):
        return "pending"
    missing = [f for f, value in filled.items() if value == ""]
    if missing:
        errors.append(f"{where}: partially reviewed; missing fields: {', '.join(missing)}")

    label = filled["human_label"]
    if label and label not in HUMAN_LABELS:
        errors.append(f"{where}: human_label {label!r} not in {sorted(HUMAN_LABELS)}")
    if filled["label_confidence"] and filled["label_confidence"] not in LABEL_CONFIDENCE:
        errors.append(f"{where}: label_confidence {filled['label_confidence']!r} not in {sorted(LABEL_CONFIDENCE)}")
    if filled["evidence_type"] and filled["evidence_type"] not in EVIDENCE_TYPES:
        errors.append(f"{where}: evidence_type {filled['evidence_type']!r} not in {sorted(EVIDENCE_TYPES)}")
    if filled["review_outcome"] and filled["review_outcome"] not in REVIEW_OUTCOMES:
        errors.append(f"{where}: review_outcome {filled['review_outcome']!r} not in {sorted(REVIEW_OUTCOMES)}")
    if filled["reviewed_at"] and not _is_iso8601(filled["reviewed_at"]):
        errors.append(f"{where}: reviewed_at {filled['reviewed_at']!r} is not ISO 8601")

    if filled["evidence_refs"] and ML_ONLY_EVIDENCE.search(filled["evidence_refs"]):
        errors.append(
            f"{where}: evidence_refs cites ML/LLM/list-only evidence; "
            "rubric requires independent human evidence"
        )

    if label in BINARY_LABELS and filled["evidence_type"] == "insufficient_evidence":
        errors.append(
            f"{where}: binary label {label!r} with insufficient_evidence; "
            "use human_label=unknown instead"
        )
    if label == "unknown" and filled["label_confidence"] == "high":
        warnings.append(f"{where}: label 'unknown' with high confidence is unusual")

    if label in BINARY_LABELS and would_block is not None and filled["review_outcome"]:
        expected = EXPECTED_OUTCOME[(would_block, label)]
        if filled["review_outcome"] != expected:
            errors.append(
                f"{where}: review_outcome {filled['review_outcome']!r} inconsistent with "
                f"shadow_would_block={would_block} and human_label={label!r} (expected {expected!r})"
            )
    return "complete"


def validate_labels(path: Path) -> dict:
    errors: list = []
    warnings: list = []
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames != TEMPLATE_COLUMNS:
            errors.append(
                "header mismatch; expected exactly: " + ",".join(TEMPLATE_COLUMNS)
            )
        seen: dict[str, int] = {}
        pending = complete = 0
        labels: dict[str, int] = {}
        reviewers: dict[str, int] = {}
        revisions = set()
        thresholds = set()
        rows = list(reader)

    for index, row in enumerate(rows, start=2):  # line 1 is the header
        case_id = (row.get("case_id") or "").strip()
        if case_id in seen:
            errors.append(f"line {index}: duplicate case_id {case_id!r} (first seen line {seen[case_id]})")
        seen[case_id] = index
        revisions.add((row.get("model_revision") or "").strip())
        thresholds.add((row.get("model_threshold") or "").strip())
        state = validate_row(row, index, errors, warnings)
        if state == "pending":
            pending += 1
        else:
            complete += 1
            label = (row.get("human_label") or "").strip()
            labels[label] = labels.get(label, 0) + 1
            reviewer = (row.get("reviewer_id") or "").strip()
            reviewers[reviewer] = reviewers.get(reviewer, 0) + 1

    if len(revisions) > 1:
        errors.append(f"multiple model_revision values in queue: {sorted(revisions)}")
    if len(thresholds) > 1:
        errors.append(f"multiple model_threshold values in queue: {sorted(thresholds)}")

    return {
        "file": str(path),
        "total_cases": len(rows),
        "pending": pending,
        "complete": complete,
        "labels": labels,
        "reviewers": reviewers,
        "errors": errors,
        "warnings": warnings,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("labels", type=Path, help="path to labels.csv")
    parser.add_argument("--require-complete", action="store_true",
                        help="fail if any case is still pending review")
    parser.add_argument("--strict", action="store_true", help="treat warnings as errors")
    parser.add_argument("--json", action="store_true", help="print the full report as JSON")
    args = parser.parse_args(argv)

    if not args.labels.is_file():
        print(f"error: {args.labels} not found", file=sys.stderr)
        return 2

    report = validate_labels(args.labels)
    if args.require_complete and report["pending"]:
        report["errors"].append(f"{report['pending']} case(s) still pending review")
    if args.strict and report["warnings"]:
        report["errors"].extend(f"strict: {w}" for w in report["warnings"])

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"{report['file']}: {report['total_cases']} cases "
              f"({report['complete']} complete, {report['pending']} pending)")
        for warning in report["warnings"]:
            print(f"warning: {warning}")
        for error in report["errors"]:
            print(f"error: {error}")
        if not report["errors"]:
            print("OK: queue satisfies the human-label rubric")
    return 1 if report["errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
