"""Generate auditable false-positive metrics for the private replay packet."""

from __future__ import annotations

import argparse
import json
import math
import re
from dataclasses import replace
from decimal import Decimal
from pathlib import Path
from typing import Iterable, Mapping

try:
    from replay_labels import (
        ALLOWED_LABELS,
        ValidationResult,
        clean,
        parse_bool,
        parse_probability,
        validate_labels,
    )
except ModuleNotFoundError:  # pragma: no cover - supports package-style pytest imports
    from ml.src.replay_labels import (
        ALLOWED_LABELS,
        ValidationResult,
        clean,
        parse_bool,
        parse_probability,
        validate_labels,
    )


BEGIN_MARKER = "<!-- BEGIN HUMAN-LABEL-METRICS -->"
END_MARKER = "<!-- END HUMAN-LABEL-METRICS -->"
CRITICAL_BENIGN_STRATA = frozenset(
    {"trusted_brand", "government_education", "shared_hosting", "idn_punycode"}
)


def _ratio(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


def _is_blocked(row: Mapping[str, object]) -> bool:
    return parse_bool(row.get("shadow_would_block")) is True


def _binary_metrics(labeled: list[Mapping[str, object]]) -> dict[str, object]:
    benign = [row for row in labeled if clean(row.get("human_label")).lower() == "benign"]
    malicious = [
        row for row in labeled if clean(row.get("human_label")).lower() == "malicious"
    ]
    false_positives = [row for row in benign if _is_blocked(row)]
    true_positives = [row for row in malicious if _is_blocked(row)]
    return {
        "benign_cases": len(benign),
        "malicious_cases": len(malicious),
        "false_positives": len(false_positives),
        "true_positives": len(true_positives),
        "fpr_at_threshold": _ratio(len(false_positives), len(benign)),
        "recall_at_threshold": _ratio(len(true_positives), len(malicious)),
        "false_positive_case_ids": [clean(row.get("case_id")) for row in false_positives],
    }


def _strata_metrics(labeled: list[Mapping[str, object]]) -> dict[str, dict[str, object]]:
    strata = sorted({clean(row.get("traffic_stratum")) for row in labeled})
    result: dict[str, dict[str, object]] = {}
    for stratum in strata:
        in_stratum = [row for row in labeled if clean(row.get("traffic_stratum")) == stratum]
        benign = [row for row in in_stratum if clean(row.get("human_label")).lower() == "benign"]
        false_positives = [row for row in benign if _is_blocked(row)]
        result[stratum] = {
            "benign_count": len(benign),
            "false_positives": len(false_positives),
            "fpr": _ratio(len(false_positives), len(benign)),
        }
    return result


def _critical_benign_metrics(
    labeled: list[Mapping[str, object]], columns: Iterable[str]
) -> tuple[dict[str, object], list[str]]:
    if "critical_benign_stratum" not in set(columns):
        return {"status": "unavailable_missing_column", "strata": {}}, [
            "critical benign strata were not collected"
        ]

    result: dict[str, dict[str, object]] = {}
    critical_false_positive_ids: list[str] = []
    for stratum in sorted(CRITICAL_BENIGN_STRATA):
        cases = [
            row
            for row in labeled
            if clean(row.get("critical_benign_stratum")).lower() == stratum
            and clean(row.get("human_label")).lower() == "benign"
        ]
        false_positives = [row for row in cases if _is_blocked(row)]
        result[stratum] = {
            "benign_count": len(cases),
            "false_positives": len(false_positives),
            "fpr": _ratio(len(false_positives), len(cases)),
        }
        critical_false_positive_ids.extend(
            clean(row.get("case_id")) for row in false_positives
        )
    blockers = ["confirmed critical-benign false positives"] if critical_false_positive_ids else []
    missing_strata = [
        stratum for stratum, values in result.items() if values["benign_count"] == 0
    ]
    if missing_strata:
        blockers.append(
            "critical benign strata have no eligible reviewed cases: "
            + ", ".join(missing_strata)
        )
    return {
        "status": "incomplete" if missing_strata else "available",
        "strata": result,
        "false_positive_case_ids": critical_false_positive_ids,
    }, blockers


def _reviewer_agreement(
    labeled: list[Mapping[str, object]],
    columns: Iterable[str],
    target: int | None = None,
) -> tuple[dict[str, object], list[str]]:
    column_set = set(columns)
    if "second_human_label" not in column_set or "second_reviewer_id" not in column_set:
        return {"status": "not_collected", "reviewed_cases": 0, "target": target}, [
            "double-label fields were not collected"
        ]
    double_labeled = [
        row for row in labeled if clean(row.get("second_human_label"))
    ]
    if not double_labeled:
        blockers = ["no double-labeled cases were recorded"]
        if target:
            blockers.append(f"double-label target not met: 0/{target}")
        return {"status": "not_collected", "reviewed_cases": 0, "target": target}, blockers
    disagreements = [
        clean(row.get("case_id"))
        for row in double_labeled
        if clean(row.get("human_label")).lower()
        != clean(row.get("second_human_label")).lower()
    ]
    agreement_count = len(double_labeled) - len(disagreements)
    blockers = ["reviewer disagreement is unresolved"] if disagreements else []
    if target and len(double_labeled) < target:
        blockers.append(
            f"double-label target not met: {len(double_labeled)}/{target}"
        )
    return {
        "status": "incomplete" if blockers else "available",
        "reviewed_cases": len(double_labeled),
        "target": target,
        "agreement_cases": agreement_count,
        "disagreement_cases": len(disagreements),
        "agreement_rate": _ratio(agreement_count, len(double_labeled)),
        "disagreement_case_ids": disagreements,
    }, blockers


def _deterministic_policy_metrics(
    labeled: list[Mapping[str, object]], columns: Iterable[str]
) -> tuple[dict[str, object], list[str]]:
    if "deterministic_would_block" not in set(columns):
        return {"status": "unavailable_missing_column", "blocked_cases": 0}, [
            "deterministic policy action was not recorded"
        ]
    missing = [
        row for row in labeled if parse_bool(row.get("deterministic_would_block")) is None
    ]
    if missing:
        return {
            "status": "incomplete",
            "blocked_cases": 0,
            "missing_case_ids": [clean(row.get("case_id")) for row in missing],
        }, ["deterministic policy action is missing for reviewed cases"]
    blocked = [row for row in labeled if parse_bool(row.get("deterministic_would_block")) is True]
    return {
        "status": "available",
        "blocked_cases": len(blocked),
        "blocked_case_ids": [clean(row.get("case_id")) for row in blocked],
    }, []


def calculate_metrics(
    rows: Iterable[Mapping[str, object]],
    threshold: float = 0.85,
    columns: Iterable[str] = (),
    double_label_target: int | None = None,
) -> dict[str, object]:
    """Calculate metrics only from binary human labels, never source membership."""

    all_rows = list(rows)
    labeled = [row for row in all_rows if clean(row.get("human_label"))]
    binary = _binary_metrics(labeled)
    critical, critical_blockers = _critical_benign_metrics(labeled, columns)
    agreement, agreement_blockers = _reviewer_agreement(
        labeled, columns, target=double_label_target
    )
    deterministic, deterministic_blockers = _deterministic_policy_metrics(labeled, columns)
    non_binary_counts = {
        label: sum(1 for row in labeled if clean(row.get("human_label")).lower() == label)
        for label in sorted(ALLOWED_LABELS - {"benign", "malicious"})
    }
    unresolved_count = sum(
        1
        for row in labeled
        if clean(row.get("human_label")).lower() == "unknown"
        or clean(row.get("review_outcome")).lower() == "unresolved"
    )
    blockers = [*critical_blockers, *agreement_blockers, *deterministic_blockers]
    if unresolved_count:
        blockers.append("unresolved or unknown review outcomes remain")
    if not binary["benign_cases"] or not binary["malicious_cases"]:
        blockers.append("both benign and malicious reviewed cases are required")
    return {
        "status": "complete",
        "threshold": threshold,
        "total_labeled": len(labeled),
        "coverage": _ratio(len(labeled), len(all_rows)),
        **binary,
        "non_binary_labels": non_binary_counts,
        "unresolved_count": unresolved_count,
        "strata_breakdown": _strata_metrics(labeled),
        "critical_benign": critical,
        "reviewer_agreement": agreement,
        "deterministic_policy": deterministic,
        "approval_blockers": sorted(set(blockers)),
    }


def _atomic_write(path: Path, content: str) -> None:
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(content, encoding="utf-8", newline="\n")
    temporary.replace(path)


def _double_label_target(summary: Mapping[str, object], total_cases: int) -> int | None:
    configured = summary.get("double_label_target")
    if configured not in (None, "", 0, "0"):
        target = int(configured)
        return target if target > 0 else None
    priority_cases = int(summary.get("review_required_cases", 0) or 0)
    if priority_cases <= 0:
        return None
    return priority_cases + math.ceil(total_cases * 0.10)


def _summary_for_validation(
    summary: dict[str, object], validation: ValidationResult, threshold: float
) -> dict[str, object]:
    output = dict(summary)
    total_cases = int(summary.get("total_cases", validation.total_cases))
    target = _double_label_target(summary, total_cases)
    output["human_label_coverage"] = _ratio(validation.labeled_cases, total_cases)
    output["human_labels_pending"] = max(total_cases - validation.labeled_cases, 0)
    if target is not None:
        output["double_label_target"] = target
    output["label_validation"] = {
        "status": "invalid" if validation.errors else "pending" if validation.pending_case_ids else "valid",
        "errors": list(validation.errors[:50]),
        "warnings": list(validation.warnings[:50]),
    }
    output.setdefault("approval_state", {})
    approval_state = dict(output["approval_state"])
    approval_state["canary"] = "blocked"
    output["approval_state"] = approval_state
    if validation.errors:
        output["false_positive_metrics"] = {
            "status": "blocked_by_label_validation",
            "threshold": threshold,
            "coverage": output["human_label_coverage"],
            "pending_cases": output["human_labels_pending"],
        }
    elif validation.pending_case_ids:
        output["false_positive_metrics"] = {
            "status": "blocked_until_human_labels_complete",
            "threshold": threshold,
            "coverage": output["human_label_coverage"],
            "labeled_cases": validation.labeled_cases,
            "pending_cases": len(validation.pending_case_ids),
        }
    return output


def update_summary(
    summary_path: str | Path,
    validation: ValidationResult,
    threshold: float,
    metrics: dict[str, object] | None,
) -> None:
    path = Path(summary_path)
    summary = json.loads(path.read_text(encoding="utf-8"))
    output = _summary_for_validation(summary, validation, threshold)
    if metrics is not None and not validation.errors and not validation.pending_case_ids:
        output["false_positive_metrics"] = metrics
        if metrics["approval_blockers"]:
            output["approval_state"]["canary"] = "blocked_by_review_gates"
        else:
            output["approval_state"]["canary"] = "ready_for_review"
    _atomic_write(path, json.dumps(output, indent=2, ensure_ascii=False) + "\n")
    print(f"[+] Updated {path}")


def _metrics_markdown(
    validation: ValidationResult,
    threshold: float,
    metrics: dict[str, object] | None,
    double_label_target: int | None,
) -> str:
    total = validation.total_cases
    lines = [
        BEGIN_MARKER,
        "### Human-label review metrics",
        f"- **Status:** `{('invalid' if validation.errors else 'pending' if validation.pending_case_ids else 'complete')}`",
        f"- **Coverage:** {validation.labeled_cases}/{total} ({_ratio(validation.labeled_cases, total):.1%})",
        f"- **Threshold:** `{threshold:.2f}`",
    ]
    if double_label_target is not None:
        lines.append(f"- **Double-label target:** {double_label_target} cases")
    if metrics is None:
        lines.append("- **False-positive metrics:** not reported until validation and adjudication are complete.")
    else:
        lines.extend(
            [
                f"- **False Positive Rate:** {metrics['fpr_at_threshold']:.4f} ({metrics['false_positives']}/{metrics['benign_cases']})",
                f"- **Recall:** {metrics['recall_at_threshold']:.4f} ({metrics['true_positives']}/{metrics['malicious_cases']})",
                f"- **Non-binary labels excluded:** {metrics['non_binary_labels']}",
                f"- **Critical-benign review:** `{metrics['critical_benign']['status']}`",
                f"- **Reviewer agreement:** `{metrics['reviewer_agreement']['status']}`",
                f"- **Deterministic policy evidence:** `{metrics['deterministic_policy']['status']}`",
                f"- **Approval blockers:** {metrics['approval_blockers'] or 'none recorded'}",
            ]
        )
    lines.append(END_MARKER)
    return "\n".join(lines)


def update_packet(
    packet_path: str | Path,
    validation: ValidationResult,
    threshold: float,
    metrics: dict[str, object] | None,
    double_label_target: int | None,
) -> None:
    path = Path(packet_path)
    content = path.read_text(encoding="utf-8")
    block = _metrics_markdown(validation, threshold, metrics, double_label_target)
    pattern = re.compile(
        re.escape(BEGIN_MARKER) + r".*?" + re.escape(END_MARKER), re.DOTALL
    )
    if pattern.search(content):
        content = pattern.sub(block, content, count=1)
    else:
        anchor = "## Current decision"
        insertion = content.find(anchor)
        if insertion >= 0:
            content = content[:insertion] + block + "\n\n" + content[insertion:]
        else:
            content = content.rstrip() + "\n\n" + block + "\n"
    content = re.sub(
        r"- Cases: `[^`]+`; human labels complete: `[^`]+`",
        f"- Cases: `{validation.total_cases}`; human labels complete: `{validation.labeled_cases}/{validation.total_cases}`",
        content,
        count=1,
    )
    _atomic_write(path, content)
    print(f"[+] Updated {path}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate auditable ML replay FP metrics")
    parser.add_argument("--labels", required=True, help="Path to labels.csv")
    parser.add_argument("--summary", required=True, help="Path to review-summary.json")
    parser.add_argument("--packet", required=True, help="Path to approval-packet.md")
    parser.add_argument("--allow-pending", action="store_true")
    args = parser.parse_args(argv)

    summary_path = Path(args.summary)
    labels_path = Path(args.labels)
    packet_path = Path(args.packet)
    try:
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        threshold = float(summary.get("model_threshold", 0.85))
        if not 0 < threshold < 1:
            raise ValueError("model_threshold must be in (0, 1)")
        expected_total = int(summary["total_cases"])
        double_label_target = _double_label_target(summary, expected_total)
        validation = validate_labels(labels_path, expected_total=expected_total)
        threshold_errors = []
        expected_threshold = Decimal(str(threshold))
        for row in validation.rows:
            row_threshold = parse_probability(row.get("model_threshold"))
            if row_threshold is not None and row_threshold != expected_threshold:
                threshold_errors.append(
                    f"[{clean(row.get('case_id'))}] model_threshold does not match review summary threshold"
                )
        if threshold_errors:
            validation = replace(
                validation,
                errors=validation.errors + tuple(threshold_errors),
            )
        metrics = (
            calculate_metrics(
                validation.rows,
                threshold,
                validation.columns,
                double_label_target=double_label_target,
            )
            if validation.is_complete
            else None
        )
        update_summary(summary_path, validation, threshold, metrics)
        update_packet(packet_path, validation, threshold, metrics, double_label_target)
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
        print(f"[ERROR] Unable to generate report: {error}")
        return 1

    if validation.errors:
        return 1
    if validation.pending_case_ids and not args.allow_pending:
        return 2
    if metrics and metrics["approval_blockers"]:
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
