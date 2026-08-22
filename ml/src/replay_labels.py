"""Shared CSV parsing and rubric validation for ML replay labels."""

from __future__ import annotations

import csv
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Iterable, Mapping


ALLOWED_LABELS = frozenset(
    {"benign", "malicious", "compromised", "shared_hosting", "unknown"}
)
ALLOWED_CONFIDENCE = frozenset({"high", "medium", "low"})
ALLOWED_EVIDENCE = frozenset(
    {
        "verified owner",
        "official source",
        "live content review",
        "strong feed with current status",
        "incident/ticket",
        "insufficient evidence",
    }
)
ALLOWED_OUTCOMES = frozenset(
    {"true_positive", "true_negative", "false_positive", "false_negative", "unresolved"}
)
CASE_COLUMNS = frozenset(
    {
        "case_id",
        "domain",
        "traffic_stratum",
        "source_ref",
        "source_trust_tier",
        "model_revision",
        "model_threshold",
        "shadow_would_block",
        "shadow_probability",
    }
)
REVIEW_COLUMNS = frozenset(
    {
        "human_label",
        "label_confidence",
        "evidence_type",
        "reviewer_id",
        "reviewed_at",
        "evidence_refs",
        "review_outcome",
        "review_notes",
    }
)
REQUIRED_COLUMNS = CASE_COLUMNS | REVIEW_COLUMNS
OPTIONAL_COLUMNS = frozenset(
    {
        "critical_benign_stratum",
        "deterministic_would_block",
        "second_human_label",
        "second_reviewer_id",
    }
)
ALLOWED_CRITICAL_BENIGN_STRATA = frozenset(
    {"trusted_brand", "government_education", "shared_hosting", "idn_punycode"}
)
_MODEL_ONLY_EVIDENCE = frozenset(
    {
        "model",
        "model output",
        "ml",
        "ml prediction",
        "prediction",
        "shadow",
        "shadow prediction",
    }
)
_DISALLOWED_REVIEWER_MARKERS = frozenset(
    {
        "ai-adjudicator",
        "ai-agent",
        "ai-auditor",
        "antigravity",
        "anthropic",
        "chatgpt",
        "claude",
        "codex",
        "copilot",
        "gemini",
        "gpt",
        "grok",
        "junie",
        "llm",
        "openai",
        "opus",
        "sonnet",
    }
)
_NO_LIVE_CONTENT_MARKERS = (
    "connection refused",
    "dns resolution failed",
    "name or service not known",
    "no address associated",
    "nxdomain",
    "timed out",
    "timeout",
)


@dataclass(frozen=True)
class ValidationResult:
    """Validation findings and normalized rows from one label queue."""

    rows: tuple[dict[str, str], ...]
    columns: tuple[str, ...]
    errors: tuple[str, ...]
    warnings: tuple[str, ...]
    pending_case_ids: tuple[str, ...]

    @property
    def total_cases(self) -> int:
        return len(self.rows)

    @property
    def labeled_cases(self) -> int:
        return self.total_cases - len(self.pending_case_ids)

    @property
    def is_complete(self) -> bool:
        return not self.pending_case_ids and not self.errors


def clean(value: object) -> str:
    return "" if value is None else str(value).strip()


def parse_bool(value: object) -> bool | None:
    normalized = clean(value).lower()
    if normalized in {"true", "1", "yes"}:
        return True
    if normalized in {"false", "0", "no"}:
        return False
    return None


def parse_probability(value: object) -> Decimal | None:
    try:
        parsed = Decimal(clean(value))
    except (InvalidOperation, ValueError):
        return None
    if not parsed.is_finite() or parsed < Decimal("0") or parsed > Decimal("1"):
        return None
    return parsed


def _parse_timestamp(value: str) -> bool:
    if not value:
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None


def _expected_outcome(label: str, would_block: bool) -> str:
    if label == "benign":
        return "false_positive" if would_block else "true_negative"
    if label == "malicious":
        return "true_positive" if would_block else "false_negative"
    return "unresolved"


def read_label_csv(path: str | Path) -> tuple[list[dict[str, str]], list[str]]:
    """Read a UTF-8 queue without requiring pandas in the ML virtualenv."""

    with Path(path).open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        fieldnames = [clean(field) for field in (reader.fieldnames or [])]
        if not fieldnames:
            raise ValueError("CSV has no header")
        if len(fieldnames) != len(set(fieldnames)):
            raise ValueError("CSV header contains duplicate column names")
        rows: list[dict[str, str]] = []
        for raw_row in reader:
            if None in raw_row:
                raise ValueError(f"CSV row {reader.line_num} has more fields than its header")
            row = {field: clean(raw_row.get(field)) for field in fieldnames}
            if any(row.values()):
                rows.append(row)
        return rows, fieldnames


def _row_issue(collection: list[str], case_id: str, message: str) -> None:
    collection.append(f"[{case_id or 'missing case_id'}] {message}")


def _normalized_reviewer_id(value: object) -> str:
    return clean(value).lower().replace("_", "-")


def _is_disallowed_reviewer(reviewer_id: str) -> bool:
    """Reject model/agent reviewer IDs; they are not authorized human reviewers."""

    normalized = _normalized_reviewer_id(reviewer_id)
    if not normalized:
        return False
    compact = normalized.replace(".", "-")
    tokens = {token for token in compact.split("-") if token}
    if tokens & _DISALLOWED_REVIEWER_MARKERS:
        return True
    return any(marker in compact for marker in _DISALLOWED_REVIEWER_MARKERS if "-" in marker)


def _notes_indicate_no_live_content(notes: str) -> bool:
    lowered = notes.lower()
    return any(marker in lowered for marker in _NO_LIVE_CONTENT_MARKERS)


def validate_rows(
    rows: Iterable[Mapping[str, object]],
    columns: Iterable[str],
    expected_total: int | None = None,
) -> ValidationResult:
    """Validate structural and human-review constraints from the runbook."""

    normalized_columns = tuple(clean(column) for column in columns)
    normalized_rows = [
        {clean(key): clean(value) for key, value in row.items()}
        for row in rows
    ]
    errors: list[str] = []
    warnings: list[str] = []
    pending_case_ids: list[str] = []

    missing_columns = sorted(REQUIRED_COLUMNS - set(normalized_columns))
    if missing_columns:
        errors.append(f"Missing required columns: {', '.join(missing_columns)}")
    unexpected_columns = sorted(
        set(normalized_columns) - REQUIRED_COLUMNS - OPTIONAL_COLUMNS
    )
    if unexpected_columns:
        warnings.append(
            f"Unknown columns are preserved but not validated: {', '.join(unexpected_columns)}"
        )
    if not normalized_rows:
        errors.append("CSV contains no cases")
    if expected_total is not None and len(normalized_rows) != expected_total:
        errors.append(
            f"Case count mismatch: labels={len(normalized_rows)}, expected={expected_total}"
        )

    seen_case_ids: set[str] = set()
    for index, row in enumerate(normalized_rows, start=2):
        case_id = clean(row.get("case_id")) or f"row {index}"
        if case_id in seen_case_ids:
            _row_issue(errors, case_id, "duplicate case_id")
        seen_case_ids.add(case_id)

        for field in CASE_COLUMNS:
            if not clean(row.get(field)):
                _row_issue(errors, case_id, f"missing {field}")

        threshold = parse_probability(row.get("model_threshold"))
        if threshold is None or threshold <= Decimal("0") or threshold >= Decimal("1"):
            _row_issue(errors, case_id, "model_threshold must be a finite number in (0, 1)")

        probability = parse_probability(row.get("shadow_probability"))
        if probability is None:
            _row_issue(errors, case_id, "shadow_probability must be a finite number in [0, 1]")

        would_block = parse_bool(row.get("shadow_would_block"))
        if would_block is None:
            _row_issue(errors, case_id, "shadow_would_block must be true or false")
        elif probability is not None and threshold is not None:
            if (probability >= threshold) != would_block:
                _row_issue(
                    errors,
                    case_id,
                    "shadow_would_block does not match shadow_probability >= model_threshold",
                )

        label = clean(row.get("human_label")).lower()
        if not label:
            pending_case_ids.append(case_id)
            partial_review = [
                field for field in REVIEW_COLUMNS if clean(row.get(field))
            ]
            if partial_review:
                _row_issue(
                    errors,
                    case_id,
                    "review fields are partially filled while human_label is pending: "
                    + ", ".join(sorted(partial_review)),
                )
            continue

        if label not in ALLOWED_LABELS:
            _row_issue(errors, case_id, f"invalid human_label: {label!r}")
        confidence = clean(row.get("label_confidence")).lower()
        if confidence not in ALLOWED_CONFIDENCE:
            _row_issue(errors, case_id, f"invalid label_confidence: {confidence!r}")
        evidence_type = clean(row.get("evidence_type")).lower()
        if evidence_type not in ALLOWED_EVIDENCE:
            _row_issue(errors, case_id, f"invalid evidence_type: {evidence_type!r}")

        reviewer_id = clean(row.get("reviewer_id"))
        if not reviewer_id or reviewer_id.lower() in {"unknown", "n/a", "na"}:
            _row_issue(errors, case_id, "reviewer_id is required and cannot be a placeholder")
        elif _is_disallowed_reviewer(reviewer_id):
            _row_issue(
                errors,
                case_id,
                "reviewer_id cannot be a model or AI agent; human authorization is required",
            )
        if not _parse_timestamp(clean(row.get("reviewed_at"))):
            _row_issue(errors, case_id, "reviewed_at must be an ISO-8601 timestamp with timezone")

        evidence_refs = clean(row.get("evidence_refs"))
        review_notes = clean(row.get("review_notes"))
        if not evidence_refs:
            _row_issue(errors, case_id, "evidence_refs is required")
        if not review_notes:
            _row_issue(errors, case_id, "review_notes is required")
        if evidence_refs.lower() in _MODEL_ONLY_EVIDENCE:
            _row_issue(
                errors,
                case_id,
                "evidence_refs cannot use model/ML output as the sole evidence",
            )
        if evidence_type == "insufficient evidence" and label != "unknown":
            _row_issue(errors, case_id, "insufficient evidence requires human_label=unknown")
        if evidence_type == "live content review" and _notes_indicate_no_live_content(review_notes):
            _row_issue(
                errors,
                case_id,
                "live content review cannot be used when notes indicate no live content",
            )

        outcome = clean(row.get("review_outcome")).lower()
        if outcome not in ALLOWED_OUTCOMES:
            _row_issue(errors, case_id, f"invalid review_outcome: {outcome!r}")
        elif would_block is not None and outcome != _expected_outcome(label, would_block):
            _row_issue(
                errors,
                case_id,
                "review_outcome does not match human_label and shadow_would_block",
            )

        second_label = clean(row.get("second_human_label")).lower()
        second_reviewer = clean(row.get("second_reviewer_id"))
        if second_label or second_reviewer:
            if not second_label or second_label not in ALLOWED_LABELS:
                _row_issue(errors, case_id, "second_human_label is missing or invalid")
            if not second_reviewer:
                _row_issue(errors, case_id, "second_reviewer_id is required with second_human_label")
            elif _is_disallowed_reviewer(second_reviewer):
                _row_issue(
                    errors,
                    case_id,
                    "second_reviewer_id cannot be a model or AI agent; independent human review is required",
                )
            elif reviewer_id and _normalized_reviewer_id(second_reviewer) == _normalized_reviewer_id(
                reviewer_id
            ):
                _row_issue(
                    errors,
                    case_id,
                    "second_reviewer_id must be an independent reviewer",
                )

        critical_stratum = clean(row.get("critical_benign_stratum")).lower()
        if critical_stratum and critical_stratum not in ALLOWED_CRITICAL_BENIGN_STRATA:
            _row_issue(errors, case_id, f"invalid critical_benign_stratum: {critical_stratum!r}")
        deterministic_action = clean(row.get("deterministic_would_block"))
        if deterministic_action and parse_bool(deterministic_action) is None:
            _row_issue(errors, case_id, "deterministic_would_block must be true or false")

    return ValidationResult(
        rows=tuple(normalized_rows),
        columns=normalized_columns,
        errors=tuple(errors),
        warnings=tuple(warnings),
        pending_case_ids=tuple(pending_case_ids),
    )


def validate_labels(path: str | Path, expected_total: int | None = None) -> ValidationResult:
    try:
        rows, columns = read_label_csv(path)
    except (OSError, ValueError) as error:
        return ValidationResult(
            rows=(),
            columns=(),
            errors=(f"Unable to read labels CSV: {error}",),
            warnings=(),
            pending_case_ids=(),
        )
    return validate_rows(rows, columns, expected_total=expected_total)


def print_validation_result(result: ValidationResult) -> None:
    print(f"[*] Progress: {result.labeled_cases}/{result.total_cases} cases labeled.")
    print("\n--- Validation Results ---")
    print(f"Errors found: {len(result.errors)}")
    for error in result.errors[:20]:
        print(f"  [ERROR] {error}")
    if len(result.errors) > 20:
        print(f"  ... and {len(result.errors) - 20} more errors")
    print(f"Warnings found: {len(result.warnings)}")
    for warning in result.warnings[:20]:
        print(f"  [WARN] {warning}")
    if len(result.warnings) > 20:
        print(f"  ... and {len(result.warnings) - 20} more warnings")
    if result.errors:
        print("\n[!] Validation failed with errors.")
    elif result.pending_case_ids:
        print(f"\n[!] Review is incomplete: {len(result.pending_case_ids)} cases remain pending.")
    else:
        print("\n[+] Success: all labels are valid and complete.")


def cli(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Validate ML replay human labels")
    parser.add_argument("csv_path", help="Path to labels.csv")
    parser.add_argument("--expected-total", type=int, default=None)
    parser.add_argument(
        "--allow-pending",
        action="store_true",
        help="Return success for a structurally valid queue with unlabeled cases",
    )
    args = parser.parse_args(argv)
    result = validate_labels(args.csv_path, expected_total=args.expected_total)
    print_validation_result(result)
    if result.errors:
        return 1
    if result.pending_case_ids and not args.allow_pending:
        return 2
    return 0