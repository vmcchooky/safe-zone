"""Normalize a replay label queue to the versioned 21-column template."""

from __future__ import annotations

import argparse
import csv
from pathlib import Path

try:
    from replay_labels import clean, read_label_csv
except ModuleNotFoundError:  # pragma: no cover - supports package-style imports
    from ml.src.replay_labels import clean, read_label_csv


QUEUE_COLUMNS = (
    "case_id",
    "domain",
    "traffic_stratum",
    "source_ref",
    "source_trust_tier",
    "model_revision",
    "model_threshold",
    "shadow_would_block",
    "shadow_probability",
    "human_label",
    "label_confidence",
    "evidence_type",
    "reviewer_id",
    "reviewed_at",
    "evidence_refs",
    "review_outcome",
    "review_notes",
    "critical_benign_stratum",
    "deterministic_would_block",
    "second_human_label",
    "second_reviewer_id",
)


def normalize_rows(path: str | Path, expected_total: int = 137) -> list[dict[str, str]]:
    """Return existing rows with the canonical header and no invented review data."""

    rows, columns = read_label_csv(path)
    if len(rows) != expected_total:
        raise ValueError(f"case count mismatch: labels={len(rows)}, expected={expected_total}")
    unknown_columns = sorted(set(columns) - set(QUEUE_COLUMNS))
    if unknown_columns:
        raise ValueError("unknown columns cannot be preserved safely: " + ", ".join(unknown_columns))
    return [
        {column: clean(row.get(column)) for column in QUEUE_COLUMNS}
        for row in rows
    ]


def write_queue(path: str | Path, rows: list[dict[str, str]]) -> None:
    """Atomically write a normalized queue without changing review values."""

    destination = Path(path)
    temporary = destination.with_name(f".{destination.name}.regen")
    with temporary.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=QUEUE_COLUMNS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    temporary.replace(destination)


def regenerate(input_path: str | Path, output_path: str | Path, expected_total: int = 137) -> int:
    rows = normalize_rows(input_path, expected_total=expected_total)
    write_queue(output_path, rows)
    print(f"[+] Wrote {len(rows)} cases with {len(QUEUE_COLUMNS)} columns to {output_path}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Normalize an ML replay label queue")
    parser.add_argument("input_csv")
    parser.add_argument("output_csv")
    parser.add_argument("--expected-total", type=int, default=137)
    args = parser.parse_args(argv)
    try:
        return regenerate(args.input_csv, args.output_csv, expected_total=args.expected_total)
    except (OSError, ValueError) as error:
        print(f"[ERROR] Unable to regenerate queue: {error}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())