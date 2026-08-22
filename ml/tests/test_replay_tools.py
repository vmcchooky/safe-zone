import json

from ml.src.replay_labels import OPTIONAL_COLUMNS, REQUIRED_COLUMNS, validate_rows
from ml.src.regenerate_labels import QUEUE_COLUMNS, normalize_rows, write_queue
from ml.src.report_fp import calculate_metrics, main as report_main


def _case(case_id, label="", would_block="false", **overrides):
    row = {column: "" for column in REQUIRED_COLUMNS}
    row.update(
        {
            "case_id": case_id,
            "domain": f"{case_id}.example.test",
            "traffic_stratum": "strong_safe",
            "source_ref": "fixture",
            "source_trust_tier": "reviewed",
            "model_revision": "revision-1",
            "model_threshold": "0.85",
            "shadow_would_block": would_block,
            "shadow_probability": "0.90" if would_block == "true" else "0.10",
            "human_label": label,
        }
    )
    row.update(overrides)
    return row


def test_pending_queue_is_not_complete():
    result = validate_rows(
        [_case("replay-1"), _case("replay-2")],
        REQUIRED_COLUMNS,
        expected_total=2,
    )

    assert result.errors == ()
    assert result.pending_case_ids == ("replay-1", "replay-2")
    assert not result.is_complete


def test_validation_rejects_missing_evidence_and_inconsistent_outcome():
    result = validate_rows(
        [
            _case(
                "replay-1",
                label="benign",
                would_block="true",
                label_confidence="high",
                evidence_type="official source",
                reviewer_id="reviewer-a",
                reviewed_at="2026-08-09T10:00:00Z",
                review_outcome="true_positive",
            )
        ],
        REQUIRED_COLUMNS,
        expected_total=1,
    )

    assert any("evidence_refs is required" in error for error in result.errors)
    assert any("review_notes is required" in error for error in result.errors)
    assert any("review_outcome does not match" in error for error in result.errors)


def test_metrics_exclude_non_binary_labels_and_report_missing_review_gates():
    columns = REQUIRED_COLUMNS
    rows = [
        _case(
            "safe-blocked",
            label="benign",
            would_block="true",
            label_confidence="high",
            evidence_type="official source",
            reviewer_id="reviewer-a",
            reviewed_at="2026-08-09T10:00:00Z",
            evidence_refs="ticket-1",
            review_outcome="false_positive",
            review_notes="Verified official owner.",
        ),
        _case(
            "safe-pass",
            label="benign",
            would_block="false",
            label_confidence="high",
            evidence_type="verified owner",
            reviewer_id="reviewer-a",
            reviewed_at="2026-08-09T10:01:00Z",
            evidence_refs="ticket-2",
            review_outcome="true_negative",
            review_notes="Verified official owner.",
        ),
        _case(
            "malicious-blocked",
            label="malicious",
            would_block="true",
            traffic_stratum="strong_malicious",
            label_confidence="high",
            evidence_type="strong feed with current status",
            reviewer_id="reviewer-b",
            reviewed_at="2026-08-09T10:02:00Z",
            evidence_refs="feed-1",
            review_outcome="true_positive",
            review_notes="Indicator is current.",
        ),
        _case(
            "unknown-case",
            label="unknown",
            would_block="true",
            label_confidence="low",
            evidence_type="insufficient evidence",
            reviewer_id="reviewer-b",
            reviewed_at="2026-08-09T10:03:00Z",
            evidence_refs="ticket-3",
            review_outcome="unresolved",
            review_notes="Insufficient evidence to adjudicate.",
        ),
    ]

    result = validate_rows(rows, columns, expected_total=4)
    assert result.errors == ()
    metrics = calculate_metrics(result.rows, 0.85, result.columns)

    assert metrics["false_positives"] == 1
    assert metrics["fpr_at_threshold"] == 0.5
    assert metrics["recall_at_threshold"] == 1.0
    assert metrics["non_binary_labels"]["unknown"] == 1
    assert metrics["unresolved_count"] == 1
    assert metrics["unresolved_case_ids"] == ["unknown-case"]
    assert metrics["critical_benign"]["status"] == "unavailable_missing_column"
    assert "critical benign strata were not collected" in metrics["approval_blockers"]
    assert "unresolved reviewed cases remain: 1" in metrics["approval_blockers"]


def test_metrics_do_not_treat_empty_optional_gate_columns_as_complete():
    columns = REQUIRED_COLUMNS | OPTIONAL_COLUMNS
    rows = [
        _case(
            "safe",
            label="benign",
            label_confidence="high",
            evidence_type="verified owner",
            reviewer_id="reviewer-a",
            reviewed_at="2026-08-09T10:00:00Z",
            evidence_refs="ticket-1",
            review_outcome="true_negative",
            review_notes="Verified owner.",
        ),
        _case(
            "bad",
            label="malicious",
            would_block="true",
            traffic_stratum="strong_malicious",
            label_confidence="high",
            evidence_type="strong feed with current status",
            reviewer_id="reviewer-b",
            reviewed_at="2026-08-09T10:01:00Z",
            evidence_refs="feed-1",
            review_outcome="true_positive",
            review_notes="Current indicator.",
        ),
    ]

    result = validate_rows(rows, columns, expected_total=2)
    assert result.errors == ()
    metrics = calculate_metrics(result.rows, 0.85, result.columns, double_label_target=2)

    assert metrics["critical_benign"]["status"] == "incomplete"
    assert metrics["reviewer_agreement"]["status"] == "not_collected"
    assert metrics["deterministic_policy"]["status"] == "incomplete"
    assert metrics["approval_blockers"]


def test_report_marks_pending_queue_and_preserves_canary_block(tmp_path):
    labels_path = tmp_path / "labels.csv"
    pending_case = _case("replay-1")
    header = sorted(REQUIRED_COLUMNS)
    labels_path.write_text(
        ",".join(header)
        + "\n"
        + ",".join(pending_case[column] for column in header)
        + "\n",
        encoding="utf-8",
    )
    summary_path = tmp_path / "review-summary.json"
    summary_path.write_text(
        json.dumps(
            {
                "total_cases": 1,
                "model_threshold": 0.85,
                "approval_state": {"product": "pending", "security": "pending", "canary": "blocked"},
            }
        ),
        encoding="utf-8",
    )
    packet_path = tmp_path / "approval-packet.md"
    packet_path.write_text(
        "- Cases: `1`; human labels complete: `0/1`\n\n## Current decision\nApproval is blocked.\n",
        encoding="utf-8",
    )

    report_args = [
        "--labels",
        str(labels_path),
        "--summary",
        str(summary_path),
        "--packet",
        str(packet_path),
    ]
    assert report_main(report_args) == 2
    assert report_main([*report_args, "--allow-pending"]) == 0
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    packet = packet_path.read_text(encoding="utf-8")
    assert summary["false_positive_metrics"]["status"] == "blocked_until_human_labels_complete"
    assert summary["approval_state"]["canary"] == "blocked"
    assert "False Positive Rate" not in packet


def test_queue_regeneration_preserves_review_fields_and_adds_optional_columns(tmp_path):
    input_path = tmp_path / "legacy-labels.csv"
    output_path = tmp_path / "labels.csv"
    header = sorted(REQUIRED_COLUMNS)
    first = _case("replay-1")
    second = _case("replay-2", reviewer_id="reviewer-a")
    input_path.write_text(
        ",".join(header)
        + "\n"
        + ",".join(first[column] for column in header)
        + "\n"
        + ",".join(second[column] for column in header)
        + "\n",
        encoding="utf-8",
    )

    rows = normalize_rows(input_path, expected_total=2)
    write_queue(output_path, rows)

    content = output_path.read_text(encoding="utf-8").splitlines()
    assert content[0].split(",") == list(QUEUE_COLUMNS)
    assert len(content) == 3
    assert rows[0]["case_id"] == "replay-1"
    assert all(rows[0][column] == "" for column in QUEUE_COLUMNS[-4:])
    assert rows[1]["reviewer_id"] == "reviewer-a"


def test_queue_regeneration_rejects_wrong_case_count(tmp_path):
    input_path = tmp_path / "labels.csv"
    header = sorted(REQUIRED_COLUMNS)
    row = _case("replay-1")
    input_path.write_text(
        ",".join(header) + "\n" + ",".join(row[column] for column in header) + "\n",
        encoding="utf-8",
    )

    try:
        normalize_rows(input_path, expected_total=2)
    except ValueError as error:
        assert "case count mismatch" in str(error)
    else:
        raise AssertionError("expected case-count validation failure")


def _complete_case(case_id, label="benign", would_block="false", **overrides):
    outcome = {
        ("benign", "true"): "false_positive",
        ("benign", "false"): "true_negative",
        ("malicious", "true"): "true_positive",
        ("malicious", "false"): "false_negative",
    }.get((label, would_block), "unresolved")
    row = _case(
        case_id,
        label=label,
        would_block=would_block,
        label_confidence="high",
        evidence_type="official source",
        reviewer_id="reviewer-a",
        reviewed_at="2026-08-09T10:00:00Z",
        evidence_refs="ticket-1",
        review_outcome=outcome,
        review_notes="Verified official owner.",
    )
    row.update(overrides)
    return row


def test_validation_rejects_ai_reviewer_ids():
    result = validate_rows(
        [_complete_case("replay-1", reviewer_id="gemini-adjudicator")],
        REQUIRED_COLUMNS,
        expected_total=1,
    )

    assert any("cannot be a model or AI agent" in error for error in result.errors)


def test_validation_rejects_identical_double_label_reviewer():
    result = validate_rows(
        [
            _complete_case(
                "replay-1",
                second_human_label="benign",
                second_reviewer_id="reviewer-a",
            )
        ],
        REQUIRED_COLUMNS | OPTIONAL_COLUMNS,
        expected_total=1,
    )

    assert any("independent reviewer" in error for error in result.errors)


def test_validation_rejects_live_content_review_without_live_content():
    result = validate_rows(
        [
            _complete_case(
                "replay-1",
                evidence_type="live content review",
                review_notes='DNS resolution failed for hostname "example.test".',
            )
        ],
        REQUIRED_COLUMNS,
        expected_total=1,
    )

    assert any("no live content" in error for error in result.errors)


def test_validation_accepts_independent_human_double_label():
    result = validate_rows(
        [
            _complete_case(
                "replay-1",
                second_human_label="benign",
                second_reviewer_id="reviewer-b",
            )
        ],
        REQUIRED_COLUMNS | OPTIONAL_COLUMNS,
        expected_total=1,
    )

    assert result.errors == ()
    assert result.pending_case_ids == ()


def test_unresolved_review_blocks_report_even_with_other_waivers(tmp_path):
    columns = REQUIRED_COLUMNS | OPTIONAL_COLUMNS
    rows = [
        _complete_case(
            "safe-1",
            label="benign",
            critical_benign_stratum="trusted_brand",
            deterministic_would_block="false",
        ),
        _complete_case(
            "safe-2",
            label="benign",
            critical_benign_stratum="government_education",
            deterministic_would_block="false",
        ),
        _complete_case(
            "safe-3",
            label="benign",
            critical_benign_stratum="shared_hosting",
            deterministic_would_block="false",
        ),
        _complete_case(
            "bad-1",
            label="malicious",
            would_block="true",
            deterministic_would_block="false",
        ),
        _case(
            "unknown-dead",
            label="unknown",
            label_confidence="low",
            evidence_type="insufficient evidence",
            reviewer_id="reviewer-a",
            reviewed_at="2026-08-09T10:00:00Z",
            evidence_refs="ticket-1",
            review_outcome="unresolved",
            review_notes="NXDOMAIN domain inactive.",
            deterministic_would_block="false",
        ),
    ]

    result = validate_rows(rows, columns, expected_total=5)
    assert result.errors == ()
    assert result.pending_case_ids == ()

    waivers = {
        "critical_benign_strata": ["idn_punycode"],
        "double_label": True,
        "reasons": {
            "idn_punycode": "Sample has no live IDN cases.",
            "double_label": "Single reviewer scope.",
        },
    }

    metrics = calculate_metrics(
        result.rows,
        0.85,
        result.columns,
        double_label_target=35,
        waivers=waivers,
    )

    assert metrics["false_positives"] == 0
    assert metrics["fpr_at_threshold"] == 0.0
    assert metrics["recall_at_threshold"] == 1.0
    assert metrics["critical_benign"]["status"] == "available_with_waiver"
    assert metrics["reviewer_agreement"]["status"] == "waived"
    assert metrics["unresolved_count"] == 1
    assert metrics["unresolved_case_ids"] == ["unknown-dead"]
    assert metrics["approval_blockers"] == ["unresolved reviewed cases remain: 1"]

    resolved_metrics = calculate_metrics(
        result.rows[:-1],
        0.85,
        result.columns,
        double_label_target=35,
        waivers=waivers,
    )
    assert resolved_metrics["unresolved_count"] == 0
    assert resolved_metrics["approval_blockers"] == []

    labels_path = tmp_path / "labels.csv"
    summary_path = tmp_path / "review-summary.json"
    packet_path = tmp_path / "approval-packet.md"

    header = sorted(columns)
    labels_content = [",".join(header)]
    for r in rows:
        labels_content.append(",".join(str(r.get(col, "")) for col in header))
    labels_path.write_text("\n".join(labels_content) + "\n", encoding="utf-8")

    summary_path.write_text(
        json.dumps(
            {
                "total_cases": 5,
                "model_threshold": 0.85,
                "approval_state": {"product": "pending", "security": "pending", "canary": "blocked"},
                "waivers": waivers,
            }
        ),
        encoding="utf-8",
    )
    packet_path.write_text(
        "- Cases: `5`; human labels complete: `0/5`\n\n## Current decision\nApproval is blocked.\n",
        encoding="utf-8",
    )

    exit_code = report_main(
        [
            "--labels",
            str(labels_path),
            "--summary",
            str(summary_path),
            "--packet",
            str(packet_path),
        ]
    )
    assert exit_code == 3
    summary_data = json.loads(summary_path.read_text(encoding="utf-8"))
    assert summary_data["approval_state"]["canary"] == "blocked_by_review_gates"
    assert summary_data["false_positive_metrics"]["approval_blockers"] == [
        "unresolved reviewed cases remain: 1"
    ]
