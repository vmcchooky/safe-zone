import pandas as pd

from src.build_time_forward_snapshot import _dedupe_groups, _training_rows


def test_time_forward_group_deduplication_is_deterministic():
    frame = pd.DataFrame(
        [
            {
                "domain_ascii": "later.example",
                "evaluation_group": "example",
                "verification_time": pd.Timestamp("2026-08-02T00:00:00Z"),
            },
            {
                "domain_ascii": "first.example",
                "evaluation_group": "example",
                "verification_time": pd.Timestamp("2026-08-01T00:00:00Z"),
            },
        ]
    )
    result = _dedupe_groups(frame, ["verification_time", "domain_ascii"])
    assert result["domain_ascii"].tolist() == ["first.example"]


def test_time_forward_training_rows_keep_provenance():
    frame = pd.DataFrame(
        [
            {
                "domain_ascii": "threat.example",
                "registrable_domain": "threat.example",
                "evaluation_group": "threat.example",
                "target": "Example Bank",
                "source_record_id": "42",
                "verification_time": pd.Timestamp("2026-08-01T00:00:00Z"),
            }
        ]
    )
    result = _training_rows(frame)
    assert result.loc[0, "label"] == 1
    assert result.loc[0, "source"] == "phishtank_time_forward"
    assert result.loc[0, "evaluation_group"] == "threat.example"
    assert result.loc[0, "source_record_id"] == "42"
