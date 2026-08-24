import csv
import hashlib
import json
from pathlib import Path

import pandas as pd
import pytest

from src.training_data import (
    _evaluation_group,
    _frozen_evaluation_mask,
    load_time_forward_hard_positives,
    prepare_training_partitions,
)


def test_shared_hosting_evaluation_group_is_tenant_aware():
    group, root = _evaluation_group(
        "login.victim.weebly.com", "weebly.com", {"weebly.com"}
    )
    assert group == "victim.weebly.com"
    assert root == "weebly.com"

    nested_group, nested_root = _evaluation_group(
        "login.victim.host.example.com",
        "example.com",
        {"example.com", "host.example.com"},
    )
    assert nested_group == "victim.host.example.com"
    assert nested_root == "host.example.com"

    frame = pd.DataFrame(
        {
            "domain_ascii": [
                "login.victim.weebly.com",
                "other.victim.weebly.com",
                "unrelated.weebly.com",
            ],
            "registrable_domain": ["weebly.com", "weebly.com", "weebly.com"],
        }
    )
    mask = _frozen_evaluation_mask(
        frame,
        {
            "groups": {"victim.weebly.com"},
            "shared_groups_by_root": {
                "weebly.com": {"victim.weebly.com"}
            },
        },
    )
    assert mask.tolist() == [True, True, False]


def _write_partition(path: Path, rows: list[dict]) -> None:
    defaults = {
        "domain": "",
        "label": 0,
        "domain_ascii": "",
        "registrable_domain": "",
        "lexical_verdict": "SAFE",
        "lexical_score": 0,
        "is_ml_candidate": False,
        "reasons": "",
        "source": "top_1m",
        "impersonated_org": "",
        "impersonated_org_category": "",
        "detected_date": "",
        "partition": "",
    }
    pd.DataFrame([{**defaults, **row} for row in rows]).to_parquet(path, index=False)


def test_time_forward_hard_positive_rejects_registrable_overlap(tmp_path):
    source_path = tmp_path / "adaptation.parquet"
    frame = pd.DataFrame(
        [
            {
                "domain": "tenant.shared.test",
                "label": 1,
                "domain_ascii": "tenant.shared.test",
                "registrable_domain": "shared.test",
                "source": "phishtank_time_forward",
                "evaluation_group": "tenant.shared.test",
            }
        ]
    )
    frame.to_parquet(source_path, index=False)
    source_sha = hashlib.sha256(source_path.read_bytes()).hexdigest()
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "outputs": {
                    "adaptation": {
                        "path": str(source_path),
                        "rows": 1,
                        "sha256": source_sha,
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="overlaps model partitions"):
        load_time_forward_hard_positives(
            {
                "source_parquet": str(source_path),
                "public_manifest": str(manifest_path),
                "manifest_output": "adaptation",
                "required_source": "phishtank_time_forward",
            },
            existing_groups={"shared.test"},
            excluded_groups=set(),
        )


def test_hard_negative_weighting_and_frozen_challenge_exclusion(tmp_path):
    source_partitions = tmp_path / "source-partitions"
    output_partitions = tmp_path / "output-partitions"
    artifacts = tmp_path / "artifacts"
    source_partitions.mkdir()

    _write_partition(
        source_partitions / "train.parquet",
        [
            {
                "domain": "hard-example.com",
                "domain_ascii": "hard-example.com",
                "registrable_domain": "hard-example.com",
                "lexical_verdict": "SUSPICIOUS",
                "lexical_score": 60,
                "is_ml_candidate": True,
                "reasons": "domain is long",
                "source": "vietnam_whitelist",
                "partition": "train",
            },
            {
                "domain": "frozen-example.com",
                "domain_ascii": "frozen-example.com",
                "registrable_domain": "frozen-example.com",
                "lexical_verdict": "SUSPICIOUS",
                "lexical_score": 60,
                "is_ml_candidate": True,
                "source": "vietnam_whitelist",
                "partition": "train",
            },
            {
                "domain": "sub.representative-malicious.test",
                "domain_ascii": "sub.representative-malicious.test",
                "registrable_domain": "representative-malicious.test",
                "label": 1,
                "source": "phishtank",
                "partition": "train",
            },
        ],
    )
    for split, domain in (("val", "val.test"), ("cal", "cal.test"), ("test", "test.test")):
        _write_partition(
            source_partitions / f"{split}.parquet",
            [
                {
                    "domain": domain,
                    "domain_ascii": domain,
                    "registrable_domain": domain,
                    "partition": split,
                }
            ],
        )

    labels_path = tmp_path / "labels.csv"
    with open(labels_path, "w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=["domain", "human_label", "review_outcome"]
        )
        writer.writeheader()
        writer.writerow(
            {
                "domain": "frozen-example.com",
                "human_label": "benign",
                "review_outcome": "false_positive",
            }
        )

    evidence_path = tmp_path / "evidence.csv"
    with open(evidence_path, "w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["domain", "detail_url"])
        writer.writeheader()
        writer.writerows(
            [
                {
                    "domain": "hard-example.com",
                    "detail_url": "https://tinnhiemmang.vn/record/hard-example",
                },
                {
                    "domain": "frozen-example.com",
                    "detail_url": "https://tinnhiemmang.vn/record/frozen-example",
                },
                {
                    "domain": "hard-example.com",
                    "detail_url": "https://tinnhiemmang.vn.attacker.example/record",
                },
            ]
        )
    source_bytes = evidence_path.read_bytes()
    data_manifest_path = tmp_path / "data_manifest.json"
    data_manifest_path.write_text(
        json.dumps(
            {
                "raw_sources": [
                    {
                        "logical_name": "evidence.csv",
                        "sha256": hashlib.sha256(source_bytes).hexdigest(),
                        "bytes": len(source_bytes),
                        "trust_tier": "strong-safe",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    evaluation_labels_path = tmp_path / "representative-labels.csv"
    with open(evaluation_labels_path, "w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["case_id", "domain", "human_label", "reviewer_id"],
        )
        writer.writeheader()
        writer.writerow(
            {
                "case_id": "replay-1",
                "domain": "representative-malicious.test",
                "human_label": "malicious",
                "reviewer_id": "reviewer.vmc",
            }
        )

    shared_hosting_path = tmp_path / "shared_hosting.json"
    shared_hosting_path.write_text("[]\n", encoding="utf-8")

    hard_positive_path = tmp_path / "adaptation.parquet"
    _write_partition(
        hard_positive_path,
        [
            {
                "domain": "novel-threat.example",
                "label": 1,
                "domain_ascii": "novel-threat.example",
                "registrable_domain": "novel-threat.example",
                "source": "phishtank_time_forward",
                "partition": "train",
            }
        ],
    )
    hard_positive_frame = pd.read_parquet(hard_positive_path)
    hard_positive_frame["evaluation_group"] = "novel-threat.example"
    hard_positive_frame.to_parquet(hard_positive_path, index=False)
    hard_positive_sha = hashlib.sha256(hard_positive_path.read_bytes()).hexdigest()
    time_forward_manifest_path = tmp_path / "time-forward-manifest.json"
    time_forward_manifest_path.write_text(
        json.dumps(
            {
                "outputs": {
                    "adaptation": {
                        "path": str(hard_positive_path),
                        "rows": 1,
                        "sha256": hard_positive_sha,
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    manifest = prepare_training_partitions(
        source_partitions,
        output_partitions,
        {
            "frozen_challenge_labels": str(labels_path),
            "frozen_evaluation_labels": str(evaluation_labels_path),
            "evaluation_group_policy": {
                "shared_hosting_snapshot": str(shared_hosting_path),
                "shared_hosting_extensions": [],
            },
            "hard_negative": {
                "source_csv": str(evidence_path),
                "data_manifest": str(data_manifest_path),
                "logical_name": "evidence.csv",
                "allowed_evidence_hosts": ["tinnhiemmang.vn"],
                "weight": 3.0,
                "max_samples": 10,
            },
            "hard_positive": {
                "source_parquet": str(hard_positive_path),
                "public_manifest": str(time_forward_manifest_path),
                "manifest_output": "adaptation",
                "required_source": "phishtank_time_forward",
            },
        },
        artifacts,
    )

    train = pd.read_parquet(output_partitions / "train.parquet")
    assert train["domain_ascii"].tolist() == [
        "hard-example.com",
        "novel-threat.example",
    ]
    assert train["sample_weight"].tolist() == [3.0, 1.0]
    assert train["label_provenance"].tolist() == [
        "benign_proxy",
        "verified_online_time_forward",
    ]
    assert manifest["frozen_challenge"]["excluded_rows_by_partition"]["train"] == 1
    assert manifest["frozen_evaluation"]["case_count"] == 1
    assert manifest["frozen_evaluation"]["excluded_rows_by_partition"]["train"] == 1
    assert manifest["combined_exclusions"]["excluded_rows_by_partition"]["train"] == 2
    assert manifest["hard_negative"]["counts"]["selected_rows"] == 1
    assert manifest["hard_positive"]["selected_rows"] == 1
    assert manifest["hard_positive"]["overlap_with_existing_partitions"] == 0
