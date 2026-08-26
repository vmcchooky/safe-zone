"""Freeze a real operational drift baseline from live URL shadow canary traffic.

Reads the *cumulative* runtime telemetry snapshot from /v1/status, extracts
the probability histogram observed under the current seeded canary scope, and
writes a frozen artifact:

  ml/models/url-baseline/operational-baseline.json   (mounted into core-api)
  ml/experiments/v10-url-canary-operational-baseline.json  (evidence copy)

The artifact carries explicit provenance: traffic scope, observation window,
sample count, seed, policy revision. The runtime loads it at startup as an
operational drift reference (fail-open); it never affects classification.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent.parent

PROBABILITY_BUCKETS = [
    "lt_0_10", "0_10_0_19", "0_20_0_29", "0_30_0_39", "0_40_0_49",
    "0_50_0_59", "0_60_0_69", "0_70_0_79", "0_80_0_89", "gte_0_90",
]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:8080")
    parser.add_argument("--traffic-scope", required=True,
                        help="honest description of the observed scope, e.g. "
                             "'compose-staging canary 5pct; synthetic-driven sdk'")
    parser.add_argument("--window-seconds", type=int, required=True)
    parser.add_argument("--min-samples", type=int, default=25)
    args = parser.parse_args()

    with urllib.request.urlopen(
        args.base_url.rstrip("/") + "/v1/status", timeout=15
    ) as resp:
        doc = json.loads(resp.read().decode("utf-8"))
    url_ml = ((doc.get("ml") or {}).get("url") or {})
    if not url_ml.get("enabled"):
        print("URL ML is not enabled; refusing to freeze a baseline")
        return 1

    histogram = url_ml.get("probability_histogram") or {}
    counts = {}
    total = 0
    for bucket in PROBABILITY_BUCKETS:
        value = int(histogram.get(bucket) or 0)
        counts[bucket] = value
        total += value
    if total < args.min_samples:
        print(f"insufficient samples for a frozen reference: {total} < {args.min_samples}")
        return 1

    sampling = url_ml.get("sampling") or {}
    artifact = {
        "schema_version": 1,
        "kind": "url_ml_operational_baseline",
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "model_version": url_ml.get("model_version"),
        "revision": url_ml.get("revision"),
        "policy_revision": url_ml.get("policy_revision"),
        "traffic_scope": args.traffic_scope,
        "observation_window": {
            "window_seconds": args.window_seconds,
            "sample_count": int(sampling.get("selected") or total),
            "excluded": int(sampling.get("excluded") or 0),
            "seeded_scope_percent": int(sampling.get("percent") or 0),
            "selector_algorithm": sampling.get("algorithm"),
            "selector_revision": sampling.get("selector_revision"),
        },
        "distribution_histograms": {
            "probability_histogram": counts,
        },
        "provenance": {
            "source_runtime": args.base_url,
            "collector": "freeze_url_canary_baseline.py",
            "raw_url_persisted": False,
            "aggregate_only": True,
            "note": (
                "frozen from live shadow canary telemetry on the compose "
                "staging runtime; supersedes the offline balanced proxy as "
                "the drift reference once loaded"
            ),
        },
        "psi_thresholds": {"watch": 0.1, "alert": 0.25},
        "minimum_live_samples": 100,
    }

    payload = json.dumps(artifact, indent=2, sort_keys=True) + "\n"
    sha = hashlib.sha256(payload.encode("utf-8")).hexdigest()

    models_dir = BASE_DIR / "ml" / "models" / "url-baseline"
    models_dir.mkdir(parents=True, exist_ok=True)
    (models_dir / "operational-baseline.json").write_text(payload, encoding="utf-8")

    evidence = BASE_DIR / "ml" / "experiments" / "v10-url-canary-operational-baseline.json"
    evidence.write_text(payload, encoding="utf-8")

    print(json.dumps({
        "sha256": sha,
        "reference_rows": total,
        "scope_percent": artifact["observation_window"]["seeded_scope_percent"],
        "written": [str(models_dir / "operational-baseline.json"), str(evidence)],
    }, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
