"""Verify that a restarted core API has rolled URL ML back to disabled."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from src.replay_v10_url_shadow import _json_request
from src.select_v10_url_aware import _write_json


def check(base_url: str, output_path: str | Path) -> dict[str, object]:
    status, _, _ = _json_request(base_url.rstrip("/") + "/v1/status")
    url_status = (status.get("ml") or {}).get("url") or {}
    baseline, _, _ = _json_request(
        base_url.rstrip("/") + "/v1/analyze?domain=example.com"
    )
    observed, raw, _ = _json_request(
        base_url.rstrip("/") + "/v1/analyze",
        method="POST",
        payload={
            "domain": "example.com",
            "requested_url": "https://example.com/login?token=rollback-secret",
        },
    )
    observation = observed.get("url_ml") or {}
    gates = {
        "mode_disabled": url_status.get("mode") == "disabled",
        "classifier_disabled": not bool(url_status.get("enabled")),
        "url_not_evaluated": not bool(observation.get("evaluated")),
        "domain_response_parity": all(
            observed.get(field) == baseline.get(field)
            for field in ("domain", "verdict", "score", "confidence")
        ),
        "raw_context_leaks_zero": "rollback-secret" not in raw
        and "requested_url" not in raw,
    }
    report: dict[str, object] = {
        "schema_version": 1,
        "kind": "url_ml_shadow_rollback_drill",
        "runtime": {
            "base_url": base_url,
            "mode": url_status.get("mode"),
            "enabled": url_status.get("enabled"),
            "state": url_status.get("state"),
        },
        "gates": gates,
        "passed": all(gates.values()),
        "raw_url_persisted": False,
    }
    _write_json(Path(output_path).resolve(), report)
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Check URL ML disabled rollback")
    parser.add_argument("--base-url", default="http://127.0.0.1:18082")
    parser.add_argument(
        "--output",
        default=str(BASE_DIR / "experiments" / "v10-url-shadow-rollback.json"),
    )
    args = parser.parse_args()
    result = check(args.base_url, args.output)
    print(json.dumps(result, indent=2))
