"""Replay frozen URL evidence through a running shadow-only core API.

The report contains aggregate counters only. Raw URLs and query values are never
written to the output artifact.
"""

from __future__ import annotations

import argparse
import json
import math
import statistics
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, Mapping

import pandas as pd

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from src.select_v10_url_aware import _load_json, _require_hash, _write_json
from src.training_data import compute_file_sha256, resolve_ml_path


def _json_request(
    url: str, method: str = "GET", payload: Mapping[str, Any] | None = None
) -> tuple[Dict[str, Any], str, float]:
    body = None
    headers = {"Accept": "application/json"}
    if payload is not None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    started = time.perf_counter()
    with urllib.request.urlopen(request, timeout=15) as response:
        raw = response.read().decode("utf-8")
        latency_ms = (time.perf_counter() - started) * 1000
        return json.loads(raw), raw, latency_ms


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    rank = max(0, min(len(ordered) - 1, math.ceil(percentile * len(ordered)) - 1))
    return round(float(ordered[rank]), 3)


def _calibration_metrics(rows: list[Dict[str, Any]]) -> Dict[str, Any]:
    evaluated = [row for row in rows if row["evaluated"]]
    if not evaluated:
        return {"rows": 0, "brier_score": 0.0, "ece_10": 0.0}
    brier = statistics.fmean(
        (float(row["probability"]) - int(row["label"])) ** 2 for row in evaluated
    )
    ece = 0.0
    for index in range(10):
        lower = index / 10
        upper = (index + 1) / 10
        bucket = [
            row
            for row in evaluated
            if float(row["probability"]) >= lower
            and (
                float(row["probability"]) < upper
                or (index == 9 and float(row["probability"]) <= 1)
            )
        ]
        if not bucket:
            continue
        mean_probability = statistics.fmean(float(row["probability"]) for row in bucket)
        positive_rate = statistics.fmean(int(row["label"]) for row in bucket)
        ece += len(bucket) / len(evaluated) * abs(mean_probability - positive_rate)
    return {
        "rows": len(evaluated),
        "brier_score": round(brier, 6),
        "ece_10": round(ece, 6),
        "mean_probability": round(
            statistics.fmean(float(row["probability"]) for row in evaluated), 6
        ),
        "positive_rate": round(
            statistics.fmean(int(row["label"]) for row in evaluated), 6
        ),
        "note": "labelled staging replay diagnostic; not live-traffic calibration",
    }


def _replay_one(base_url: str, row: Mapping[str, Any]) -> Dict[str, Any]:
    domain = str(row["domain_ascii"])
    requested_url = str(row["requested_url"])
    baseline_url = base_url.rstrip("/") + "/v1/analyze?" + urllib.parse.urlencode(
        {"domain": domain}
    )
    baseline, _, baseline_latency = _json_request(baseline_url)
    observed, raw, observed_latency = _json_request(
        base_url.rstrip("/") + "/v1/analyze",
        method="POST",
        payload={
            "domain": domain,
            "requested_url": requested_url,
            "redirect_chain": [],
        },
    )
    url_ml = observed.get("url_ml") or {}
    parsed = urllib.parse.urlsplit(requested_url)
    secret_values = [
        value
        for _, value in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        if len(value) >= 4
    ]
    privacy_leak = requested_url in raw or any(value in raw for value in secret_values)
    parity = all(
        observed.get(field) == baseline.get(field)
        for field in ("domain", "verdict", "score", "confidence")
    )
    primary_malicious = str(baseline.get("verdict", "")).upper() == "MALICIOUS"
    return {
        "label": int(row["label"]),
        "parity": parity,
        "privacy_leak": privacy_leak,
        "sampled": bool(url_ml.get("sampled")),
        "evaluated": bool(url_ml.get("evaluated")),
        "would_promote": bool(url_ml.get("would_promote")),
        "would_promote_non_malicious_verdict": bool(url_ml.get("would_promote"))
        and not primary_malicious,
        "probability": float(url_ml.get("probability", 0.0)),
        "error_class": str(url_ml.get("error_class", "")),
        "client_latency_ms": observed_latency,
        "baseline_latency_ms": baseline_latency,
    }


def _invalid_context_checks(base_url: str) -> Dict[str, Any]:
    cases = [
        ("ftp_scheme", "example.com", "ftp://example.com/file"),
        ("credentials", "example.com", "https://user:secret@example.com/login"),
        ("host_mismatch", "safe.example", "https://evil.example/login"),
        ("oversized", "example.com", "https://example.com/" + "a" * 4096),
    ]
    accepted = 0
    fail_open = 0
    for _, domain, requested_url in cases:
        baseline, _, _ = _json_request(
            base_url.rstrip("/")
            + "/v1/analyze?"
            + urllib.parse.urlencode({"domain": domain})
        )
        observed, raw, _ = _json_request(
            base_url.rstrip("/") + "/v1/analyze",
            method="POST",
            payload={"domain": domain, "requested_url": requested_url},
        )
        url_ml = observed.get("url_ml") or {}
        if url_ml.get("evaluated"):
            accepted += 1
        if (
            url_ml.get("error_class") == "invalid_url_context"
            and observed.get("verdict") == baseline.get("verdict")
            and requested_url not in raw
        ):
            fail_open += 1
    return {"cases": len(cases), "unexpectedly_accepted": accepted, "fail_open": fail_open}


def replay(
    base_url: str,
    protocol_path: str | Path,
    output_path: str | Path,
    workers: int,
) -> Dict[str, Any]:
    started = time.time()
    protocol_file = Path(protocol_path).resolve()
    protocol = _load_json(protocol_file)
    snapshot_path = resolve_ml_path(protocol["outputs"]["snapshot_manifest"])
    snapshot = _load_json(snapshot_path)
    final_meta = snapshot["outputs"]["final"]
    final_path = resolve_ml_path(final_meta["path"])
    _require_hash(final_path, final_meta["sha256"], "v10 frozen final cohort")
    frame = pd.read_parquet(final_path)

    status_before, _, _ = _json_request(base_url.rstrip("/") + "/v1/status")
    url_status_before = (status_before.get("ml") or {}).get("url") or {}
    if url_status_before.get("mode") != "shadow" or not url_status_before.get("enabled"):
        raise RuntimeError(f"URL ML shadow is not ready: {url_status_before}")

    results: list[Dict[str, Any]] = []
    failures = 0
    with ThreadPoolExecutor(max_workers=max(1, workers)) as executor:
        futures = [
            executor.submit(_replay_one, base_url, row)
            for row in frame.to_dict("records")
        ]
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except (urllib.error.URLError, TimeoutError, ValueError, KeyError):
                failures += 1

    invalid = _invalid_context_checks(base_url)
    status_after, _, _ = _json_request(base_url.rstrip("/") + "/metrics")
    url_status_after = (status_after.get("ml") or {}).get("url") or {}
    latency = [row["client_latency_ms"] for row in results]
    benign = [row for row in results if row["label"] == 0]
    malicious = [row for row in results if row["label"] == 1]
    report = {
        "schema_version": 1,
        "kind": "url_ml_shadow_staging_replay",
        "protocol_sha256": compute_file_sha256(protocol_file),
        "snapshot_manifest_sha256": compute_file_sha256(snapshot_path),
        "input": {
            "rows": len(frame),
            "labels": final_meta["labels"],
            "sha256": final_meta["sha256"],
            "raw_url_persisted": False,
        },
        "runtime": {
            "base_url": base_url,
            "mode": url_status_after.get("mode"),
            "enabled": url_status_after.get("enabled"),
            "model_version": url_status_after.get("model_version"),
            "revision": url_status_after.get("revision"),
            "sampling": url_status_after.get("sampling"),
            "drift": url_status_after.get("drift"),
        },
        "results": {
            "completed": len(results),
            "request_failures": failures,
            "sampled": sum(row["sampled"] for row in results),
            "evaluated": sum(row["evaluated"] for row in results),
            "prediction_errors": sum(bool(row["error_class"]) for row in results),
            "response_parity_mismatches": sum(not row["parity"] for row in results),
            "privacy_leaks": sum(row["privacy_leak"] for row in results),
            "would_promote": {
                "benign": sum(row["would_promote"] for row in benign),
                "malicious": sum(row["would_promote"] for row in malicious),
            },
            "would_promote_when_runtime_verdict_not_malicious": {
                "benign": sum(
                    row["would_promote_non_malicious_verdict"] for row in benign
                ),
                "malicious": sum(
                    row["would_promote_non_malicious_verdict"] for row in malicious
                ),
            },
            "calibration": _calibration_metrics(results),
            "client_latency_ms": {
                "mean": round(statistics.fmean(latency), 3) if latency else 0.0,
                "p50": _percentile(latency, 0.50),
                "p95": _percentile(latency, 0.95),
                "p99": _percentile(latency, 0.99),
                "max": round(max(latency), 3) if latency else 0.0,
            },
            "invalid_context": invalid,
        },
        "runtime_telemetry": url_status_after,
        "gates": {},
        "duration_seconds": round(time.time() - started, 3),
    }
    gates = {
        "all_requests_completed": failures == 0 and len(results) == len(frame),
        "all_selected_requests_evaluated": sum(row["sampled"] for row in results)
        == sum(row["evaluated"] for row in results),
        "valid_prediction_errors_zero": not any(row["error_class"] for row in results),
        "domain_response_parity": all(row["parity"] for row in results),
        "raw_context_leaks_zero": not any(row["privacy_leak"] for row in results),
        "benign_non_malicious_verdict_promotions_zero": not any(
            row["would_promote_non_malicious_verdict"] for row in benign
        ),
        "malicious_non_malicious_verdict_promotions_positive": any(
            row["would_promote_non_malicious_verdict"] for row in malicious
        ),
        "invalid_context_fail_open": invalid["fail_open"] == invalid["cases"]
        and invalid["unexpectedly_accepted"] == 0,
        "enforce_unavailable": url_status_after.get("mode") == "shadow",
    }
    report["gates"] = gates
    report["passed"] = all(gates.values())
    _write_json(Path(output_path).resolve(), report)
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Replay v10 URL shadow through core-api")
    parser.add_argument("--base-url", default="http://127.0.0.1:18082")
    parser.add_argument(
        "--protocol",
        default=str(BASE_DIR / "configs" / "v10-url-aware-signal-protocol.json"),
    )
    parser.add_argument(
        "--output",
        default=str(BASE_DIR / "experiments" / "v10-url-shadow-staging.json"),
    )
    parser.add_argument("--workers", type=int, default=8)
    args = parser.parse_args()
    result = replay(args.base_url, args.protocol, args.output, args.workers)
    print(json.dumps({"passed": result["passed"], "results": result["results"], "gates": result["gates"]}, indent=2))
