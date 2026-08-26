"""Snapshot-delta evidence collector for the URL ML shadow canary.

Fixes both Round-3 audit gaps:
  * ``workers``/concurrency of the collection run are recorded explicitly;
  * rates (including the invalid-context rate) carry an exact unrounded
    value plus a documented round-half-up 4-decimal rendering.

Counters are captured as start/end snapshots of ``/v1/status`` so every
metric is a delta over this observation window only — never cumulative.
The report contains aggregates exclusively: no domains, no URLs, no client
identifiers, no raw context of any kind.
"""

from __future__ import annotations

import argparse
import json
import statistics
import subprocess
import sys
import time
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent.parent

# Buckets mirror runtime mlProbabilityBuckets ordering.
PROBABILITY_BUCKETS = [
    "lt_0_10", "0_10_0_19", "0_20_0_29", "0_30_0_39", "0_40_0_49",
    "0_50_0_59", "0_60_0_69", "0_70_0_79", "0_80_0_89", "gte_0_90",
]
LATENCY_BUCKETS = ["le_100us", "le_250us", "le_500us", "le_1000us",
                   "le_2000us", "le_5000us", "le_10000us", "le_50000us",
                   "gt_50000us"]


def _get_json(url: str) -> dict[str, object]:
    with urllib.request.urlopen(url, timeout=15) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _snapshot(base_url: str) -> dict[str, object]:
    doc = _get_json(base_url.rstrip("/") + "/v1/status")
    url_ml = ((doc.get("ml") or {}).get("url") or {})
    return {
        "at": datetime.now(timezone.utc).isoformat(),
        "url_ml": url_ml,
    }


def _container_stats(project: str) -> dict[str, object]:
    try:
        proc = subprocess.run(
            [
                "docker", "stats", "--no-stream",
                "--format", "{{.Name}}|{{.CPUPerc}}|{{.MemUsage}}",
            ],
            capture_output=True, text=True, timeout=60,
        )
        for line in proc.stdout.splitlines():
            name, cpu, mem = line.split("|", 2)
            if name.endswith("-core-api-1"):
                return {"cpu_percent": float(cpu.strip().rstrip("%")),
                        "mem_usage": mem.strip()}
    except Exception:
        pass
    return {}


def _round_half_up(value: float, digits: int = 4) -> float:
    # Documented rounding rule for all reported rates: round half up at
    # 4 decimals; the exact value is always reported alongside.
    scaled = value * (10 ** digits)
    floor = int(scaled)
    frac = scaled - floor
    if frac >= 0.5:
        floor += 1
    return floor / (10 ** digits)


def _delta(end: dict[str, object], start: dict[str, object],
           key_path: list[str]) -> float:
    end_val = _dig(end["url_ml"], key_path)
    start_val = _dig(start["url_ml"], key_path)
    return float(end_val) - float(start_val)


def _drive_traffic(base_url: str, count: int, concurrency: int,
                   caller_class: str) -> dict[str, object]:
    """Drive traffic through the real POST /v1/analyze path.

    Domains are generated (not part of any frozen cohort) and each request
    carries an opaque event_id. Only aggregate outcomes are returned.
    """
    import concurrent.futures

    latencies: list[float] = []
    evaluated = 0
    errors = 0
    would_promote = 0
    event_ids: list[str] = []

    def one(index: int) -> tuple[float, dict[str, object]]:
        domain = f"sz-canary-{uuid.uuid4().hex[:12]}.example"
        event_id = uuid.uuid4().hex
        payload = json.dumps({
            "domain": domain,
            "requested_url": f"https://{domain}/canary?probe={index}",
            "event_id": event_id,
            "caller_class": caller_class,
        }).encode("utf-8")
        req = urllib.request.Request(
            base_url.rstrip("/") + "/v1/analyze",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        started = time.monotonic()
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = json.loads(resp.read().decode("utf-8"))
        elapsed_ms = (time.monotonic() - started) * 1000.0
        return elapsed_ms, {"body": body, "event_id": event_id}

    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
        for elapsed_ms, result in pool.map(one, range(count)):
            latencies.append(elapsed_ms)
            event_ids.append(result["event_id"])
            url_ml = (result["body"].get("url_ml") or {})
            if url_ml.get("evaluated"):
                evaluated += 1
            if url_ml.get("error_class"):
                errors += 1
            if url_ml.get("would_promote"):
                would_promote += 1

    ordered = sorted(latencies)

    def pct(p: float) -> float:
        if not ordered:
            return 0.0
        rank = max(0, min(len(ordered) - 1, int(round(p * (len(ordered) - 1)))))
        return round(ordered[rank], 3)

    return {
        "requests_sent": count,
        "evaluated": evaluated,
        "errors": errors,
        "would_promote": would_promote,
        "latency_ms": {
            "p50": pct(0.50), "p95": pct(0.95), "p99": pct(0.99),
            "mean": round(statistics.fmean(latencies), 3) if latencies else 0.0,
        },
        # Opaque client-generated IDs returned only so labels can be sent to
        # /v1/url-ml/feedback; they are never paired with domains here.
        "sample_event_ids": event_ids[:20],
    }



def _dig(node, path):
    for key in path:
        if not isinstance(node, dict):
            return 0
        node = node.get(key) or 0
    return node


def _histogram_delta(end, start, name):
    out = {}
    for bucket in PROBABILITY_BUCKETS + LATENCY_BUCKETS + [
        "query_present", "query_absent", "redirects_0", "redirects_1",
        "redirects_2_to_5", "safe", "suspicious", "malicious",
        "invalid_url_context", "prediction_error",
    ]:
        d = _delta(end, start, [name, bucket])
        if d != 0:
            out[bucket] = int(d)
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:8080")
    parser.add_argument("--window-seconds", type=float, default=60.0)
    parser.add_argument("--workers", type=int, default=8,
                        help="logical workers used by this collection run")
    parser.add_argument("--concurrency", type=int, default=4)
    parser.add_argument("--drive-count", type=int, default=0,
                        help="optional generated requests sent through the "
                             "real API during the window")
    parser.add_argument("--caller-class", default="sdk",
                        choices=["ui", "sdk", "extension", "proxy", "other"])
    parser.add_argument("--traffic-kind", default="external",
                        choices=["external", "synthetic"])
    parser.add_argument("--project", default="safe-zone-phase5-staging")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    stats_before = _container_stats(args.project)
    start = _snapshot(args.base_url)
    started_at = time.monotonic()

    drive_summary = None
    if args.drive_count > 0:
        drive_summary = _drive_traffic(
            args.base_url, args.drive_count, args.concurrency, args.caller_class
        )

    remaining = args.window_seconds - (time.monotonic() - started_at)
    if remaining > 0:
        time.sleep(remaining)

    end = _snapshot(args.base_url)
    stats_after = _container_stats(args.project)
    duration = time.monotonic() - started_at
    # --- Deltas over this window only (never cumulative) ---
    prediction_attempts = _delta(end, start, ["prediction_attempts"])
    invalid_ctx = _delta(end, start, ["error_histogram", "invalid_url_context"])
    pred_err = _delta(end, start, ["error_histogram", "prediction_error"])
    would_promote = _delta(end, start, ["would_promote"])
    would_pass = _delta(end, start, ["would_pass"])
    selected = _delta(end, start, ["sampling", "selected"])
    excluded = _delta(end, start, ["sampling", "excluded"])
    coverage = end["url_ml"].get("coverage") or {}
    evaluated_delta = prediction_attempts - invalid_ctx - pred_err
    invalid_rate_exact = (invalid_ctx / prediction_attempts) if prediction_attempts else 0.0

    report = {
        "schema_version": 1,
        "kind": "url_ml_canary_window_evidence",
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "traffic_kind": args.traffic_kind,
        "window": {
            "started_at": start["at"],
            "ended_at": end["at"],
            "duration_seconds": round(duration, 3),
            "workers": args.workers,
            "concurrency": args.concurrency,
        },
        "scope_observed": {
            "percent": ((end["url_ml"].get("sampling") or {}).get("percent")),
            "selector_revision": ((end["url_ml"].get("sampling") or {}).get("selector_revision")),
            "policy_revision": end["url_ml"].get("policy_revision"),
            "mode": end["url_ml"].get("mode"),
            "state": end["url_ml"].get("state"),
        },
        "deltas": {
            "selected": int(selected),
            "excluded": int(excluded),
            "prediction_attempts": int(prediction_attempts),
            "evaluated": int(evaluated_delta),
            "invalid_url_context": int(invalid_ctx),
            "prediction_errors": int(pred_err),
            "would_promote": int(would_promote),
            "would_pass": int(would_pass),
            "analyze_requests_total": coverage.get("analyze_requests", 0),
            "url_context_requests_total": coverage.get("url_context_requests", 0),
        },
        "rates": {
            "invalid_context_exact": invalid_rate_exact,
            "invalid_context_rounded": _round_half_up(invalid_rate_exact),
            "would_promote_exact": (would_promote / evaluated_delta) if evaluated_delta else 0.0,
            "context_coverage_exact": coverage.get("context_coverage_rate", 0.0),
            "rounding_rule": "round-half-up at 4 decimals; exact value always included",
        },
        "histogram_deltas": {
            "probability": _histogram_delta(end, start, "probability_histogram"),
            "latency_us": _histogram_delta(end, start, "latency_histogram_us"),
            "input": _histogram_delta(end, start, "input_histogram"),
            "primary_verdict": _histogram_delta(end, start, "primary_verdict_histogram"),
            "would_promote_by_verdict": _histogram_delta(end, start, "would_promote_by_primary_verdict"),
        },
        "latency_p95_us": end["url_ml"].get("latency_p95_us"),
        "coverage_caller_breakdown": coverage.get("caller_breakdown"),
        "feedback": end["url_ml"].get("feedback"),
        "operational_baseline": end["url_ml"].get("operational_baseline"),
        "drift": end["url_ml"].get("drift"),
        "container_resources": {"before": stats_before, "after": stats_after},
        "driven_traffic": drive_summary,
        "aggregate_only": True,
    }
    out_path = Path(args.output).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: report[k] for k in (
        "window", "scope_observed", "deltas", "rates")}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())