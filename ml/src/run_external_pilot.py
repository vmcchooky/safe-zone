"""Run a bounded, gated URL ML shadow pilot window on real external traffic.

This is the Round-5 external pilot kit. It is meant for an operator who has a
staging/VPS deployment that already receives real user traffic through
``POST /v1/analyze`` callers (UI/SDK/extension). It:

  1. verifies the runtime is strictly in shadow mode before observing;
  2. records one observation window as snapshot-delta evidence (no driven
     traffic by default — external windows must never be padded with
     generated requests);
  3. evaluates the observable promotion-gate conditions on the window;
  4. optionally advances the seeded sampling scope ONLY when every gate on
     this window passes AND the external volume minimum is met.

Honesty guardrails:
  * ``--traffic-kind external`` (the default) refuses ``--drive-count``;
    generated traffic can never be folded into external evidence.
  * Scope advancement is refused with a machine-readable reason when any
    gate fails, so partial windows can never be stepped up silently.
  * Reports carry aggregate counters only; no domains, URLs, query values,
    redirect targets or client identifiers are ever written.

A small or failed window never becomes a production baseline: freezing an
operational baseline remains a separate, explicitly provenanced step
(``freeze_url_canary_baseline.py``) whose artifact states its own sample
count, observation time and staging/external provenance.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(BASE_DIR / "ml"))
sys.path.insert(0, str(BASE_DIR))

try:
    from src.canary_snapshot_delta import (  # noqa: E402
        _dig,
        _round_half_up,
        _snapshot,
    )
except ModuleNotFoundError:  # pragma: no cover - direct script execution
    from canary_snapshot_delta import (  # type: ignore  # noqa: E402
        _dig,
        _round_half_up,
        _snapshot,
    )

LATENCY_P95_LIMIT_US = 2000
INVALID_CONTEXT_RATE_LIMIT = 0.05
MIN_ATTEMPTS_FOR_RATE_GATE = 100


def _get_json(url: str) -> dict[str, object]:
    with urllib.request.urlopen(url, timeout=15) as resp:
        return json.loads(resp.read().decode("utf-8"))


def verify_shadow_runtime(base_url: str) -> dict[str, object]:
    """Refuse to observe anything that is not a ready shadow runtime."""
    url_ml = ((_get_json(base_url.rstrip("/") + "/v1/status") or {}).get("ml") or {}).get("url") or {}
    problems = []
    if url_ml.get("mode") != "shadow":
        problems.append(f"mode={url_ml.get('mode')!r} (must be shadow)")
    if not url_ml.get("enabled"):
        problems.append("classifier disabled")
    if url_ml.get("state") != "ready":
        problems.append(f"state={url_ml.get('state')!r}")
    if problems:
        raise SystemExit(
            "refusing to run an external pilot: URL ML is not a healthy "
            f"shadow observer ({'; '.join(problems)})"
        )
    return url_ml


def window_deltas(start: dict[str, object], end: dict[str, object]) -> dict[str, int]:
    return {
        "prediction_attempts": int(_dig(end["url_ml"], ["prediction_attempts"]) - _dig(start["url_ml"], ["prediction_attempts"])),
        "invalid_url_context": int(_dig(end["url_ml"], ["error_histogram", "invalid_url_context"]) - _dig(start["url_ml"], ["error_histogram", "invalid_url_context"])),
        "prediction_errors": int(_dig(end["url_ml"], ["error_histogram", "prediction_error"]) - _dig(start["url_ml"], ["error_histogram", "prediction_error"])),
        "evaluated": int(
            _dig(end["url_ml"], ["prediction_attempts"])
            - _dig(end["url_ml"], ["error_histogram", "invalid_url_context"])
            - _dig(end["url_ml"], ["error_histogram", "prediction_error"])
            - (
                _dig(start["url_ml"], ["prediction_attempts"])
                - _dig(start["url_ml"], ["error_histogram", "invalid_url_context"])
                - _dig(start["url_ml"], ["error_histogram", "prediction_error"])
            )
        ),
        "would_promote": int(_dig(end["url_ml"], ["would_promote"]) - _dig(start["url_ml"], ["would_promote"])),
        "selected": int(_dig(end["url_ml"], ["sampling", "selected"]) - _dig(start["url_ml"], ["sampling", "selected"])),
        "excluded": int(_dig(end["url_ml"], ["sampling", "excluded"]) - _dig(start["url_ml"], ["sampling", "excluded"])),
        "context_requests": int(_dig(end["url_ml"], ["context_requests"]) - _dig(start["url_ml"], ["context_requests"])),
    }


def caller_delta(start: dict[str, object], end: dict[str, object]) -> dict[str, int]:
    breakdown = ((end["url_ml"].get("coverage") or {}).get("caller_breakdown")) or {}
    before = ((start["url_ml"].get("coverage") or {}).get("caller_breakdown")) or {}
    return {
        name: int(breakdown.get(name, 0) - before.get(name, 0))
        for name in sorted(set(breakdown) | set(before))
    }


def evaluate_gates(deltas: dict[str, int], end: dict[str, object],
                   min_evaluated: int) -> dict[str, object]:
    attempts = deltas["prediction_attempts"]
    invalid_rate = (deltas["invalid_url_context"] / attempts) if attempts else 0.0
    p95 = end["url_ml"].get("latency_p95_us")
    gates: dict[str, object] = {
        "zero_prediction_errors": {
            "pass": deltas["prediction_errors"] == 0,
            "observed": deltas["prediction_errors"],
        },
        "invalid_context_rate_below_5pct": {
            "pass": attempts >= MIN_ATTEMPTS_FOR_RATE_GATE and invalid_rate < INVALID_CONTEXT_RATE_LIMIT,
            "observed_exact": invalid_rate,
            "observed_rounded": _round_half_up(invalid_rate),
            "attempts": attempts,
            "note": None if attempts >= MIN_ATTEMPTS_FOR_RATE_GATE
            else f"insufficient attempts (<{MIN_ATTEMPTS_FOR_RATE_GATE}); gate inconclusive",
        },
        "latency_p95_under_2000us": {
            "pass": isinstance(p95, (int, float)) and 0 <= p95 < LATENCY_P95_LIMIT_US,
            "observed_cumulative_p95_us": p95,
            "note": "cumulative process p95; conservative bound for the window",
        },
        "external_volume_minimum": {
            "pass": deltas["evaluated"] >= min_evaluated,
            "observed": deltas["evaluated"],
            "required": min_evaluated,
        },
        "shadow_mode_unchanged": {
            "pass": end["url_ml"].get("mode") == "shadow" and bool(end["url_ml"].get("enabled")),
            "observed_mode": end["url_ml"].get("mode"),
        },
    }
    gates["all_pass"] = all(bool(g.get("pass")) for g in gates.values())
    return gates


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:8080")
    parser.add_argument("--window-minutes", type=float, default=60.0)
    parser.add_argument("--traffic-kind", default="external",
                        choices=["external", "synthetic"],
                        help="synthetic requires --drive-count and is never "
                             "eligible for scope advancement")
    parser.add_argument("--drive-count", type=int, default=0,
                        help="generated requests; forbidden together with "
                             "--traffic-kind external")
    parser.add_argument("--caller-class", default="sdk",
                        choices=["ui", "sdk", "extension", "proxy", "other"])
    parser.add_argument("--min-evaluated", type=int, default=1000,
                        help="minimum evaluated external URL-context requests "
                             "in this window before scope may advance")
    parser.add_argument("--advance-to", type=int, choices=[1, 5, 10],
                        help="attempt a seeded scope step after the window "
                             "when every gate passes")
    parser.add_argument("--seed", default="",
                        help="seed used with --advance-to (kept stable across steps)")
    parser.add_argument("--reason", default="", help="audit note for the scope step")
    parser.add_argument("--project", default="safe-zone-phase5-staging")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    if args.traffic_kind == "external" and args.drive_count > 0:
        parser.error("--drive-count is not allowed with --traffic-kind external; "
                     "generated traffic must never be counted as external evidence")

    verify_shadow_runtime(args.base_url)

    try:
        from src.canary_snapshot_delta import _container_stats  # noqa: E402
    except ModuleNotFoundError:  # pragma: no cover
        from canary_snapshot_delta import _container_stats  # type: ignore  # noqa: E402

    stats_before = _container_stats(args.project)
    start = _snapshot(args.base_url)
    started_at = time.monotonic()

    drive_summary = None
    if args.drive_count > 0:
        try:
            from src.canary_snapshot_delta import _drive_traffic  # noqa: E402
        except ModuleNotFoundError:  # pragma: no cover
            from canary_snapshot_delta import _drive_traffic  # type: ignore  # noqa: E402
        drive_summary = _drive_traffic(
            args.base_url, args.drive_count, max(1, min(8, args.drive_count)), args.caller_class
        )

    remaining = args.window_minutes * 60.0 - (time.monotonic() - started_at)
    if remaining > 0:
        print(f"observing external window for {remaining/60:.1f} more minutes ...")
        time.sleep(remaining)

    end = _snapshot(args.base_url)
    stats_after = _container_stats(args.project)
    duration = time.monotonic() - started_at

    deltas = window_deltas(start, end)
    gates = evaluate_gates(deltas, end, args.min_evaluated)

    advancement: dict[str, object] = {"requested": False}
    if args.advance_to:
        advancement = {"requested": True, "target_percent": args.advance_to}
        if args.traffic_kind != "external":
            advancement.update({"performed": False,
                                "reason": "synthetic windows never authorize scope advancement"})
        elif not gates["all_pass"]:
            advancement.update({"performed": False,
                                "reason": "one or more window gates failed"})
        else:
            cmd = [sys.executable, str(BASE_DIR / "ml" / "src" / "canary_scope.py"),
                   "--percent", str(args.advance_to)]
            if args.seed:
                cmd += ["--seed", args.seed]
            if args.reason:
                cmd += ["--reason", args.reason]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            advancement.update({
                "performed": proc.returncode == 0,
                "tool_stdout_tail": proc.stdout.strip().splitlines()[-5:],
                "tool_returncode": proc.returncode,
            })

    report = {
        "schema_version": 1,
        "kind": "url_ml_external_pilot_window",
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "traffic_kind": args.traffic_kind,
        "honesty_note": (
            "external windows contain zero generated requests; synthetic "
            "probes are recorded under traffic_kind=synthetic and never "
            "contribute to promotion-gate volume"
            if args.traffic_kind == "external" else
            "synthetic probe window; NOT production evidence"
        ),
        "window": {
            "started_at": start["at"],
            "ended_at": end["at"],
            "duration_seconds": round(duration, 3),
        },
        "scope_observed": {
            "percent": (end["url_ml"].get("sampling") or {}).get("percent"),
            "selector_revision": (end["url_ml"].get("sampling") or {}).get("selector_revision"),
            "policy_revision": end["url_ml"].get("policy_revision"),
            "mode": end["url_ml"].get("mode"),
            "state": end["url_ml"].get("state"),
        },
        "deltas": deltas,
        "caller_breakdown_delta": caller_delta(start, end),
        "coverage_totals_at_end": (end["url_ml"].get("coverage") or {}),
        "missing_context_breakdown_at_end": ((end["url_ml"].get("coverage") or {}).get("missing_context_breakdown") or {}),
        "gates": gates,
        "scope_advancement": advancement,
        "driven_traffic": drive_summary,
        "feedback_status_at_end": end["url_ml"].get("feedback"),
        "drift_at_end": end["url_ml"].get("drift"),
        "operational_baseline_at_end": end["url_ml"].get("operational_baseline"),
        "container_resources": {"before": stats_before, "after": stats_after},
        "baseline_provenance_rule": (
            "this window alone does not create a production baseline; freeze "
            "an operational baseline only from a completed external window "
            "with stated sample count, observation time and confidence"
        ),
        "aggregate_only": True,
    }
    out_path = Path(args.output).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "output": str(out_path),
        "traffic_kind": args.traffic_kind,
        "deltas": deltas,
        "gates_all_pass": gates["all_pass"],
        "scope_advancement": advancement,
    }, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
