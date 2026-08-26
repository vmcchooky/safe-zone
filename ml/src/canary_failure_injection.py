"""Short failure-injection drill for the URL ML canary deployment.

Cases (all against the live compose staging runtime):
  1. missing_baseline_fail_open   — baseline artifact absent at startup;
  2. corrupt_baseline_fail_open   — baseline artifact is malformed JSON;
  3. malformed_context_rejected   — ftp://, credentials, host mismatch,
     oversized URL must fail open as ``invalid_url_context``;
  4. restart_with_valid_baseline  — after restoring a valid baseline and
     restarting, drift monitoring reports ``operational_reference=true``.

Every case must leave the URL classifier available (fail-open) and the API
healthy. Aggregate-only output; no domains or URLs are recorded beyond the
fixed synthetic probe strings from the existing replay harness.
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
    from canary_override import compose_files  # noqa: E402
    from replay_v10_url_shadow import _invalid_context_checks, _json_request  # noqa: E402
except ModuleNotFoundError:
    from src.canary_override import compose_files  # type: ignore  # noqa: E402
    from src.replay_v10_url_shadow import _invalid_context_checks, _json_request  # type: ignore  # noqa: E402

BASELINE_HOST_PATH = (
    BASE_DIR / "ml" / "models" / "url-baseline" / "operational-baseline.json"
)


def _get_json(url: str) -> dict[str, object]:
    with urllib.request.urlopen(url, timeout=15) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _url_status(base_url: str) -> dict[str, object]:
    doc = _get_json(base_url.rstrip("/") + "/v1/status")
    return ((doc.get("ml") or {}).get("url") or {})


def _wait_healthy(base_url: str, timeout_seconds: int = 180) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(
                base_url.rstrip("/") + "/healthz", timeout=5
            ) as resp:
                if resp.status == 200:
                    return True
        except Exception:
            pass
        time.sleep(2)
    return False


def _recreate(project: str) -> None:
    cmd = ["docker", "compose", "-p", project]
    for f in compose_files():
        cmd += ["-f", f]
    cmd += ["up", "-d", "--no-deps", "--force-recreate", "core-api"]
    subprocess.run(
        cmd,
        check=True, capture_output=True, text=True, cwd=str(BASE_DIR),
    )


def _baseline_fail_open(url_status):
    """Fail-open means: classifier still enabled, no operational reference."""
    baseline = url_status.get("operational_baseline") or {}
    return (
        bool(url_status.get("enabled"))
        and not baseline.get("loaded", False)
        and not baseline.get("operational_reference", False)
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:8080")
    parser.add_argument("--project", default="safe-zone-phase5-staging")
    parser.add_argument("--output",
                        default=str(BASE_DIR / "ml" / "experiments" /
                                    "v10-url-canary-failure-injection.json"))
    args = parser.parse_args()

    results = []
    backup = None
    if BASELINE_HOST_PATH.exists():
        backup = BASELINE_HOST_PATH.read_bytes()

    def record(name, passed, detail):
        results.append({"case": name, "passed": passed, "detail": detail})
        print(("PASS " if passed else "FAIL ") + name)

    # --- Case 1: missing baseline ---
    if backup is not None:
        BASELINE_HOST_PATH.unlink()
    _recreate(args.project)
    healthy = _wait_healthy(args.base_url)
    status = _url_status(args.base_url)
    record("missing_baseline_fail_open",
           healthy and _baseline_fail_open(status), {
               "healthy": healthy,
               "url_ml_enabled": bool(status.get("enabled")),
               "operational_baseline": status.get("operational_baseline"),
               "drift_state": ((status.get("drift") or {}).get("state")),
           })

    # --- Case 2: corrupt baseline ---
    try:
        BASELINE_HOST_PATH.write_bytes(b'{"schema_version": 1, "kind": "broken"')
        _recreate(args.project)
        healthy = _wait_healthy(args.base_url)
        status = _url_status(args.base_url)
        record("corrupt_baseline_fail_open",
               healthy and _baseline_fail_open(status), {
                   "healthy": healthy,
                   "url_ml_enabled": bool(status.get("enabled")),
                   "operational_baseline": status.get("operational_baseline"),
               })
    finally:
        if backup is not None:
            BASELINE_HOST_PATH.write_bytes(backup)
        elif BASELINE_HOST_PATH.exists():
            BASELINE_HOST_PATH.unlink()

    # --- Case 3: malformed context ---
    # At a bounded canary scope only cohort domains reach the classifier, so
    # pick probe domains hashing into the current seeded cohort (same
    # selector as the runtime: sha256(seed \\0 domain) % 100 < percent).
    import hashlib

    import urllib.parse

    status_now = _url_status(args.base_url)
    sampling = status_now.get("sampling") or {}
    scope_percent = int(sampling.get("percent") or 100)
    seed_line = ""
    for line in (BASE_DIR / ".env").read_text(encoding="utf-8").splitlines():
        if line.startswith("SAFE_ZONE_URL_ML_SHADOW_SEED="):
            seed_line = line.split("=", 1)[1].strip()

    def in_cohort(domain):
        if scope_percent >= 100:
            return True
        digest = hashlib.sha256(
            (seed_line + "\x00" + domain.strip().lower()).encode("utf-8")
        ).digest()
        return int.from_bytes(digest[:8], "big") % 100 < scope_percent

    def eligible_domain(prefix):
        counter = 0
        while True:
            candidate = prefix + "-" + str(counter) + ".example"
            if in_cohort(candidate):
                return candidate
            counter += 1

    invalid_cases = [
        (eligible_domain("sz-fi-ftp"), "ftp://%s/file"),
        (eligible_domain("sz-fi-cred"), "https://user:secret@%s/login"),
        (eligible_domain("sz-fi-host"), "https://evil.example/login"),
        (eligible_domain("sz-fi-big"), "https://%s/" + "a" * 4096),
    ]
    accepted = 0
    fail_open = 0
    for domain, template in invalid_cases:
        requested_url = (template % domain) if "%s" in template else template
        baseline, _, _ = _json_request(
            args.base_url.rstrip("/") + "/v1/analyze?domain="
            + urllib.parse.quote(domain)
        )
        observed, raw, _ = _json_request(
            args.base_url.rstrip("/") + "/v1/analyze",
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
    record("malformed_context_rejected",
           len(invalid_cases) == 4 and accepted == 0 and fail_open == 4,
           {"cases": len(invalid_cases), "unexpectedly_accepted": accepted,
            "fail_open": fail_open, "error_class": "invalid_url_context",
            "scope_percent": scope_percent})

    # --- Case 4: restart with valid baseline ---
    if backup is not None:
        BASELINE_HOST_PATH.write_bytes(backup)
        _recreate(args.project)
        healthy = _wait_healthy(args.base_url)
        status = _url_status(args.base_url)
        baseline = status.get("operational_baseline") or {}
        drift = status.get("drift") or {}
        record("restart_with_valid_baseline_loaded",
               healthy and bool(baseline.get("loaded"))
               and bool(baseline.get("operational_reference")),
               {"healthy": healthy,
                "operational_baseline": {
                    k: baseline.get(k) for k in (
                        "loaded", "sha256", "reference_rows",
                        "traffic_scope", "operational_reference")},
                "drift_state": drift.get("state"),
                "drift_operational": drift.get("operational_reference")})
    else:
        record("restart_with_valid_baseline_loaded", False,
               {"error": "no valid baseline artifact available to restore"})

    report = {
        "schema_version": 1,
        "kind": "url_ml_canary_failure_injection",
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "base_url": args.base_url,
        "cases": results,
        "passed": all(r["passed"] for r in results),
        "aggregate_only": True,
    }
    out = Path(args.output).resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"passed": report["passed"],
                      "cases": [r["case"] for r in results]}, indent=2))
    return 0 if report["passed"] else 2


if __name__ == "__main__":
    sys.exit(main())
