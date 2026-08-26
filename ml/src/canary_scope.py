"""Change the URL ML shadow canary scope on the compose staging runtime.

Scope policy is applied through a literal Compose override
(``docker-compose.canary.yml``, see canary_override.py) so stale shell env
vars can never win over the intended scope. Each change:
  1. records current percent / selector revision / policy revision;
  2. writes the new literal scope into the override file and syncs .env as
     documentation of record;
  3. recreates core-api (no rebuild);
  4. verifies the new percent is live and records the new revisions.

Every change appends to ml/experiments/v10-url-canary-scope-changes.json.
Rollback: re-run with the previous --percent or use --rollback.
Aggregate-only output; no domains, URLs or client identifiers recorded.
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

from src.canary_override import compose_files, write  # noqa: E402

ENV_PATH = BASE_DIR / ".env"
SCOPE_LOG = (
    BASE_DIR / "ml" / "experiments" / "v10-url-canary-scope-changes.json"
)
VALID_PERCENTS = {1, 5, 10}


def _status(base_url: str) -> dict[str, object]:
    with urllib.request.urlopen(base_url.rstrip("/") + "/v1/status", timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _url_status(base_url: str) -> dict[str, object]:
    doc = _status(base_url)
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


def _current_seed() -> str:
    for line in ENV_PATH.read_text(encoding="utf-8").splitlines():
        if line.startswith("SAFE_ZONE_URL_ML_SHADOW_SEED="):
            return line.split("=", 1)[1].strip()
    return ""


def _sync_env_documentation(percent: int, seed: str, mode: str = "shadow") -> None:
    lines = ENV_PATH.read_text(encoding="utf-8").splitlines()
    out: list[str] = []
    seen_percent = seen_seed = seen_mode = False
    for line in lines:
        if line.startswith("SAFE_ZONE_URL_ML_SHADOW_PERCENT="):
            out.append(f"SAFE_ZONE_URL_ML_SHADOW_PERCENT={percent}")
            seen_percent = True
        elif line.startswith("SAFE_ZONE_URL_ML_SHADOW_SEED="):
            out.append(f"SAFE_ZONE_URL_ML_SHADOW_SEED={seed}")
            seen_seed = True
        elif line.startswith("SAFE_ZONE_URL_ML_MODE="):
            out.append(f"SAFE_ZONE_URL_ML_MODE={mode}")
            seen_mode = True
        else:
            out.append(line)
    if not seen_percent:
        out.append(f"SAFE_ZONE_URL_ML_SHADOW_PERCENT={percent}")
    if not seen_seed:
        out.append(f"SAFE_ZONE_URL_ML_SHADOW_SEED={seed}")
    if not seen_mode:
        out.append(f"SAFE_ZONE_URL_ML_MODE={mode}")
    ENV_PATH.write_text("\n".join(out) + "\n", encoding="utf-8")


def compose_recreate(project: str) -> None:
    cmd = ["docker", "compose", "-p", project]
    for f in compose_files():
        cmd += ["-f", f]
    cmd += ["up", "-d", "--no-deps", "--force-recreate", "core-api"]
    subprocess.run(
        cmd,
        check=True,
        capture_output=True,
        text=True,
        cwd=str(BASE_DIR),
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:8080")
    parser.add_argument("--percent", type=int, choices=sorted(VALID_PERCENTS))
    parser.add_argument("--seed", default="")
    parser.add_argument("--project", default="safe-zone-phase5-staging")
    parser.add_argument("--reason", default="")
    parser.add_argument("--rollback", action="store_true",
                        help="restore the previous scope from the change log")
    parser.add_argument("--output", default=str(SCOPE_LOG))
    args = parser.parse_args()

    before = _url_status(args.base_url)
    old_percent = (before.get("sampling") or {}).get("percent")
    log_path = Path(args.output).resolve()
    history = []
    if log_path.exists():
        history = json.loads(log_path.read_text(encoding="utf-8"))

    if args.rollback:
        if not history:
            print("rollback requested but no prior scope changes are logged")
            return 1
        last = history[-1]
        target_percent = int(last["from_percent"])
        target_seed = str(last["seed"])
    else:
        if args.percent is None:
            print("--percent is required unless --rollback is used")
            return 1
        target_percent = args.percent
        target_seed = args.seed

    if target_seed == "":
        # Cohort stability across scope levels requires the same fixed seed.
        target_seed = _current_seed()
        if not target_seed:
            print("a fixed seed is required; pass --seed explicitly once")
            return 1

    # Literal override wins over any stale shell env interpolation.
    write("shadow", target_percent, target_seed)
    _sync_env_documentation(target_percent, target_seed)
    try:
        compose_recreate(args.project)
    except subprocess.CalledProcessError as exc:
        print(f"compose recreate failed: {exc.stderr}")
        return 1
    if not _wait_healthy(args.base_url):
        print("core-api did not become healthy after recreate")
        return 1

    after = _url_status(args.base_url)
    new_percent = (after.get("sampling") or {}).get("percent")
    entry = {
        "schema_version": 1,
        "kind": "url_ml_canary_scope_change",
        "at": datetime.now(timezone.utc).isoformat(),
        "reason": args.reason or ("rollback" if args.rollback else "promotion"),
        "from_percent": old_percent,
        "to_percent": new_percent,
        "seed": target_seed,
        "before_selector_revision": (before.get("sampling") or {}).get("selector_revision"),
        "after_selector_revision": (after.get("sampling") or {}).get("selector_revision"),
        "before_policy_revision": before.get("policy_revision"),
        "after_policy_revision": after.get("policy_revision"),
        "verified": new_percent == target_percent,
    }
    history.append(entry)
    Path(log_path).write_text(json.dumps(history, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(entry, indent=2))
    return 0 if entry["verified"] else 2


if __name__ == "__main__":
    sys.exit(main())