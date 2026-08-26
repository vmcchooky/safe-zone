"""Round-4 rollback drill on the live canary deployment.

Steps (all via the literal canary override, immune to stale shell env):
  1. write override mode=disabled and recreate core-api;
  2. run the existing five-gate rollback checker into a NEW artifact
     (never touching frozen Round-3 evidence);
  3. restore override shadow@10% seeded and verify state=ready plus
     operational baseline still loaded.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(BASE / "ml"))
sys.path.insert(0, str(BASE))

try:
    from canary_override import compose_files, write  # noqa: E402
except ModuleNotFoundError:
    from src.canary_override import compose_files, write  # type: ignore  # noqa: E402

PROJECT = "safe-zone-phase5-staging"
CHECKER_OUTPUT = (
    BASE / "ml" / "experiments" / "v10-url-canary-rollback-drill.json"
)
SEED = "url-canary-v4-r4-20260826"


def recreate() -> None:
    cmd = ["docker", "compose", "-p", PROJECT]
    for f in compose_files():
        cmd += ["-f", f]
    cmd += ["up", "-d", "--no-deps", "--force-recreate", "core-api"]
    subprocess.run(cmd, check=True, capture_output=True, text=True, cwd=str(BASE))


def wait_healthy(timeout: int = 180) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(
                "http://127.0.0.1:8080/healthz", timeout=5
            ) as resp:
                if resp.status == 200:
                    return True
        except Exception:
            pass
        time.sleep(2)
    return False


def url_status() -> dict[str, object]:
    with urllib.request.urlopen("http://127.0.0.1:8080/v1/status", timeout=15) as r:
        return ((json.loads(r.read()).get("ml") or {}).get("url") or {})


def main() -> int:
    # --- disabled phase ---
    write("disabled", 10, SEED)
    recreate()
    if not wait_healthy():
        print("container not healthy after disable")
        return 1
    status_disabled = url_status()
    proc = subprocess.run(
        [
            sys.executable, "ml/src/check_v10_url_rollback.py",
            "--base-url", "http://127.0.0.1:8080",
            "--output", str(CHECKER_OUTPUT),
        ],
        capture_output=True, text=True, cwd=str(BASE),
    )
    checker = json.loads(CHECKER_OUTPUT.read_text(encoding="utf-8"))
    gates_ok = bool(checker.get("passed")) and proc.returncode == 0
    print("checker gates:", json.dumps(checker.get("gates"), indent=2))
    print("gates_ok:", gates_ok)

    # --- restore phase ---
    write("shadow", 10, SEED)
    recreate()
    healthy = wait_healthy()
    u = url_status()
    restored = (
        healthy
        and u.get("mode") == "shadow"
        and u.get("state") == "ready"
        and (u.get("sampling") or {}).get("percent") == 10
        and bool((u.get("operational_baseline") or {}).get("loaded"))
    )
    print("restored shadow@10% + baseline loaded:", restored)

    # Sanity: runtime really was disabled during the drill.
    was_disabled = (
        status_disabled.get("mode") == "disabled"
        or not status_disabled.get("enabled")
    )
    print("runtime observed disabled during drill:", was_disabled)
    return 0 if (gates_ok and restored) else 2


if __name__ == "__main__":
    sys.exit(main())
