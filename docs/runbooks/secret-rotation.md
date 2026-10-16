# Admin secret rotation workflow

Use this runbook when admin credentials must be replaced: on a schedule
(every 90 days is the default), when someone with access leaves, when a
secret may have leaked, or once after the SafeRoad dev defaults
(`SafeRoadLocalAdmin123!` / `SafeRoadLocalApiKey1234567890`) that shipped in
`start.bat` history. Those two strings are public in git history forever —
treat any deployment that ever ran the old `start.bat` as exposed until it
has been rotated with this procedure.

## Goal

Replace `SAFE_ZONE_ADMIN_PASSWORD` and `SAFE_ZONE_ADMIN_API_KEY` on a
deployment with zero silent failure: backup, rotate, verify the new secret
works, verify the old secret is dead, roll back automatically otherwise.

## Triggers

- Calendar rotation is due.
- A secret was pasted into chat, tickets, logs, or a shell history file.
- Anyone with admin access leaves the operator team.
- The production gate rejects startup with a placeholder-style secret error
  (that means a dev default reached production — rotate immediately).

## Inputs to collect

- Which host the Compose stack runs on (the script runs **on that host**,
  inside the repo checkout that owns the stack's `.env`).
- Whether the deployment uses `_FILE` secret variants
  (`SAFE_ZONE_ADMIN_PASSWORD_FILE` / `SAFE_ZONE_ADMIN_API_KEY_FILE`).
  If it does, the script refuses and you rotate the referenced files by
  hand, then restart `core-api`.

## Step 1: Rotate with the script (preferred)

Linux/macOS (or Git Bash on Windows):

```sh
sh ./scripts/ops/rotate-admin-secrets.sh
```

Windows:

```powershell
pwsh -NoProfile -File scripts/ops/rotate-admin-secrets.ps1
```

Or through mise (same defaults):

```sh
mise run ops:rotate-secrets
```

Useful overrides (flags exist on both scripts):

- `--env-file PATH` — env file to rotate (default `.env` in repo root).
- `--api-url URL` — core-api base URL (default `http://127.0.0.1:8080`).
- `--compose-file FILE` — repeatable; default `docker-compose.yml`.
- `--service NAME` — Compose service to recreate (default `core-api`).
- `--yes` — skip the confirmation prompt (for automation only).

What the script does, in order:

1. Refuses when `_FILE` secret variants are set (it cannot rotate files it
   does not own).
2. Backs up the env file to `backups/rotate-admin-secrets-<timestamp>.env`
   with owner-only permissions.
3. Generates a 32-char admin password and a 40-char API key from the OS
   crypto RNG and writes them in place (existing values are replaced, never
   appended twice).
4. Recreates only the `core-api` container and waits up to 90 s for
   `/healthz`. A bad value crashes startup, so an unhealthy container
   triggers automatic rollback.
5. Verifies against the admin-only `/metrics` endpoint: the **new** key must
   return 200 and the **old** key must return 401/403.
6. On any failure: restores the backup, recreates the container, waits for
   health, and exits non-zero. On success: prints the new credentials
   **once** — store them in the team password manager immediately.

Restarting `core-api` also rotates the in-memory session signing secret
(generated fresh every boot), so all existing admin sessions die with the
old credentials. No separate session purge is needed.

## Step 2: Manual fallback (script unavailable)

1. `cp .env "backups/manual-rotate-$(date -u +%Y%m%dT%H%M%SZ).env" && chmod 600` the copy.
2. Generate: `openssl rand -base64 36 | tr -dc 'A-Za-z0-9' | head -c 32`
   (password) and `head -c 40` (API key).
3. Replace the two `KEY=value` lines in `.env`.
4. `docker compose -f docker-compose.yml up -d --force-recreate core-api`,
   wait for `/healthz`.
5. `curl -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer <new-key>" <api>/metrics`
   must print 200; same with the old key must print 401/403.
6. Any deviation: restore the backup, recreate, re-verify.

## Step 3: Sweep for leftovers

Search the host for the retired values (shell history, old backups, logs,
the pre-rotation `.env` copies you no longer need):

```sh
rg -l "SafeRoadLocalAdmin123!|SafeRoadLocalApiKey1234567890" /home/safe-zone/ 2>/dev/null
```

Delete what you find, or rotate again if a live file still references them.
Never re-introduce the `SafeRoadLocal*` pattern anywhere: the production
startup gate now rejects it, and the regression test
`TestLoadRuntimeSecurityProductionRejectsShippedDevDefaults` pins that
behavior.

## Non-goals

- Rewriting git history to erase the old defaults. The strings were public
  in a MIT repo and may exist in any clone; rewriting every SHA breaks all
  forks for zero security gain once rotation is done and reuse is gated.
- Rotating Redis passwords, webhook URLs, or TLS material — same shape of
  procedure (backup, replace, recreate, verify, rollback), different keys.
