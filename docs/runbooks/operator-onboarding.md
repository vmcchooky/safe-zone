# Operator onboarding

This is the short handover guide for a new Safe Zone operator.

## Goal

Get a new operator from first login to first backup and first restore reference without reverse-engineering the repo.

## 1. First login

1. Open `/dashboard`.
2. Sign in with the admin password for the target environment.
3. Confirm `core-api`, Redis, and metrics cards load in the dashboard.
4. If login fails, use [credential-rotation.md](D:/Quorix/services/safe-zone/docs/runbooks/credential-rotation.md).

## 2. First health check

Verify:

- `/healthz`
- `/readyz`
- `/v1/version`
- dashboard loads after login

For production edge, also run:

```sh
scripts/public-edge-smoke.sh "$SAFE_ZONE_PUBLIC_HOST"
```

## 3. First feed sync

Run one manual feed sync and confirm the system reports feed freshness:

Linux:

```sh
scripts/safe-zone.sh feed-sync
```

Windows:

```powershell
pwsh ./scripts/safe-zone.ps1 feed-sync
```

Then review feed status from `/` or the dashboard.

## 4. First override

1. Analyze a test domain in the dashboard.
2. Add a temporary allow or block override in the `Overrides` tab.
3. Re-run analysis and confirm the result shows `admin override`.
4. Delete the test override after verification.

For false positives, use [false-positive-workflow.md](D:/Quorix/services/safe-zone/docs/runbooks/false-positive-workflow.md).

## 5. First backup

Run one manual backup:

Linux:

```sh
SAFE_ZONE_BACKUP_ENCRYPT=1 scripts/safe-zone.sh backup
```

Windows:

```powershell
$env:SAFE_ZONE_BACKUP_ENCRYPT='1'
pwsh ./scripts/safe-zone.ps1 backup
```

Confirm the backup directory contains:

- Redis snapshot
- SQLite backup
- config snapshots
- checksum manifest
- encrypted bundle when encryption is enabled

## 6. First restore reference

Do not restore on production first. Read and follow [restore-drill.md](D:/Quorix/services/safe-zone/docs/runbooks/restore-drill.md) on a staging target.

The standard commands are:

Linux:

```sh
scripts/safe-zone.sh restore backups/<timestamp>
```

Windows:

```powershell
pwsh ./scripts/safe-zone.ps1 restore -BackupPath backups\<timestamp>
```

## 7. First periodic reviews

During the first week of ownership, confirm:

- threat feed freshness
- backup output exists
- agent tasks are healthy if enabled
- telemetry retention matches policy
- release rollback inputs are documented

Related docs:

- [release-gate.md](D:/Quorix/services/safe-zone/docs/runbooks/release-gate.md)
- [release-rollback.md](D:/Quorix/services/safe-zone/docs/runbooks/release-rollback.md)
- [data-retention-privacy.md](D:/Quorix/services/safe-zone/docs/security/data-retention-privacy.md)
