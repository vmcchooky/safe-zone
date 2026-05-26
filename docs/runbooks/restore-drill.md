# Restore drill runbook

Use this runbook to practice Safe Zone disaster recovery on a clean staging directory or clean VM before production incidents force the issue.

## Objective

Prove that backups are not only present, but actually restorable within the service target window.

## Recovery targets

For the current single-VPS MVP, use these targets:

| Metric | Target | Meaning |
| --- | --- | --- |
| RTO | 60 minutes | Time from declaring restore work has started until health checks and smoke checks pass again. |
| RPO | 24 hours | Maximum accepted data loss between the most recent good backup and the restore point. |

Notes:

- If operators run a manual backup before risky releases, the practical RPO for that release can be much smaller than 24 hours.
- If actual restore timing repeatedly exceeds RTO, treat that as an operational defect and open follow-up work.

## Drill frequency

- Monthly: restore the latest backup into a clean local staging directory or disposable VM.
- Quarterly: perform a full clean-machine drill with the intended production edge mode.
- Before major production changes: run an extra drill if backup format, Redis layout, SQLite path, or edge config changed.

## Required inputs

- Latest backup directory under `./backups/<timestamp>/`
- Access to the GPG private key or symmetric passphrase when encrypted backups are enabled
- Last-known-good `.env` handling procedure
- A disposable staging target, not the live production host

## Backup format expectations

The backup helpers now capture:

- Redis RDB snapshot
- SQLite backup
- `.env` snapshot
- Caddy snapshot
- DuckDNS helper snapshot
- SHA-256 checksum manifest
- Optional GPG-encrypted bundle inside the backup directory

Linux helper:

```sh
scripts/safe-zone.sh backup
```

Windows helper:

```powershell
pwsh ./scripts/safe-zone.ps1 backup
```

## Drill procedure

1. Record the drill start time.
2. Choose the backup directory to test.
3. Verify the backup directory contains either plaintext snapshots or `backup.tar.gz.gpg`.
4. Provision a clean staging path or disposable VM.
5. Restore using the standard helper:

   Linux:

   ```sh
   SAFE_ZONE_STACK=production scripts/safe-zone.sh restore backups/<timestamp>
   ```

   Windows:

   ```powershell
   pwsh ./scripts/safe-zone.ps1 restore -BackupPath backups\<timestamp>
   ```

6. After restore, verify:
   - `http://127.0.0.1:8080/healthz`
   - `http://127.0.0.1:8081/healthz`
   - `/v1/version` responds as expected
   - a safe domain analysis works
   - an existing override or telemetry sample expected from the backup is present
7. Record the drill end time and compute actual RTO.
8. Compare backup timestamp vs. restore point to compute actual RPO.

## Evidence to record

Store the following with the release or operations record:

- Backup timestamp used
- Whether the drill used encrypted backup mode
- Actual restore duration
- Actual data loss window
- Any manual steps required
- Any failed health or smoke checks

## Pass/fail criteria

Pass when all are true:

- Restore completes without corrupting Redis or SQLite
- Health checks pass
- At least one domain analysis and one admin workflow check succeed
- Actual RTO is 60 minutes or less
- Actual RPO is 24 hours or less

Fail when any are true:

- Decryption keys or passphrases are missing
- Restore requires undocumented steps
- Health checks fail after restore
- Actual RTO or RPO exceed the targets without approved exception

## If the drill fails

1. Do not mark production recovery as proven.
2. Open remediation work immediately.
3. Update this runbook if the failure came from unclear operator steps.
4. Re-run the drill after the fix and attach the new evidence.
