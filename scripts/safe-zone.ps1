param(
  [Parameter(Position = 0)]
  [ValidateSet('help', 'deploy', 'deploy-dev', 'status', 'backup', 'restore', 'prune', 'feed-sync')]
  [string]$Command = 'help',
  [ValidateSet('production', 'dev')]
  [string]$Stack = 'production',
  [string]$BackupPath,
  [int]$Keep = 7,
  [int]$LogRetentionDays = 7,
  [switch]$FeedSync
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoRoot = Split-Path -Parent $PSScriptRoot
$BackupsRoot = Join-Path $RepoRoot 'backups'
$TmpRoot = Join-Path $RepoRoot 'tmp'
$SqliteContainerPath = '/app/data/safe-zone.db'

function Write-Section {
  param([string]$Text)
  Write-Host ''
  Write-Host $Text -ForegroundColor Cyan
}

function Write-Warn {
  param([string]$Text)
  Write-Host "WARN: $Text" -ForegroundColor Yellow
}

function Write-ErrorMessage {
  param([string]$Text)
  Write-Host "ERROR: $Text" -ForegroundColor Red
}

function Get-ComposeBaseArgs {
  param([string]$TargetStack = $Stack)

  $composeArgs = @('-f', 'docker-compose.yml')
  switch ($TargetStack) {
    'production' { $composeArgs += @('-f', 'docker-compose.production.yml') }
    'dev' { $composeArgs += @('-f', 'docker-compose.dev.yml') }
    default { throw "unsupported stack: $TargetStack" }
  }
  return $composeArgs
}

function Invoke-Compose {
  param(
    [string[]]$SubCommandArgs,
    [string]$TargetStack = $Stack,
    [switch]$UseProductionProfile
  )

  $composeArgs = Get-ComposeBaseArgs -TargetStack $TargetStack
  if ($UseProductionProfile) {
    $composeArgs += @('--profile', 'production-edge')
  }
  $composeArgs += $SubCommandArgs

  & docker compose @composeArgs
  if ($LASTEXITCODE -ne 0) {
    throw "docker compose $($composeArgs -join ' ') failed with exit code $LASTEXITCODE"
  }
}

function Invoke-ComposeBestEffort {
  param(
    [string[]]$SubCommandArgs,
    [string]$TargetStack = $Stack
  )

  $composeArgs = Get-ComposeBaseArgs -TargetStack $TargetStack
  $composeArgs += $SubCommandArgs
  & docker compose @composeArgs | Out-Null
  if ($LASTEXITCODE -ne 0) {
    Write-Warn "docker compose $($composeArgs -join ' ') exited with code $LASTEXITCODE"
  }
}

function Start-ComposeStack {
  if ($Stack -eq 'production') {
    Invoke-Compose -SubCommandArgs @('up', '-d') -TargetStack 'production' -UseProductionProfile
    return
  }
  Invoke-Compose -SubCommandArgs @('up', '-d') -TargetStack 'dev'
}

function Get-ComposeContainerId {
  param(
    [string]$ServiceName,
    [string]$TargetStack = $Stack,
    [switch]$All
  )

  $composeArgs = Get-ComposeBaseArgs -TargetStack $TargetStack
  if ($All) {
    $composeArgs += @('ps', '-aq', $ServiceName)
  } else {
    $composeArgs += @('ps', '-q', $ServiceName)
  }

  $rawOutput = & docker compose @composeArgs
  if ($rawOutput -is [array]) {
    $rawOutput = $rawOutput -join "`n"
  }
  if (-not $rawOutput) {
    return $null
  }

  $containerId = $rawOutput.Trim()
  if (-not $containerId) {
    return $null
  }

  return $containerId
}

function Get-DotEnvValue {
  param([string]$Name)

  $environmentValue = [Environment]::GetEnvironmentVariable($Name)
  if ($environmentValue) {
    return $environmentValue
  }

  $envFile = Join-Path $RepoRoot '.env'
  if (-not (Test-Path $envFile)) {
    return $null
  }

  $line = Get-Content -Path $envFile |
    Where-Object { $_ -match "^\s*$([regex]::Escape($Name))=" } |
    Select-Object -Last 1

  if (-not $line) {
    return $null
  }

  $value = ($line -replace "^\s*$([regex]::Escape($Name))=", '').Trim()
  return $value.Trim('"').Trim("'")
}

function Get-SecretValue {
  param([string]$Name)

  $value = Get-DotEnvValue -Name $Name
  if ($value) {
    return $value
  }

  $filePath = Get-DotEnvValue -Name "${Name}_FILE"
  if (-not $filePath) {
    return $null
  }
  if (-not (Test-Path $filePath -PathType Leaf)) {
    throw "secret file not found: $filePath"
  }
  return (Get-Content -Path $filePath -Raw).Trim()
}

function Get-FlagEnabled {
  param([string]$Name)

  $raw = Get-DotEnvValue -Name $Name
  if (-not $raw) {
    return $false
  }
  switch ($raw.Trim().ToLowerInvariant()) {
    '1' { return $true }
    'true' { return $true }
    'yes' { return $true }
    'on' { return $true }
    default { return $false }
  }
}

function Resolve-SqliteRuntimePath {
  $configured = Get-DotEnvValue -Name 'SAFE_ZONE_SQLITE_PATH'
  if (-not $configured) {
    $configured = 'data/safe-zone.db'
  }

  if ($configured.StartsWith('/app/data/')) {
    return Join-Path (Join-Path $RepoRoot 'data') $configured.Substring('/app/data/'.Length)
  }
  if ([System.IO.Path]::IsPathRooted($configured)) {
    return $configured
  }
  if ($configured.StartsWith('./')) {
    $configured = $configured.Substring(2)
  }
  return Join-Path $RepoRoot $configured
}

function Wait-ForHealth {
  param(
    [string]$Url,
    [string]$Name,
    [int]$TimeoutSeconds = 60
  )

  $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
  while ((Get-Date) -lt $deadline) {
    try {
      $response = Invoke-WebRequest -Uri $Url -Method Get -TimeoutSec 3
      if ($response.StatusCode -eq 200) {
        return
      }
    } catch {
      Start-Sleep -Milliseconds 500
    }
  }

  throw "$Name did not become healthy within $TimeoutSeconds seconds"
}

function Backup-Redis {
  param([string]$TargetDir)

  $containerId = Get-ComposeContainerId -ServiceName 'redis'
  if (-not $containerId) {
    Write-Warn 'Redis container is not running; skipping Redis snapshot copy'
    return
  }

  Write-Host 'Creating Redis snapshot...'
  try {
    Invoke-Compose -SubCommandArgs @('exec', '-T', 'redis', 'redis-cli', 'SAVE')
    $targetFile = Join-Path $TargetDir 'redis-dump.rdb'
    & docker cp "${containerId}:/data/dump.rdb" $targetFile
    if ($LASTEXITCODE -ne 0) {
      Write-Warn 'docker cp failed while exporting the Redis snapshot'
    }
  } catch {
    Write-Warn "Failed to trigger Redis SAVE or copy dump: $_"
  }
}

function Backup-Sqlite {
  param([string]$TargetDir)

  $sourcePath = Resolve-SqliteRuntimePath
  $targetFile = Join-Path $TargetDir 'safe-zone.db'

  if (Test-Path $sourcePath -PathType Leaf) {
    if (Get-Command sqlite3 -ErrorAction SilentlyContinue) {
      Write-Host "Creating SQLite hot backup from $sourcePath..."
      $escapedTarget = $targetFile.Replace("'", "''")
      & sqlite3 $sourcePath ".backup '$escapedTarget'"
      if ($LASTEXITCODE -ne 0) {
        throw "sqlite3 hot backup failed with exit code $LASTEXITCODE"
      }
    } else {
      Write-Warn 'sqlite3 CLI not found; copying SQLite database directly'
      Copy-Item -Force -Path $sourcePath -Destination $targetFile
    }
    return
  }

  $containerId = Get-ComposeContainerId -ServiceName 'core-api'
  if ($containerId) {
    Write-Warn "Host SQLite database not found at $sourcePath; copying from core-api container"
    & docker cp "${containerId}:$SqliteContainerPath" $targetFile
    if ($LASTEXITCODE -ne 0) {
      Write-Warn 'SQLite database not found in core-api container'
    }
    return
  }

  Write-Warn "SQLite database not found at $sourcePath; skipping SQLite backup"
}

function Copy-OptionalSnapshots {
  param([string]$TargetDir)

  $envFile = Join-Path $RepoRoot '.env'
  if (Test-Path $envFile -PathType Leaf) {
    Copy-Item -Force -Path $envFile -Destination (Join-Path $TargetDir 'env.snapshot')
  }

  $caddyFile = Join-Path $RepoRoot 'Caddyfile'
  if (Test-Path $caddyFile -PathType Leaf) {
    Copy-Item -Force -Path $caddyFile -Destination (Join-Path $TargetDir 'Caddyfile.snapshot')
  }

  $duckDNS = Join-Path $PSScriptRoot 'duckdns-update.sh'
  if (Test-Path $duckDNS -PathType Leaf) {
    Copy-Item -Force -Path $duckDNS -Destination (Join-Path $TargetDir 'duckdns-update.sh.snapshot')
  }

  $productionCompose = Join-Path $RepoRoot 'docker-compose.production.yml'
  if (Test-Path $productionCompose -PathType Leaf) {
    Copy-Item -Force -Path $productionCompose -Destination (Join-Path $TargetDir 'docker-compose.production.yml.snapshot')
  }
}

function Write-ChecksumManifest {
  param([string]$TargetDir)

  $manifest = Join-Path $TargetDir 'SHA256SUMS'
  $lines = @()
  $files = Get-ChildItem -Path $TargetDir -File | Where-Object { $_.Name -ne 'SHA256SUMS' }
  foreach ($file in $files) {
    $hash = (Get-FileHash -Algorithm SHA256 -Path $file.FullName).Hash.ToLowerInvariant()
    $lines += "$hash  $($file.Name)"
  }
  Set-Content -Path $manifest -Value $lines
}

function Test-BackupArtifacts {
  param([string]$TargetDir)

  $files = Get-ChildItem -Path $TargetDir -File
  if (-not $files) {
    throw "backup directory is empty: $TargetDir"
  }
  foreach ($file in $files) {
    if ($file.Length -le 0) {
      throw "backup artifact is empty: $($file.FullName)"
    }
  }
}

function Protect-BackupBundle {
  param(
    [string]$TargetDir,
    [string]$Timestamp
  )

  if (-not (Get-FlagEnabled -Name 'SAFE_ZONE_BACKUP_ENCRYPT')) {
    return
  }
  if (-not (Get-Command gpg -ErrorAction SilentlyContinue)) {
    throw 'SAFE_ZONE_BACKUP_ENCRYPT is enabled but gpg is not installed'
  }

  $recipient = Get-DotEnvValue -Name 'SAFE_ZONE_BACKUP_GPG_RECIPIENT'
  $passphrase = Get-SecretValue -Name 'SAFE_ZONE_BACKUP_GPG_PASSPHRASE'
  if (-not $recipient -and -not $passphrase) {
    throw 'Backup encryption requires SAFE_ZONE_BACKUP_GPG_RECIPIENT or SAFE_ZONE_BACKUP_GPG_PASSPHRASE(_FILE)'
  }

  $archivePath = Join-Path $BackupsRoot "$Timestamp.tar.gz"
  $encryptedPath = Join-Path $TargetDir 'backup.tar.gz.gpg'
  $checksumPath = Join-Path $TargetDir 'backup.tar.gz.gpg.sha256'

  Write-Host "Packaging backup into $archivePath..."
  & tar -czf $archivePath -C $TargetDir .
  if ($LASTEXITCODE -ne 0) {
    throw "tar archive creation failed with exit code $LASTEXITCODE"
  }

  Write-Host 'Encrypting backup archive with GPG...'
  if ($recipient) {
    & gpg --batch --yes --trust-model always --output $encryptedPath --encrypt --recipient $recipient $archivePath
  } else {
    & gpg --batch --yes --pinentry-mode loopback --passphrase $passphrase --cipher-algo AES256 --output $encryptedPath --symmetric $archivePath
  }
  if ($LASTEXITCODE -ne 0) {
    throw "gpg backup encryption failed with exit code $LASTEXITCODE"
  }

  Remove-Item -Force $archivePath
  $encryptedHash = (Get-FileHash -Algorithm SHA256 -Path $encryptedPath).Hash.ToLowerInvariant()
  Set-Content -Path $checksumPath -Value "$encryptedHash  $(Split-Path -Leaf $encryptedPath)"

  if (-not (Get-FlagEnabled -Name 'SAFE_ZONE_BACKUP_KEEP_PLAINTEXT')) {
    Get-ChildItem -Path $TargetDir -Force | Where-Object {
      $_.Name -notin @('backup.tar.gz.gpg', 'backup.tar.gz.gpg.sha256')
    } | Remove-Item -Recurse -Force
  }
}

function Sync-OffsiteBackup {
  param(
    [string]$LocalDir,
    [string]$Timestamp
  )

  $remote = Get-DotEnvValue -Name 'SAFE_ZONE_RCLONE_REMOTE'
  if (-not $remote) {
    return
  }

  $dest = Get-DotEnvValue -Name 'SAFE_ZONE_RCLONE_DEST'
  if (-not $dest) {
    $dest = 'safe-zone-backups'
  }

  if (-not (Get-Command rclone -ErrorAction SilentlyContinue)) {
    Write-ErrorMessage 'SAFE_ZONE_RCLONE_REMOTE is configured but rclone is not installed; skipping offsite upload'
    return
  }

  $remoteName = $remote.TrimEnd(':')
  $remoteTarget = "${remoteName}:$dest/$Timestamp"
  Write-Host "Uploading backup to $remoteTarget..."
  & rclone copy $LocalDir $remoteTarget
  if ($LASTEXITCODE -eq 0) {
    Write-Host "Offsite backup upload completed: $remoteTarget" -ForegroundColor Green
  } else {
    Write-ErrorMessage "Offsite backup upload failed: $remoteTarget"
  }
}

function New-Backup {
  if (-not (Test-Path $BackupsRoot)) {
    New-Item -ItemType Directory -Force -Path $BackupsRoot | Out-Null
  }

  $timestamp = (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss')
  $targetDir = Join-Path $BackupsRoot $timestamp
  New-Item -ItemType Directory -Force -Path $targetDir | Out-Null

  Backup-Redis -TargetDir $targetDir
  Copy-OptionalSnapshots -TargetDir $targetDir
  Backup-Sqlite -TargetDir $targetDir
  Write-ChecksumManifest -TargetDir $targetDir
  Test-BackupArtifacts -TargetDir $targetDir
  Protect-BackupBundle -TargetDir $targetDir -Timestamp $timestamp
  Sync-OffsiteBackup -LocalDir $targetDir -Timestamp $timestamp

  Write-Host "Backup written to $targetDir" -ForegroundColor Green
}

function Resolve-BackupDirectory {
  param([string]$Path)

  if ($Path) {
    if (-not (Test-Path $Path)) {
      throw "backup path not found: $Path"
    }

    if (Test-Path $Path -PathType Container) {
      return (Resolve-Path $Path).Path
    }

    return (Resolve-Path (Split-Path -Parent $Path)).Path
  }

  if (-not (Test-Path $BackupsRoot)) {
    throw "no backups found in $BackupsRoot"
  }

  $latest = Get-ChildItem -Path $BackupsRoot -Directory |
    Sort-Object Name -Descending |
    Select-Object -First 1

  if (-not $latest) {
    throw "no backups found in $BackupsRoot"
  }

  return $latest.FullName
}

function Stop-ForRestore {
  Write-Host 'Stopping services that may hold Redis/SQLite locks...'
  Invoke-ComposeBestEffort -SubCommandArgs @('stop', 'core-api', 'dns-resolver', 'feed-syncd', 'redis')
}

function Restore-Sqlite {
  param([string]$BackupDir)

  $sourceDb = Join-Path $BackupDir 'safe-zone.db'
  if (-not (Test-Path $sourceDb -PathType Leaf)) {
    Write-Warn "No safe-zone.db found in $BackupDir; skipping SQLite restore"
    return
  }

  $targetDb = Resolve-SqliteRuntimePath
  $targetParent = Split-Path -Parent $targetDb
  if (-not (Test-Path $targetParent)) {
    New-Item -ItemType Directory -Force -Path $targetParent | Out-Null
  }
  Copy-Item -Force -Path $sourceDb -Destination $targetDb
  Write-Host "Restored SQLite database to $targetDb"

  $containerId = Get-ComposeContainerId -ServiceName 'core-api' -All
  if ($containerId) {
    & docker cp $sourceDb "${containerId}:$SqliteContainerPath"
    if ($LASTEXITCODE -ne 0) {
      Write-Warn 'Could not copy SQLite database into core-api container volume'
    }
  }
}

function Restore-Redis {
  param([string]$BackupDir)

  $sourceRdb = Join-Path $BackupDir 'redis-dump.rdb'
  if (-not (Test-Path $sourceRdb -PathType Leaf)) {
    $sourceRdb = Join-Path $BackupDir 'dump.rdb'
  }

  if (-not (Test-Path $sourceRdb -PathType Leaf)) {
    Write-Warn "No redis-dump.rdb or dump.rdb found in $BackupDir; skipping Redis restore"
    return
  }

  $containerId = Get-ComposeContainerId -ServiceName 'redis' -All
  if (-not $containerId) {
    Write-Warn 'Redis container does not exist yet; creating it before Redis restore'
    Invoke-Compose -SubCommandArgs @('up', '--no-start', 'redis')
    $containerId = Get-ComposeContainerId -ServiceName 'redis' -All
  }

  if (-not $containerId) {
    Write-Warn 'Could not locate Redis container; skipping Redis restore'
    return
  }

  & docker cp $sourceRdb "${containerId}:/data/dump.rdb"
  if ($LASTEXITCODE -ne 0) {
    throw 'docker cp failed while restoring the Redis snapshot'
  }
  Write-Host "Restored Redis snapshot from $sourceRdb"
}

function Restore-EnvNotice {
  param([string]$BackupDir)

  $envSnapshot = Join-Path $BackupDir 'env.snapshot'
  if (Test-Path $envSnapshot -PathType Leaf) {
    Write-Warn "Environment snapshot available at $envSnapshot. Review it and copy to .env manually if needed."
  }
}

function Expand-BackupBundleIfNeeded {
  param([string]$BackupDir)

  $encryptedBundle = Join-Path $BackupDir 'backup.tar.gz.gpg'
  $archiveBundle = Join-Path $BackupDir 'backup.tar.gz'
  if (-not (Test-Path $encryptedBundle -PathType Leaf) -and -not (Test-Path $archiveBundle -PathType Leaf)) {
    return @{
      Path    = $BackupDir
      TempDir = $null
    }
  }

  $tempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("safe-zone-restore-" + [guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Force -Path $tempDir | Out-Null
  $bundleDir = Join-Path $tempDir 'bundle'
  New-Item -ItemType Directory -Force -Path $bundleDir | Out-Null

  if (Test-Path $encryptedBundle -PathType Leaf) {
    if (-not (Get-Command gpg -ErrorAction SilentlyContinue)) {
      throw 'Encrypted backup found but gpg is not installed'
    }
    $passphrase = Get-SecretValue -Name 'SAFE_ZONE_BACKUP_GPG_PASSPHRASE'
    $tarPath = Join-Path $tempDir 'backup.tar.gz'
    Write-Host "Decrypting encrypted backup bundle from $encryptedBundle..."
    if ($passphrase) {
      & gpg --batch --yes --pinentry-mode loopback --passphrase $passphrase --output $tarPath --decrypt $encryptedBundle
    } else {
      & gpg --batch --yes --output $tarPath --decrypt $encryptedBundle
    }
    if ($LASTEXITCODE -ne 0) {
      throw "gpg backup decryption failed with exit code $LASTEXITCODE"
    }
    & tar -xzf $tarPath -C $bundleDir
  } else {
    Write-Host "Extracting backup bundle from $archiveBundle..."
    & tar -xzf $archiveBundle -C $bundleDir
  }
  if ($LASTEXITCODE -ne 0) {
    throw "tar extraction failed with exit code $LASTEXITCODE"
  }

  return @{
    Path    = $bundleDir
    TempDir = $tempDir
  }
}

function Restore-Backup {
  param([string]$Path)

  $backupDir = Resolve-BackupDirectory -Path $Path
  Write-Host "Restoring backup from $backupDir"
  $prepared = Expand-BackupBundleIfNeeded -BackupDir $backupDir
  Stop-ForRestore
  Restore-Sqlite -BackupDir $prepared.Path
  Restore-Redis -BackupDir $prepared.Path
  Restore-EnvNotice -BackupDir $prepared.Path
  Write-Host 'Restarting stack...'
  Start-ComposeStack
  if ($prepared.TempDir) {
    Remove-Item -Recurse -Force $prepared.TempDir
  }
  Write-Host 'Restore completed.' -ForegroundColor Green
}

function Prune-Backups {
  param([int]$KeepCount)

  if (-not (Test-Path $BackupsRoot)) {
    Write-Host "No backups directory found at $BackupsRoot"
    return
  }

  $backups = Get-ChildItem -Path $BackupsRoot -Directory |
    Sort-Object Name -Descending

  if ($backups.Count -le $KeepCount) {
    Write-Host "Backup retention already satisfied ($($backups.Count) <= $KeepCount)"
    return
  }

  $toRemove = $backups | Select-Object -Skip $KeepCount
  foreach ($entry in $toRemove) {
    Remove-Item -Recurse -Force $entry.FullName
    Write-Host "Removed backup $($entry.Name)"
  }
}

function Prune-Logs {
  param([int]$RetentionDays)

  if (-not (Test-Path $TmpRoot)) {
    Write-Host "No tmp directory found at $TmpRoot"
    return
  }

  $cutoff = (Get-Date).AddDays(-1 * $RetentionDays)
  $oldLogs = Get-ChildItem -Path $TmpRoot -File -Filter '*.log' |
    Where-Object { $_.LastWriteTime -lt $cutoff }

  foreach ($log in $oldLogs) {
    Remove-Item -Force $log.FullName
    Write-Host "Removed log $($log.Name)"
  }

  if (-not $oldLogs) {
    Write-Host "No logs older than $RetentionDays day(s)"
  }
}

function Show-Help {
  @'
Safe Zone ops helper

Usage:
  pwsh ./scripts/safe-zone.ps1 deploy
  pwsh ./scripts/safe-zone.ps1 deploy-dev
  pwsh ./scripts/safe-zone.ps1 status
  pwsh ./scripts/safe-zone.ps1 backup
  pwsh ./scripts/safe-zone.ps1 restore [-BackupPath <backup-directory>]
  pwsh ./scripts/safe-zone.ps1 prune [-Keep 7] [-LogRetentionDays 7]
  pwsh ./scripts/safe-zone.ps1 feed-sync

Commands:
  deploy      Build and start the production Compose stack, then wait for loopback health.
  deploy-dev  Build and start the local developer stack.
  status      Show Compose status and probe the local health endpoints.
  backup      Save Redis, SQLite, env, and Caddy snapshots into ./backups/<timestamp>/.
  restore     Restore Redis and SQLite from the latest backup directory or -BackupPath.
  prune       Keep the newest backup directories and delete stale tmp/*.log files.
  feed-sync   Run the configured threat feed sync sources once.

Options:
  -Stack production|dev   Choose the stack used by status/backup/restore/prune helpers.

Environment:
  SAFE_ZONE_BACKUP_ENCRYPT=1
  SAFE_ZONE_BACKUP_GPG_RECIPIENT=<gpg-recipient>
  SAFE_ZONE_BACKUP_GPG_PASSPHRASE=<passphrase>
  SAFE_ZONE_BACKUP_GPG_PASSPHRASE_FILE=<path>
  SAFE_ZONE_BACKUP_KEEP_PLAINTEXT=1
'@ | Write-Host
}

function Resolve-FeedSources {
  if ($env:SAFE_ZONE_AGENT_FEED_SOURCES) {
    return $env:SAFE_ZONE_AGENT_FEED_SOURCES -split ','
  }

  if ($env:SAFE_ZONE_AGENT_FEED_PRESET -eq 'production-free') {
    return @(
      'https://urlhaus.abuse.ch/downloads/csv_recent/',
      'https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt'
    )
  }

  if ($env:SAFE_ZONE_THREAT_FEED_SOURCE) {
    return @($env:SAFE_ZONE_THREAT_FEED_SOURCE)
  }

  return @()
}

switch ($Command) {
  'help' {
    Show-Help
  }
  'deploy' {
    Write-Section 'Deploying Safe Zone'
    $composeArgs = @('up', '-d', '--build')
    if ($FeedSync) {
      $composeArgs = @('--profile', 'feed-sync') + $composeArgs
    }
    Invoke-Compose -SubCommandArgs $composeArgs -TargetStack 'production' -UseProductionProfile
    Wait-ForHealth -Url 'http://localhost:8080/healthz' -Name 'core-api'
    Wait-ForHealth -Url 'http://localhost:8081/healthz' -Name 'dns-resolver'
    Write-Host 'Deployment healthy.' -ForegroundColor Green
  }
  'deploy-dev' {
    Write-Section 'Deploying Safe Zone (dev stack)'
    Invoke-Compose -SubCommandArgs @('up', '-d', '--build') -TargetStack 'dev'
    Wait-ForHealth -Url 'http://localhost:8080/healthz' -Name 'core-api'
    Wait-ForHealth -Url 'http://localhost:8081/healthz' -Name 'dns-resolver'
    Write-Host 'Deployment healthy.' -ForegroundColor Green
  }
  'status' {
    Write-Section 'Compose status'
    Invoke-Compose -SubCommandArgs @('ps')
    Write-Section 'Health checks'
    foreach ($item in @(
      @{ Name = 'core-api'; Url = 'http://localhost:8080/healthz' },
      @{ Name = 'dns-resolver'; Url = 'http://localhost:8081/healthz' }
    )) {
      try {
        $response = Invoke-WebRequest -Uri $item.Url -Method Get -TimeoutSec 3
        Write-Host "$($item.Name): $($response.StatusCode)"
      } catch {
        Write-Host "$($item.Name): offline"
      }
    }
  }
  'backup' {
    Write-Section 'Backing up Safe Zone'
    New-Backup
  }
  'restore' {
    Write-Section 'Restoring Safe Zone'
    Restore-Backup -Path $BackupPath
  }
  'prune' {
    Write-Section 'Pruning backups and logs'
    Prune-Backups -KeepCount $Keep
    Prune-Logs -RetentionDays $LogRetentionDays
  }
  'feed-sync' {
    $sources = Resolve-FeedSources | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    if (-not $sources) {
      throw 'No feed sources configured. Set SAFE_ZONE_AGENT_FEED_SOURCES, SAFE_ZONE_AGENT_FEED_PRESET, or SAFE_ZONE_THREAT_FEED_SOURCE.'
    }

    foreach ($source in $sources) {
      Write-Section "Syncing $source"
      Invoke-Compose -SubCommandArgs @('--profile', 'feed-sync', 'run', '--rm', 'feed-sync', '/app/service', '-source', $source)
    }
  }
  default {
    throw "unsupported command: $Command"
  }
}
