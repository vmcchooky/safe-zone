# Backup/restore contract tests for scripts/ops/safe-zone.ps1.
#
# Runs the real helper against stub Compose and Docker commands in a throwaway
# project, so no daemon, image or network is required. Covers the Windows
# restore-drill parity fixes:
#   * Get-ComposeContainerId must honour SAFE_ZONE_COMPOSE; calling
#     `docker compose` directly made an isolated drill look at the wrong
#     project and skip every Redis/SQLite container lookup.
#   * The Redis AOF bundle must be produced with tar, not by piping docker cp
#     into gzip.exe, which is not present on a stock Windows install.
#   * SAFE_ZONE_BACKUP_DIR must select the backup root, like the sh helper.
#   * An AOF-only bundle must restore even when the RDB copy is absent.
$ErrorActionPreference = 'Stop'

$sourceSafeZone = Join-Path $PSScriptRoot '..\safe-zone.ps1'
if (-not (Test-Path $sourceSafeZone)) {
  Write-Host "FATAL: cannot find safe-zone.ps1 next to the test: $sourceSafeZone" -ForegroundColor Red
  exit 2
}

$workRoot = Join-Path ([IO.Path]::GetTempPath()) ("safe-zone-ps-backup-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $workRoot | Out-Null
$script:Passed = 0
$script:Failed = 0

function Pass([string]$Message) {
  Write-Host "ok: $Message" -ForegroundColor Green
  $script:Passed++
}

function Fail([string]$Message) {
  Write-Host "FAIL: $Message" -ForegroundColor Red
  $script:Failed++
}

function Require-File([string]$Path, [string]$Label) {
  if (Test-Path $Path -PathType Leaf) {
    Pass $Label
  } else {
    Fail "${Label}: missing $Path"
  }
}

function Require-LogContains([string]$Path, [string]$Needle, [string]$Label) {
  if ((Test-Path $Path) -and ((Get-Content $Path -Raw) -match [regex]::Escape($Needle))) {
    Pass $Label
  } else {
    Fail "${Label}: log is missing: $Needle"
    if (Test-Path $Path) { Get-Content $Path | ForEach-Object { Write-Host "  log: $_" } }
  }
}

try {
  $proj = Join-Path $workRoot 'proj'
  $stubDir = Join-Path $workRoot 'bin'
  $backupRoot = Join-Path $workRoot 'backups'
  $composeLog = Join-Path $workRoot 'compose.log'
  $dockerLog = Join-Path $workRoot 'docker.log'
  New-Item -ItemType Directory -Force -Path "$proj\scripts\ops", "$proj\data", $stubDir | Out-Null
  Copy-Item $sourceSafeZone "$proj\scripts\ops\safe-zone.ps1"
  Set-Content -Path "$proj\.env" -Value @'
SAFE_ZONE_SQLITE_PATH=./data/missing.db
'@

  # Fixtures stand in for the files docker cp would export from the running
  # containers. The bytes only need to be non-empty and distinguishable.
  $fixtureDb = Join-Path $workRoot 'fixture.db'
  $fixtureAof = Join-Path $workRoot 'fixture.aof'
  Set-Content -Path $fixtureDb -Value 'sqlite-fixture-bytes' -NoNewline
  Set-Content -Path $fixtureAof -Value 'aof-fixture-bytes' -NoNewline

  $composeStub = Join-Path $stubDir 'compose-stub.ps1'
  @'
$joined = $args -join ' '
Add-Content -Path $env:SZ_COMPOSE_LOG -Value $joined
if ($joined -match ' ps -aq (core-api|redis)$') {
  "fake-$($Matches[1])-id"
  exit 0
}
if ($joined -match ' ps -q (core-api|redis)$') {
  "fake-$($Matches[1])-id"
  exit 0
}
if ($joined -match ' config get appendonly$') {
  'appendonly'
  'yes'
  exit 0
}
if ($joined -match ' info persistence$') {
  'aof_rewrite_in_progress:0'
  exit 0
}
exit 0
'@ | Set-Content -Path $composeStub

  $dockerStub = Join-Path $stubDir 'docker-stub.ps1'
  @'
Add-Content -Path $env:SZ_DOCKER_LOG -Value ($args -join ' ')
if ($args.Count -ge 3 -and $args[0] -eq 'cp') {
  $source = $args[1]
  $target = $args[2]
  if ($source -match ':/data/dump\.rdb$') {
    Copy-Item -Force $env:SZ_FIXTURE_DB $target
    exit 0
  }
  if ($source -match ':/data/appendonlydir$') {
    $dir = Join-Path $target 'appendonlydir'
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    Copy-Item -Force $env:SZ_FIXTURE_AOF (Join-Path $dir 'appendonly.aof')
    exit 0
  }
  if ($source -match ':/app/data/safe-zone\.db$') {
    Copy-Item -Force $env:SZ_FIXTURE_DB $target
    exit 0
  }
  if ($target -match ':/data/appendonlydir$') {
    if (-not (Test-Path (Join-Path $source 'appendonly.aof') -PathType Leaf)) {
      Write-Error "restore did not provide appendonlydir/appendonly.aof (source: $source)"
      exit 1
    }
    exit 0
  }
  if ($target -match ':/app/data/safe-zone\.db$') {
    if (-not (Test-Path $source -PathType Leaf)) {
      Write-Error "restore did not provide a SQLite file (source: $source)"
      exit 1
    }
    exit 0
  }
}
exit 0
'@ | Set-Content -Path $dockerStub

  # docker must resolve to the stub for the helper's direct docker cp calls.
  Set-Content -Path (Join-Path $stubDir 'docker.cmd') -Value @'
@echo off
pwsh -NoProfile -File "%~dp0docker-stub.ps1" %*
exit /b %ERRORLEVEL%
'@

  $env:SAFE_ZONE_SKIP_MISE = '1'
  # Invoke-ComposeCommand splits on whitespace, so keep the stub path free of
  # spaces (the temp root is per-user and normally is).
  $env:SAFE_ZONE_COMPOSE = "pwsh -NoProfile -File $composeStub"
  $env:SAFE_ZONE_BACKUP_DIR = $backupRoot
  $env:PATH = "$stubDir;$env:PATH"
  $env:SZ_COMPOSE_LOG = $composeLog
  $env:SZ_DOCKER_LOG = $dockerLog
  $env:SZ_FIXTURE_DB = $fixtureDb
  $env:SZ_FIXTURE_AOF = $fixtureAof

  & pwsh -NoProfile -File "$proj\scripts\ops\safe-zone.ps1" backup -Stack dev
  if ($LASTEXITCODE -ne 0) {
    Fail "backup should succeed (exit $LASTEXITCODE)"
  } else {
    Pass 'backup succeeds against the stubbed project'
  }

  $backups = @(Get-ChildItem -Path $backupRoot -Directory)
  if ($backups.Count -eq 1) {
    Pass 'SAFE_ZONE_BACKUP_DIR selects the backup root'
  } else {
    Fail "expected exactly one backup under SAFE_ZONE_BACKUP_DIR, found $($backups.Count)"
  }
  $backupDir = $backups | Select-Object -First 1
  if ($backupDir) {
    Require-File (Join-Path $backupDir.FullName 'safe-zone.db') 'backup captures SQLite through the core-api container'
    Require-File (Join-Path $backupDir.FullName 'redis-dump.rdb') 'backup captures the Redis RDB'
    Require-File (Join-Path $backupDir.FullName 'redis-aof.tar.gz') 'backup captures the Redis AOF bundle with tar'

    $checksumsOk = $true
    foreach ($line in Get-Content (Join-Path $backupDir.FullName 'SHA256SUMS')) {
      if (-not $line.Trim()) { continue }
      $parts = $line -split '\s+', 2
      $actual = (Get-FileHash -Algorithm SHA256 -Path (Join-Path $backupDir.FullName $parts[1])).Hash.ToLowerInvariant()
      if ($actual -ne $parts[0]) { $checksumsOk = $false }
    }
    if ($checksumsOk) {
      Pass 'backup checksum manifest verifies'
    } else {
      Fail 'backup checksum manifest does not verify'
    }
    Require-LogContains $composeLog '-f docker-compose.yml -f docker-compose.dev.yml ps -q redis' `
      'container lookup uses SAFE_ZONE_COMPOSE'
  }

  # An AOF-only bundle must restore even without the RDB copy: appendonly
  # deployments treat the AOF as authoritative and start empty without it.
  $aofOnly = Join-Path $workRoot 'aof-only'
  Copy-Item -Recurse -Force $backupDir.FullName $aofOnly
  Remove-Item -Force (Join-Path $aofOnly 'redis-dump.rdb')
  & pwsh -NoProfile -File "$proj\scripts\ops\safe-zone.ps1" restore -Stack dev -BackupPath $aofOnly
  if ($LASTEXITCODE -ne 0) {
    Fail "AOF-only restore should succeed (exit $LASTEXITCODE)"
  } else {
    Pass 'AOF-only restore succeeds without an RDB copy'
  }
  Require-LogContains $dockerLog 'appendonlydir' 'AOF-only restore copies the AOF directory into the container'
  if ((Test-Path "$proj\data\missing.db" -PathType Leaf) -and
    ((Get-FileHash -Algorithm SHA256 -Path "$proj\data\missing.db").Hash -eq (Get-FileHash -Algorithm SHA256 -Path $fixtureDb).Hash)) {
    Pass 'restore puts the backed-up SQLite file at SAFE_ZONE_SQLITE_PATH'
  } else {
    Fail 'restore did not put the backed-up SQLite file at SAFE_ZONE_SQLITE_PATH'
  }

  # The RDB fallback must still work for pre-AOF backups and AOF-disabled
  # deployments.
  $rdbOnly = Join-Path $workRoot 'rdb-only'
  Copy-Item -Recurse -Force $backupDir.FullName $rdbOnly
  Remove-Item -Force (Join-Path $rdbOnly 'redis-aof.tar.gz')
  & pwsh -NoProfile -File "$proj\scripts\ops\safe-zone.ps1" restore -Stack dev -BackupPath $rdbOnly
  if ($LASTEXITCODE -ne 0) {
    Fail "RDB-only restore should succeed (exit $LASTEXITCODE)"
  } else {
    Pass 'RDB-only restore succeeds for pre-AOF backups'
  }
} finally {
  Remove-Item -Recurse -Force $workRoot -ErrorAction SilentlyContinue
}

Write-Host ''
Write-Host "$($script:Passed) passed, $($script:Failed) failed"
if ($script:Failed -ne 0) { exit 1 }
# The GitHub Actions PowerShell wrapper dot-sources this file. Without an
# explicit success exit, a native command that failed inside a test can leave
# $LASTEXITCODE=1 and fail the job even when every assertion passed.
exit 0
