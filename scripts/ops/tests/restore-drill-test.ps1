# Automated restore drill for the developer Compose stack on Windows.
#
# Mirror of restore-drill-test.sh: boot an isolated project, seed state through
# the admin API, take a backup through scripts/ops/safe-zone.ps1, verify its
# checksum manifest, delete the seeded state, restore through the same helper,
# and verify both the restored SQLite file / Redis state and the live API.
#
# Requires Docker Desktop with Linux containers. The bash drill remains the CI
# path (windows-latest cannot run Linux containers); this script exists so the
# Windows helper is exercised end to end where an operator can run it.
$ErrorActionPreference = 'Stop'

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
Set-Location $RepoRoot

$project = 'restore-drill-win'
$composeArgs = @('-p', $project, '-f', 'docker-compose.yml', '-f', 'docker-compose.dev.yml')
$composeOverride = "docker compose -p $project"
$diagDir = Join-Path $RepoRoot 'tmp\restore-drill-win'
$envFile = Join-Path $RepoRoot '.env'
$envBackup = Join-Path $RepoRoot '.env.restore-drill-win-backup'
$hostDb = Join-Path $RepoRoot 'data\safe-zone.db'
$hostDbPristine = Join-Path $RepoRoot 'tmp\restore-drill-win-host-db.pristine'
$backupRoot = Join-Path ([IO.Path]::GetTempPath()) ("safe-zone-restore-drill-" + [guid]::NewGuid().ToString('N'))
$script:StackTouched = $false
$script:ExitCode = 0

function Write-DrillLog([string]$Message) {
  Write-Host "[restore-drill-win] $Message"
}

function Invoke-ComposeDrill {
  param([string[]]$CommandArgs, [switch]$BestEffort)
  & docker compose @composeArgs @CommandArgs
  if ($LASTEXITCODE -ne 0 -and -not $BestEffort) {
    throw "docker compose $($CommandArgs -join ' ') failed with exit code $LASTEXITCODE"
  }
}

function Wait-Http([string]$Url, [string]$Name, [int]$TimeoutSeconds = 300) {
  $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
  while ((Get-Date) -lt $deadline) {
    try {
      $response = Invoke-WebRequest -Uri $Url -Method Get -TimeoutSec 5
      if ($response.StatusCode -eq 200) {
        Write-DrillLog "$Name ready"
        return
      }
    } catch {
      Start-Sleep -Seconds 2
    }
  }
  throw "timed out waiting for $Name at $Url"
}

function Invoke-Api {
  param(
    [string]$Method,
    [string]$Path,
    [string]$ApiKey,
    [object]$Body
  )
  $params = @{
    Uri        = "http://127.0.0.1:8080$Path"
    Method     = $Method
    Headers    = @{ Authorization = "Bearer $ApiKey" }
    TimeoutSec = 30
  }
  if ($null -ne $Body) {
    $params.ContentType = 'application/json'
    $params.Body = ($Body | ConvertTo-Json -Compress)
  }
  Invoke-RestMethod @params
}

function Get-BrandCount([string]$ApiKey) {
  $response = Invoke-Api -Method Get -Path '/v1/brands' -ApiKey $ApiKey
  return @($response.items).Count
}

function Collect-Diagnostics {
  New-Item -ItemType Directory -Force -Path $diagDir | Out-Null
  Invoke-ComposeDrill -CommandArgs @('ps', '-a') -BestEffort *> (Join-Path $diagDir 'ps.txt')
  Invoke-ComposeDrill -CommandArgs @('logs', '--no-color') -BestEffort *> (Join-Path $diagDir 'logs.txt')
  Write-DrillLog "diagnostics written to $diagDir"
}

function Cleanup {
  try {
    if ($script:StackTouched) {
      Invoke-ComposeDrill -CommandArgs @('down', '-v', '--remove-orphans', '--timeout', '20') -BestEffort *> $null
    }
  } catch {
    Write-Warning "stack teardown failed: $_"
  }
  Remove-Item -Force $hostDb -ErrorAction SilentlyContinue
  if (Test-Path $hostDbPristine -PathType Leaf) {
    Move-Item -Force $hostDbPristine $hostDb
  }
  Remove-Item -Force $envFile -ErrorAction SilentlyContinue
  if (Test-Path $envBackup -PathType Leaf) {
    Move-Item -Force $envBackup $envFile
  }
  Remove-Item -Recurse -Force $backupRoot -ErrorAction SilentlyContinue
  exit $script:ExitCode
}

try {
  docker info *> $null
  if ($LASTEXITCODE -ne 0) {
    throw 'docker daemon not reachable; start Docker Desktop with Linux containers'
  }
  New-Item -ItemType Directory -Force -Path $diagDir | Out-Null
  if (Test-Path $envFile -PathType Leaf) {
    Move-Item -Force $envFile $envBackup
    Write-DrillLog 'backed up an existing .env; it is restored on exit'
  }
  Copy-Item .env.example $envFile
  Add-Content -Path $envFile -Value @'

SAFE_ZONE_RATELIMIT_OVERRIDE_RPM=600
SAFE_ZONE_RATELIMIT_OVERRIDE_BURST=50
SAFE_ZONE_RATELIMIT_ANALYZE_RPM=600
SAFE_ZONE_RATELIMIT_ANALYZE_BURST=50
SAFE_ZONE_RATELIMIT_AUTH_RPM=60
SAFE_ZONE_RATELIMIT_AUTH_BURST=20
'@
  if (Test-Path $hostDb -PathType Leaf) {
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $hostDbPristine) | Out-Null
    Copy-Item -Force $hostDb $hostDbPristine
    Write-DrillLog 'host SQLite file exists; it is put back after the drill'
  }
  New-Item -ItemType Directory -Force -Path $backupRoot | Out-Null

  Write-DrillLog "starting isolated stack (project $project); builds images on a cold run"
  Invoke-ComposeDrill -CommandArgs @('down', '-v', '--remove-orphans') -BestEffort *> $null
  $script:StackTouched = $true
  Invoke-ComposeDrill -CommandArgs @('up', '-d', '--build', '--wait', '--wait-timeout', '600', 'redis', 'core-api', 'dns-resolver')
  Wait-Http -Url 'http://127.0.0.1:8080/readyz' -Name 'core-api /readyz'

  $secrets = & docker compose @composeArgs exec -T core-api cat /app/tmp/local_admin_secrets.txt
  if ($LASTEXITCODE -ne 0) {
    throw 'could not read the generated admin credentials from core-api'
  }
  $adminApiKey = (($secrets -join "`n") -split "`r?`n" |
    Where-Object { $_ -match '^SAFE_ZONE_ADMIN_API_KEY=' } |
    Select-Object -First 1) -replace '^SAFE_ZONE_ADMIN_API_KEY=', ''
  if (-not $adminApiKey) {
    throw 'generated admin API key missing from /app/tmp/local_admin_secrets.txt'
  }

  $initialCount = Get-BrandCount $adminApiKey
  Write-DrillLog "baseline brand count: $initialCount"
  $seededIds = @()
  foreach ($suffix in 'a', 'b', 'c') {
    $created = Invoke-Api -Method Post -Path '/v1/brands' -ApiKey $adminApiKey -Body @{
      name            = "restore-drill-win-$suffix"
      official_domain = "restore-drill-win-$suffix.invalid"
      alt_domains     = @()
    }
    $seededIds += $created.id
  }
  $count = Get-BrandCount $adminApiKey
  if ($count -ne ($initialCount + 3)) {
    throw "expected $($initialCount + 3) brands after seeding, saw $count"
  }
  Write-DrillLog "seeded 3 brands (ids: $($seededIds -join ', '))"

  Invoke-Api -Method Post -Path '/v1/analyze' -ApiKey $adminApiKey -Body @{
    domain = 'restore-drill-redis-check.example'
  } | Out-Null
  Write-DrillLog 'seeded one analysis cache entry in Redis'

  $env:SAFE_ZONE_SKIP_MISE = '1'
  $env:SAFE_ZONE_STACK = 'dev'
  $env:SAFE_ZONE_COMPOSE = $composeOverride
  $env:SAFE_ZONE_BACKUP_DIR = $backupRoot
  & pwsh -NoProfile -File (Join-Path $RepoRoot 'scripts\ops\safe-zone.ps1') backup -Stack dev
  if ($LASTEXITCODE -ne 0) {
    throw "backup helper failed with exit code $LASTEXITCODE"
  }
  $backupPath = Get-ChildItem -Path $backupRoot -Directory | Sort-Object Name | Select-Object -Last 1
  if (-not $backupPath -or -not (Test-Path (Join-Path $backupPath.FullName 'safe-zone.db') -PathType Leaf)) {
    throw "backup did not produce a SQLite snapshot under $backupRoot"
  }
  foreach ($line in Get-Content (Join-Path $backupPath.FullName 'SHA256SUMS')) {
    if (-not $line.Trim()) { continue }
    $parts = $line -split '\s+', 2
    $actual = (Get-FileHash -Algorithm SHA256 -Path (Join-Path $backupPath.FullName $parts[1])).Hash.ToLowerInvariant()
    if ($actual -ne $parts[0]) {
      throw "backup checksum mismatch for $($parts[1])"
    }
  }
  $backupDbChecksum = (Get-FileHash -Algorithm SHA256 -Path (Join-Path $backupPath.FullName 'safe-zone.db')).Hash.ToLowerInvariant()
  Write-DrillLog "backup verified at $($backupPath.FullName) (db checksum $($backupDbChecksum.Substring(0, 12))...)"

  foreach ($id in $seededIds) {
    Invoke-Api -Method Delete -Path "/v1/brands?id=$id" -ApiKey $adminApiKey | Out-Null
  }
  $count = Get-BrandCount $adminApiKey
  if ($count -ne $initialCount) {
    throw "expected $initialCount brands after the mutation, saw $count"
  }
  Write-DrillLog 'mutation applied: seeded brands deleted (restore must undo this)'

  & pwsh -NoProfile -File (Join-Path $RepoRoot 'scripts\ops\safe-zone.ps1') restore -Stack dev -BackupPath $backupPath.FullName
  if ($LASTEXITCODE -ne 0) {
    throw "restore helper failed with exit code $LASTEXITCODE"
  }
  Wait-Http -Url 'http://127.0.0.1:8080/readyz' -Name 'core-api /readyz after restore'

  if (-not (Test-Path $hostDb -PathType Leaf)) {
    throw "restored host SQLite file missing at $hostDb"
  }
  $restoredChecksum = (Get-FileHash -Algorithm SHA256 -Path $hostDb).Hash.ToLowerInvariant()
  if ($restoredChecksum -ne $backupDbChecksum) {
    throw "restored SQLite checksum $restoredChecksum != backup $backupDbChecksum"
  }
  Write-DrillLog 'restored SQLite file matches the backup checksum'

  $redisKeys = @(& docker compose @composeArgs exec -T redis redis-cli --scan --pattern 'safe-zone:analysis:restore-drill-redis-check.example*' |
    Where-Object { $_ })
  if ($redisKeys.Count -lt 1) {
    throw 'Redis analysis cache entry did not survive the restore'
  }
  Write-DrillLog 'Redis analysis cache entry survived the restore'

  $count = Get-BrandCount $adminApiKey
  if ($count -ne ($initialCount + 3)) {
    throw "expected $($initialCount + 3) brands after restore, saw $count"
  }
  $brands = Invoke-Api -Method Get -Path '/v1/brands' -ApiKey $adminApiKey
  $names = @($brands.items | ForEach-Object { $_.name })
  foreach ($suffix in 'a', 'b', 'c') {
    if ($names -notcontains "restore-drill-win-$suffix") {
      throw "brand restore-drill-win-$suffix missing from the restored API state"
    }
  }
  Write-DrillLog 'restored API state matches the backup (3 brands, names verified)'
  Write-DrillLog 'RESTORE DRILL PASS'
} catch {
  Write-Host "FATAL: $_" -ForegroundColor Red
  Collect-Diagnostics
  $script:ExitCode = 1
} finally {
  Cleanup
}
