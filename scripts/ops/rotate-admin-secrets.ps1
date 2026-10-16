# Rotate the core-api admin password and API key in a Compose .env file.
#
#   pwsh -NoProfile -File scripts/ops/rotate-admin-secrets.ps1 `
#     [-EnvFile .env] [-ApiUrl http://127.0.0.1:8080] `
#     [-ComposeFile docker-compose.yml] [-Service core-api] [-Yes]
#
# Backup, rotate, verify (new key 200, old key 401/403 on admin-only
# /metrics), roll back automatically on any failure. Restarting core-api
# also rotates the in-memory session signing secret, so old sessions die.
param(
  [string]$EnvFile = '.env',
  [string]$ApiUrl = 'http://127.0.0.1:8080',
  [string[]]$ComposeFile = @('docker-compose.yml'),
  [string]$Service = 'core-api',
  [switch]$Yes
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Set-Location -LiteralPath $RepoRoot

function Get-EnvKey([string]$Path, [string]$Key) {
  $match = Select-String -LiteralPath $Path -Pattern ("^\s*" + [regex]::Escape($Key) + "\s*=") |
    Select-Object -Last 1
  if ($null -eq $match) { return '' }
  return ($match.Line -replace ("^\s*" + [regex]::Escape($Key) + "\s*=\s*"), '').Trim()
}

function Set-EnvKey([string]$Path, [string]$Key, [string]$Value) {
  $text = Get-Content -LiteralPath $Path -Raw
  $pattern = "(?m)^\s*" + [regex]::Escape($Key) + "\s*=.*$"
  if ($text -match $pattern) {
    $text = [regex]::Replace($text, $pattern, ($Key + '=' + $Value))
  } else {
    if (-not $text.EndsWith([Environment]::NewLine)) { $text += [Environment]::NewLine }
    $text += $Key + '=' + $Value + [Environment]::NewLine
  }
  Set-Content -LiteralPath $Path -Value $text -NoNewline
}

function New-AdminSecret([int]$Length) {
  $alphabet = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789'.ToCharArray()
  $rng = [System.Security.Cryptography.RNGCryptoServiceProvider]::new()
  try {
    $bytes = New-Object byte[] $Length
    $rng.GetBytes($bytes)
    -join ($bytes | ForEach-Object { $alphabet[$_ % $alphabet.Length] })
  } finally {
    $rng.Dispose()
  }
}

function Get-HttpCode([string]$Url, [string]$Bearer) {
  try {
    $response = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 10 `
      -Headers @{ Authorization = "Bearer $Bearer" }
    return [int]$response.StatusCode
  } catch {
    $httpResponse = $_.Exception.Response
    if ($null -ne $httpResponse -and $null -ne $httpResponse.StatusCode) {
      return [int]$httpResponse.StatusCode
    }
    return 0
  }
}

foreach ($command in @('docker', 'curl.exe')) {
  if (-not (Get-Command $command -ErrorAction SilentlyContinue)) {
    throw "required command not found: $command"
  }
}
if (-not (Test-Path -LiteralPath $EnvFile -PathType Leaf)) {
  throw "env file not found: $EnvFile (run from the checkout that owns the stack)"
}

# _FILE variants take precedence in the service; editing plain keys would
# silently do nothing, so refuse instead of pretending to rotate.
$fileVariant = Select-String -LiteralPath $EnvFile `
  -Pattern '^\s*SAFE_ZONE_ADMIN_(PASSWORD|API_KEY)_FILE\s*=[^#\s]' | Select-Object -First 1
if ($null -ne $fileVariant) {
  throw "env file uses SAFE_ZONE_ADMIN_*_FILE variants; rotate the referenced secret files by hand, then recreate $Service"
}

$oldPassword = Get-EnvKey $EnvFile 'SAFE_ZONE_ADMIN_PASSWORD'
$oldKey = Get-EnvKey $EnvFile 'SAFE_ZONE_ADMIN_API_KEY'

if (-not $Yes) {
  $answer = Read-Host "Rotate admin password + API key in $EnvFile and recreate $Service? [y/N]"
  if ($answer -notmatch '^[yY]([eE][sS])?$') {
    Write-Host 'aborted; nothing changed'
    exit 0
  }
}

$stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$backup = Join-Path 'backups' "rotate-admin-secrets-$stamp.env"
New-Item -ItemType Directory -Force -Path 'backups' | Out-Null
Copy-Item -LiteralPath $EnvFile -Destination $backup -Force
Write-Host "backed up $EnvFile to $backup"

$composeArgs = @()
foreach ($file in $ComposeFile) { $composeArgs += @('-f', $file) }

function Invoke-Recreate {
  & docker compose @composeArgs up -d --force-recreate $Service
  if ($LASTEXITCODE -ne 0) { throw 'compose recreate failed' }
}

function Restore-Backup([string]$Reason) {
  Write-Host "ERROR: $Reason; restoring backup" -ForegroundColor Red
  Copy-Item -LiteralPath $backup -Destination $EnvFile -Force
  try {
    & docker compose @composeArgs up -d --force-recreate $Service | Out-Null
  } catch {
    Write-Host 'WARNING: rollback recreate also failed; restore manually from $backup' -ForegroundColor Red
  }
  exit 1
}

$newPassword = New-AdminSecret 32
$newKey = New-AdminSecret 40
Set-EnvKey $EnvFile 'SAFE_ZONE_ADMIN_PASSWORD' $newPassword
Set-EnvKey $EnvFile 'SAFE_ZONE_ADMIN_API_KEY' $newKey

try {
  Invoke-Recreate
} catch {
  Restore-Backup 'compose recreate failed'
}

$deadline = (Get-Date).AddSeconds(90)
while ($true) {
  try {
    $health = Invoke-WebRequest -Uri "$ApiUrl/healthz" -UseBasicParsing -TimeoutSec 3
    if ([int]$health.StatusCode -eq 200) { break }
  } catch {
    # Not healthy yet; keep waiting below.
  }
  if ((Get-Date) -ge $deadline) {
    Restore-Backup 'core-api unhealthy after recreate'
  }
  Start-Sleep -Seconds 2
}

if ((Get-HttpCode "$ApiUrl/metrics" $newKey) -ne 200) {
  Restore-Backup 'new API key did not authenticate (want 200)'
}
if ($oldKey -ne '') {
  $oldCode = Get-HttpCode "$ApiUrl/metrics" $oldKey
  if ($oldCode -ne 401 -and $oldCode -ne 403) {
    Restore-Backup "old API key still authenticates (want 401/403, got $oldCode)"
  }
}

Write-Host 'rotation verified: new key 200, old key rejected'
Write-Host ''
Write-Host 'NEW ADMIN CREDENTIALS (store in the password manager now, this is the only display):'
Write-Host '  username: admin'
Write-Host "  password: $newPassword"
Write-Host "  api key:  $newKey"
Write-Host ''
Write-Host 'All previous admin sessions were invalidated by the restart.'
