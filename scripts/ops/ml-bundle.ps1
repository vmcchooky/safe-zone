[CmdletBinding()]
param(
  [ValidateSet('validate', 'provision', 'rollback', 'status', 'help')]
  [string]$Command = 'status',
  [string]$Source,
  [string]$Version,
  [string]$BundleRoot
)

$ErrorActionPreference = 'Stop'
$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
if (-not $BundleRoot) { $BundleRoot = if ($env:SAFE_ZONE_ML_BUNDLE_ROOT) { $env:SAFE_ZONE_ML_BUNDLE_ROOT } else { Join-Path $ProjectRoot 'deploy/model-bundle' } }
if (-not $Source) { $Source = if ($env:SAFE_ZONE_ML_BUNDLE_SOURCE) { $env:SAFE_ZONE_ML_BUNDLE_SOURCE } else { Join-Path $ProjectRoot 'ml/models/v1' } }
if (-not $Version) { $Version = if ($env:SAFE_ZONE_ML_BUNDLE_VERSION) { $env:SAFE_ZONE_ML_BUNDLE_VERSION } else { 'v1' } }

function Fail([string]$Message) {
  throw $Message
}

function Resolve-ProjectPath([string]$Path) {
  if ([IO.Path]::IsPathRooted($Path)) { return $Path }
  return Join-Path $ProjectRoot $Path
}

function Assert-SafeVersion([string]$Value) {
  if ($Value -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]*$') { Fail "invalid ML bundle version: $Value" }
}

function Get-ExpectedHash([string]$SumsPath, [string]$Name) {
  $matches = @(Get-Content -LiteralPath $SumsPath | Where-Object {
      $parts = $_ -split '\s+'
      $parts.Count -eq 2 -and $parts[1] -eq $Name
    })
  if ($matches.Count -ne 1) { Fail "SHA256SUMS must contain exactly one entry for $Name" }
  $parts = $matches[0] -split '\s+'
  if ($parts[0] -notmatch '^[0-9a-fA-F]{64}$') { Fail "invalid checksum for $Name" }
  return $parts[0].ToLowerInvariant()
}

function Get-CanonicalSha256([string]$Path) {
  # Bundle files are UTF-8 text. Normalize CRLF exactly like the Go loader
  # before hashing so Windows checkout line endings do not invalidate a release.
  $text = [IO.File]::ReadAllText($Path, [Text.Encoding]::UTF8).Replace("`r`n", "`n")
  $bytes = [Text.Encoding]::UTF8.GetBytes($text)
  $sha256 = [Security.Cryptography.SHA256]::Create()
  try {
    return ([BitConverter]::ToString($sha256.ComputeHash($bytes)) -replace '-', '').ToLowerInvariant()
  } finally {
    $sha256.Dispose()
  }
}

function Test-Bundle([string]$BundlePath) {
  if (-not (Test-Path -LiteralPath $BundlePath -PathType Container)) { Fail "ML bundle directory does not exist: $BundlePath" }
  $sumsPath = Join-Path $BundlePath 'SHA256SUMS'
  if (-not (Test-Path -LiteralPath $sumsPath -PathType Leaf)) { Fail "ML bundle is missing SHA256SUMS: $BundlePath" }
  if ((Get-Item -LiteralPath $sumsPath -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { Fail "ML bundle checksum file must not be a symlink: $sumsPath" }
  $names = @('domain_threat_lgbm.txt', 'feature_manifest.v1.json', 'calibration.json', 'policy.json', 'model_report.json')
  foreach ($name in $names) {
    $path = Join-Path $BundlePath $name
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { Fail "ML bundle is missing ${name}: $BundlePath" }
    if ((Get-Item -LiteralPath $path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { Fail "ML bundle file must not be a symlink: $path" }
    $expected = Get-ExpectedHash -SumsPath $sumsPath -Name $name
    $actual = Get-CanonicalSha256 $path
    if ($actual -ne $expected) { Fail "SHA256 mismatch for ${name}: expected $expected, got $actual" }
  }
  foreach ($line in Get-Content -LiteralPath $sumsPath) {
    if ($line.Trim() -and (($line -split '\s+').Count -ne 2)) { Fail "malformed SHA256SUMS: $sumsPath" }
  }
  Write-Output "ML bundle valid: $BundlePath"
}

function Set-ActiveVersion([string]$RequestedVersion) {
  Assert-SafeVersion $RequestedVersion
  $releasePath = Join-Path $BundleRoot $RequestedVersion
  Test-Bundle $releasePath
  New-Item -ItemType Directory -Force -Path $BundleRoot | Out-Null

  $currentPath = Join-Path $BundleRoot 'current'
  if (Test-Path -LiteralPath $currentPath) {
    $currentItem = Get-Item -LiteralPath $currentPath -Force
    if ($currentItem.Attributes -band [IO.FileAttributes]::ReparsePoint) {
      Remove-Item -LiteralPath $currentPath -Force
    } elseif ($currentItem.PSIsContainer -and @(Get-ChildItem -LiteralPath $currentPath -Force).Count -eq 0) {
      Remove-Item -LiteralPath $currentPath -Force
    } else {
      Fail "current exists and is not an empty junction/symlink: $currentPath"
    }
  }
  New-Item -ItemType Junction -Path $currentPath -Target $releasePath | Out-Null
  Write-Output "ML bundle activated: $currentPath -> $RequestedVersion"
}

function Invoke-Provision {
  param([string]$InputSource, [string]$RequestedVersion)
  $sourcePath = Resolve-ProjectPath $InputSource
  Assert-SafeVersion $RequestedVersion
  if (-not (Test-Path -LiteralPath $sourcePath -PathType Container)) { Fail "ML bundle source directory does not exist: $sourcePath" }
  Test-Bundle $sourcePath
  New-Item -ItemType Directory -Force -Path $BundleRoot | Out-Null
  $releasePath = Join-Path $BundleRoot $RequestedVersion

  if (Test-Path -LiteralPath $releasePath) {
    Test-Bundle $releasePath
    $sourceSums = (Get-FileHash -LiteralPath (Join-Path $sourcePath 'SHA256SUMS') -Algorithm SHA256).Hash
    $releaseSums = (Get-FileHash -LiteralPath (Join-Path $releasePath 'SHA256SUMS') -Algorithm SHA256).Hash
    if ($sourceSums -ne $releaseSums) { Fail "immutable release already exists with different checksums: $releasePath" }
  } else {
    $stagingPath = Join-Path $BundleRoot ('.provision.' + [guid]::NewGuid().ToString('N'))
    try {
      Copy-Item -LiteralPath $sourcePath -Destination $stagingPath -Recurse
      Test-Bundle $stagingPath
      Move-Item -LiteralPath $stagingPath -Destination $releasePath
      Get-ChildItem -LiteralPath $releasePath -Recurse -File | ForEach-Object { $_.IsReadOnly = $true }
      Write-Output "ML bundle provisioned: $releasePath"
    } finally {
      if (Test-Path -LiteralPath $stagingPath) { Remove-Item -LiteralPath $stagingPath -Recurse -Force }
    }
  }
  Set-ActiveVersion $RequestedVersion
}

switch ($Command) {
  'validate' { Test-Bundle (Resolve-ProjectPath (Join-Path $BundleRoot 'current')) }
  'provision' { Invoke-Provision -InputSource $Source -RequestedVersion $Version }
  'rollback' {
    if (-not $Version) { Fail 'rollback requires -Version, for example: ml-bundle.ps1 rollback -Version v1' }
    Set-ActiveVersion $Version
  }
  'status' {
    $current = Join-Path $BundleRoot 'current'
    if (Test-Path -LiteralPath $current) {
      Test-Bundle $current
      Write-Output "ML bundle current target: $((Get-Item -LiteralPath $current -Force).Target)"
    } else {
      Write-Output "ML bundle is not provisioned: $current"
    }
  }
  default {
    Write-Output 'Usage: ml-bundle.ps1 validate|provision|rollback|status [-Source path] [-Version name] [-BundleRoot path]'
  }
}
