param(
  [Parameter(Position = 0)]
  [ValidateSet('install', 'dev', 'build', 'bundle', 'preview', 'typecheck', 'check')]
  [string]$Command = 'dev'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoRoot = Split-Path -Parent $PSScriptRoot
$UiRoot = Join-Path $RepoRoot 'ui'
$BackendBundleRoot = Join-Path $RepoRoot 'internal\api\app\dist'
$UiLockfile = Join-Path $UiRoot 'package-lock.json'

if (-not (Test-Path $UiRoot -PathType Container)) {
  throw "ui workspace not found: $UiRoot"
}

function Get-UiInstallArgs {
  if (Test-Path $UiLockfile -PathType Leaf) {
    return @('ci')
  }
  return @('install')
}

function Invoke-UiNpm {
  param([string[]]$NpmArgs)

  Push-Location $UiRoot
  try {
    & npm $NpmArgs
    if ($LASTEXITCODE -ne 0) {
      throw "npm $($NpmArgs -join ' ') failed with exit code $LASTEXITCODE"
    }
  } finally {
    Pop-Location
  }
}

function Ensure-UiDependencies {
  $nodeModules = Join-Path $UiRoot 'node_modules'
  if (-not (Test-Path $nodeModules -PathType Container)) {
    Invoke-UiNpm -NpmArgs (Get-UiInstallArgs)
  }
}

function Sync-UiBundle {
  $UiDistRoot = Join-Path $UiRoot 'dist'
  if (-not (Test-Path $UiDistRoot -PathType Container)) {
    throw "ui dist output not found: $UiDistRoot"
  }

  if (Test-Path $BackendBundleRoot -PathType Container) {
    Remove-Item -LiteralPath $BackendBundleRoot -Recurse -Force
  }

  New-Item -ItemType Directory -Path $BackendBundleRoot | Out-Null
  Copy-Item -Path (Join-Path $UiDistRoot '*') -Destination $BackendBundleRoot -Recurse -Force
  New-Item -ItemType File -Path (Join-Path $BackendBundleRoot '.keep') -Force | Out-Null
}

switch ($Command) {
  'install' {
    Invoke-UiNpm -NpmArgs (Get-UiInstallArgs)
  }
  'dev' {
    Ensure-UiDependencies
    Invoke-UiNpm -NpmArgs @('run', 'dev')
  }
  'build' {
    Ensure-UiDependencies
    Invoke-UiNpm -NpmArgs @('run', 'build')
  }
  'bundle' {
    Ensure-UiDependencies
    Invoke-UiNpm -NpmArgs @('run', 'check')
    Sync-UiBundle
  }
  'preview' {
    Ensure-UiDependencies
    Invoke-UiNpm -NpmArgs @('run', 'preview')
  }
  'typecheck' {
    Ensure-UiDependencies
    Invoke-UiNpm -NpmArgs @('run', 'typecheck')
  }
  'check' {
    Ensure-UiDependencies
    Invoke-UiNpm -NpmArgs @('run', 'check')
  }
}
