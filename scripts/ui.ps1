param(
  [Parameter(Position = 0)]
  [ValidateSet('install', 'dev', 'build', 'preview', 'typecheck', 'check')]
  [string]$Command = 'dev'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoRoot = Split-Path -Parent $PSScriptRoot
$UiRoot = Join-Path $RepoRoot 'ui'

if (-not (Test-Path $UiRoot -PathType Container)) {
  throw "ui workspace not found: $UiRoot"
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
    Invoke-UiNpm -NpmArgs @('install')
  }
}

switch ($Command) {
  'install' {
    Invoke-UiNpm -NpmArgs @('install')
  }
  'dev' {
    Ensure-UiDependencies
    Invoke-UiNpm -NpmArgs @('run', 'dev')
  }
  'build' {
    Ensure-UiDependencies
    Invoke-UiNpm -NpmArgs @('run', 'build')
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
