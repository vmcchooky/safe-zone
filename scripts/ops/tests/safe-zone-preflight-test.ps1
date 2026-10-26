# Preflight tests for scripts/ops/safe-zone.ps1.
#
# Runs the real deploy path against a stub SAFE_ZONE_COMPOSE inside a
# throwaway project skeleton, so the .env the helper reads is fully
# controlled and nothing ever touches Docker. Covers the three file-set
# combinations (production, shared-host, shared-host+DoT) plus the failure
# gates: old Compose, wrong SAFE_ZONE_ENV, placeholder block IP, missing DoT
# certificates.
#
# The deploy path ends with Wait-ForHealth, so a best-effort throwaway
# HTTP listener answers /healthz on 127.0.0.1:8080/8081 while the suite runs.
# It is skipped silently when those ports already serve something healthy.
$ErrorActionPreference = 'Stop'

$sourceSafeZone = Join-Path $PSScriptRoot '..\safe-zone.ps1'
if (-not (Test-Path $sourceSafeZone)) {
  Write-Host "FATAL: cannot find safe-zone.ps1 next to the test: $sourceSafeZone" -ForegroundColor Red
  exit 2
}

$workRoot = Join-Path ([IO.Path]::GetTempPath()) ("safe-zone-ps-preflight-" + [guid]::NewGuid().ToString('N'))
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

try {
  $stubCompose = Join-Path $workRoot 'sz-stub-compose.cmd'
  $script:StubLog = Join-Path $workRoot 'stub.log'
  $script:ErrLog = Join-Path $workRoot 'stderr.log'

  # The stub records every invocation (one line each) and answers
  # `version --short` with SZ_STUB_COMPOSE_VERSION so the version gate can be
  # driven up and down.
  @'
@echo off
echo %* >> "%SZ_STUB_LOG%"
if "%1" == "version" (
  if "%2" == "--short" (
    echo %SZ_STUB_COMPOSE_VERSION%
    exit /b 0
  )
)
exit /b 0
'@ | Set-Content -Path $stubCompose -Encoding ASCII

  # function MakeProject writes a controlled project skeleton: so the helper
  # resolves $RepoRoot relative to its own location, the copy isolates the
  # .env it falls back to.
  function MakeProject([string]$EnvContent, [string]$WithCerts) {
    $proj = Join-Path $workRoot 'proj'
    if (Test-Path $proj) { Remove-Item -Recurse -Force $proj }
    New-Item -ItemType Directory -Force -Path "$proj\scripts\ops" | Out-Null
    New-Item -ItemType Directory -Force -Path "$proj\ops\vps-edge" | Out-Null
    Copy-Item $sourceSafeZone "$proj\scripts\ops\safe-zone.ps1"
    Set-Content -Path "$proj\.env" -Value $EnvContent
    if ($WithCerts -eq 'certs') {
      New-Item -ItemType Directory -Force -Path "$proj\ops\certs\dot" | Out-Null
      New-Item -ItemType File -Force -Path "$proj\ops\certs\dot\fullchain.pem" | Out-Null
      New-Item -ItemType File -Force -Path "$proj\ops\certs\dot\privkey.pem" | Out-Null
    }
    return $proj
  }

  function Invoke-Deploy([string]$Proj, [string]$ComposeVersion) {
    '' | Set-Content -Path $script:StubLog -NoNewline
    '' | Set-Content -Path $script:ErrLog -NoNewline
    $env:SAFE_ZONE_SKIP_MISE = '1'
    $env:SAFE_ZONE_COMPOSE = $stubCompose
    $env:SZ_STUB_LOG = $script:StubLog
    if (Test-Path env:SZ_STUB_LOG) { Remove-Item env:SZ_STUB_LOG }
    $env:SZ_STUB_LOG = $script:StubLog
    if (Test-Path env:SZ_STUB_COMPOSE_VERSION) { Remove-Item env:SZ_STUB_COMPOSE_VERSION }
    $env:SZ_STUB_COMPOSE_VERSION = $ComposeVersion
    & pwsh -NoProfile -File (Join-Path $Proj 'scripts\ops\safe-zone.ps1') deploy 1>$null 2>$script:ErrLog
    return $LASTEXITCODE
  }

  function Invoke-DeployOk([string]$Proj, [string]$ComposeVersion, [string]$Label) {
    $code = Invoke-Deploy $Proj $ComposeVersion
    if ($code -eq 0) {
      Pass "${Label}: deploy succeeded"
    } else {
      Fail "${Label}: deploy should succeed (exit $code)"
      Get-Content $script:ErrLog | ForEach-Object { Write-Host "  err: $_" }
    }
  }

  function Invoke-DeployFail([string]$Proj, [string]$ComposeVersion, [string]$Label) {
    $code = Invoke-Deploy $Proj $ComposeVersion
    if ($code -eq 0) {
      Fail "${Label}: deploy must fail"
    } else {
      Pass "${Label}: deploy failed with exit $code"
    }
    if ((Get-Content $script:StubLog) -match 'up -d --build') {
      Fail "${Label}: never reaches up -d --build"
    } else {
      Pass "${Label}: never reaches up -d --build"
    }
  }

  function Require-LogContains([string]$Needle, [string]$Label) {
    if ((Get-Content $script:StubLog) -match [regex]::Escape($Needle)) {
      Pass $Label
    } else {
      Fail "${Label}: stub log is missing: $Needle"
      Get-Content $script:StubLog | ForEach-Object { Write-Host "  log: $_" }
    }
  }

  function Require-LogNotContains([string]$Needle, [string]$Label) {
    if ((Get-Content $script:StubLog) -match [regex]::Escape($Needle)) {
      Fail "${Label}: stub log unexpectedly contains: $Needle"
    } else {
      Pass $Label
    }
  }

  function Require-StderrContains([string]$Needle, [string]$Label) {
    if ((Get-Content $script:ErrLog) -match [regex]::Escape($Needle)) {
      Pass $Label
    } else {
      Fail "${Label}: stderr is missing: $Needle"
      Get-Content $script:ErrLog | ForEach-Object { Write-Host "  err: $_" }
    }
  }

  # Best-effort throwaway /healthz listener so Wait-ForHealth can succeed.
  # When something is already serving those ports (for example a running
  # stack), the listener simply stays unused.
  $healthJob = Start-Job -ScriptBlock {
    param($Root)
    $listener = [System.Net.HttpListener]::New()
    foreach ($port in 8080, 8081) {
      $listener.Prefixes.Add("http://127.0.0.1:${port}/")
      $listener.Prefixes.Add("http://localhost:${port}/")
    }
    try {
      $listener.Start()
      while ($listener.IsListening) {
        $ctx = $listener.GetContext()
        $resp = $ctx.Response
        $bytes = [Text.Encoding]::UTF8.GetBytes('ok')
        $resp.ContentType = 'text/plain'
        $resp.ContentLength64 = $bytes.Length
        $resp.OutputStream.Write($bytes, 0, $bytes.Length)
        $resp.OutputStream.Close()
      }
    } catch {
      # Port busy or stopping: the real deployment's endpoints take over.
    }
  } -ArgumentList $workRoot

  try {
    ### 1. Plain production: base files only, version check, config -q before up.

    $proj = MakeProject @'
SAFE_ZONE_ENV=production
SAFE_ZONE_BLOCK_PAGE_IP=93.184.216.34
SAFE_ZONE_DNS_DOT_ENABLED=false
SAFE_ZONE_DNS_BLOCK_STRATEGY=sinkhole
'@ 'nocerts'

    Invoke-DeployOk $proj 'v2.39.2' 'production'
    # cmd's echo leaves a trailing space per line; trim for order checks.
    $lines = @(Get-Content $script:StubLog | ForEach-Object { $_.Trim() })
    if ($lines[0] -eq 'version --short') {
      Pass 'production: compose version is checked first'
    } else {
      Fail "production: first compose call should be 'version --short', got: $($lines[0])"
    }
    Require-LogContains '-f docker-compose.yml -f docker-compose.production.yml --profile production-edge config -q' `
      'production: config -q runs on the exact file set'
    Require-LogContains '-f docker-compose.yml -f docker-compose.production.yml --profile production-edge up -d --build' `
      'production: up -d --build uses the same file set'
    Require-LogNotContains 'docker-compose.host-edge.yml' 'production: no host-edge overlay'
    Require-LogNotContains 'docker-compose.dot.yml' 'production: no DoT overlay'
    if ($lines[1] -eq '-f docker-compose.yml -f docker-compose.production.yml --profile production-edge config -q' -and
      $lines[2] -eq '-f docker-compose.yml -f docker-compose.production.yml --profile production-edge up -d --build') {
      Pass 'production: config -q runs before up'
    } else {
      Fail 'production: expected order version -> config -q -> up'
    }

    ### 2. shared-host-edge: host overlay merged, still config -q first, still no Caddy change.

    $proj = MakeProject @'
SAFE_ZONE_ENV=production
SAFE_ZONE_DEPLOYMENT_TIER=shared-host-edge
SAFE_ZONE_BLOCK_PAGE_IP=93.184.216.34
SAFE_ZONE_DNS_DOT_ENABLED=false
'@ 'nocerts'

    Invoke-DeployOk $proj 'v2.39.2' 'shared-host'
    Require-LogContains '-f docker-compose.yml -f docker-compose.production.yml -f ops/vps-edge/docker-compose.host-edge.yml --profile production-edge config -q' `
      'shared-host: config -q includes the host-edge overlay'
    Require-LogContains '-f docker-compose.yml -f docker-compose.production.yml -f ops/vps-edge/docker-compose.host-edge.yml --profile production-edge up -d --build' `
      'shared-host: up includes the host-edge overlay'
    Require-LogNotContains 'docker-compose.dot.yml' 'shared-host: no DoT overlay'

    ### 3. shared-host-edge + DoT: dot overlay merged, certificate files required.

    $proj = MakeProject @'
SAFE_ZONE_ENV=production
SAFE_ZONE_DEPLOYMENT_TIER=shared-host-edge
SAFE_ZONE_BLOCK_PAGE_IP=93.184.216.34
SAFE_ZONE_DNS_DOT_ENABLED=true
SAFE_ZONE_DNS_DOT_CERTS_DIR=./ops/certs/dot
'@ 'certs'

    Invoke-DeployOk $proj 'v2.39.2' 'shared-host+DoT'
    Require-LogContains '-f docker-compose.yml -f docker-compose.production.yml -f ops/vps-edge/docker-compose.host-edge.yml -f ops/vps-edge/docker-compose.dot.yml --profile production-edge config -q' `
      'shared-host+DoT: config -q includes the DoT overlay'
    Require-LogContains '-f ops/vps-edge/docker-compose.dot.yml --profile production-edge up -d --build' `
      'shared-host+DoT: up includes the DoT overlay'

    ### 4. Compose too old for !override/!reset: clear error, never builds.

    $proj = MakeProject @'
SAFE_ZONE_ENV=production
SAFE_ZONE_BLOCK_PAGE_IP=93.184.216.34
SAFE_ZONE_DNS_DOT_ENABLED=false
'@ 'nocerts'

    Invoke-DeployFail $proj 'v2.20.0' 'compose v2.20'
    Require-StderrContains 'v2.24' 'compose v2.20: error names the required version'

    ### 5. Placeholder block page IP with the default sinkhole strategy.

    $proj = MakeProject @'
SAFE_ZONE_ENV=production
SAFE_ZONE_BLOCK_PAGE_IP=replace-with-vps-public-ip
SAFE_ZONE_DNS_BLOCK_STRATEGY=sinkhole
SAFE_ZONE_DNS_DOT_ENABLED=false
'@ 'nocerts'

    Invoke-DeployFail $proj 'v2.39.2' 'placeholder block IP'
    Require-StderrContains 'SAFE_ZONE_BLOCK_PAGE_IP' 'placeholder block IP: error names the variable'

    ### 6. SAFE_ZONE_ENV not production.

    $proj = MakeProject @'
SAFE_ZONE_ENV=local
SAFE_ZONE_BLOCK_PAGE_IP=93.184.216.34
SAFE_ZONE_DNS_DOT_ENABLED=false
'@ 'nocerts'

    Invoke-DeployFail $proj 'v2.39.2' 'SAFE_ZONE_ENV=local'
    Require-StderrContains 'SAFE_ZONE_ENV' 'SAFE_ZONE_ENV=local: error names the variable'

    ### 7. DoT enabled but certificate pair missing.

    $proj = MakeProject @'
SAFE_ZONE_ENV=production
SAFE_ZONE_BLOCK_PAGE_IP=93.184.216.34
SAFE_ZONE_DNS_DOT_ENABLED=true
SAFE_ZONE_DNS_DOT_CERTS_DIR=./ops/certs/dot
'@ 'nocerts'

    Invoke-DeployFail $proj 'v2.39.2' 'missing DoT certs'
    Require-StderrContains 'fullchain.pem' 'missing DoT certs: error names the certificate'

    ### 8. Non-sinkhole strategy does not require a block page IP.

    $proj = MakeProject @'
SAFE_ZONE_ENV=production
SAFE_ZONE_DNS_BLOCK_STRATEGY=nxdomain
SAFE_ZONE_BLOCK_PAGE_IP=replace-with-vps-public-ip
SAFE_ZONE_DNS_DOT_ENABLED=false
'@ 'nocerts'

    Invoke-DeployOk $proj 'v2.39.2' 'nxdomain'
  } finally {
    Stop-Job $healthJob -ErrorAction SilentlyContinue
    Remove-Job $healthJob -Force -ErrorAction SilentlyContinue
  }
} finally {
  Remove-Item -Recurse -Force $workRoot -ErrorAction SilentlyContinue
}

Write-Host ''
Write-Host "$($script:Passed) passed, $($script:Failed) failed"
if ($script:Failed -ne 0) { exit 1 }
