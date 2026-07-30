param(
  [ValidateSet('production-edge', 'shared-host-edge')]
  [string]$EdgeMode = 'production-edge',
  [string]$Version = $env:SAFE_ZONE_RELEASE_VERSION,
  [string]$SourceRepo = $env:SAFE_ZONE_SOURCE_REPO,
  [string]$EvidenceDir
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $RepoRoot

if (-not $Version) {
  $Version = 'unreleased'
}
if (-not $SourceRepo) {
  $SourceRepo = (& git config --get remote.origin.url 2>$null).Trim()
}
if (-not $SourceRepo) {
  $SourceRepo = 'unknown'
}

$GitCommit = (& git rev-parse HEAD).Trim()
$ShortCommit = (& git rev-parse --short HEAD).Trim()
$BuildTime = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$EvidenceStamp = (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss')
$ReleaseTag = "$Version-$ShortCommit"

if (-not $EvidenceDir) {
  $EvidenceDir = Join-Path $RepoRoot "tmp/release-gate/$EvidenceStamp`_$EdgeMode"
}

$null = New-Item -ItemType Directory -Force -Path $EvidenceDir
$null = New-Item -ItemType Directory -Force -Path (Join-Path $EvidenceDir 'binaries')
$null = New-Item -ItemType Directory -Force -Path (Join-Path $EvidenceDir 'docker')

function Invoke-AndCapture {
  param(
    [string]$Label,
    [scriptblock]$Script
  )

  $outputFile = Join-Path $EvidenceDir "$Label.txt"
  Write-Host "==> $Label"
  
  $oldPreference = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  try {
    & $Script *> $outputFile
  } finally {
    $ErrorActionPreference = $oldPreference
  }

  if ($LASTEXITCODE -ne 0) {
    Get-Content $outputFile
    throw "$Label failed"
  }
}

function Build-Binary {
  param([string]$Service)

  $imageRef = "safe-zone-${Service}:$ReleaseTag"
  $outputFile = Join-Path $EvidenceDir "build-$Service.txt"
  $binaryPath = Join-Path (Join-Path $EvidenceDir 'binaries') $Service
  $ldflags = @(
    '-s',
    '-w',
    "-X safe-zone/internal/buildinfo.Version=$Version",
    "-X safe-zone/internal/buildinfo.GitCommit=$GitCommit",
    "-X safe-zone/internal/buildinfo.BuildTime=$BuildTime",
    "-X safe-zone/internal/buildinfo.ImageTag=$imageRef",
    "-X safe-zone/internal/buildinfo.SourceRepo=$SourceRepo"
  ) -join ' '

  Write-Host "==> build-$Service"
  
  $oldPreference = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  try {
    & {
      $env:CGO_ENABLED = '0'
      $env:GOOS = 'linux'
      go build -trimpath -ldflags $ldflags -o $binaryPath "./cmd/$Service"
    } *> $outputFile
  } finally {
    $ErrorActionPreference = $oldPreference
  }
  
  if ($LASTEXITCODE -ne 0) {
    Get-Content $outputFile
    throw "build-$Service failed"
  }
}

function Build-Image {
  param([string]$Service)

  $imageRef = "safe-zone-${Service}:$ReleaseTag"
  $buildLog = Join-Path (Join-Path $EvidenceDir 'docker') "$Service.build.txt"
  $inspectFile = Join-Path (Join-Path $EvidenceDir 'docker') "$Service.inspect.json"

  Write-Host "==> docker-build-$Service"
  
  $oldPreference = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  try {
    for ($attempt = 1; $attempt -le 3; $attempt++) {
      & docker build `
        --build-arg "SERVICE=$Service" `
        --build-arg "VERSION=$Version" `
        --build-arg "GIT_COMMIT=$GitCommit" `
        --build-arg "BUILD_TIME=$BuildTime" `
        --build-arg "IMAGE_TAG=$imageRef" `
        --build-arg "SOURCE_REPO=$SourceRepo" `
        -t $imageRef . *> $buildLog
      if ($LASTEXITCODE -eq 0) {
        break
      }
      if ($attempt -lt 3) {
        Write-Warning "docker-build-$Service attempt $attempt failed, retrying..."
        Start-Sleep -Seconds 2
      }
    }
  } finally {
    $ErrorActionPreference = $oldPreference
  }

  if ($LASTEXITCODE -ne 0) {
    Get-Content $buildLog
    throw "docker-build-$Service failed"
  }

  & docker image inspect $imageRef | Out-File -FilePath $inspectFile -Encoding utf8
}

@"
EDGE_MODE=$EdgeMode
RELEASE_VERSION=$Version
RELEASE_TAG=$ReleaseTag
GIT_COMMIT=$GitCommit
BUILD_TIME=$BuildTime
SOURCE_REPO=$SourceRepo
EVIDENCE_DIR=$EvidenceDir
"@ | Out-File -FilePath (Join-Path $EvidenceDir 'metadata.env') -Encoding ascii

@"
{
  "edge_mode": "$EdgeMode",
  "release_version": "$Version",
  "release_tag": "$ReleaseTag",
  "git_commit": "$GitCommit",
  "build_time": "$BuildTime",
  "source_repo": "$SourceRepo",
  "evidence_dir": "$EvidenceDir"
}
"@ | Out-File -FilePath (Join-Path $EvidenceDir 'metadata.json') -Encoding utf8

Invoke-AndCapture -Label 'go-test' -Script { go test ./... }
Invoke-AndCapture -Label 'go-build' -Script { go build ./... }
Invoke-AndCapture -Label 'gosec' -Script { go run github.com/securego/gosec/v2/cmd/gosec@latest ./... }
Invoke-AndCapture -Label 'govulncheck' -Script { go run golang.org/x/vuln/cmd/govulncheck@latest ./... }

Build-Binary -Service 'core-api'
Build-Binary -Service 'dns-resolver'

foreach ($service in 'core-api', 'dns-resolver', 'feed-sync', 'feed-syncd') {
  Build-Image -Service $service
}

@"
Release preflight completed successfully.

Edge mode: $EdgeMode
Release version: $Version
Release tag: $ReleaseTag
Git commit: $GitCommit
Build time: $BuildTime
Source repo: $SourceRepo

Artifacts:
- $(Join-Path $EvidenceDir 'metadata.env')
- $(Join-Path $EvidenceDir 'metadata.json')
- $(Join-Path $EvidenceDir 'go-test.txt')
- $(Join-Path $EvidenceDir 'go-build.txt')
- $(Join-Path $EvidenceDir 'gosec.txt')
- $(Join-Path $EvidenceDir 'govulncheck.txt')
- $(Join-Path $EvidenceDir 'build-core-api.txt')
- $(Join-Path $EvidenceDir 'build-dns-resolver.txt')
- $(Join-Path $EvidenceDir 'docker')
"@ | Out-File -FilePath (Join-Path $EvidenceDir 'summary.txt') -Encoding utf8

Write-Host "Release preflight evidence written to $EvidenceDir" -ForegroundColor Green
