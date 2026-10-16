# Coverage gate for the Go test suite. Runs the suite with -race and a
# -coverprofile, then fails when total statement coverage drops below
# $env:SAFE_ZONE_COVER_THRESHOLD (default 50).
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# NOTE: the profile variable is deliberately NOT named $profile — that name
# collides with PowerShell's automatic $profile variable and makes `go test`
# write a stray file literally named "$profile" next to the real profile.
$threshold = if ($env:SAFE_ZONE_COVER_THRESHOLD) { [double]$env:SAFE_ZONE_COVER_THRESHOLD } else { 65.0 }
$coverProfile = if ($env:SAFE_ZONE_COVER_PROFILE) { $env:SAFE_ZONE_COVER_PROFILE } else { 'coverage.out' }
if ($env:SAFE_ZONE_COVER_PKGS) {
  $pkgs = @($env:SAFE_ZONE_COVER_PKGS.Split(' ', [System.StringSplitOptions]::RemoveEmptyEntries))
} else {
  $pkgs = @('./cmd/...', './internal/...', './ml/...', './tools/...')
}

if ($env:SAFE_ZONE_COVER_RUN_TESTS -ne '0') {
  & go test -race "-coverprofile=$coverProfile" @pkgs
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

$total = $null
foreach ($line in (& go tool cover "-func=$coverProfile")) {
  if ($line -match '^total:\s+\S+\s+([\d.]+)%$') { $total = [double]$Matches[1] }
}
if ($null -eq $total) { throw "coverage gate FAILED: could not parse total coverage from $coverProfile (run the test suite with -coverprofile first)" }
if ($total -lt $threshold) {
  Write-Host ("coverage gate FAILED: total {0:N1}% < threshold {1:N1}% ({2})" -f $total, $threshold, $coverProfile) -ForegroundColor Red
  exit 1
}
Write-Host ("coverage gate passed: total {0:N1}% >= threshold {1:N1}% ({2})" -f $total, $threshold, $coverProfile) -ForegroundColor Green
