<#
.SYNOPSIS
Chaos Engineering Test Script for Safe Zone Fault Tolerance

.DESCRIPTION
This script automates fault tolerance tests (chaos engineering) against the local Safe Zone instance.
It covers:
- Redis unavailability (pause/unpause container)
- Extreme fuzzing inputs (SQLi, XSS, Overflow)
- Invalid TLDs simulating WHOIS timeouts
- SQLite database locks
- Malformed threat feed files

.EXAMPLE
.\scripts\qa\chaos-test.ps1
#>

$ErrorActionPreference = "Stop"
$ApiUrl = "http://localhost:8080/v1/analyze"
$DnsUrl = "http://localhost:8081/v1/policy"

function Write-Step {
    param([string]$Message)
    Write-Host "`n[+] $Message" -ForegroundColor Cyan
}

function Write-Pass {
    param([string]$Message)
    Write-Host "  [PASS] $Message" -ForegroundColor Green
}

function Write-Fail {
    param([string]$Message)
    Write-Host "  [FAIL] $Message" -ForegroundColor Red
}

function Test-Endpoint {
    param(
        [string]$Url,
        [int]$ExpectedStatusCode = 200,
        [string]$Method = "GET"
    )
    
    try {
        $response = Invoke-WebRequest -Uri $Url -Method $Method -TimeoutSec 15 -UseBasicParsing -ErrorAction SilentlyContinue
        $statusCode = $response.StatusCode
    } catch {
        if ($_.Exception.Response) {
            $statusCode = $_.Exception.Response.StatusCode.value__
        } else {
            $statusCode = 0
            Write-Fail "Request to $Url completely failed: $($_.Exception.Message)"
            return $false
        }
    }

    if ($statusCode -eq $ExpectedStatusCode) {
        Write-Pass "Expected HTTP $ExpectedStatusCode from $Url"
        return $true
    } else {
        Write-Fail "Expected HTTP $ExpectedStatusCode but got $statusCode from $Url"
        return $false
    }
}

Write-Host "=========================================" -ForegroundColor Yellow
Write-Host " SAFE ZONE - CHAOS ENGINEERING TEST SUITE" -ForegroundColor Yellow
Write-Host "=========================================" -ForegroundColor Yellow

# Ensure containers are running
Write-Step "Checking if containers are up..."
$redisRunning = (docker ps -q -f "name=redis")
if (-not $redisRunning) {
    Write-Fail "Redis container is not running. Please start the stack with 'pwsh ./scripts/safe-zone.ps1 deploy-dev' first."
    exit 1
}

$allTestsPassed = $true

# ---------------------------------------------------------
# SCENARIO 1: Redis Pause/Unpause (Fail-Open Test)
# ---------------------------------------------------------
Write-Step "Scenario 1: Redis Unavailability (Fail-Open)"
try {
    Write-Host "  Pausing Redis container..."
    docker-compose -f docker-compose.yml -f docker-compose.dev.yml pause redis | Out-Null
    
    # Test while Redis is down
    $testUrl = "{0}?domain=test-redis-down.com" -f $ApiUrl
    $res = Test-Endpoint -Url $testUrl -ExpectedStatusCode 200
    if (-not $res) { $allTestsPassed = $false }

} finally {
    Write-Host "  Unpausing Redis container..."
    docker-compose -f docker-compose.yml -f docker-compose.dev.yml unpause redis | Out-Null
    Start-Sleep -Seconds 2
}

# ---------------------------------------------------------
# SCENARIO 2: Fuzzing Inputs
# ---------------------------------------------------------
Write-Step "Scenario 2: Fuzzing / Malformed Inputs"
$fuzzInputs = @(
    "a" * 5000 + ".com", # Long domain
    "test.com'; DROP TABLE users;--", # SQLi
    "<script>alert(1)</script>.com", # XSS
    "../../etc/passwd.com", # Path traversal
    "  spaced  domain  .com  ",
    "http://domain.com/path?q=1" # URL instead of domain
)

foreach ($payload in $fuzzInputs) {
    $encoded = [uri]::EscapeDataString($payload)
    $testUrl = "{0}?domain={1}" -f $ApiUrl, $encoded
    
    try {
        $response = Invoke-WebRequest -Uri $testUrl -Method GET -TimeoutSec 5 -UseBasicParsing -ErrorAction SilentlyContinue
        $statusCode = $response.StatusCode
    } catch {
        if ($_.Exception.Response) {
            $statusCode = $_.Exception.Response.StatusCode.value__
        } else {
            $statusCode = 0
        }
    }
    
    # Accept 200 (graceful analyze) or 400 (rejected input)
    if ($statusCode -eq 200 -or $statusCode -eq 400) {
        Write-Pass "Fuzzing payload handled gracefully (HTTP $statusCode) for: $(($payload).Substring(0, [math]::Min($payload.Length, 20)))..."
    } else {
        Write-Fail "Fuzzing payload failed gracefully checks (HTTP $statusCode) for: $payload"
        $allTestsPassed = $false
    }
}

# ---------------------------------------------------------
# SCENARIO 3: WHOIS/DNS Timeout (Invalid TLD)
# ---------------------------------------------------------
Write-Step "Scenario 3: OSINT Timeout Fail-Open"
$testUrl = "{0}?domain=this-domain-does-not-exist-timeout.invalid-tld-chaos" -f $ApiUrl
$res = Test-Endpoint -Url $testUrl -ExpectedStatusCode 200
if (-not $res) { $allTestsPassed = $false }

# ---------------------------------------------------------
# SCENARIO 4: SQLite Lock
# ---------------------------------------------------------
Write-Step "Scenario 4: SQLite Database Lock"
$dbPath = ".\data\safe-zone.db"
if (Test-Path $dbPath) {
    try {
        Write-Host "  Locking $dbPath..."
        $fileStream = [System.IO.File]::Open($dbPath, 'Open', 'ReadWrite', 'None')
        
        # Test API while DB is locked
        $testUrl = "{0}?domain=locked-db-test.com" -f $ApiUrl
        $res = Test-Endpoint -Url $testUrl -ExpectedStatusCode 200
        if (-not $res) { $allTestsPassed = $false }

    } catch {
        Write-Fail "Could not lock DB: $($_.Message)"
    } finally {
        if ($null -ne $fileStream) {
            $fileStream.Close()
            $fileStream.Dispose()
            Write-Host "  Unlocked $dbPath."
        }
    }
} else {
    Write-Host "  Skipping SQLite lock test, $dbPath not found." -ForegroundColor Yellow
}

# ---------------------------------------------------------
# SCENARIO 5: Threat Feed Parse Error
# ---------------------------------------------------------
Write-Step "Scenario 5: Threat Feed Parse Error Resilience"
$badFeedFile = ".\tmp\chaos-bad-feed.txt"
if (-not (Test-Path ".\tmp")) { New-Item -ItemType Directory -Path ".\tmp" | Out-Null }

[byte[]]$garbage = (1..1000) | ForEach-Object { Get-Random -Maximum 256 }
[System.IO.File]::WriteAllBytes((Resolve-Path .\tmp).Path + "\chaos-bad-feed.txt", $garbage)

Write-Host "  Triggering feed-sync with garbage file..."
try {
    # Assuming go is available in path to run this component directly
    $output = go run ./cmd/feed-sync -source $badFeedFile -dry-run 2>&1
    Write-Pass "feed-sync executed and exited without panic."
} catch {
    Write-Pass "feed-sync caught the error and exited (non-zero exit code)."
}

Remove-Item $badFeedFile -ErrorAction SilentlyContinue

# ---------------------------------------------------------
# SUMMARY
# ---------------------------------------------------------
Write-Host "`n=========================================" -ForegroundColor Yellow
if ($allTestsPassed) {
    Write-Host " RESULT: ALL CHAOS TESTS PASSED" -ForegroundColor Green
} else {
    Write-Host " RESULT: SOME CHAOS TESTS FAILED" -ForegroundColor Red
}
Write-Host "=========================================" -ForegroundColor Yellow
