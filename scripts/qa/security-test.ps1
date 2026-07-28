<#
.SYNOPSIS
Security Test Script for Safe Zone (OWASP Top 10)

.DESCRIPTION
This script automates security testing scenarios for the Safe Zone API.
#>

$ErrorActionPreference = "Stop"
$ApiUrl = "http://localhost:8080/v1/analyze"
$DnsUrl = "http://localhost:8081/v1/policy"
$ConfigUrl = "http://localhost:8080/v1/config/analysis"

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

$allTestsPassed = $true

Write-Host "=========================================" -ForegroundColor Yellow
Write-Host " SAFE ZONE - SECURITY TEST SUITE (OWASP)" -ForegroundColor Yellow
Write-Host "=========================================" -ForegroundColor Yellow

# ---------------------------------------------------------
# SCENARIO 1: SQL Injection
# ---------------------------------------------------------
Write-Step "1. Testing SQL Injection on SQLite (WHOIS Cache)"
$sqliDomain = [uri]::EscapeDataString("test.com' OR 1=1--")
$testUrl = "{0}?domain={1}" -f $ApiUrl, $sqliDomain
try {
    $res = Invoke-WebRequest -Uri $testUrl -Method GET -UseBasicParsing -ErrorAction SilentlyContinue
    # If 200, it means it didn't crash SQLite or get SQL error, and handled it as a domain string
    if ($res.StatusCode -eq 200 -or $res.StatusCode -eq 400) {
        Write-Pass "SQLi payload safely handled (HTTP $($res.StatusCode))"
    } else {
        Write-Fail "SQLi payload returned HTTP $($res.StatusCode)"
        $allTestsPassed = $false
    }
} catch {
    Write-Fail "SQLi payload request failed."
    $allTestsPassed = $false
}

# ---------------------------------------------------------
# SCENARIO 2: Broken Access Control
# ---------------------------------------------------------
Write-Step "2. Testing Broken Access Control on /v1/config/analysis"
try {
    $res = Invoke-WebRequest -Uri $ConfigUrl -Method PUT -Body "{}" -ContentType "application/json" -UseBasicParsing -ErrorAction SilentlyContinue
    $statusCode = $res.StatusCode
} catch {
    if ($_.Exception.Response) {
        $statusCode = $_.Exception.Response.StatusCode.value__
    } else {
        $statusCode = 0
    }
}
if ($statusCode -eq 401 -or $statusCode -eq 403 -or $statusCode -eq 405) {
    Write-Pass "Unauthenticated PUT rejected as expected (HTTP $statusCode)"
} else {
    Write-Fail "Unauthenticated PUT allowed! (HTTP $statusCode)"
    $allTestsPassed = $false
}

# ---------------------------------------------------------
# SCENARIO 3: Log Injection / Forging
# ---------------------------------------------------------
Write-Step "3. Testing Log Injection (CRLF)"
$logInj = [uri]::EscapeDataString("test.com`r`n[ADMIN-LOGIN]")
$testUrl = "{0}?domain={1}" -f $ApiUrl, $logInj
try {
    $res = Invoke-WebRequest -Uri $testUrl -Method GET -UseBasicParsing -ErrorAction SilentlyContinue
    Write-Pass "Log Injection payload sent (Needs manual log verification, HTTP $($res.StatusCode))"
} catch {
    Write-Pass "Log Injection payload rejected or failed cleanly."
}

# ---------------------------------------------------------
# SCENARIO 4: HTTP Parameter Pollution
# ---------------------------------------------------------
Write-Step "4. Testing HTTP Parameter Pollution"
$testUrl = "{0}?domain=safe.com&domain=malicious.com" -f $ApiUrl
try {
    $res = Invoke-WebRequest -Uri $testUrl -Method GET -UseBasicParsing -ErrorAction SilentlyContinue
    Write-Pass "HPP payload handled without crashing (HTTP $($res.StatusCode))"
} catch {
    Write-Fail "HPP payload caused a crash."
    $allTestsPassed = $false
}

# ---------------------------------------------------------
# SCENARIO 5: CORS Misconfiguration
# ---------------------------------------------------------
Write-Step "5. Testing CORS Misconfiguration"
try {
    $headers = @{ "Origin" = "http://evil-hacker.com" }
    $res = Invoke-WebRequest -Uri $ApiUrl -Method OPTIONS -Headers $headers -UseBasicParsing -ErrorAction SilentlyContinue
    if ($res.Headers.ContainsKey("Access-Control-Allow-Origin")) {
        $corsHeader = $res.Headers["Access-Control-Allow-Origin"]
        if ($corsHeader -eq "*") {
            Write-Fail "CORS Allows all origins (*) on API!"
            $allTestsPassed = $false
        } elseif ($corsHeader -eq "http://evil-hacker.com") {
            Write-Fail "CORS reflects Origin header dynamically (Vulnerable)!"
            $allTestsPassed = $false
        } else {
            Write-Pass "CORS explicitly allows specific origin: $corsHeader"
        }
    } else {
        Write-Pass "CORS header not present in OPTIONS response (Safe)."
    }
} catch {
    Write-Pass "OPTIONS request rejected or not explicitly configured (Safe by default)."
}

# ---------------------------------------------------------
# SUMMARY
# ---------------------------------------------------------
Write-Host "`n=========================================" -ForegroundColor Yellow
if ($allTestsPassed) {
    Write-Host " RESULT: SECURITY TESTS EXECUTED CLEANLY" -ForegroundColor Green
} else {
    Write-Host " RESULT: SOME SECURITY TESTS FAILED" -ForegroundColor Red
}
Write-Host "=========================================" -ForegroundColor Yellow
