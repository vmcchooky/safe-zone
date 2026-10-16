@echo off
setlocal EnableExtensions

cd /d "%~dp0"

set "STACK=%~1"
if "%STACK%"=="" set "STACK=dev"

if /i "%STACK%"=="dev" goto prerequisites
if /i "%STACK%"=="local" goto prerequisites
if /i "%STACK%"=="test" goto prerequisites
if /i "%STACK%"=="development" goto prerequisites
if /i "%STACK%"=="prod" goto prerequisites
if /i "%STACK%"=="production" goto prerequisites
goto usage

:prerequisites
where docker >nul 2>nul
if not "%ERRORLEVEL%"=="0" (
  echo [ERROR] Docker was not found on PATH.
  echo Install Docker Desktop, start it, then run start.bat again.
  exit /b 1
)

docker info >nul 2>nul
if not "%ERRORLEVEL%"=="0" (
  echo [ERROR] Docker is not running.
  echo Start Docker Desktop, wait until it is ready, then run start.bat again.
  exit /b 1
)

where pwsh >nul 2>nul
if "%ERRORLEVEL%"=="0" (
  set "PS_EXE=pwsh"
) else (
  set "PS_EXE=powershell"
)

if /i "%STACK%"=="dev" goto start_dev
if /i "%STACK%"=="local" goto start_dev
if /i "%STACK%"=="test" goto start_dev
if /i "%STACK%"=="development" goto start_dev
if /i "%STACK%"=="prod" goto start_prod
if /i "%STACK%"=="production" goto start_prod

:usage
echo Usage: start.bat [dev^|production]
echo.
echo   dev         Start local test stack on:
echo               - Operator UI:   http://127.0.0.1:8080/app/
echo               - DNS resolver:  http://127.0.0.1:8081/healthz
echo   production  Start production Compose stack.
exit /b 2

:start_dev
call :ensure_local_env
if errorlevel 1 exit /b %ERRORLEVEL%

echo.
echo [Safe Zone] Starting local test stack...
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --build
if errorlevel 1 exit /b %ERRORLEVEL%

call :wait_health "http://127.0.0.1:8080/healthz" "core-api"
if errorlevel 1 exit /b %ERRORLEVEL%
call :wait_health "http://127.0.0.1:8081/healthz" "dns-resolver"
if errorlevel 1 exit /b %ERRORLEVEL%

echo.
echo [OK] Safe Zone local stack is ready.
echo.
echo Operator UI: http://127.0.0.1:8080/app/
echo Core API:   http://127.0.0.1:8080/healthz
echo Resolver:   http://127.0.0.1:8081/healthz
echo.
echo Login:
echo   username: admin
echo   password: (printed above when .env was prepared; stored in local .env only)
echo.
echo Quick test:
echo   http://127.0.0.1:8080/v1/analyze?domain=dichvucong-vn.com
echo.
exit /b 0

:start_prod
echo.
echo [Safe Zone] Starting production stack...
"%PS_EXE%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\ops\safe-zone.ps1" deploy
exit /b %ERRORLEVEL%

:ensure_local_env
if not exist ".env" (
  if exist ".env.example" (
    copy ".env.example" ".env" >nul
    echo [Safe Zone] Created .env from .env.example.
  ) else (
    echo [ERROR] .env is missing and .env.example was not found.
    exit /b 1
  )
)

"%PS_EXE%" -NoProfile -ExecutionPolicy Bypass -Command ^
  "$path = Join-Path (Get-Location) '.env';" ^
  "$text = Get-Content -Raw -Path $path;" ^
  "$pairs = [ordered]@{" ^
  "  'SAFE_ZONE_ENV'='local';" ^
  "  'SAFE_ZONE_CORE_API_ADDR'=':8080';" ^
  "  'SAFE_ZONE_DNS_RESOLVER_ADDR'=':8081';" ^
  "  'SAFE_ZONE_REDIS_ADDR'='redis:6379';" ^
  "  'SAFE_ZONE_OSINT_ENABLED'='true';" ^
  "  'SAFE_ZONE_OSINT_MODE'='background_on_demand';" ^
  "  'SAFE_ZONE_OSINT_TIMEOUT_MS'='2000';" ^
  "  'SAFE_ZONE_OSINT_CACHE_TTL_SECONDS'='21600';" ^
  "  'SAFE_ZONE_OSINT_TRUSTED_DOMAINS'='gov.vn,bocongan.gov.vn,mps.gov.vn,baochinhphu.vn,thanhnien.vn,tuoitre.vn,vnexpress.net,vietnamnet.vn,nhandan.vn,vtv.vn,vov.vn';" ^
  "};" ^
  "foreach ($key in $pairs.Keys) {" ^
  "  $pattern = '(?m)^\s*' + [regex]::Escape($key) + '\s*=';" ^
  "  if ($text -match $pattern) {" ^
  "    $text = [regex]::Replace($text, '(?m)^\s*' + [regex]::Escape($key) + '\s*=.*$', $key + '=' + $pairs[$key]);" ^
  "  } else {" ^
  "    if (-not $text.EndsWith([Environment]::NewLine)) { $text += [Environment]::NewLine }" ^
  "    $text += $key + '=' + $pairs[$key] + [Environment]::NewLine;" ^
  "  }" ^
  "}" ^
  "function New-DevSecret([int]$len) {" ^
  "  $alphabet = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789'.ToCharArray();" ^
  "  $rng = [System.Security.Cryptography.RNGCryptoServiceProvider]::new();" ^
  "  try {" ^
  "    $bytes = New-Object byte[] $len;" ^
  "    $rng.GetBytes($bytes);" ^
  "    -join ($bytes | ForEach-Object { $alphabet[$_ % $alphabet.Length] });" ^
  "  } finally { $rng.Dispose(); }" ^
  "};" ^
  "$secrets = [ordered]@{'SAFE_ZONE_ADMIN_PASSWORD'=24; 'SAFE_ZONE_ADMIN_API_KEY'=32};" ^
  "$shown = @{};" ^
  "foreach ($key in $secrets.Keys) {" ^
  "  $m = [regex]::Match($text, '(?m)^[ \t]*' + [regex]::Escape($key) + '[ \t]*=[ \t]*(.*?)[ \t]*$');" ^
  "  $existing = $m.Groups[1].Value.Trim();" ^
  "  if ($m.Success -and $existing -ne '') { $shown[$key] = $existing; }" ^
  "  else {" ^
  "    $v = New-DevSecret $secrets[$key];" ^
  "    if (-not $text.EndsWith([Environment]::NewLine)) { $text += [Environment]::NewLine }" ^
  "    $text += $key + '=' + $v + [Environment]::NewLine;" ^
  "    $shown[$key] = $v;" ^
  "    Write-Host ('[Safe Zone] Generated dev-only ' + $key + ' (local .env only; set a real secret for production).');" ^
  "  }" ^
  "};" ^
  "Set-Content -Path $path -Value $text -NoNewline;" ^
  "Write-Host 'Login:';" ^
  "Write-Host '  username: admin';" ^
  "Write-Host ('  password: ' + $shown['SAFE_ZONE_ADMIN_PASSWORD']);"
if errorlevel 1 (
  echo [ERROR] Could not prepare local .env.
  exit /b 1
)
exit /b 0

:wait_health
set "URL=%~1"
set "NAME=%~2"
echo [Safe Zone] Waiting for %NAME%...
"%PS_EXE%" -NoProfile -ExecutionPolicy Bypass -Command ^
  "$url='%URL%'; $name='%NAME%'; $deadline=(Get-Date).AddSeconds(90);" ^
  "while ((Get-Date) -lt $deadline) {" ^
  "  try { $r=Invoke-WebRequest -Uri $url -Method Get -TimeoutSec 3; if ($r.StatusCode -eq 200) { exit 0 } } catch {}" ^
  "  Start-Sleep -Milliseconds 700" ^
  "}" ^
  "Write-Host ('[ERROR] ' + $name + ' did not become healthy: ' + $url); exit 1"
exit /b %ERRORLEVEL%
