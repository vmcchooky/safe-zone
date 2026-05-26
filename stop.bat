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
  exit /b 1
)

docker info >nul 2>nul
if not "%ERRORLEVEL%"=="0" (
  echo [Safe Zone] Docker is not running; local containers are already stopped.
  call :cleanup_sqlite_sidecars
  exit /b 0
)

if /i "%STACK%"=="dev" goto stop_dev
if /i "%STACK%"=="local" goto stop_dev
if /i "%STACK%"=="test" goto stop_dev
if /i "%STACK%"=="development" goto stop_dev
if /i "%STACK%"=="prod" goto stop_prod
if /i "%STACK%"=="production" goto stop_prod

:usage
echo Usage: stop.bat [dev^|production]
echo.
echo   dev         Stop local test stack.
echo   production  Stop production Compose stack.
exit /b 2

:stop_dev
echo.
echo [Safe Zone] Stopping local test stack...
docker compose -f docker-compose.yml -f docker-compose.dev.yml --profile feed-sync down
set "CODE=%ERRORLEVEL%"
call :cleanup_sqlite_sidecars
if not "%CODE%"=="0" exit /b %CODE%
echo.
echo [OK] Safe Zone local stack stopped.
exit /b 0

:stop_prod
echo.
echo [Safe Zone] Stopping production stack...
docker compose -f docker-compose.yml -f docker-compose.production.yml --profile production-edge --profile feed-sync down
exit /b %ERRORLEVEL%

:cleanup_sqlite_sidecars
if exist "data\safe-zone.db-shm" del /f /q "data\safe-zone.db-shm" >nul 2>nul
if exist "data\safe-zone.db-wal" del /f /q "data\safe-zone.db-wal" >nul 2>nul
exit /b 0
