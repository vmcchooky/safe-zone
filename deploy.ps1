param (
    [string]$TargetHost = "experiment-mode",
    [string]$RemoteDir = "~/safe-zone",
    [string]$BuildVersion = "",
    [string]$BuildCommit = ""
)

# Resolve build metadata from the LOCAL checkout so production reports the
# deployed SHA even when the remote .git clone is stale. The server-side
# deploy prefers these env values over git (see set_build_metadata_env).
if ([string]::IsNullOrWhiteSpace($BuildCommit)) {
    $BuildCommit = (& git rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($BuildCommit)) {
        Write-Host "Cannot resolve git commit for version stamping!" -ForegroundColor Red
        exit 1
    }
}
if ([string]::IsNullOrWhiteSpace($BuildVersion)) {
    $BuildVersion = (& git rev-parse --short HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($BuildVersion)) {
        Write-Host "Cannot resolve git version for version stamping!" -ForegroundColor Red
        exit 1
    }
}
Write-Host "Deploying $BuildVersion ($BuildCommit) to ${TargetHost}:${RemoteDir}..." -ForegroundColor Cyan

Write-Host "Packaging safe-zone source code..." -ForegroundColor Cyan
# ops/secrets and deploy/model-bundle are host-local state (production
# credentials, downloaded ML bundles): never ship dev copies over them, and
# never fail extraction on their protected permissions. The remote skeleton
# dirs are created below for fresh installs.
tar -czf deploy.tar.gz --exclude=.git --exclude=tmp --exclude=backups --exclude=data --exclude=ops/certs --exclude=ops/secrets --exclude=deploy/model-bundle --exclude=.env --exclude=deploy.tar.gz .

if ($LASTEXITCODE -ne 0) {
    Write-Host "Packaging failed!" -ForegroundColor Red
    exit $LASTEXITCODE
}

Write-Host "Uploading to VPS ($TargetHost)..." -ForegroundColor Cyan
scp deploy.tar.gz ${TargetHost}:/tmp/

if ($LASTEXITCODE -ne 0) {
    Write-Host "Upload failed!" -ForegroundColor Red
    exit $LASTEXITCODE
}

Write-Host "Extracting and deploying on VPS..." -ForegroundColor Cyan
# No sudo: the project tree is owned by the deploy user; protected
# host-local dirs keep their permissions and are never overwritten.
$remoteCmd = "mkdir -p `"${RemoteDir}/ops/secrets`" `"${RemoteDir}/deploy/model-bundle/current`" && tar -xzf /tmp/deploy.tar.gz -C `"${RemoteDir}`" && cd `"${RemoteDir}`" && chmod +x ./scripts/*/*.sh && SAFE_ZONE_BUILD_VERSION=`"${BuildVersion}`" SAFE_ZONE_BUILD_GIT_COMMIT=`"${BuildCommit}`" ./scripts/ops/safe-zone.sh deploy; rm -f /tmp/deploy.tar.gz"
ssh $TargetHost $remoteCmd

if ($LASTEXITCODE -ne 0) {
    Write-Host "Deployment on VPS failed!" -ForegroundColor Red
    exit $LASTEXITCODE
}

# Best-effort post-deploy check: the running build must report the SHA we
# just shipped. A mismatch fails the script because it means production is
# not running the deployed code.
Write-Host "Verifying deployed version..." -ForegroundColor Cyan
$reported = ssh $TargetHost "docker exec safe-zone-core-api-1 wget -qO- http://localhost:8080/v1/version" 2>$null
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($reported) -or ($reported -notmatch [regex]::Escape($BuildVersion))) {
    Write-Host "Version mismatch! Expected $BuildVersion in: $reported" -ForegroundColor Red
    exit 1
}

Write-Host "Deployment completed successfully! Production reports $BuildVersion." -ForegroundColor Green
