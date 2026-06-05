param (
    [string]$TargetHost = "experiment-mode"
)

Write-Host "Packaging safe-zone source code..." -ForegroundColor Cyan
tar -czf deploy.tar.gz --exclude=.git --exclude=tmp --exclude=backups --exclude=data --exclude=ops/certs --exclude=.env --exclude=deploy.tar.gz .

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
ssh $TargetHost "sudo tar -xzf /tmp/deploy.tar.gz -C /opt/safe-zone && cd /opt/safe-zone && sudo chmod +x ./scripts/*.sh && ./scripts/safe-zone.sh deploy"

if ($LASTEXITCODE -ne 0) {
    Write-Host "Deployment on VPS failed!" -ForegroundColor Red
    exit $LASTEXITCODE
}

Write-Host "Deployment completed successfully!" -ForegroundColor Green
