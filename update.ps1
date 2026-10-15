# Stop containers, back up compose + wordlists, pull latest code, rebuild, and
# bring the stack back up. DB migrations run automatically on API startup (§12).
$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$backupDir = Join-Path "backups" $stamp

Write-Host "==> Stopping stack"
docker compose down

New-Item -ItemType Directory -Force -Path $backupDir | Out-Null
foreach ($path in @("docker-compose.yml", ".env", "wordlists", "custom-templates")) {
    if (Test-Path -LiteralPath $path) {
        Copy-Item -LiteralPath $path -Destination $backupDir -Recurse -Force
    }
}
Write-Host "==> Backed up configuration to $backupDir"

Write-Host "==> Pulling latest code"
git pull --ff-only

Write-Host "==> Rebuilding images sequentially"
& (Join-Path $PSScriptRoot "build.ps1")

Write-Host "==> Starting stack (migrations run on API boot)"
docker compose up -d

Write-Host "==> Update complete"
