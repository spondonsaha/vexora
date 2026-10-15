# Sequential image build (§12). Parallel builds of many source-compiled tool
# images race on Docker's image store; build one service at a time.
$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot

$services = @("api", "worker", "client", "mcp-server")

Write-Host "==> Building self-hosted tool images"
& "$PSScriptRoot\build-tools.ps1"
if ($LASTEXITCODE -ne 0) { throw "tool image build failed" }

Write-Host "==> Building $($services.Count) service image(s) sequentially"
foreach ($svc in $services) {
    Write-Host "==> Building $svc ..."
    docker compose build $svc
    if ($LASTEXITCODE -ne 0) { throw "build failed for $svc" }
}

Write-Host "==> All images built. Start the stack with: docker compose up -d"
